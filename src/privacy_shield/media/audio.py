"""
Privacy Shield - Audio Processing

Speech-to-text transcription and audio metadata extraction.
All processing is 100% local - no external API calls.
"""

from __future__ import annotations

import logging
import os
import tempfile
import wave
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from ._tools import channel_unavailable, operand, run_tool, tool_available

logger = logging.getLogger(__name__)


@dataclass
class TranscriptSegment:
    """A segment of transcribed audio."""
    text: str
    start_time: float  # seconds
    end_time: float
    confidence: float
    speaker: Optional[str] = None  # For diarization
    language: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "confidence": self.confidence,
            "speaker": self.speaker,
            "language": self.language,
        }


@dataclass
class AudioMetadata:
    """Metadata extracted from audio file."""
    duration_seconds: float
    sample_rate: int
    channels: int
    format: str
    bitrate: Optional[int] = None
    title: Optional[str] = None
    artist: Optional[str] = None
    album: Optional[str] = None
    year: Optional[str] = None
    comment: Optional[str] = None
    pii_fields: List[str] = field(default_factory=list)
    raw_tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "duration_seconds": self.duration_seconds,
            "sample_rate": self.sample_rate,
            "channels": self.channels,
            "format": self.format,
            "bitrate": self.bitrate,
            "title": self.title,
            "artist": self.artist,
            "album": self.album,
            "year": self.year,
            "comment": self.comment,
            "pii_fields": self.pii_fields,
        }


@dataclass
class AudioResult:
    """Result of audio processing."""
    file_path: str
    metadata: AudioMetadata
    segments: List[TranscriptSegment] = field(default_factory=list)
    full_transcript: str = ""
    processing_time_ms: float = 0.0
    stt_engine: Optional[str] = None
    detected_language: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    @property
    def has_transcript(self) -> bool:
        return len(self.full_transcript.strip()) > 0

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "metadata": self.metadata.to_dict(),
            "segment_count": len(self.segments),
            "transcript_length": len(self.full_transcript),
            "processing_time_ms": self.processing_time_ms,
            "stt_engine": self.stt_engine,
            "detected_language": self.detected_language,
            "errors": self.errors,
        }


def _check_ffmpeg() -> bool:
    """Check if ffmpeg is available."""
    return tool_available("ffmpeg")


def _check_ffprobe() -> bool:
    """Check if ffprobe is available."""
    return tool_available("ffprobe")


def _extract_audio_metadata(
    file_path: Path,
    errors: Optional[List[str]] = None,
) -> AudioMetadata:
    """Extract metadata from audio file using ffprobe and local fallbacks.

    Appends a channel-unavailable error to *errors* when no tag reader is
    present. ID3 frames are a PII channel of their own - TPE1 names a person,
    COMM is free text, APIC is a photograph - and the only two readers here are
    ffprobe and mutagen, neither declared by any extra. With both absent this
    returned `pii_fields=[]`, which reads as "no personal data in the tags" and
    meant "no reader opened the tags".
    """
    metadata = AudioMetadata(
        duration_seconds=0.0,
        sample_rate=0,
        channels=0,
        format="unknown",
    )

    have_ffprobe = _check_ffprobe()
    if have_ffprobe:
        try:
            _extract_av_metadata(file_path, metadata)
        except Exception as exc:
            logger.debug("Primary audio tag extraction failed for %s: %s", file_path, exc)
            have_ffprobe = False

    have_mutagen = False
    try:
        from mutagen import File as MutagenFile
        audio = MutagenFile(str(file_path))
        # Set on a successful PARSE, not on a successful import - the ffprobe
        # branch above already worked this way and this one did not. mutagen
        # raises HeaderNotFoundError on a container it cannot sync to, and with
        # the flag already True the handler below left `have_mutagen` set, so a
        # malformed or truncated mp3 - the attacker-controlled case - reported
        # `pii_fields=[]` and NO container_tags marker while TPE1 and COMM sat
        # in the bytes. `audio` is None when mutagen does not recognise the
        # container at all, which is also a channel that did not run; an object
        # with `tags is None` is a real read of a file that has no tags.
        have_mutagen = audio is not None
        if audio:
            info = getattr(audio, "info", None)
            if info is not None:
                if not metadata.duration_seconds:
                    metadata.duration_seconds = float(getattr(info, "length", 0.0) or 0.0)
                if not metadata.sample_rate:
                    metadata.sample_rate = int(getattr(info, "sample_rate", 0) or 0)
                if not metadata.channels:
                    metadata.channels = int(getattr(info, "channels", 0) or 0)
                if metadata.bitrate is None:
                    raw_bitrate = getattr(info, "bitrate", None)
                    metadata.bitrate = int(raw_bitrate) if raw_bitrate else None
            if audio.tags:
                for key in audio.tags.keys():
                    value = str(audio.tags[key])
                    metadata.raw_tags[str(key)] = value[:200]
                _apply_audio_tags(metadata, dict(audio.tags))
    except ImportError as exc:
        logger.debug("Mutagen not installed: %s", exc)
    except Exception as exc:
        logger.debug("Mutagen audio metadata extraction failed for %s: %s", file_path, exc)
        have_mutagen = False

    if file_path.suffix.lower() == ".wav":
        try:
            _extract_wave_metadata(file_path, metadata)
        except Exception as exc:
            logger.debug("Wave metadata extraction failed for %s: %s", file_path, exc)

    if metadata.format == "unknown":
        metadata.format = file_path.suffix.lower().lstrip(".") or "unknown"

    # `wave` is in the standard library but reads only RIFF geometry - never a
    # tag - so it does not make this channel available.
    if errors is not None and not have_ffprobe and not have_mutagen:
        errors.append(
            channel_unavailable(
                "container_tags",
                "no tag reader available (need ffprobe on PATH or `pip install mutagen`)",
            )
        )

    return metadata


_NAMED_ATTRS = {
    "title": "title",
    "artist": "artist",
    "album": "album",
    "date": "year",
    "year": "year",
    "comment": "comment",
}


def _apply_audio_tags(metadata: AudioMetadata, tags: Dict[str, Any]) -> None:
    """Record every tag present, and flag the PII ones by the shared taxonomy.

    This used to iterate a hardcoded six-key map and flag exactly two of them
    (`artist`, `comment`), which lost three things at once: every ID3 frame id
    (mutagen keys an mp3's tags `TPE1`/`COMM::eng`, none of which were in the
    map, so a fully installed mutagen still reported no tag PII); every field
    the map did not list (composer, lyricist, encodedby, owner, publisher, the
    QuickTime `©`-prefixed forms); and cover art, which is a photograph. The
    classification now comes from `metadata.tag_pii_type`, the one table.
    """
    from .metadata import normalise_tag_key, tag_pii_type

    for tag_key in list(tags):
        raw_value = tags[tag_key]
        if isinstance(raw_value, (list, tuple)):
            value = str(raw_value[0]) if raw_value else ""
        else:
            value = str(raw_value)

        name = normalise_tag_key(tag_key)
        pii_type = tag_pii_type(tag_key)

        # An embedded payload (APIC cover art, GEOB) has no text value worth
        # recording, and its presence is the whole finding.
        if pii_type == "embedded_payload":
            if name not in metadata.pii_fields:
                metadata.pii_fields.append(name)
            continue

        if not value:
            continue

        attr = _NAMED_ATTRS.get(name)
        if attr:
            setattr(metadata, attr, value)
        metadata.raw_tags[str(tag_key)] = value[:200]
        if pii_type and name not in metadata.pii_fields:
            metadata.pii_fields.append(name)


def _extract_wave_metadata(file_path: Path, metadata: AudioMetadata) -> None:
    with wave.open(str(file_path), "rb") as wav_file:
        frames = wav_file.getnframes()
        sample_rate = wav_file.getframerate()
        channels = wav_file.getnchannels()
        sample_width = wav_file.getsampwidth()

    if sample_rate and not metadata.sample_rate:
        metadata.sample_rate = int(sample_rate)
    if channels and not metadata.channels:
        metadata.channels = int(channels)
    if frames and sample_rate and not metadata.duration_seconds:
        metadata.duration_seconds = frames / float(sample_rate)
    if sample_width and sample_rate and channels and metadata.bitrate is None:
        metadata.bitrate = int(sample_width * sample_rate * channels * 8)
    if metadata.format == "unknown":
        metadata.format = "wav"


def _extract_av_metadata(file_path: Path, metadata: AudioMetadata) -> None:
    result = run_tool(
        [
            "ffprobe",
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            "-i", operand(file_path),
        ],
        text=True,
    )

    import json
    data = json.loads(result.stdout)

    fmt = data.get("format", {})
    metadata.format = fmt.get("format_name", metadata.format or "unknown")
    metadata.duration_seconds = float(fmt.get("duration", metadata.duration_seconds or 0))
    metadata.bitrate = int(fmt.get("bit_rate", 0)) if fmt.get("bit_rate") else metadata.bitrate

    seen_audio = False
    for stream in data.get("streams", []):
        if stream.get("codec_type") == "audio" and not seen_audio:
            seen_audio = True
            if not metadata.sample_rate:
                metadata.sample_rate = int(stream.get("sample_rate", 0))
            if not metadata.channels:
                metadata.channels = int(stream.get("channels", 0))
        # Cover art is carried as a video stream with the attached_pic
        # disposition. It is a photograph inside the audio file, with its own
        # EXIF block, and it is not a format-level tag - so reading only
        # `format.tags` never saw it.
        if stream.get("disposition", {}).get("attached_pic"):
            if "picture" not in metadata.pii_fields:
                metadata.pii_fields.append("picture")
        # Per-stream tags, which the format-level read also skipped.
        _apply_audio_tags(metadata, stream.get("tags", {}) or {})

    _apply_audio_tags(metadata, fmt.get("tags", {}))


def _convert_to_wav(input_path: Path, output_path: Path) -> bool:
    """Convert audio to WAV format for processing."""
    if not _check_ffmpeg():
        return False

    try:
        run_tool(
            [
                "ffmpeg",
                "-nostdin",
                "-i", operand(input_path),
                "-ar", "16000",  # 16kHz for speech
                "-ac", "1",  # Mono
                "-c:a", "pcm_s16le",
                "-y",  # Overwrite
                operand(output_path),
            ]
        )
        return True
    except Exception as exc:
        logger.debug("Audio conversion to wav failed for %s: %s", input_path, exc)
        return False


class AudioProcessor:
    """
    Process audio files for PII detection.

    Supports:
    - Speech-to-text transcription (Whisper, Vosk)
    - Audio metadata extraction
    - Speaker diarization (optional)

    All processing is 100% local.
    """

    def __init__(
        self,
        stt_engine: str = "auto",
        model_size: str = "base",
        language: Optional[str] = None,
        enable_diarization: bool = False,
    ):
        """
        Initialize the audio processor.

        Args:
            stt_engine: STT engine ('whisper', 'faster-whisper', 'vosk', 'auto').
            model_size: Model size for Whisper ('tiny', 'base', 'small', 'medium', 'large').
            language: Language code (None for auto-detect).
            enable_diarization: Whether to separate speakers.
        """
        self.stt_engine_name = stt_engine
        self.model_size = model_size
        self.language = language
        self.enable_diarization = enable_diarization

        # Lazy-loaded engines
        self._stt_engine: Any = None
        self._stt_model: Any = None

    def _init_stt(self) -> Tuple[Any, str]:
        """Initialize speech-to-text engine."""
        if self._stt_engine is not None:
            return self._stt_engine, self.stt_engine_name

        engine_name = self.stt_engine_name

        # Try faster-whisper first (best performance)
        if engine_name in ("auto", "faster-whisper"):
            try:
                from faster_whisper import WhisperModel
                self._stt_model = WhisperModel(
                    self.model_size,
                    device="cpu",
                    compute_type="int8",
                )
                self._stt_engine = "faster_whisper"
                self.stt_engine_name = "faster-whisper"
                return self._stt_model, "faster-whisper"
            except ImportError:
                if engine_name == "faster-whisper":
                    raise ImportError(
                        "faster-whisper not installed. Install with: pip install faster-whisper"
                    )

        # Try whisper.cpp via python bindings
        if engine_name in ("auto", "whisper"):
            try:
                import whisper
                self._stt_model = whisper.load_model(self.model_size)
                self._stt_engine = "whisper"
                self.stt_engine_name = "whisper"
                return self._stt_model, "whisper"
            except ImportError:
                if engine_name == "whisper":
                    raise ImportError(
                        "whisper not installed. Install with: pip install openai-whisper"
                    )

        # Try Vosk
        if engine_name in ("auto", "vosk"):
            try:
                from vosk import Model, KaldiRecognizer
                # Vosk requires model download
                model_path = os.path.expanduser("~/.cache/vosk/vosk-model-small-en-us-0.15")
                if os.path.exists(model_path):
                    self._stt_model = Model(model_path)
                    self._stt_engine = "vosk"
                    self.stt_engine_name = "vosk"
                    return self._stt_model, "vosk"
                elif engine_name == "vosk":
                    raise ImportError(f"Vosk model not found at {model_path}")
            except ImportError:
                if engine_name == "vosk":
                    raise ImportError("vosk not installed. Install with: pip install vosk")

        raise ImportError(f"No STT engine available. Tried: {engine_name}")

    def _transcribe_whisper(self, audio_path: Path) -> List[TranscriptSegment]:
        """Transcribe using OpenAI Whisper."""
        segments: List[TranscriptSegment] = []

        try:
            result = self._stt_model.transcribe(
                str(audio_path),
                language=self.language,
            )

            for seg in result.get("segments", []):
                segments.append(TranscriptSegment(
                    text=seg["text"].strip(),
                    start_time=seg["start"],
                    end_time=seg["end"],
                    confidence=seg.get("avg_logprob", 0.0),
                    language=result.get("language"),
                ))
        except Exception as exc:
            logger.debug("Whisper transcription failed for %s: %s", audio_path, exc)

        return segments

    def _transcribe_faster_whisper(self, audio_path: Path) -> List[TranscriptSegment]:
        """Transcribe using faster-whisper."""
        segments: List[TranscriptSegment] = []

        try:
            result_segments, info = self._stt_model.transcribe(
                str(audio_path),
                language=self.language,
                beam_size=5,
            )

            for seg in result_segments:
                segments.append(TranscriptSegment(
                    text=seg.text.strip(),
                    start_time=seg.start,
                    end_time=seg.end,
                    confidence=seg.avg_logprob if hasattr(seg, 'avg_logprob') else 0.8,
                    language=info.language,
                ))
        except Exception as exc:
            logger.debug("Faster-whisper transcription failed for %s: %s", audio_path, exc)

        return segments

    def _transcribe_vosk(self, audio_path: Path) -> List[TranscriptSegment]:
        """Transcribe using Vosk."""
        segments: List[TranscriptSegment] = []

        try:
            import json
            import wave
            from vosk import KaldiRecognizer

            wf = wave.open(str(audio_path), "rb")
            rec = KaldiRecognizer(self._stt_model, wf.getframerate())
            rec.SetWords(True)

            while True:
                data = wf.readframes(4000)
                if len(data) == 0:
                    break
                rec.AcceptWaveform(data)

            final_result = json.loads(rec.FinalResult())
            if "result" in final_result:
                for word_info in final_result["result"]:
                    segments.append(TranscriptSegment(
                        text=word_info["word"],
                        start_time=word_info["start"],
                        end_time=word_info["end"],
                        confidence=word_info.get("conf", 0.8),
                    ))
        except Exception as exc:
            logger.debug("Vosk transcription failed for %s: %s", audio_path, exc)

        return segments

    def process(self, file_path: Union[str, Path]) -> AudioResult:
        """
        Process an audio file for PII detection.

        Args:
            file_path: Path to the audio file.

        Returns:
            AudioResult with transcript and metadata.
        """
        import time
        start_time = time.perf_counter()

        path = Path(file_path)
        result = AudioResult(
            file_path=str(path),
            metadata=AudioMetadata(0, 0, 0, "unknown"),
        )

        if not path.exists():
            result.errors.append(f"File not found: {path}")
            return result

        # Extract metadata
        result.metadata = _extract_audio_metadata(path, result.errors)

        # Initialize STT engine
        try:
            _, engine_name = self._init_stt()
            result.stt_engine = engine_name
        except ImportError as e:
            result.errors.append(channel_unavailable("speech_to_text", e))
            result.processing_time_ms = (time.perf_counter() - start_time) * 1000
            return result

        # Convert to WAV only for engines that require PCM input.
        suffix = path.suffix.lower()
        transcription_path = path

        if self.stt_engine_name != "faster-whisper" and suffix not in (".wav",):
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                transcription_path = Path(tmp.name)

            if not _convert_to_wav(path, transcription_path):
                result.errors.append(
                    channel_unavailable(
                        "speech_to_text",
                        "could not decode to wav (need ffmpeg on PATH)",
                    )
                )
                result.processing_time_ms = (time.perf_counter() - start_time) * 1000
                return result

        # Run transcription
        try:
            if self.stt_engine_name == "faster-whisper":
                result.segments = self._transcribe_faster_whisper(transcription_path)
            elif self.stt_engine_name == "whisper":
                result.segments = self._transcribe_whisper(transcription_path)
            elif self.stt_engine_name == "vosk":
                result.segments = self._transcribe_vosk(transcription_path)

            # Build full transcript
            result.full_transcript = " ".join(
                seg.text for seg in result.segments
            )

            # Detect language from first segment
            if result.segments:
                result.detected_language = result.segments[0].language

        except Exception as e:
            result.errors.append(f"Transcription error: {str(e)}")

        # Cleanup temp file
        if transcription_path != path and transcription_path.exists():
            try:
                transcription_path.unlink()
            except Exception as exc:
                logger.debug("Failed to remove temporary wav file %s: %s", transcription_path, exc)

        result.processing_time_ms = (time.perf_counter() - start_time) * 1000

        return result

    def redact_audio(
        self,
        file_path: Union[str, Path],
        output_path: Union[str, Path],
        segments_to_redact: List[TranscriptSegment],
        redaction_type: str = "silence",
    ) -> bool:
        """
        Create a redacted version of an audio file.

        Args:
            file_path: Input audio path.
            output_path: Output audio path.
            segments_to_redact: Segments to silence. May be empty: the tags and
                any cover art are redacted regardless.
            redaction_type: 'silence' (the only implemented behaviour).

        Returns:
            True only if a redacted file was written.

        **This used to copy the input to the output byte for byte and return
        True whenever `segments_to_redact` was empty**, which is the state the
        caller is in whenever transcription found nothing - and no STT engine is
        declared by any extra of this package, so "found nothing" is the default
        outcome. The artefact cleared for egress was the original file: ID3
        artist, COMM free text, cover art, every byte. An empty segment list is
        not a reason to skip redaction, because the tags and the attached
        picture are PII channels of their own; it only means there is no speech
        to silence.
        """
        if not _check_ffmpeg():
            return False

        if redaction_type not in ("silence", "beep"):
            logger.debug("unknown redaction_type %r", redaction_type)
            return False
        if redaction_type == "beep":
            # `beep` built the identical `volume=0` filtergraph as `silence`, so
            # the documented option did nothing. Refuse rather than silently
            # substitute: a caller who asked for an audible marker and got
            # silence cannot tell a redacted gap from a pause in the recording.
            logger.debug("redaction_type='beep' is not implemented")
            return False

        try:
            filter_parts = []
            for seg in sorted(segments_to_redact or [], key=lambda s: float(s.start_time)):
                # float() rather than interpolating the attribute: a
                # TranscriptSegment is a plain dataclass with no validation, and
                # these values are formatted straight into an ffmpeg
                # filtergraph, where a string would be read as filter syntax.
                start = float(seg.start_time)
                end = float(seg.end_time)
                filter_parts.append(
                    f"volume=enable='between(t,{start!r},{end!r})':volume=0"
                )

            filter_str = ",".join(filter_parts) if filter_parts else "anull"

            run_tool(
                [
                    "ffmpeg",
                    "-nostdin",
                    "-i", operand(file_path),
                    # Take the audio and only the audio. Cover art rides along
                    # as an attached_pic video stream and ffmpeg's default
                    # stream selection would have copied it into the output.
                    "-map", "0:a",
                    "-vn",
                    "-af", filter_str,
                    # Container tags are PII (artist, comment, copyright) and
                    # ffmpeg copies them by default; -1 means copy from nowhere.
                    # The `:s` form is needed as well because per-stream tags
                    # are not covered by the global one.
                    "-map_metadata", "-1",
                    "-map_metadata:s", "-1",
                    "-y",
                    operand(output_path),
                ]
            )
            return True

        except Exception as exc:
            logger.debug("redact_audio failed for %s: %s", file_path, exc)
            return False
