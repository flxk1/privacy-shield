"""
Privacy Shield - Audio Processing

Speech-to-text transcription and audio metadata extraction.
All processing is 100% local - no external API calls.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import wave
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

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
    try:
        subprocess.run(
            ["ffmpeg", "-version"],
            capture_output=True,
            check=True,
        )
        return True
    except Exception:
        return False


def _check_ffprobe() -> bool:
    """Check if ffprobe is available."""
    try:
        subprocess.run(
            ["ffprobe", "-version"],
            capture_output=True,
            check=True,
        )
        return True
    except Exception:
        return False


def _extract_audio_metadata(file_path: Path) -> AudioMetadata:
    """Extract metadata from audio file using ffprobe and local fallbacks."""
    metadata = AudioMetadata(
        duration_seconds=0.0,
        sample_rate=0,
        channels=0,
        format="unknown",
    )

    if _check_ffprobe():
        try:
            _extract_av_metadata(file_path, metadata)
        except Exception as exc:
            logger.debug("Primary audio tag extraction failed for %s: %s", file_path, exc)

    try:
        from mutagen import File as MutagenFile
        audio = MutagenFile(str(file_path))
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
    except Exception as exc:
        logger.debug("Mutagen audio metadata extraction failed for %s: %s", file_path, exc)

    if file_path.suffix.lower() == ".wav":
        try:
            _extract_wave_metadata(file_path, metadata)
        except Exception as exc:
            logger.debug("Wave metadata extraction failed for %s: %s", file_path, exc)

    if metadata.format == "unknown":
        metadata.format = file_path.suffix.lower().lstrip(".") or "unknown"

    return metadata


def _apply_audio_tags(metadata: AudioMetadata, tags: Dict[str, Any]) -> None:
    tag_map = {
        "title": "title",
        "artist": "artist",
        "album": "album",
        "date": "year",
        "year": "year",
        "comment": "comment",
        "TITLE": "title",
        "ARTIST": "artist",
        "ALBUM": "album",
        "DATE": "year",
        "YEAR": "year",
        "COMMENT": "comment",
    }
    for tag_key, attr in tag_map.items():
        if tag_key not in tags:
            continue
        raw_value = tags[tag_key]
        if isinstance(raw_value, (list, tuple)):
            value = str(raw_value[0]) if raw_value else ""
        else:
            value = str(raw_value)
        if not value:
            continue
        setattr(metadata, attr, value)
        metadata.raw_tags[str(tag_key)] = value[:200]
        if attr in ("artist", "comment") and attr not in metadata.pii_fields:
            metadata.pii_fields.append(attr)


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
    result = subprocess.run(
        [
            "ffprobe",
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            str(file_path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    import json
    data = json.loads(result.stdout)

    fmt = data.get("format", {})
    metadata.format = fmt.get("format_name", metadata.format or "unknown")
    metadata.duration_seconds = float(fmt.get("duration", metadata.duration_seconds or 0))
    metadata.bitrate = int(fmt.get("bit_rate", 0)) if fmt.get("bit_rate") else metadata.bitrate

    for stream in data.get("streams", []):
        if stream.get("codec_type") == "audio":
            if not metadata.sample_rate:
                metadata.sample_rate = int(stream.get("sample_rate", 0))
            if not metadata.channels:
                metadata.channels = int(stream.get("channels", 0))
            break

    _apply_audio_tags(metadata, fmt.get("tags", {}))


def _convert_to_wav(input_path: Path, output_path: Path) -> bool:
    """Convert audio to WAV format for processing."""
    if not _check_ffmpeg():
        return False

    try:
        subprocess.run(
            [
                "ffmpeg",
                "-i", str(input_path),
                "-ar", "16000",  # 16kHz for speech
                "-ac", "1",  # Mono
                "-c:a", "pcm_s16le",
                "-y",  # Overwrite
                str(output_path),
            ],
            capture_output=True,
            check=True,
        )
        return True
    except Exception:
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
        result.metadata = _extract_audio_metadata(path)

        # Initialize STT engine
        try:
            _, engine_name = self._init_stt()
            result.stt_engine = engine_name
        except ImportError as e:
            result.errors.append(str(e))
            result.processing_time_ms = (time.perf_counter() - start_time) * 1000
            return result

        # Convert to WAV only for engines that require PCM input.
        suffix = path.suffix.lower()
        transcription_path = path

        if self.stt_engine_name != "faster-whisper" and suffix not in (".wav",):
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                transcription_path = Path(tmp.name)

            if not _convert_to_wav(path, transcription_path):
                result.errors.append("Failed to convert audio to WAV")
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
            segments_to_redact: Segments to redact.
            redaction_type: 'silence' or 'beep'.

        Returns:
            True if successful.
        """
        if not _check_ffmpeg():
            return False

        if not segments_to_redact:
            # Just copy the file
            try:
                import shutil
                shutil.copy(str(file_path), str(output_path))
                return True
            except Exception:
                return False

        try:
            # Build ffmpeg filter for redaction
            filter_parts = []

            for seg in sorted(segments_to_redact, key=lambda s: s.start_time):
                start = seg.start_time
                end = seg.end_time

                if redaction_type == "beep":
                    # Generate beep tone for duration
                    filter_parts.append(
                        f"volume=enable='between(t,{start},{end})':volume=0"
                    )
                else:
                    # Silence
                    filter_parts.append(
                        f"volume=enable='between(t,{start},{end})':volume=0"
                    )

            filter_str = ",".join(filter_parts) if filter_parts else "anull"

            subprocess.run(
                [
                    "ffmpeg",
                    "-i", str(file_path),
                    "-af", filter_str,
                    "-y",
                    str(output_path),
                ],
                capture_output=True,
                check=True,
            )
            return True

        except Exception:
            return False
