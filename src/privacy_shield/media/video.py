"""
Privacy Shield - Video Processing

Combines audio transcription and frame analysis.
All processing is 100% local - no external API calls.
"""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from ._tools import channel_unavailable, operand, run_tool, tool_available
from .audio import AudioProcessor, AudioResult, TranscriptSegment
from .image import ImageProcessor, FaceRegion, TextRegion, BoundingBox
from .metadata import normalise_tag_key, tag_pii_type

logger = logging.getLogger(__name__)


@dataclass
class FrameResult:
    """Result from analyzing a single video frame."""
    frame_number: int
    timestamp: float  # seconds
    text_regions: List[TextRegion] = field(default_factory=list)
    faces: List[FaceRegion] = field(default_factory=list)
    full_text: str = ""

    def to_dict(self) -> dict:
        return {
            "frame_number": self.frame_number,
            "timestamp": self.timestamp,
            "text_region_count": len(self.text_regions),
            "face_count": len(self.faces),
            "full_text_length": len(self.full_text),
        }


@dataclass
class VideoMetadata:
    """Metadata extracted from video file."""
    duration_seconds: float
    width: int
    height: int
    fps: float
    format: str
    video_codec: Optional[str] = None
    audio_codec: Optional[str] = None
    bitrate: Optional[int] = None
    title: Optional[str] = None
    artist: Optional[str] = None
    creation_time: Optional[str] = None
    gps: Optional[tuple] = None
    pii_fields: List[str] = field(default_factory=list)
    raw_tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "duration_seconds": self.duration_seconds,
            "width": self.width,
            "height": self.height,
            "fps": self.fps,
            "format": self.format,
            "video_codec": self.video_codec,
            "audio_codec": self.audio_codec,
            "gps": self.gps,
            "pii_fields": self.pii_fields,
        }


@dataclass
class VideoResult:
    """Result of video processing."""
    file_path: str
    metadata: VideoMetadata
    audio_result: Optional[AudioResult] = None
    frame_results: List[FrameResult] = field(default_factory=list)
    processing_time_ms: float = 0.0
    frames_analyzed: int = 0
    total_faces_detected: int = 0
    total_text_regions: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def full_transcript(self) -> str:
        return self.audio_result.full_transcript if self.audio_result else ""

    @property
    def all_visual_text(self) -> str:
        return " ".join(f.full_text for f in self.frame_results if f.full_text)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "metadata": self.metadata.to_dict(),
            "has_transcript": bool(self.full_transcript),
            "transcript_length": len(self.full_transcript),
            "frames_analyzed": self.frames_analyzed,
            "total_faces_detected": self.total_faces_detected,
            "total_text_regions": self.total_text_regions,
            "processing_time_ms": self.processing_time_ms,
            "errors": self.errors,
        }


def _check_ffmpeg() -> bool:
    """Check if ffmpeg is available."""
    return tool_available("ffmpeg")


def _check_ffprobe() -> bool:
    """Check if ffprobe is available."""
    return tool_available("ffprobe")


# The QuickTime/ISO-BMFF location atom surfaces under several keys, and a phone
# writes more than one of them. `location` and the reverse-DNS Apple key were
# the only two matched; `location-eng` is the language-tagged form ffprobe
# reports for the `udta.©xyz` atom and is frequently the ONLY one present, and
# Android writes `com.android.*`. Matching is done on a normalised prefix so a
# new language suffix does not need a new entry.
_GPS_TAG_PREFIXES = (
    "location",
    "com.apple.quicktime.location",
    "com.android.location",
    "gps",
    "xyz",
)


def _looks_like_gps_tag(key: object) -> bool:
    name = str(key).strip().lower().lstrip("©")
    return any(name.startswith(prefix) for prefix in _GPS_TAG_PREFIXES)


def _apply_container_tags(metadata: VideoMetadata, tags: Dict[str, Any]) -> None:
    """Record container tags and flag the PII ones by the shared taxonomy.

    Only `artist` and two literal GPS keys used to reach `pii_fields`, while
    `title`, `creation_time`, `comment`, `author`, `copyright`, `composer` and
    the QuickTime `©`-prefixed forms were stored in `raw_tags` - which does not
    appear in `to_dict()` and never reaches `ShieldResult` - and dropped. The
    classification is now `metadata.tag_pii_type`, the same table audio and the
    metadata extractor use.
    """
    for key, value in (tags or {}).items():
        text = str(value)
        metadata.raw_tags[str(key)] = text[:200]

        name = normalise_tag_key(key)
        if name == "title":
            metadata.title = metadata.title or text
        elif name == "artist":
            metadata.artist = metadata.artist or text
        elif name in ("creation_time", "creationdate", "date"):
            metadata.creation_time = metadata.creation_time or text

        if _looks_like_gps_tag(key):
            if "gps" not in metadata.pii_fields:
                metadata.pii_fields.append("gps")
            if metadata.gps is None:
                metadata.gps = _parse_iso6709(text)
            continue

        if tag_pii_type(key) and name not in metadata.pii_fields:
            metadata.pii_fields.append(name)


def _parse_iso6709(gps_str: object) -> Optional[tuple]:
    """Parse an ISO 6709 location string (`+48.1372+011.5756/`)."""
    try:
        import re

        match = re.match(r"([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)", str(gps_str))
        if match:
            return (float(match.group(1)), float(match.group(2)))
    except Exception as exc:
        # Was `logger.debug(..., video_path, exc)` - `video_path` is not a name
        # in this module, so every arrival here raised NameError out of metadata
        # extraction instead of logging. The handler that parses GPS out of a
        # video container had never once executed.
        logger.debug("Failed to parse ISO 6709 location %r: %s", gps_str, exc)
    return None


def _extract_video_metadata(
    file_path: Path,
    errors: Optional[List[str]] = None,
) -> VideoMetadata:
    """Extract metadata from video file using ffprobe.

    Appends a channel-unavailable error to *errors* when ffprobe is absent.
    ffprobe is the only reader here and it is not a Python package, so it is
    not installable by any extra: without it a geotagged video returned
    `pii_fields=[]` and `errors=[]`, i.e. certified as carrying no metadata PII
    by a code path that never opened the container.
    """
    metadata = VideoMetadata(
        duration_seconds=0.0,
        width=0,
        height=0,
        fps=0.0,
        format="unknown",
    )

    if not _check_ffprobe():
        if errors is not None:
            errors.append(
                channel_unavailable("container_metadata", "ffprobe not on PATH")
            )
        return metadata

    try:
        import json
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

        data = json.loads(result.stdout)

        # Format info
        fmt = data.get("format", {})
        metadata.format = fmt.get("format_name", "unknown")
        metadata.duration_seconds = float(fmt.get("duration", 0))
        metadata.bitrate = int(fmt.get("bit_rate", 0)) if fmt.get("bit_rate") else None

        # Stream info
        for stream in data.get("streams", []):
            if stream.get("codec_type") == "video":
                metadata.width = int(stream.get("width", 0))
                metadata.height = int(stream.get("height", 0))
                metadata.video_codec = stream.get("codec_name")

                # Parse FPS
                fps_str = stream.get("r_frame_rate", "0/1")
                if "/" in fps_str:
                    num, den = fps_str.split("/")
                    metadata.fps = float(num) / float(den) if float(den) > 0 else 0

            elif stream.get("codec_type") == "audio":
                metadata.audio_codec = stream.get("codec_name")

            # Per-stream tags. The QuickTime location atom and creation_time
            # both live here as often as at format level, and only format
            # level was read.
            _apply_container_tags(metadata, stream.get("tags", {}))

        _apply_container_tags(metadata, fmt.get("tags", {}))

    except Exception as exc:
        # Was `logger.debug(..., video_path, exc)`. Any failure in this block -
        # a malformed duration, a non-numeric width, ffprobe emitting
        # something other than JSON - raised NameError out of this function
        # instead of logging, destroying the real cause and abandoning the
        # metadata pass with an error the caller could not act on.
        logger.debug("Failed to extract video metadata for %s: %s", file_path, exc)
        if errors is not None:
            errors.append(channel_unavailable("container_metadata", exc))

    return metadata


def _extract_audio_track(video_path: Path, output_path: Path) -> bool:
    """Extract audio track from video."""
    if not _check_ffmpeg():
        return False

    try:
        run_tool(
            [
                "ffmpeg",
                "-nostdin",
                "-i", operand(video_path),
                "-vn",  # No video
                "-acodec", "pcm_s16le",
                "-ar", "16000",
                "-ac", "1",
                "-y",
                operand(output_path),
            ]
        )
        return True
    except Exception as exc:
        logger.debug("Failed to extract audio track from %s: %s", video_path, exc)
        return False


def _extract_frames(
    video_path: Path,
    output_dir: Path,
    fps: float = 1.0,
    max_frames: int = 100,
) -> Tuple[List[tuple], Optional[str]]:
    """Extract frames from video.

    Returns ``(frames, error)`` where frames is a list of
    ``(frame_path, frame_number, timestamp)``. The error is not None whenever
    the frame channel could not run - without it, "ffmpeg is not installed"
    and "this video contains no frames with anything in them" were the same
    empty list.
    """
    if not _check_ffmpeg():
        return [], channel_unavailable("video_frames", "ffmpeg not on PATH")

    try:
        rate = float(fps)
    except (TypeError, ValueError):
        rate = 0.0
    if rate <= 0:
        # `timestamp = i / fps` divided by zero, which the blanket handler
        # below caught and turned into "no frames", so a misconfigured sample
        # rate silently disabled the whole visual channel.
        return [], channel_unavailable("video_frames", f"frame_sample_rate={fps!r}")

    frames = []

    try:
        # Extract frames at specified FPS
        pattern = output_dir / "frame_%04d.jpg"

        run_tool(
            [
                "ffmpeg",
                "-nostdin",
                "-i", operand(video_path),
                "-vf", f"fps={rate!r}",
                "-frames:v", str(int(max_frames)),
                "-q:v", "2",  # Quality
                "-y",
                operand(pattern),
            ]
        )

        # Collect extracted frames
        for i, frame_path in enumerate(sorted(output_dir.glob("frame_*.jpg"))):
            timestamp = i / rate
            frames.append((frame_path, i, timestamp))

    except Exception as exc:
        logger.debug("Failed to extract video frames for %s: %s", video_path, exc)
        return frames, channel_unavailable("video_frames", exc)

    return frames, None


class VideoProcessor:
    """
    Process video files for PII detection.

    Combines:
    - Audio transcription (speech-to-text)
    - Frame analysis (OCR, face detection)
    - Metadata extraction

    All processing is 100% local.
    """

    def __init__(
        self,
        process_audio: bool = True,
        process_frames: bool = True,
        frame_sample_rate: float = 1.0,  # Frames per second to analyze
        max_frames: int = 100,
        detect_faces: bool = True,
        detect_text: bool = True,
        stt_engine: str = "auto",
        stt_model_size: str = "base",
        ocr_engine: str = "auto",
    ):
        """
        Initialize the video processor.

        Args:
            process_audio: Whether to transcribe audio track.
            process_frames: Whether to analyze video frames.
            frame_sample_rate: How many frames per second to analyze.
            max_frames: Maximum number of frames to analyze.
            detect_faces: Whether to detect faces in frames.
            detect_text: Whether to run OCR on frames.
            stt_engine: Speech-to-text engine for audio.
            stt_model_size: Model size for STT.
            ocr_engine: OCR engine for frame text.
        """
        self.process_audio = process_audio
        self.process_frames = process_frames
        self.frame_sample_rate = frame_sample_rate
        self.max_frames = max_frames
        self.detect_faces = detect_faces
        self.detect_text = detect_text

        # Initialize sub-processors
        self.audio_processor = AudioProcessor(
            stt_engine=stt_engine,
            model_size=stt_model_size,
        ) if process_audio else None

        self.image_processor = ImageProcessor(
            ocr_engine=ocr_engine,
            detect_faces=detect_faces,
            extract_metadata=False,  # Don't need EXIF for frames
        ) if process_frames else None

    def process(self, file_path: Union[str, Path]) -> VideoResult:
        """
        Process a video file for PII detection.

        Args:
            file_path: Path to the video file.

        Returns:
            VideoResult with transcript, frame analysis, and metadata.
        """
        import time
        start_time = time.perf_counter()

        path = Path(file_path)
        result = VideoResult(
            file_path=str(path),
            metadata=VideoMetadata(0, 0, 0, 0, "unknown"),
        )

        if not path.exists():
            result.errors.append(f"File not found: {path}")
            return result

        # Extract metadata
        result.metadata = _extract_video_metadata(path, result.errors)

        # Create temp directory for processing
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Process audio track
            if self.process_audio and self.audio_processor:
                audio_path = tmp_path / "audio.wav"
                if _extract_audio_track(path, audio_path):
                    try:
                        result.audio_result = self.audio_processor.process(audio_path)
                        # The sub-processor's own channel gaps are this
                        # result's gaps: an unavailable STT engine is the
                        # reason this video has no transcript.
                        for err in result.audio_result.errors:
                            if err not in result.errors:
                                result.errors.append(err)
                    except Exception as e:
                        result.errors.append(f"Audio processing error: {str(e)}")
                else:
                    result.errors.append(
                        channel_unavailable(
                            "video_audio_track",
                            "could not demux an audio track (need ffmpeg on PATH)",
                        )
                    )

            # Process video frames
            if self.process_frames and self.image_processor:
                frames_dir = tmp_path / "frames"
                frames_dir.mkdir()

                frames, frames_error = _extract_frames(
                    path,
                    frames_dir,
                    fps=self.frame_sample_rate,
                    max_frames=self.max_frames,
                )
                if frames_error:
                    result.errors.append(frames_error)

                for frame_path, frame_num, timestamp in frames:
                    try:
                        img_result = self.image_processor.process(frame_path)
                        # Per-frame channel gaps are identical across frames;
                        # record each distinct one once rather than a hundred
                        # times.
                        for err in img_result.errors:
                            if err not in result.errors:
                                result.errors.append(err)

                        frame_result = FrameResult(
                            frame_number=frame_num,
                            timestamp=timestamp,
                            text_regions=img_result.text_regions,
                            faces=img_result.faces,
                            full_text=img_result.full_text,
                        )

                        result.frame_results.append(frame_result)
                        result.total_faces_detected += len(img_result.faces)
                        result.total_text_regions += len(img_result.text_regions)

                    except Exception as e:
                        result.errors.append(f"Frame {frame_num} error: {str(e)}")

                result.frames_analyzed = len(result.frame_results)

        result.processing_time_ms = (time.perf_counter() - start_time) * 1000

        return result

    def redact_video(
        self,
        file_path: Union[str, Path],
        output_path: Union[str, Path],
        blur_faces: bool = True,
        redact_audio_segments: Optional[List[TranscriptSegment]] = None,
        redact_text_boxes: Optional[List[tuple]] = None,  # (frame_num, TextRegion)
        strip_metadata: bool = True,
    ) -> bool:
        """
        Create a redacted version of a video.

        Args:
            file_path: Input video path.
            output_path: Output video path.
            blur_faces: Whether to blur all detected faces.
            redact_audio_segments: Audio segments to silence.
            redact_text_boxes: Text regions to black out (frame_num, region).
            strip_metadata: Whether to remove metadata.

        Returns:
            True only if every requested redaction was applied.

        `blur_faces` defaults to True and **was silently ignored** - the body
        never built a video filter, so the function accepted "blur every face
        in this video", did not, and returned True. A caller had no way to
        learn that the artefact cleared for egress still showed every face in
        it. Face blurring is still not implemented; the difference is that
        asking for it now fails instead of passing.
        """
        if not _check_ffmpeg():
            return False

        if blur_faces:
            logger.debug(
                "redact_video cannot blur faces (not implemented); refusing to "
                "report success for a request it cannot honour"
            )
            return False

        if redact_text_boxes:
            logger.debug("redact_video cannot black out text boxes (not implemented)")
            return False

        try:
            audio_filters = []

            if redact_audio_segments:
                for seg in sorted(redact_audio_segments, key=lambda s: float(s.start_time)):
                    start = float(seg.start_time)
                    end = float(seg.end_time)
                    audio_filters.append(
                        f"volume=enable='between(t,{start!r},{end!r})':volume=0"
                    )

            af = ",".join(audio_filters) if audio_filters else None

            cmd = [
                "ffmpeg",
                "-nostdin",
                "-i", operand(file_path),
            ]

            if af:
                cmd.extend(["-af", af])

            if strip_metadata:
                # The global form alone leaves per-stream tags in place, and
                # the QuickTime location atom - the GPS fix on every phone
                # video - is a stream tag as often as a format tag. Both forms
                # are required; with only the first, `strip_metadata=True`
                # returned a video that still knew where it was shot.
                cmd.extend([
                    "-map_metadata", "-1",
                    "-map_metadata:s", "-1",
                    "-map_chapters", "-1",
                    "-fflags", "+bitexact",
                ])

            cmd.extend(["-y", operand(output_path)])

            run_tool(cmd)
            return True

        except Exception as exc:
            logger.debug("redact_video failed for %s: %s", file_path, exc)
            return False
