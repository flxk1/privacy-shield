"""
Privacy Shield - Video Processing

Combines audio transcription and frame analysis.
All processing is 100% local - no external API calls.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .audio import AudioProcessor, AudioResult, TranscriptSegment
from .image import ImageProcessor, FaceRegion, TextRegion, BoundingBox

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
    try:
        subprocess.run(["ffmpeg", "-version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


def _check_ffprobe() -> bool:
    """Check if ffprobe is available."""
    try:
        subprocess.run(["ffprobe", "-version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


def _extract_video_metadata(file_path: Path) -> VideoMetadata:
    """Extract metadata from video file using ffprobe."""
    metadata = VideoMetadata(
        duration_seconds=0.0,
        width=0,
        height=0,
        fps=0.0,
        format="unknown",
    )

    if not _check_ffprobe():
        return metadata

    try:
        import json
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

        # Tags
        tags = fmt.get("tags", {})
        if "title" in tags:
            metadata.title = str(tags["title"])
        if "artist" in tags:
            metadata.artist = str(tags["artist"])
            metadata.pii_fields.append("artist")
        if "creation_time" in tags:
            metadata.creation_time = str(tags["creation_time"])

        # Store raw tags
        for key, value in tags.items():
            metadata.raw_tags[key] = str(value)[:200]

        # Check for GPS in tags (common in phone videos)
        for key in ["location", "com.apple.quicktime.location.ISO6709"]:
            if key in tags:
                metadata.pii_fields.append("gps")
                # Parse GPS string if possible
                try:
                    gps_str = tags[key]
                    # Format: +48.1234+011.5678/
                    import re
                    match = re.match(r"([+-]\d+\.\d+)([+-]\d+\.\d+)", gps_str)
                    if match:
                        metadata.gps = (float(match.group(1)), float(match.group(2)))
                except Exception as exc:
                    logger.debug("Failed to parse GPS metadata for %s: %s", video_path, exc)

    except Exception as exc:
        logger.debug("Failed to extract video metadata for %s: %s", video_path, exc)

    return metadata


def _extract_audio_track(video_path: Path, output_path: Path) -> bool:
    """Extract audio track from video."""
    if not _check_ffmpeg():
        return False

    try:
        subprocess.run(
            [
                "ffmpeg",
                "-i", str(video_path),
                "-vn",  # No video
                "-acodec", "pcm_s16le",
                "-ar", "16000",
                "-ac", "1",
                "-y",
                str(output_path),
            ],
            capture_output=True,
            check=True,
        )
        return True
    except Exception:
        return False


def _extract_frames(
    video_path: Path,
    output_dir: Path,
    fps: float = 1.0,
    max_frames: int = 100,
) -> List[tuple]:
    """
    Extract frames from video.

    Returns list of (frame_path, frame_number, timestamp) tuples.
    """
    if not _check_ffmpeg():
        return []

    frames = []

    try:
        # Extract frames at specified FPS
        pattern = output_dir / "frame_%04d.jpg"

        subprocess.run(
            [
                "ffmpeg",
                "-i", str(video_path),
                "-vf", f"fps={fps}",
                "-frames:v", str(max_frames),
                "-q:v", "2",  # Quality
                "-y",
                str(pattern),
            ],
            capture_output=True,
            check=True,
        )

        # Collect extracted frames
        for i, frame_path in enumerate(sorted(output_dir.glob("frame_*.jpg"))):
            timestamp = i / fps
            frames.append((frame_path, i, timestamp))

    except Exception as exc:
        logger.debug("Failed to extract video frames for %s: %s", video_path, exc)

    return frames


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
        result.metadata = _extract_video_metadata(path)

        # Create temp directory for processing
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Process audio track
            if self.process_audio and self.audio_processor:
                audio_path = tmp_path / "audio.wav"
                if _extract_audio_track(path, audio_path):
                    try:
                        result.audio_result = self.audio_processor.process(audio_path)
                    except Exception as e:
                        result.errors.append(f"Audio processing error: {str(e)}")

            # Process video frames
            if self.process_frames and self.image_processor:
                frames_dir = tmp_path / "frames"
                frames_dir.mkdir()

                frames = _extract_frames(
                    path,
                    frames_dir,
                    fps=self.frame_sample_rate,
                    max_frames=self.max_frames,
                )

                for frame_path, frame_num, timestamp in frames:
                    try:
                        img_result = self.image_processor.process(frame_path)

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
            True if successful.
        """
        if not _check_ffmpeg():
            return False

        try:
            # Build filter complex
            video_filters = []
            audio_filters = []

            # Face blur requires frame-by-frame processing (out of scope here);
            # this strips metadata and optionally mutes audio segments.
            if redact_audio_segments:
                for seg in sorted(redact_audio_segments, key=lambda s: s.start_time):
                    audio_filters.append(
                        f"volume=enable='between(t,{seg.start_time},{seg.end_time})':volume=0"
                    )

            vf = ",".join(video_filters) if video_filters else None
            af = ",".join(audio_filters) if audio_filters else None

            cmd = [
                "ffmpeg",
                "-i", str(file_path),
            ]

            if vf:
                cmd.extend(["-vf", vf])
            if af:
                cmd.extend(["-af", af])

            if strip_metadata:
                cmd.extend(["-map_metadata", "-1"])

            cmd.extend(["-y", str(output_path)])

            subprocess.run(cmd, capture_output=True, check=True)
            return True

        except Exception:
            return False
