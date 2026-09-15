"""
Privacy Shield - Media Processing

Handles OCR, speech-to-text, face detection, and metadata extraction.
All processing is 100% local - no external API calls.
"""

from .image import ImageProcessor, ImageResult
from .audio import AudioProcessor, AudioResult
from .video import VideoProcessor, VideoResult
from .metadata import MetadataExtractor, MetadataResult

__all__ = [
    "ImageProcessor",
    "ImageResult",
    "AudioProcessor",
    "AudioResult",
    "VideoProcessor",
    "VideoResult",
    "MetadataExtractor",
    "MetadataResult",
]
