"""
Privacy Shield - Image Processing

OCR, face detection, and EXIF metadata extraction.
All processing is 100% local - no external API calls.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Optional imports - gracefully handle missing dependencies
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import cv2
    import numpy as np
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

logger = logging.getLogger(__name__)


@dataclass
class BoundingBox:
    """Bounding box coordinates."""
    x: int
    y: int
    width: int
    height: int
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "confidence": self.confidence,
        }


@dataclass
class TextRegion:
    """Text detected in image via OCR."""
    text: str
    bbox: BoundingBox
    confidence: float
    language: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "bbox": self.bbox.to_dict(),
            "confidence": self.confidence,
            "language": self.language,
        }


@dataclass
class FaceRegion:
    """Face detected in image."""
    bbox: BoundingBox
    confidence: float
    landmarks: Optional[Dict[str, Tuple[int, int]]] = None

    def to_dict(self) -> dict:
        return {
            "bbox": self.bbox.to_dict(),
            "confidence": self.confidence,
            "has_landmarks": self.landmarks is not None,
        }


@dataclass
class ImageMetadata:
    """Metadata extracted from image."""
    width: int
    height: int
    format: str
    exif: Dict[str, Any] = field(default_factory=dict)
    gps: Optional[Tuple[float, float]] = None
    datetime: Optional[str] = None
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    software: Optional[str] = None
    owner: Optional[str] = None
    pii_fields: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "width": self.width,
            "height": self.height,
            "format": self.format,
            "gps": self.gps,
            "datetime": self.datetime,
            "camera_make": self.camera_make,
            "camera_model": self.camera_model,
            "software": self.software,
            "owner": self.owner,
            "pii_fields": self.pii_fields,
            "exif_field_count": len(self.exif),
        }


@dataclass
class ImageResult:
    """Result of image processing."""
    file_path: str
    metadata: ImageMetadata
    text_regions: List[TextRegion] = field(default_factory=list)
    faces: List[FaceRegion] = field(default_factory=list)
    full_text: str = ""
    processing_time_ms: float = 0.0
    ocr_engine: Optional[str] = None
    face_detector: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return (
            len(self.faces) > 0 or
            len(self.metadata.pii_fields) > 0 or
            len(self.text_regions) > 0
        )

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "metadata": self.metadata.to_dict(),
            "text_region_count": len(self.text_regions),
            "face_count": len(self.faces),
            "full_text_length": len(self.full_text),
            "processing_time_ms": self.processing_time_ms,
            "ocr_engine": self.ocr_engine,
            "face_detector": self.face_detector,
            "has_pii": self.has_pii,
            "errors": self.errors,
        }


# =============================================================================
# EXIF / METADATA PII FIELDS
# =============================================================================

# EXIF fields that may contain PII
PII_EXIF_FIELDS = {
    # GPS data
    "GPS GPSLatitude",
    "GPS GPSLongitude",
    "GPS GPSLatitudeRef",
    "GPS GPSLongitudeRef",
    "GPSInfo",
    # Owner/Author
    "Image Artist",
    "Image Copyright",
    "Image ImageDescription",
    "EXIF UserComment",
    "XMP Creator",
    "XMP Rights",
    "IPTC By-line",
    "IPTC Caption-Abstract",
    # Device identifiers
    "Image Make",
    "Image Model",
    "EXIF LensModel",
    "EXIF SerialNumber",
    "EXIF BodySerialNumber",
    "EXIF LensSerialNumber",
    # Dates
    "EXIF DateTimeOriginal",
    "EXIF DateTimeDigitized",
    "Image DateTime",
    # Software
    "Image Software",
    "Image ProcessingSoftware",
}


def _convert_gps_to_decimal(gps_data: Any, ref: str) -> Optional[float]:
    """Convert GPS coordinates from EXIF format to decimal."""
    try:
        if hasattr(gps_data, 'values'):
            values = gps_data.values
        elif isinstance(gps_data, (list, tuple)):
            values = gps_data
        else:
            return None

        if len(values) >= 3:
            d = float(values[0])
            m = float(values[1])
            s = float(values[2])
            decimal = d + m / 60 + s / 3600
            if ref in ('S', 'W'):
                decimal = -decimal
            return decimal
    except Exception as exc:
        logger.debug("Failed converting GPS coordinates from EXIF: %s", exc)
    return None


class ImageProcessor:
    """
    Process images for PII detection.

    Supports:
    - OCR (text in images)
    - Face detection
    - EXIF metadata extraction
    - GPS coordinate extraction

    All processing is 100% local.
    """

    def __init__(
        self,
        ocr_engine: str = "auto",
        detect_faces: bool = True,
        extract_metadata: bool = True,
        ocr_languages: Optional[List[str]] = None,
    ):
        """
        Initialize the image processor.

        Args:
            ocr_engine: OCR engine to use ('paddleocr', 'tesseract', 'doctr', 'auto').
            detect_faces: Whether to detect faces.
            extract_metadata: Whether to extract EXIF metadata.
            ocr_languages: Languages for OCR (default: ['en', 'de']).
        """
        self.ocr_engine_name = ocr_engine
        self.detect_faces = detect_faces
        self.extract_metadata = extract_metadata
        self.ocr_languages = ocr_languages or ["en", "de"]

        # Lazy-loaded engines
        self._ocr_engine: Any = None
        self._face_detector: Any = None
        self._face_detector_name: Optional[str] = None

    def _init_ocr(self) -> Tuple[Any, str]:
        """Initialize OCR engine."""
        if self._ocr_engine is not None:
            return self._ocr_engine, self.ocr_engine_name

        engine_name = self.ocr_engine_name

        if engine_name in ("auto", "paddleocr"):
            try:
                from paddleocr import PaddleOCR
                self._ocr_engine = PaddleOCR(
                    use_angle_cls=True,
                    lang="en",
                    show_log=False,
                )
                self.ocr_engine_name = "paddleocr"
                return self._ocr_engine, "paddleocr"
            except ImportError:
                if engine_name == "paddleocr":
                    raise ImportError("PaddleOCR not installed. Install with: pip install paddleocr")

        if engine_name in ("auto", "tesseract"):
            try:
                import pytesseract
                # Test that tesseract is available
                pytesseract.get_tesseract_version()
                self._ocr_engine = pytesseract
                self.ocr_engine_name = "tesseract"
                return self._ocr_engine, "tesseract"
            except Exception:
                if engine_name == "tesseract":
                    raise ImportError("Tesseract not installed or not in PATH")

        if engine_name in ("auto", "doctr"):
            try:
                from doctr.models import ocr_predictor
                self._ocr_engine = ocr_predictor(pretrained=True)
                self.ocr_engine_name = "doctr"
                return self._ocr_engine, "doctr"
            except ImportError:
                if engine_name == "doctr":
                    raise ImportError("docTR not installed. Install with: pip install python-doctr")

        raise ImportError(f"No OCR engine available. Tried: {engine_name}")

    def _init_face_detector(self) -> Tuple[Any, str]:
        """Initialize face detector."""
        if self._face_detector is not None:
            return self._face_detector, self._face_detector_name or "unknown"

        # Try MediaPipe first (fast and accurate)
        try:
            import mediapipe as mp
            self._face_detector = mp.solutions.face_detection.FaceDetection(
                model_selection=1,  # Full range model
                min_detection_confidence=0.5,
            )
            self._face_detector_name = "mediapipe"
            return self._face_detector, "mediapipe"
        except ImportError:
            self._face_detector = None

        # Fall back to OpenCV Haar cascade
        if HAS_CV2:
            cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            if os.path.exists(cascade_path):
                self._face_detector = cv2.CascadeClassifier(cascade_path)
                self._face_detector_name = "opencv_haar"
                return self._face_detector, "opencv_haar"

        raise ImportError("No face detector available. Install mediapipe or opencv-python")

    def _extract_exif(self, image_path: Path) -> ImageMetadata:
        """Extract EXIF metadata from image."""
        metadata = ImageMetadata(
            width=0,
            height=0,
            format="unknown",
        )

        if not HAS_PIL:
            return metadata

        try:
            with Image.open(image_path) as img:
                metadata.width = img.width
                metadata.height = img.height
                metadata.format = img.format or "unknown"

                # Extract EXIF
                exif_data = img._getexif() if hasattr(img, '_getexif') else None
                if exif_data:
                    from PIL.ExifTags import TAGS, GPSTAGS

                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, str(tag_id))

                        # Handle GPS data
                        if tag == "GPSInfo" and isinstance(value, dict):
                            gps_data = {}
                            for gps_tag_id, gps_value in value.items():
                                gps_tag = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                                gps_data[gps_tag] = gps_value

                            lat = _convert_gps_to_decimal(
                                gps_data.get("GPSLatitude"),
                                gps_data.get("GPSLatitudeRef", "N"),
                            )
                            lon = _convert_gps_to_decimal(
                                gps_data.get("GPSLongitude"),
                                gps_data.get("GPSLongitudeRef", "E"),
                            )
                            if lat and lon:
                                metadata.gps = (lat, lon)
                                metadata.pii_fields.append("GPS")
                        else:
                            metadata.exif[tag] = str(value)[:200]  # Truncate long values

                            # Check for PII fields
                            if tag in ("Artist", "Copyright", "ImageDescription"):
                                metadata.owner = str(value)
                                metadata.pii_fields.append(tag)
                            elif tag == "DateTime":
                                metadata.datetime = str(value)
                            elif tag == "DateTimeOriginal":
                                metadata.datetime = str(value)
                            elif tag == "Make":
                                metadata.camera_make = str(value)
                            elif tag == "Model":
                                metadata.camera_model = str(value)
                            elif tag == "Software":
                                metadata.software = str(value)
        except Exception as exc:
            logger.debug("EXIF extraction failed for %s: %s", image_path, exc)

        return metadata

    def _run_ocr(self, image_path: Path) -> List[TextRegion]:
        """Run OCR on image."""
        regions: List[TextRegion] = []

        try:
            engine, engine_name = self._init_ocr()
        except ImportError:
            return regions

        try:
            if engine_name == "paddleocr":
                result = engine.ocr(str(image_path))
                if result and result[0]:
                    for line in result[0]:
                        if line and len(line) >= 2:
                            box, (text, confidence) = line[0], line[1]
                            if box and len(box) >= 4:
                                x = int(min(p[0] for p in box))
                                y = int(min(p[1] for p in box))
                                w = int(max(p[0] for p in box)) - x
                                h = int(max(p[1] for p in box)) - y
                                regions.append(TextRegion(
                                    text=text,
                                    bbox=BoundingBox(x, y, w, h, confidence),
                                    confidence=confidence,
                                ))

            elif engine_name == "tesseract":
                import pytesseract
                data = pytesseract.image_to_data(
                    str(image_path),
                    output_type=pytesseract.Output.DICT,
                )
                for i, text in enumerate(data["text"]):
                    if text.strip():
                        conf = float(data["conf"][i]) / 100.0
                        if conf > 0.3:
                            regions.append(TextRegion(
                                text=text,
                                bbox=BoundingBox(
                                    data["left"][i],
                                    data["top"][i],
                                    data["width"][i],
                                    data["height"][i],
                                    conf,
                                ),
                                confidence=conf,
                            ))

            elif engine_name == "doctr":
                from doctr.io import DocumentFile
                doc = DocumentFile.from_images(str(image_path))
                result = engine(doc)
                for page in result.pages:
                    for block in page.blocks:
                        for line in block.lines:
                            for word in line.words:
                                bbox = word.geometry
                                x = int(bbox[0][0] * page.dimensions[1])
                                y = int(bbox[0][1] * page.dimensions[0])
                                w = int((bbox[1][0] - bbox[0][0]) * page.dimensions[1])
                                h = int((bbox[1][1] - bbox[0][1]) * page.dimensions[0])
                                regions.append(TextRegion(
                                    text=word.value,
                                    bbox=BoundingBox(x, y, w, h, word.confidence),
                                    confidence=word.confidence,
                                ))
        except Exception as exc:
            logger.debug("OCR failed for %s: %s", image_path, exc)

        return regions

    def _detect_faces_in_image(self, image_path: Path) -> List[FaceRegion]:
        """Detect faces in image."""
        faces: List[FaceRegion] = []

        if not self.detect_faces:
            return faces

        try:
            detector, detector_name = self._init_face_detector()
        except ImportError:
            return faces

        try:
            if detector_name == "mediapipe":
                import mediapipe as mp
                if HAS_CV2:
                    img = cv2.imread(str(image_path))
                    if img is not None:
                        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                        results = detector.process(rgb)
                        if results.detections:
                            h, w = img.shape[:2]
                            for detection in results.detections:
                                bbox = detection.location_data.relative_bounding_box
                                faces.append(FaceRegion(
                                    bbox=BoundingBox(
                                        int(bbox.xmin * w),
                                        int(bbox.ymin * h),
                                        int(bbox.width * w),
                                        int(bbox.height * h),
                                        detection.score[0],
                                    ),
                                    confidence=detection.score[0],
                                ))

            elif detector_name == "opencv_haar":
                if HAS_CV2:
                    img = cv2.imread(str(image_path))
                    if img is not None:
                        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                        detected = detector.detectMultiScale(
                            gray,
                            scaleFactor=1.1,
                            minNeighbors=5,
                            minSize=(30, 30),
                        )
                        for (x, y, w, h) in detected:
                            faces.append(FaceRegion(
                                bbox=BoundingBox(x, y, w, h, 0.8),
                                confidence=0.8,
                            ))
        except Exception as exc:
            logger.debug("Face detection failed for %s: %s", image_path, exc)

        return faces

    def process(self, file_path: Union[str, Path]) -> ImageResult:
        """
        Process an image for PII detection.

        Args:
            file_path: Path to the image file.

        Returns:
            ImageResult with detected text, faces, and metadata.
        """
        import time
        start_time = time.perf_counter()

        path = Path(file_path)
        result = ImageResult(
            file_path=str(path),
            metadata=ImageMetadata(0, 0, "unknown"),
        )

        if not path.exists():
            result.errors.append(f"File not found: {path}")
            return result

        # Extract metadata
        if self.extract_metadata:
            result.metadata = self._extract_exif(path)

        # Run OCR
        try:
            result.text_regions = self._run_ocr(path)
            result.ocr_engine = self.ocr_engine_name
            result.full_text = " ".join(r.text for r in result.text_regions)
        except Exception as e:
            result.errors.append(f"OCR error: {str(e)}")

        # Detect faces
        if self.detect_faces:
            try:
                result.faces = self._detect_faces_in_image(path)
                result.face_detector = self._face_detector_name
            except Exception as e:
                result.errors.append(f"Face detection error: {str(e)}")

        result.processing_time_ms = (time.perf_counter() - start_time) * 1000

        return result

    def redact_image(
        self,
        file_path: Union[str, Path],
        output_path: Union[str, Path],
        blur_faces: bool = True,
        redact_text_regions: Optional[List[TextRegion]] = None,
        strip_metadata: bool = True,
    ) -> bool:
        """
        Create a redacted version of an image.

        Args:
            file_path: Input image path.
            output_path: Output image path.
            blur_faces: Whether to blur detected faces.
            redact_text_regions: Text regions to black out.
            strip_metadata: Whether to remove EXIF data.

        Returns:
            True if successful.
        """
        if not HAS_CV2 or not HAS_PIL:
            return False

        try:
            # Load image
            img = cv2.imread(str(file_path))
            if img is None:
                return False

            # Blur faces
            if blur_faces:
                faces = self._detect_faces_in_image(Path(file_path))
                for face in faces:
                    x, y, w, h = face.bbox.x, face.bbox.y, face.bbox.width, face.bbox.height
                    roi = img[y:y+h, x:x+w]
                    blurred = cv2.GaussianBlur(roi, (99, 99), 30)
                    img[y:y+h, x:x+w] = blurred

            # Black out text regions
            if redact_text_regions:
                for region in redact_text_regions:
                    x, y = region.bbox.x, region.bbox.y
                    w, h = region.bbox.width, region.bbox.height
                    cv2.rectangle(img, (x, y), (x+w, y+h), (0, 0, 0), -1)

            # Save without EXIF
            cv2.imwrite(str(output_path), img)

            # Optionally strip all metadata using PIL
            if strip_metadata and HAS_PIL:
                with Image.open(output_path) as pil_img:
                    # Create new image without EXIF
                    data = list(pil_img.getdata())
                    clean_img = Image.new(pil_img.mode, pil_img.size)
                    clean_img.putdata(data)
                    clean_img.save(output_path)

            return True
        except Exception:
            return False
