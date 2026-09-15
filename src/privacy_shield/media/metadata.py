"""
Privacy Shield - Metadata Extraction and Stripping

Extract and remove PII from file metadata (EXIF, ID3, PDF properties, etc.).
All processing is 100% local.
"""

from __future__ import annotations

import os
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)

@dataclass
class MetadataFinding:
    """A PII finding in metadata."""
    field_name: str
    value: str
    pii_type: str  # gps, name, email, device, datetime, etc.
    source: str  # exif, id3, pdf, etc.

    def to_dict(self) -> dict:
        return {
            "field_name": self.field_name,
            "value": self.value,
            "pii_type": self.pii_type,
            "source": self.source,
        }


@dataclass
class MetadataResult:
    """Result of metadata extraction."""
    file_path: str
    file_type: str
    all_fields: Dict[str, str] = field(default_factory=dict)
    pii_findings: List[MetadataFinding] = field(default_factory=list)
    extraction_time_ms: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return len(self.pii_findings) > 0

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_type": self.file_type,
            "total_fields": len(self.all_fields),
            "pii_finding_count": len(self.pii_findings),
            "pii_types": list(set(f.pii_type for f in self.pii_findings)),
            "has_pii": self.has_pii,
            "errors": self.errors,
        }


# =============================================================================
# PII FIELD DEFINITIONS
# =============================================================================

# Fields that contain GPS data
GPS_FIELDS = {
    "gps:gpslatitude", "gps:gpslongitude", "gps:gpsposition",
    "xmp:gpslatitude", "xmp:gpslongitude",
    "composite:gpsposition", "composite:gpslongitude", "composite:gpslatitude",
    "quicktime:gpscoordinates", "quicktime:gpslongitude", "quicktime:gpslatitude",
    "location", "com.apple.quicktime.location.iso6709",
}

# Fields that contain personal names
NAME_FIELDS = {
    "exif:artist", "exif:xpauthor", "iptc:by-line", "iptc:credit",
    "xmp:creator", "xmp:author", "pdf:author", "dc:creator",
    "id3:artist", "id3:albumartist", "id3:composer", "id3:lyricist",
    "quicktime:artist", "quicktime:author",
    "file:owner", "system:owner",
}

# Fields that contain organization/company
ORG_FIELDS = {
    "iptc:source", "xmp:credit", "pdf:producer", "pdf:creator",
    "exif:make", "exif:model",  # Device manufacturer
}

# Fields that contain identifiers
ID_FIELDS = {
    "exif:serialnumber", "exif:bodyserialnumber", "exif:lensserialnumber",
    "exif:cameraserialnumber", "xmp:serialnumber",
    "file:inode", "system:fileid",
}

# Fields that contain dates
DATE_FIELDS = {
    "exif:datetimeoriginal", "exif:datetimedigitized", "exif:datetime",
    "iptc:datecreated", "xmp:createdate", "xmp:modifydate",
    "quicktime:creationdate", "quicktime:modificationdate",
    "pdf:createdate", "pdf:modifydate",
    "id3:year", "id3:date",
}

# Fields that contain descriptions/comments (may contain arbitrary PII)
CONTENT_FIELDS = {
    "exif:usercomment", "exif:imagedescription", "iptc:caption-abstract",
    "xmp:description", "xmp:title", "pdf:subject", "pdf:title",
    "id3:comment", "id3:title", "id3:album",
}

# All PII-relevant fields combined
ALL_PII_FIELDS = GPS_FIELDS | NAME_FIELDS | ORG_FIELDS | ID_FIELDS | DATE_FIELDS | CONTENT_FIELDS


def _classify_pii_type(field_name: str) -> Optional[str]:
    """Classify the PII type for a metadata field."""
    field_lower = field_name.lower()

    if field_lower in GPS_FIELDS or "gps" in field_lower or "location" in field_lower:
        return "gps"
    if field_lower in NAME_FIELDS or "author" in field_lower or "artist" in field_lower:
        return "name"
    if field_lower in ORG_FIELDS or "make" in field_lower or "producer" in field_lower:
        return "organization"
    if field_lower in ID_FIELDS or "serial" in field_lower:
        return "device_id"
    if field_lower in DATE_FIELDS or "date" in field_lower or "time" in field_lower:
        return "datetime"
    if field_lower in CONTENT_FIELDS or "comment" in field_lower or "description" in field_lower:
        return "content"

    return None


def _check_exiftool() -> bool:
    """Check if exiftool is available."""
    try:
        subprocess.run(["exiftool", "-ver"], capture_output=True, check=True)
        return True
    except Exception:
        return False


class MetadataExtractor:
    """
    Extract and analyze metadata from files.

    Supports:
    - Images (EXIF, IPTC, XMP)
    - Audio (ID3, Vorbis comments)
    - Video (QuickTime, Matroska)
    - Documents (PDF properties, Office metadata)

    All processing is 100% local.
    """

    def __init__(
        self,
        detect_all_pii: bool = True,
        include_non_pii: bool = False,
    ):
        """
        Initialize the metadata extractor.

        Args:
            detect_all_pii: Whether to scan all fields for PII patterns.
            include_non_pii: Whether to include non-PII fields in results.
        """
        self.detect_all_pii = detect_all_pii
        self.include_non_pii = include_non_pii

    def extract(self, file_path: Union[str, Path]) -> MetadataResult:
        """
        Extract metadata from a file.

        Args:
            file_path: Path to the file.

        Returns:
            MetadataResult with metadata and PII findings.
        """
        import time
        start_time = time.perf_counter()

        path = Path(file_path)
        result = MetadataResult(
            file_path=str(path),
            file_type=path.suffix.lower().lstrip("."),
        )

        if not path.exists():
            result.errors.append(f"File not found: {path}")
            return result

        # Try exiftool first (most comprehensive)
        if _check_exiftool():
            self._extract_with_exiftool(path, result)
        else:
            # Fall back to Python libraries
            self._extract_with_python(path, result)

        result.extraction_time_ms = (time.perf_counter() - start_time) * 1000

        return result

    def _extract_with_exiftool(self, path: Path, result: MetadataResult) -> None:
        """Extract metadata using exiftool."""
        try:
            import json
            output = subprocess.run(
                ["exiftool", "-json", "-a", "-G", str(path)],
                capture_output=True,
                text=True,
                check=True,
            )

            data = json.loads(output.stdout)
            if data and len(data) > 0:
                metadata = data[0]

                for key, value in metadata.items():
                    if key == "SourceFile":
                        continue

                    str_value = str(value)[:500]  # Truncate long values

                    # Check if this is a PII field
                    pii_type = _classify_pii_type(key)

                    if pii_type:
                        result.pii_findings.append(MetadataFinding(
                            field_name=key,
                            value=str_value,
                            pii_type=pii_type,
                            source="exiftool",
                        ))
                        result.all_fields[key] = str_value
                    elif self.include_non_pii:
                        result.all_fields[key] = str_value

        except Exception as e:
            result.errors.append(f"Exiftool error: {str(e)}")

    def _extract_with_python(self, path: Path, result: MetadataResult) -> None:
        """Extract metadata using Python libraries."""
        suffix = path.suffix.lower()

        # Images
        if suffix in (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".heic", ".heif"):
            self._extract_image_metadata(path, result)

        # Audio
        elif suffix in (".mp3", ".m4a", ".flac", ".ogg", ".wav", ".aac"):
            self._extract_audio_metadata(path, result)

        # PDF
        elif suffix == ".pdf":
            self._extract_pdf_metadata(path, result)

        # Office documents
        elif suffix in (".docx", ".xlsx", ".pptx"):
            self._extract_office_metadata(path, result)

    def _extract_image_metadata(self, path: Path, result: MetadataResult) -> None:
        """Extract metadata from image files."""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS

            with Image.open(path) as img:
                exif_data = img._getexif() if hasattr(img, '_getexif') else None

                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, str(tag_id))
                        key = f"EXIF:{tag}"
                        str_value = str(value)[:500]

                        pii_type = _classify_pii_type(key)
                        if pii_type:
                            result.pii_findings.append(MetadataFinding(
                                field_name=key,
                                value=str_value,
                                pii_type=pii_type,
                                source="pillow",
                            ))
                            result.all_fields[key] = str_value
                        elif self.include_non_pii:
                            result.all_fields[key] = str_value

        except ImportError:
            result.errors.append("Pillow not installed for image metadata")
        except Exception as e:
            result.errors.append(f"Image metadata error: {str(e)}")

    def _extract_audio_metadata(self, path: Path, result: MetadataResult) -> None:
        """Extract metadata from audio files."""
        try:
            from mutagen import File as MutagenFile

            audio = MutagenFile(str(path))
            if audio and audio.tags:
                for key in audio.tags.keys():
                    value = audio.tags[key]
                    str_value = str(value)[:500]
                    field_key = f"ID3:{key}"

                    pii_type = _classify_pii_type(field_key)
                    if pii_type or "artist" in str(key).lower():
                        result.pii_findings.append(MetadataFinding(
                            field_name=field_key,
                            value=str_value,
                            pii_type=pii_type or "name",
                            source="mutagen",
                        ))
                        result.all_fields[field_key] = str_value
                    elif self.include_non_pii:
                        result.all_fields[field_key] = str_value

        except ImportError:
            result.errors.append("Mutagen not installed for audio metadata")
        except Exception as e:
            result.errors.append(f"Audio metadata error: {str(e)}")

    def _extract_pdf_metadata(self, path: Path, result: MetadataResult) -> None:
        """Extract metadata from PDF files."""
        use_pymupdf = os.getenv("PRIVACY_SHIELD_ENABLE_PYMUPDF", "").strip().lower() in {"1", "true", "yes", "on"}
        try:
            if not use_pymupdf:
                raise ImportError("PyMuPDF feature not enabled")
            import fitz  # PyMuPDF

            with fitz.open(str(path)) as doc:
                metadata = doc.metadata or {}

                for key, value in metadata.items():
                    if value:
                        field_key = f"PDF:{key}"
                        str_value = str(value)[:500]

                        pii_type = _classify_pii_type(field_key)
                        if pii_type:
                            result.pii_findings.append(MetadataFinding(
                                field_name=field_key,
                                value=str_value,
                                pii_type=pii_type,
                                source="pymupdf",
                            ))
                            result.all_fields[field_key] = str_value
                        elif self.include_non_pii:
                            result.all_fields[field_key] = str_value

        except ImportError:
            try:
                from pypdf import PdfReader
            except ImportError:
                result.errors.append("PDF metadata parser not installed (need PyMuPDF or pypdf)")
                return
            reader = PdfReader(str(path))
            metadata = reader.metadata or {}
            for key, value in metadata.items():
                if not value:
                    continue
                field_key = f"PDF:{str(key).lstrip('/')}"
                str_value = str(value)[:500]
                pii_type = _classify_pii_type(field_key)
                if pii_type:
                    result.pii_findings.append(MetadataFinding(
                        field_name=field_key,
                        value=str_value,
                        pii_type=pii_type,
                        source="pypdf",
                    ))
                    result.all_fields[field_key] = str_value
                elif self.include_non_pii:
                    result.all_fields[field_key] = str_value
        except Exception as e:
            result.errors.append(f"PDF metadata error: {str(e)}")

    def _extract_office_metadata(self, path: Path, result: MetadataResult) -> None:
        """Extract metadata from Office documents."""
        try:
            from docx import Document

            doc = Document(str(path))
            props = doc.core_properties

            prop_map = {
                "author": props.author,
                "last_modified_by": props.last_modified_by,
                "title": props.title,
                "subject": props.subject,
                "keywords": props.keywords,
                "comments": props.comments,
                "category": props.category,
                "created": props.created,
                "modified": props.modified,
            }

            for key, value in prop_map.items():
                if value:
                    field_key = f"Office:{key}"
                    str_value = str(value)[:500]

                    pii_type = _classify_pii_type(field_key)
                    if pii_type or key in ("author", "last_modified_by"):
                        result.pii_findings.append(MetadataFinding(
                            field_name=field_key,
                            value=str_value,
                            pii_type=pii_type or "name",
                            source="python-docx",
                        ))
                        result.all_fields[field_key] = str_value
                    elif self.include_non_pii:
                        result.all_fields[field_key] = str_value

        except ImportError:
            result.errors.append("python-docx not installed for Office metadata")
        except Exception as e:
            result.errors.append(f"Office metadata error: {str(e)}")

    def strip_metadata(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        preserve_fields: Optional[Set[str]] = None,
    ) -> bool:
        """
        Strip metadata from a file.

        Args:
            input_path: Input file path.
            output_path: Output file path.
            preserve_fields: Fields to preserve (if any).

        Returns:
            True if successful.
        """
        input_p = Path(input_path)
        output_p = Path(output_path)

        # Use exiftool if available (most comprehensive)
        if _check_exiftool():
            try:
                cmd = ["exiftool", "-all="]

                if preserve_fields:
                    for field in preserve_fields:
                        cmd.extend([f"-{field}<{field}"])

                cmd.extend(["-o", str(output_p), str(input_p)])

                subprocess.run(cmd, capture_output=True, check=True)
                return True

            except Exception as exc:
                logger.debug("ExifTool metadata strip attempt failed for %s: %s", input_p, exc)

        # Fall back to Python-based stripping
        suffix = input_p.suffix.lower()

        if suffix in (".jpg", ".jpeg", ".png"):
            return self._strip_image_metadata(input_p, output_p)
        elif suffix == ".pdf":
            return self._strip_pdf_metadata(input_p, output_p)

        return False

    def _strip_image_metadata(self, input_path: Path, output_path: Path) -> bool:
        """Strip metadata from image using PIL."""
        try:
            from PIL import Image

            with Image.open(input_path) as img:
                # Create new image without EXIF
                data = list(img.getdata())
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(data)
                clean_img.save(output_path)
                return True

        except Exception:
            return False

    def _strip_pdf_metadata(self, input_path: Path, output_path: Path) -> bool:
        """Strip metadata from PDF using PyMuPDF."""
        use_pymupdf = os.getenv("PRIVACY_SHIELD_ENABLE_PYMUPDF", "").strip().lower() in {"1", "true", "yes", "on"}
        try:
            if not use_pymupdf:
                raise RuntimeError("PyMuPDF feature not enabled")
            import fitz

            with fitz.open(str(input_path)) as doc:
                # Clear metadata
                doc.set_metadata({})
                doc.save(str(output_path))
                return True

        except Exception:
            try:
                from pypdf import PdfReader, PdfWriter
                reader = PdfReader(str(input_path))
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                writer.add_metadata({})
                with output_path.open("wb") as f:
                    writer.write(f)
                return True
            except Exception:
                return False
