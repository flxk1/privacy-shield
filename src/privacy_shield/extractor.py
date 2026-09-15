"""
Privacy Shield - Document Extractor

Extract text from various document formats.
Uses native extraction when possible, OCR as fallback.
All processing is 100% local.
"""

from __future__ import annotations

import io
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Optional imports - gracefully handle missing dependencies
_ENABLE_PYMUPDF = os.getenv("PRIVACY_SHIELD_ENABLE_PYMUPDF", "").strip().lower() in {"1", "true", "yes", "on"}
if _ENABLE_PYMUPDF:
    try:
        import fitz  # PyMuPDF
        HAS_PYMUPDF = True
    except ImportError:
        HAS_PYMUPDF = False
else:
    HAS_PYMUPDF = False

try:
    from docx import Document as DocxDocument
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


class DocumentType(str, Enum):
    """Supported document types."""
    PDF_NATIVE = "pdf_native"  # PDF with text layer
    PDF_SCANNED = "pdf_scanned"  # PDF requiring OCR
    DOCX = "docx"
    DOC = "doc"
    TXT = "txt"
    RTF = "rtf"
    HTML = "html"
    IMAGE = "image"
    UNKNOWN = "unknown"


class ExtractionMethod(str, Enum):
    """How text was extracted."""
    TEXT_LAYER = "text_layer"  # Native PDF text
    XML_PARSE = "xml_parse"  # Office documents
    OCR = "ocr"  # Optical character recognition
    DIRECT = "direct"  # Plain text


@dataclass
class PageContent:
    """Content extracted from a single page."""
    page_number: int
    text: str
    width: float = 0.0
    height: float = 0.0
    char_count: int = 0
    has_images: bool = False
    ocr_used: bool = False


@dataclass
class DocumentZone:
    """A detected zone within a document page."""
    zone_type: str  # header, body, signature, footer
    page: int
    y_start: float  # Relative position (0-1)
    y_end: float
    text: str


@dataclass
class ExtractionResult:
    """Result of document text extraction."""
    file_path: str
    document_type: DocumentType
    extraction_method: ExtractionMethod
    pages: List[PageContent] = field(default_factory=list)
    zones: List[DocumentZone] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    total_chars: int = 0
    total_pages: int = 0
    ocr_pages: int = 0
    extraction_time_ms: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def full_text(self) -> str:
        """Get all text concatenated."""
        return "\n\n".join(p.text for p in self.pages if p.text)

    @property
    def needs_ocr(self) -> bool:
        """Check if document needs OCR."""
        return self.document_type == DocumentType.PDF_SCANNED

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "document_type": self.document_type.value,
            "extraction_method": self.extraction_method.value,
            "total_pages": self.total_pages,
            "total_chars": self.total_chars,
            "ocr_pages": self.ocr_pages,
            "extraction_time_ms": self.extraction_time_ms,
            "metadata": self.metadata,
            "errors": self.errors,
        }


def detect_document_type(file_path: Union[str, Path]) -> DocumentType:
    """
    Detect document type from file.

    Uses magic bytes when available, falls back to extension.
    """
    path = Path(file_path)

    if not path.exists():
        return DocumentType.UNKNOWN

    # Try magic bytes first
    if HAS_MAGIC:
        try:
            mime = magic.from_file(str(path), mime=True)
            if mime == "application/pdf":
                # Check if PDF has text layer
                if HAS_PYMUPDF:
                    return _check_pdf_type(path)
                return DocumentType.PDF_NATIVE  # Assume native if can't check
            elif mime in ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",):
                return DocumentType.DOCX
            elif mime == "application/msword":
                return DocumentType.DOC
            elif mime == "text/plain":
                return DocumentType.TXT
            elif mime == "text/html":
                return DocumentType.HTML
            elif mime == "text/rtf":
                return DocumentType.RTF
            elif mime and mime.startswith("image/"):
                return DocumentType.IMAGE
        except Exception as exc:
            logger.debug("MIME-based document type detection failed for %s: %s", path, exc)

    # Fall back to extension
    ext = path.suffix.lower()
    ext_map = {
        ".pdf": DocumentType.PDF_NATIVE,
        ".docx": DocumentType.DOCX,
        ".doc": DocumentType.DOC,
        ".txt": DocumentType.TXT,
        ".rtf": DocumentType.RTF,
        ".html": DocumentType.HTML,
        ".htm": DocumentType.HTML,
        ".png": DocumentType.IMAGE,
        ".jpg": DocumentType.IMAGE,
        ".jpeg": DocumentType.IMAGE,
        ".tiff": DocumentType.IMAGE,
        ".tif": DocumentType.IMAGE,
        ".bmp": DocumentType.IMAGE,
        ".gif": DocumentType.IMAGE,
        ".webp": DocumentType.IMAGE,
    }

    doc_type = ext_map.get(ext, DocumentType.UNKNOWN)

    # For PDF, check if it has text
    if doc_type == DocumentType.PDF_NATIVE and HAS_PYMUPDF:
        doc_type = _check_pdf_type(path)

    return doc_type


def _check_pdf_type(file_path: Path) -> DocumentType:
    """Check if PDF has text layer or needs OCR."""
    try:
        with fitz.open(str(file_path)) as doc:
            total_chars = 0
            total_images = 0
            for page in doc:
                total_chars += len(page.get_text())
                total_images += len(page.get_images())

            # Heuristic: if very few chars but many images, likely scanned
            if total_chars < 100 and total_images > 0:
                return DocumentType.PDF_SCANNED
            return DocumentType.PDF_NATIVE
    except Exception:
        return DocumentType.PDF_NATIVE


def _detect_zones(page_text: str, page_height: float) -> List[Tuple[str, float, float]]:
    """
    Detect document zones based on content heuristics.

    Returns list of (zone_type, y_start, y_end) tuples.
    """
    # Simple zone detection based on page position
    # In a real implementation, this would use bounding boxes
    zones = []

    lines = page_text.split("\n")
    if not lines:
        return [("body", 0.0, 1.0)]

    total_lines = len(lines)
    if total_lines < 5:
        return [("body", 0.0, 1.0)]

    # Rough zone detection
    header_end = min(0.15, 3 / total_lines)
    footer_start = max(0.85, (total_lines - 3) / total_lines)
    signature_start = max(0.75, (total_lines - 6) / total_lines)

    # Check for signature indicators in bottom portion
    bottom_text = "\n".join(lines[int(total_lines * 0.7):]).lower()
    has_signature = any(
        indicator in bottom_text
        for indicator in [
            "unterschrift", "signature", "signed", "gezeichnet",
            "mit freundlichen", "kind regards", "sincerely",
            "datum", "date:", "ort,", "place,"
        ]
    )

    zones.append(("header", 0.0, header_end))
    if has_signature:
        zones.append(("body", header_end, signature_start))
        zones.append(("signature", signature_start, footer_start))
    else:
        zones.append(("body", header_end, footer_start))
    zones.append(("footer", footer_start, 1.0))

    return zones


class DocumentExtractor:
    """
    Extract text from various document formats.

    All processing is 100% local - no external API calls.
    """

    def __init__(
        self,
        detect_zones: bool = True,
        extract_metadata: bool = True,
        ocr_engine: Optional[str] = None,
    ):
        """
        Initialize the extractor.

        Args:
            detect_zones: Whether to detect document zones.
            extract_metadata: Whether to extract document metadata.
            ocr_engine: OCR engine to use ('paddleocr', 'tesseract', 'doctr').
                       None = use first available.
        """
        self.detect_zones = detect_zones
        self.extract_metadata = extract_metadata
        self.ocr_engine = ocr_engine

    def extract(self, file_path: Union[str, Path]) -> ExtractionResult:
        """
        Extract text from a document.

        Args:
            file_path: Path to the document.

        Returns:
            ExtractionResult with extracted content.
        """
        import time
        start_time = time.perf_counter()

        path = Path(file_path)
        result = ExtractionResult(
            file_path=str(path),
            document_type=DocumentType.UNKNOWN,
            extraction_method=ExtractionMethod.DIRECT,
        )

        if not path.exists():
            result.errors.append(f"File not found: {path}")
            return result

        doc_type = detect_document_type(path)
        result.document_type = doc_type

        try:
            if doc_type in (DocumentType.PDF_NATIVE, DocumentType.PDF_SCANNED):
                self._extract_pdf(path, result)
            elif doc_type == DocumentType.DOCX:
                self._extract_docx(path, result)
            elif doc_type == DocumentType.TXT:
                self._extract_text(path, result)
            elif doc_type == DocumentType.IMAGE:
                self._extract_image(path, result)
            else:
                result.errors.append(f"Unsupported document type: {doc_type.value}")
        except Exception as e:
            result.errors.append(f"Extraction error: {str(e)}")

        # Calculate totals
        result.total_pages = len(result.pages)
        result.total_chars = sum(p.char_count for p in result.pages)
        result.ocr_pages = sum(1 for p in result.pages if p.ocr_used)

        result.extraction_time_ms = (time.perf_counter() - start_time) * 1000

        return result

    def _extract_pdf(self, path: Path, result: ExtractionResult) -> None:
        """Extract text from PDF."""
        if not HAS_PYMUPDF:
            try:
                from pypdf import PdfReader
            except ImportError:
                result.errors.append("PDF parser not installed. Install PyMuPDF or pypdf.")
                return
            result.extraction_method = ExtractionMethod.TEXT_LAYER
            reader = PdfReader(str(path))
            meta = reader.metadata or {}
            if self.extract_metadata:
                for key, source in {
                    "title": "/Title",
                    "author": "/Author",
                    "subject": "/Subject",
                    "creator": "/Creator",
                    "producer": "/Producer",
                }.items():
                    if meta.get(source):
                        result.metadata[key] = str(meta[source])
            for page_num, page in enumerate(reader.pages, start=1):
                text = page.extract_text() or ""
                result.pages.append(
                    PageContent(
                        page_number=page_num,
                        text=text,
                        width=0.0,
                        height=0.0,
                        char_count=len(text),
                        has_images=False,
                        ocr_used=False,
                    )
                )
            return

        result.extraction_method = ExtractionMethod.TEXT_LAYER

        with fitz.open(str(path)) as doc:
            # Extract metadata
            if self.extract_metadata:
                meta = doc.metadata or {}
                for key in ["title", "author", "subject", "creator", "producer"]:
                    if meta.get(key):
                        result.metadata[key] = str(meta[key])

            for page_num, page in enumerate(doc, start=1):
                text = page.get_text()
                rect = page.rect

                page_content = PageContent(
                    page_number=page_num,
                    text=text,
                    width=rect.width,
                    height=rect.height,
                    char_count=len(text),
                    has_images=len(page.get_images()) > 0,
                    ocr_used=False,
                )

                # Check if page needs OCR (scanned page)
                if len(text.strip()) < 50 and page_content.has_images:
                    # Mark for OCR - actual OCR done by image pipeline
                    page_content.ocr_used = True
                    result.extraction_method = ExtractionMethod.OCR

                result.pages.append(page_content)

                # Detect zones
                if self.detect_zones and text.strip():
                    zones = _detect_zones(text, rect.height)
                    lines = text.split("\n")
                    total_lines = max(1, len(lines))

                    for zone_type, y_start, y_end in zones:
                        line_start = int(y_start * total_lines)
                        line_end = int(y_end * total_lines)
                        zone_text = "\n".join(lines[line_start:line_end])

                        if zone_text.strip():
                            result.zones.append(DocumentZone(
                                zone_type=zone_type,
                                page=page_num,
                                y_start=y_start,
                                y_end=y_end,
                                text=zone_text,
                            ))

    def _extract_docx(self, path: Path, result: ExtractionResult) -> None:
        """Extract text from DOCX."""
        if not HAS_DOCX:
            result.errors.append("python-docx not installed. Install with: pip install python-docx")
            return

        result.extraction_method = ExtractionMethod.XML_PARSE

        try:
            doc = DocxDocument(str(path))
        except Exception as e:
            result.errors.append(f"Failed to open DOCX file: {e}")
            return

        # Extract core properties as metadata
        try:
            if self.extract_metadata:
                props = doc.core_properties
                if props.author:
                    result.metadata["author"] = str(props.author)
                if props.title:
                    result.metadata["title"] = str(props.title)
                if props.subject:
                    result.metadata["subject"] = str(props.subject)
                if props.last_modified_by:
                    result.metadata["last_modified_by"] = str(props.last_modified_by)
                if props.company:
                    result.metadata["company"] = str(props.company)
        except Exception as e:
            result.errors.append(f"Failed to extract DOCX metadata: {e}")

        # Extract all paragraphs as single page
        try:
            paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        except Exception as e:
            result.errors.append(f"Failed to extract DOCX paragraphs: {e}")
            return

        full_text = "\n\n".join(paragraphs)

        result.pages.append(PageContent(
            page_number=1,
            text=full_text,
            char_count=len(full_text),
        ))

        # Basic zone detection for DOCX
        if self.detect_zones and paragraphs:
            # First few paragraphs = header
            header_text = "\n".join(paragraphs[:3])
            result.zones.append(DocumentZone(
                zone_type="header",
                page=1,
                y_start=0.0,
                y_end=0.1,
                text=header_text,
            ))

            # Middle = body
            if len(paragraphs) > 6:
                body_text = "\n".join(paragraphs[3:-3])
                result.zones.append(DocumentZone(
                    zone_type="body",
                    page=1,
                    y_start=0.1,
                    y_end=0.9,
                    text=body_text,
                ))

                # Last few paragraphs = signature/footer
                footer_text = "\n".join(paragraphs[-3:])
                result.zones.append(DocumentZone(
                    zone_type="signature",
                    page=1,
                    y_start=0.9,
                    y_end=1.0,
                    text=footer_text,
                ))
            else:
                body_text = "\n".join(paragraphs[3:])
                result.zones.append(DocumentZone(
                    zone_type="body",
                    page=1,
                    y_start=0.1,
                    y_end=1.0,
                    text=body_text,
                ))

    def _extract_text(self, path: Path, result: ExtractionResult) -> None:
        """Extract text from plain text file."""
        result.extraction_method = ExtractionMethod.DIRECT

        # Try different encodings
        encodings = ["utf-8", "latin-1", "cp1252"]
        text = None

        for encoding in encodings:
            try:
                text = path.read_text(encoding=encoding)
                break
            except UnicodeDecodeError:
                continue

        if text is None:
            result.errors.append("Could not decode text file with any supported encoding")
            return

        result.pages.append(PageContent(
            page_number=1,
            text=text,
            char_count=len(text),
        ))

    def _extract_image(self, path: Path, result: ExtractionResult) -> None:
        """Mark image for OCR processing."""
        result.extraction_method = ExtractionMethod.OCR
        result.document_type = DocumentType.IMAGE

        # Actual OCR is done by the image pipeline
        # Here we just mark it as needing OCR
        result.pages.append(PageContent(
            page_number=1,
            text="",  # Will be filled by OCR
            has_images=True,
            ocr_used=True,
        ))


def extract_document(
    file_path: Union[str, Path],
    detect_zones: bool = True,
    extract_metadata: bool = True,
) -> ExtractionResult:
    """
    Convenience function to extract text from a document.

    Args:
        file_path: Path to the document.
        detect_zones: Whether to detect document zones.
        extract_metadata: Whether to extract metadata.

    Returns:
        ExtractionResult with extracted content.
    """
    extractor = DocumentExtractor(
        detect_zones=detect_zones,
        extract_metadata=extract_metadata,
    )
    return extractor.extract(file_path)
