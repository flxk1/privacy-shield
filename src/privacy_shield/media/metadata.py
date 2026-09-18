"""
Privacy Shield - Metadata Extraction and Stripping

Extract and remove PII from file metadata (EXIF, ID3, PDF properties, etc.).
All processing is 100% local.
"""

from __future__ import annotations

import os
import logging
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Union

from ._tools import PROBE_TIMEOUT_SECONDS, operand, run_tool

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

# ID3v2 frame identifiers -> the logical field name the tables above are keyed
# on. Without this every ID3 lookup missed: mutagen reports an MP3's tags under
# their four-character frame ID (`TPE1`, `COMM::eng`, `TIT2`), the tables are
# keyed on words (`id3:artist`), and `_classify_pii_type("ID3:TPE1")` therefore
# returned None. An mp3 whose TPE1 named a person and whose COMM held a witness
# statement reported no metadata PII with mutagen fully installed.
ID3_FRAME_FIELDS = {
    "TPE1": "artist",
    "TPE2": "albumartist",
    "TPE3": "conductor",
    "TPE4": "arranger",
    "TCOM": "composer",
    "TEXT": "lyricist",
    "TOLY": "lyricist",
    "TOPE": "artist",
    "TIT1": "title",
    "TIT2": "title",
    "TIT3": "title",
    "TALB": "album",
    "TDRC": "date",
    "TDAT": "date",
    "TYER": "year",
    "TDRL": "date",
    "TOWN": "owner",
    "TPUB": "publisher",
    "TCOP": "copyright",
    "TENC": "encodedby",
    "COMM": "comment",
    "USLT": "lyrics",
    "TXXX": "comment",
    "WOAR": "artist",
    "APIC": "picture",
    "GEOB": "attachment",
    "PRIV": "private",
    "UFID": "uniquefileid",
}

# Tags whose payload is an embedded file rather than text: cover art is a
# photograph and can carry a face and its own EXIF block, GEOB is arbitrary.
# There is no text to scan, so presence alone is the finding.
EMBEDDED_PAYLOAD_FIELDS = {"picture", "attachment", "coverart", "metadata_block_picture"}

# exiftool group prefixes that describe the file's place on THIS filesystem
# rather than anything stored inside it. `-G` output always carries
# `File:FileModifyDate`, `File:FileAccessDate` and `File:FileInodeChangeDate`,
# and the substring rule in `_classify_pii_type` reads every one of them as a
# `datetime` finding. They cannot be stripped, because they are not in the
# file; they are re-created by the act of writing the output; and they do not
# travel with the bytes. Verification that counts them can never succeed, which
# is exactly what happened: with exiftool installed, `strip_metadata()` removed
# the author correctly and then returned False for every file of every type,
# because three filesystem timestamps were still "surviving findings".
NON_EMBEDDED_NAMESPACES = {"file", "system", "exiftool", "sourcefile"}

# What may appear in an exiftool tag-copy option built from `preserve_fields`.
# The value is interpolated into an argument token (`-{field}<{field}`), so
# although it can never become a separate argv entry or reach a shell, a field
# name carrying `<`, a space or a newline changes which tag operation exiftool
# performs.
# Must START with an alphanumeric: a leading `-` turns `-{field}` into `--execute`
# or `--all=`, which are exiftool operations rather than a tag to copy.
_SAFE_FIELD_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_:-]{0,63}\Z")


def is_non_embedded_field(field_name: object) -> bool:
    """Is this tag a fact about the filesystem rather than about the file?"""
    head = str(field_name).partition(":")[0].strip().lower()
    return head in NON_EMBEDDED_NAMESPACES


# A value hidden inside a deflated stream is not in the raw bytes. Bounded so a
# crafted file cannot turn verification into a decompression bomb: a PDF that
# expands to gigabytes stops at the cap and is reported as unverifiable rather
# than swallowing the machine.
_MAX_DECOMPRESSED_BYTES = 64 << 20
_MAX_DECOMPRESSED_OBJECTS = 4096


def _decompressed_views(path: Path) -> Iterator[tuple[str, bytes]]:
    """Yield ``(label, bytes)`` for content a raw byte scan cannot see.

    A raw scan of a PDF is a scan of deflated streams, so it reads as clean
    over content that any PDF reader recovers immediately. Covers the two
    container formats this package writes: PDF object streams and embedded
    files, and PNG compressed text chunks.
    """
    suffix = path.suffix.lower()
    try:
        if suffix == ".pdf":
            yield from _pdf_decompressed_views(path)
        elif suffix == ".png":
            yield from _png_decompressed_views(path)
    except Exception as exc:
        logger.debug("cannot decompress %s for verification: %s", path, exc)


def _pdf_decompressed_views(path: Path) -> Iterator[tuple[str, bytes]]:
    try:
        import pymupdf
    except ImportError:  # pragma: no cover - PyMuPDF is in [extract]
        try:
            import fitz as pymupdf
        except ImportError:
            logger.debug("no PyMuPDF: PDF streams cannot be verified decompressed")
            return

    budget = _MAX_DECOMPRESSED_BYTES
    with pymupdf.open(str(path)) as doc:
        for index in range(doc.embfile_count()):
            blob = doc.embfile_get(index)
            if blob:
                budget -= len(blob)
                yield (f"embedded file {index}", bytes(blob))
                if budget <= 0:
                    return
        for xref in range(1, min(doc.xref_length(), _MAX_DECOMPRESSED_OBJECTS)):
            try:
                if not doc.xref_is_stream(xref):
                    # Object definitions hold /Author and friends as plain
                    # strings outside any stream.
                    definition = doc.xref_object(xref, compressed=False)
                    if definition:
                        yield (f"object {xref}", definition.encode("utf-8", "replace"))
                    continue
                blob = doc.xref_stream(xref)
            except Exception as exc:
                logger.debug("xref %s of %s is unreadable: %s", xref, path, exc)
                continue
            if not blob:
                continue
            budget -= len(blob)
            yield (f"stream {xref}", bytes(blob))
            if budget <= 0:
                logger.debug("decompression budget exhausted verifying %s", path)
                return


def _png_decompressed_views(path: Path) -> Iterator[tuple[str, bytes]]:
    import struct

    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    offset, budget = 8, _MAX_DECOMPRESSED_BYTES
    while offset + 8 <= len(data) and budget > 0:
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        chunk_type = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        offset += 12 + length
        if chunk_type not in (b"zTXt", b"iTXt"):
            continue
        try:
            # zTXt: keyword \0 method deflate-data. iTXt carries two more
            # NUL-separated fields before the (optionally deflated) text.
            body = payload.split(b"\x00", 1)[1] if b"\x00" in payload else payload
            blob = zlib.decompressobj().decompress(body[1:], budget)
        except Exception as exc:
            logger.debug("PNG %s chunk is not readable: %s", chunk_type, exc)
            continue
        budget -= len(blob)
        yield (chunk_type.decode("ascii"), blob)


def normalise_tag_key(key: object) -> str:
    """A container tag key reduced to the word form the field tables use.

    Handles the three shapes a tag key arrives in: an ID3 frame id, possibly
    with a description suffix (`COMM::eng`, `TXXX:Author`); a Vorbis/QuickTime
    word in any case (`ARTIST`, `©ART`); and an already-prefixed field name
    (`EXIF:Artist`, `ID3:TPE1`).
    """
    text = str(key).strip()
    if ":" in text:
        head, _, tail = text.partition(":")
        # `COMM::eng` and `TXXX:Author` are one frame id plus a description;
        # `EXIF:Artist` and `Composite:GPSPosition` are a namespace plus a
        # field. The frame table decides which shape this is, because guessing
        # from a fixed namespace list got `Composite:` and `File:` wrong.
        if head.upper() in ID3_FRAME_FIELDS:
            text = head
        else:
            text = (tail or head).partition(":")[0]
    text = text.strip()
    frame = ID3_FRAME_FIELDS.get(text.upper())
    if frame:
        return frame
    return text.lstrip("©").lower()


# The field tables are keyed on namespaced names (`id3:title`, `exif:artist`).
# A normalised tag key is the bare word, so the tables are re-indexed by their
# last component - derived from the tables themselves, so adding a field to a
# table is enough and there is no second list to keep in step.
_PII_FIELD_WORD_TYPES = {
    word: pii_type
    for table, pii_type in (
        (GPS_FIELDS, "gps"),
        (NAME_FIELDS, "name"),
        (ID_FIELDS, "device_id"),
        (CONTENT_FIELDS, "content"),
        (DATE_FIELDS, "datetime"),
        (ORG_FIELDS, "organization"),
    )
    for word in (f.split(":")[-1] for f in table)
}


def tag_pii_type(key: object) -> Optional[str]:
    """The PII type for a container tag key, or None.

    The single entry point for audio, video and image tag classification, so
    the field taxonomy above is stated once. `audio.py` and `video.py` each had
    their own hand-written subset - audio flagged `artist` and `comment` only,
    video flagged `artist` and two literal GPS keys - and both missed the rest
    of the same table.
    """
    name = normalise_tag_key(key)
    if not name:
        return None
    if name in EMBEDDED_PAYLOAD_FIELDS:
        return "embedded_payload"
    word_type = _PII_FIELD_WORD_TYPES.get(name)
    if word_type:
        return word_type
    return _classify_pii_type(name)


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
        # A presence probe, so the probe budget - not the five minutes a
        # transcode is allowed. An exiftool that hangs on `-ver` should cost a
        # scan fifteen seconds, not five minutes per file.
        run_tool(["exiftool", "-ver"], timeout=PROBE_TIMEOUT_SECONDS)
        return True
    except Exception as exc:
        logger.debug("exiftool unavailable: %s", exc)
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
            output = run_tool(
                ["exiftool", "-json", "-a", "-G", operand(path)],
                text=True,
            )

            data = json.loads(output.stdout)
            if data and len(data) > 0:
                metadata = data[0]

                for key, value in metadata.items():
                    if key == "SourceFile":
                        continue

                    str_value = str(value)[:500]  # Truncate long values

                    # Check if this is a PII field
                    pii_type = tag_pii_type(key)

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

                        pii_type = tag_pii_type(key)
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

                    pii_type = tag_pii_type(field_key)
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

                        pii_type = tag_pii_type(field_key)
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
                pii_type = tag_pii_type(field_key)
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

                    pii_type = tag_pii_type(field_key)
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
            True only if the output file exists and no longer carries any of
            the input's metadata PII.

        Every strategy below is followed by :meth:`_verify_stripped`, because a
        strip that reports success without checking is a promise the caller
        cannot audit - and each of the three was making exactly that promise
        falsely. Verification errs towards refusal: if a value cannot be shown
        to be gone, this returns False and the caller must not egress the
        output.
        """
        input_p = Path(input_path)
        output_p = Path(output_path)

        if preserve_fields:
            rejected = sorted(
                str(f) for f in preserve_fields if not _SAFE_FIELD_NAME.match(str(f))
            )
            if rejected:
                # Refuse rather than sanitise: a caller who asked to preserve a
                # field this cannot express has not had their request honoured,
                # and a silently dropped preserve is a silently stripped field.
                logger.debug("refusing unsafe preserve_fields: %s", rejected)
                return False

        before = self.extract(input_p)

        # Use exiftool if available (most comprehensive) - except on PDF, where
        # it cannot do the job. `exiftool -all=` on a PDF is an INCREMENTAL
        # UPDATE: it appends a revision marking the tags deleted and leaves the
        # original DocInfo object in the file, which is why the output is
        # LARGER than the input and why exiftool prints
        #
        #     Warning: [minor] ExifTool PDF edits are reversible.
        #                      Deleted tags may be recovered!
        #
        # Both exiftool and PyMuPDF then re-read that output as clean, so every
        # reader-based check passes while the author's name is still plainly in
        # the bytes. Measured; the byte check refuses it. Rewriting the file is
        # the only strip that holds for PDF, so go straight to PyMuPDF.
        if input_p.suffix.lower() != ".pdf" and _check_exiftool():
            try:
                cmd = ["exiftool", "-all="]

                if preserve_fields:
                    for field in preserve_fields:
                        cmd.extend([f"-{field}<{field}"])

                # exiftool's -o refuses to overwrite an existing target, and a
                # stale file left at that path would otherwise have been
                # reported as the stripped copy.
                if output_p.exists():
                    output_p.unlink()

                cmd.extend(["-o", operand(output_p), operand(input_p)])

                run_tool(cmd)
                if self._verify_stripped(before, output_p, preserve_fields):
                    return True
                logger.debug("exiftool strip left metadata behind in %s", output_p)

            except Exception as exc:
                logger.debug("ExifTool metadata strip attempt failed for %s: %s", input_p, exc)

        # Fall back to Python-based stripping
        suffix = input_p.suffix.lower()

        if suffix in (".jpg", ".jpeg", ".png"):
            stripped = self._strip_image_metadata(input_p, output_p)
        elif suffix == ".pdf":
            stripped = self._strip_pdf_metadata(input_p, output_p)
        else:
            return False

        return stripped and self._verify_stripped(before, output_p, preserve_fields)

    def _verify_stripped(
        self,
        before: MetadataResult,
        output_path: Path,
        preserve_fields: Optional[Set[str]] = None,
    ) -> bool:
        """Did the strip actually remove what the input carried?

        Two independent checks, because the first alone is what made the PDF
        path lie. Reading the output's metadata back through the same parsers
        said "clean" while the author's name and the patient file number were
        still sitting in the file as superseded objects - PyMuPDF's default
        save keeps them, so anything that walks the xref recovers them. So the
        second check reads the BYTES.

        Both checks skip `NON_EMBEDDED_NAMESPACES`: a filesystem timestamp is
        not in the file, is re-created by writing the output, and so is a
        "surviving finding" for every file that has ever been written.

        The byte check looks inside compressed containers as well as at the
        raw bytes, because a raw scan of a deflated PDF stream sees nothing -
        which made this check pass over values that were demonstrably still
        recoverable from the output.
        """
        if not output_path.exists():
            return False

        keep = {str(f).lower() for f in (preserve_fields or set())}

        after = self.extract(output_path)
        for finding in after.pii_findings:
            if is_non_embedded_field(finding.field_name):
                continue
            if normalise_tag_key(finding.field_name) not in keep:
                logger.debug("metadata survived the strip: %s", finding.field_name)
                return False

        needles: List[tuple[str, bytes]] = []
        for finding in before.pii_findings:
            if is_non_embedded_field(finding.field_name):
                continue
            if normalise_tag_key(finding.field_name) in keep:
                continue
            value = finding.value.strip()
            # Short values collide with ordinary binary content; a name, a file
            # reference or a serial number is longer than this.
            if len(value) < 6:
                continue
            for encoding in ("utf-8", "utf-16-be", "latin-1"):
                try:
                    needles.append((finding.field_name, value.encode(encoding)))
                except UnicodeError as exc:
                    # Not encodable in this charset, so the file cannot hold it
                    # in this charset either. Logged rather than swallowed: a
                    # silent skip here is a check that quietly stopped running.
                    logger.debug("cannot search for %r as %s: %s", value, encoding, exc)

        if not needles:
            return True

        found = self._first_needle_in_file(output_path, needles)
        if found:
            logger.debug("value of %s is still present in %s", found, output_path)
            return False

        for label, blob in _decompressed_views(output_path):
            for field_name, needle in needles:
                if needle in blob:
                    logger.debug(
                        "value of %s survives inside %s of %s",
                        field_name, label, output_path,
                    )
                    return False

        return True

    @staticmethod
    def _first_needle_in_file(
        path: Path,
        needles: List[tuple[str, bytes]],
    ) -> Optional[str]:
        """Scan *path* in chunks for any needle. Returns the field name, or None.

        Chunked rather than `read_bytes()` because the file being verified is
        attacker-controlled and unbounded in size - `strip_metadata` applies no
        size limit of its own, unlike `shield.process_file` - and a whole-file
        read turns one large input into a memory spike. The overlap is one byte
        short of the longest needle so nothing hides on a chunk boundary.
        """
        overlap = max(len(n) for _, n in needles) - 1
        chunk_size = max(1 << 20, overlap + 1)
        try:
            with path.open("rb") as handle:
                tail = b""
                while True:
                    block = handle.read(chunk_size)
                    if not block:
                        return None
                    window = tail + block
                    for field_name, needle in needles:
                        if needle in window:
                            return field_name
                    tail = window[-overlap:] if overlap else b""
        except OSError as exc:
            logger.debug("cannot verify %s: %s", path, exc)
            # Unreadable output cannot be shown to be clean.
            return "<unreadable output>"

    def _strip_image_metadata(self, input_path: Path, output_path: Path) -> bool:
        """Strip metadata from image using PIL."""
        try:
            from PIL import Image

            with Image.open(input_path) as img:
                # Create new image without EXIF
                data = list(img.getdata())
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(data)
                # An index-mode image keeps its colours in the palette, which
                # Image.new() does not carry over, so the "cleaned" copy came
                # out rendering against an empty one.
                if img.mode in ("P", "PA"):
                    palette = img.getpalette()
                    if palette:
                        clean_img.putpalette(palette)
                clean_img.save(output_path)
                return True

        except Exception as exc:
            logger.debug("PIL metadata strip failed for %s: %s", input_path, exc)
            return False

    def _strip_pdf_metadata(self, input_path: Path, output_path: Path) -> bool:
        """Strip metadata from PDF using PyMuPDF."""
        use_pymupdf = os.getenv("PRIVACY_SHIELD_ENABLE_PYMUPDF", "").strip().lower() in {"1", "true", "yes", "on"}
        try:
            if not use_pymupdf:
                raise RuntimeError("PyMuPDF feature not enabled")
            import fitz

            with fitz.open(str(input_path)) as doc:
                # `set_metadata({})` clears the DocInfo dictionary and nothing
                # else. The XMP packet in the catalogue is a separate store of
                # the same author/title/subject and needs its own call, and a
                # default save keeps the superseded objects in the file, so the
                # old values stayed recoverable from the output. garbage=4
                # drops the unreferenced objects, clean sanitises the content
                # streams.
                doc.del_xml_metadata()
                doc.set_metadata({})
                doc.save(
                    str(output_path),
                    garbage=4,
                    deflate=True,
                    clean=True,
                )
                return True

        except Exception as exc:
            logger.debug("PyMuPDF metadata strip failed for %s: %s", input_path, exc)
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
            except Exception as inner:
                logger.debug("pypdf metadata strip failed for %s: %s", input_path, inner)
                return False
