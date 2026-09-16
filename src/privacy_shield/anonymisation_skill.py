"""
Anonymisation & Pseudonymisation Skill

Higher-level orchestration layer on top of Privacy Shield.
Adds: persistent sessions, granular field-level control, batch processing,
anonymisation quality assessment (k-anonymity), and rehydration workflows.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Counter, Dict, List, Optional, Set

from .audit_log import _STATE_APP_DIR, _user_state_home
from .redactor import Redactor, RedactionMode, RedactionResult, SelectionMode
from .scanner import Confidence, Finding, PIIType, PrivacyScanner, ScanResult

logger = logging.getLogger(__name__)

SESSION_STORE_ENV = "PRIVACY_SHIELD_SESSION_STORE_DIR"


# =============================================================================
# ENUMS & CONFIGURATION
# =============================================================================


class AnonymisationMode(str, Enum):
    """Processing mode for the anonymisation skill."""

    ANONYMISE = "anonymise"  # Irreversible de-identification
    PSEUDONYMISE = "pseudonymise"  # Reversible consistent replacement
    ASSESS = "assess"  # Evaluate anonymisation quality
    REHYDRATE = "rehydrate"  # Restore originals from pseudonymised data
    BATCH = "batch"  # Process multiple documents


class OutputFormat(str, Enum):
    """Output format for results."""

    TEXT = "text"
    JSON = "json"
    REPORT = "report"


class ReIdentificationRisk(str, Enum):
    """Re-identification risk level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Generalisation rules for anonymisation mode
GENERALISATION_RULES: Dict[PIIType, str] = {
    PIIType.DATE_OF_BIRTH: "year_only",  # 15.03.1985 → 1985
    PIIType.AGE: "range",  # 34 → 30-39
    PIIType.PLZ_CITY: "region",  # 80331 München → Bayern
    PIIType.ADDRESS: "suppress",  # Remove entirely
}

# Art. 9 types that must always be suppressed (never generalised)
ART9_TYPES: Set[PIIType] = {
    PIIType.HEALTH_DATA,
    PIIType.ICD_CODE,
    PIIType.BIOMETRIC,
    PIIType.POLITICAL,
    PIIType.RELIGIOUS,
    PIIType.UNION,
    PIIType.SEXUAL,
    PIIType.CRIMINAL,
    PIIType.GENETIC,
}

# German region mapping for PLZ generalisation
PLZ_REGION_MAP = {
    "0": "Sachsen/Thüringen",
    "1": "Berlin/Brandenburg",
    "2": "Hamburg/Schleswig-Holstein/Mecklenburg-Vorpommern",
    "3": "Niedersachsen/Bremen",
    "4": "Nordrhein-Westfalen (West)",
    "5": "Nordrhein-Westfalen (Süd)/Rheinland-Pfalz",
    "6": "Hessen/Saarland",
    "7": "Baden-Württemberg",
    "8": "Bayern (Süd)",
    "9": "Bayern (Nord)/Thüringen",
}


# =============================================================================
# RESULT TYPES
# =============================================================================


@dataclass
class QualityAssessment:
    """Anonymisation quality assessment result."""

    k_anonymity: Optional[int] = None
    l_diversity: Optional[int] = None
    re_identification_risk: ReIdentificationRisk = ReIdentificationRisk.HIGH
    residual_quasi_identifiers: List[str] = field(default_factory=list)
    residual_direct_identifiers: int = 0
    art9_remaining: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "k_anonymity": self.k_anonymity,
            "l_diversity": self.l_diversity,
            "re_identification_risk": self.re_identification_risk.value,
            "residual_quasi_identifiers": self.residual_quasi_identifiers,
            "residual_direct_identifiers": self.residual_direct_identifiers,
            "art9_remaining": self.art9_remaining,
            "notes": self.notes,
        }


@dataclass
class BatchDocumentResult:
    """Result for a single document in batch mode."""

    file_path: str
    findings_count: int = 0
    transformations_applied: int = 0
    residual_pii: int = 0
    quality_score: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "findings_count": self.findings_count,
            "transformations_applied": self.transformations_applied,
            "residual_pii": self.residual_pii,
            "quality_score": self.quality_score,
            "error": self.error,
        }


@dataclass
class BatchSummary:
    """Summary of batch processing."""

    total_documents: int = 0
    documents_processed: int = 0
    documents_failed: int = 0
    cross_document_entities: int = 0
    per_document_results: List[BatchDocumentResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_documents": self.total_documents,
            "documents_processed": self.documents_processed,
            "documents_failed": self.documents_failed,
            "cross_document_entities": self.cross_document_entities,
            "per_document_results": [r.to_dict() for r in self.per_document_results],
        }


@dataclass
class AnonymisationResult:
    """Complete result of anonymisation/pseudonymisation processing."""

    processed_text: str
    mode: AnonymisationMode
    findings_count: int = 0
    transformations_applied: int = 0
    residual_pii: int = 0
    quality_score: float = 0.0
    pii_types_found: List[str] = field(default_factory=list)
    art9_detected: bool = False
    session_id: Optional[str] = None
    mappings_stored: bool = False
    assessment: Optional[QualityAssessment] = None
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    warnings: List[str] = field(default_factory=list)
    batch_summary: Optional[BatchSummary] = None

    def to_dict(self) -> dict:
        result: Dict[str, Any] = {
            "processed_text": self.processed_text,
            "mode": self.mode.value,
            "findings_count": self.findings_count,
            "transformations_applied": self.transformations_applied,
            "residual_pii": self.residual_pii,
            "quality_score": self.quality_score,
            "pii_types_found": self.pii_types_found,
            "art9_detected": self.art9_detected,
            "session_id": self.session_id,
            "mappings_stored": self.mappings_stored,
            "audit_id": self.audit_id,
            "warnings": self.warnings,
        }
        if self.assessment:
            result["assessment"] = self.assessment.to_dict()
        if self.batch_summary:
            result["batch_summary"] = self.batch_summary.to_dict()
        return result


# =============================================================================
# SESSION STORE
# =============================================================================


class PseudonymisationSession:
    """
    Persistent pseudonymisation session.

    Maintains consistent pseudonym mappings across multiple calls.

    A saved session holds the full re-identification map - pseudonym back to
    the real name, email or IBAN it stands for. It is stored as PLAINTEXT
    JSON; nothing in this package encrypts it. What it gets instead is the
    user-state home rather than the installed package tree, and 0600 on the
    file with 0700 on the directory. Treat a saved session as being exactly
    as sensitive as the source document, because it is.
    """

    def __init__(self, session_id: Optional[str] = None, store_path: Optional[str] = None):
        self.session_id = session_id or str(uuid.uuid4())
        self._store_path = store_path
        self._mappings: Dict[str, str] = {}
        self._reverse_mappings: Dict[str, str] = {}
        self._entity_counter: Dict[str, int] = {}

        # Resume existing session if ID provided
        if session_id:
            self._load_session()

    def store_path(self) -> Path:
        """Where sessions live - resolved at call time.

        The OS user-state home, the same root as the audit log and the breach
        log, NOT ``os.path.dirname(__file__)``: site-packages is shared between
        every user of the interpreter, is world-readable by default, and is
        wiped on reinstall. A re-identification map does not belong there.
        """
        if self._store_path:
            return Path(self._store_path)
        override = str(os.environ.get(SESSION_STORE_ENV, "")).strip()
        if override:
            return Path(override)
        return _user_state_home() / _STATE_APP_DIR / "pseudonymisation_sessions"

    def _session_file(self) -> Path:
        """Get path to session file."""
        path = self.store_path()
        path.mkdir(parents=True, exist_ok=True)
        try:
            path.chmod(0o700)
        except OSError as exc:
            logger.warning("Cannot restrict %s to 0700: %s", path, exc)
        # Sanitise session_id for filesystem safety
        safe_id = "".join(c for c in self.session_id if c.isalnum() or c in "-_")[:64]
        return path / f"{safe_id}.json"

    def _load_session(self) -> None:
        """Load existing session from disk."""
        session_file = self._session_file()
        if session_file.exists():
            try:
                data = json.loads(session_file.read_text(encoding="utf-8"))
                self._mappings = data.get("mappings", {})
                self._reverse_mappings = data.get("reverse_mappings", {})
                self._entity_counter = data.get("entity_counter", {})
                logger.info("Resumed pseudonymisation session %s", self.session_id)
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("Failed to load session %s: %s", self.session_id, exc)

    def save(self) -> None:
        """Persist session to disk."""
        session_file = self._session_file()
        data = {
            "session_id": self.session_id,
            "mappings": self._mappings,
            "reverse_mappings": self._reverse_mappings,
            "entity_counter": self._entity_counter,
            "saved_at": time.time(),
        }
        session_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            session_file.chmod(0o600)
        except OSError as exc:
            logger.warning("Cannot restrict %s to 0600: %s", session_file, exc)
        logger.info("Saved pseudonymisation session %s", self.session_id)

    def get_or_create_pseudonym(self, original: str, pii_type: PIIType) -> str:
        """Get existing pseudonym or create a new consistent one."""
        if original in self._mappings:
            return self._mappings[original]

        type_key = pii_type.value
        counter = self._entity_counter.get(type_key, 0)
        self._entity_counter[type_key] = counter + 1

        pseudo = self._generate_pseudonym(pii_type, counter)
        self._mappings[original] = pseudo
        self._reverse_mappings[pseudo] = original
        return pseudo

    def _generate_pseudonym(self, pii_type: PIIType, counter: int) -> str:
        """Generate a type-appropriate pseudonym."""
        from .redactor import (
            FAKE_ADDRESSES,
            FAKE_CITIES,
            FAKE_EMAIL_DOMAINS,
            FAKE_NAMES,
        )

        if pii_type == PIIType.NAME:
            return FAKE_NAMES[counter % len(FAKE_NAMES)]
        elif pii_type == PIIType.EMAIL:
            domain = FAKE_EMAIL_DOMAINS[counter % len(FAKE_EMAIL_DOMAINS)]
            return f"person{counter}@{domain}"
        elif pii_type == PIIType.PHONE:
            return f"+49 000 000{counter:04d}"
        elif pii_type == PIIType.ADDRESS:
            return FAKE_ADDRESSES[counter % len(FAKE_ADDRESSES)]
        elif pii_type == PIIType.PLZ_CITY:
            return FAKE_CITIES[counter % len(FAKE_CITIES)]
        elif pii_type == PIIType.IBAN:
            return f"DE00 0000 0000 0000 0000 {counter:02d}"
        elif pii_type == PIIType.DATE_OF_BIRTH:
            return "01.01.1990"
        elif pii_type == PIIType.IP_ADDRESS:
            return f"10.0.0.{counter % 256}"
        elif pii_type == PIIType.CREDIT_CARD:
            return f"0000 0000 0000 {counter:04d}"
        else:
            return f"[{pii_type.value.upper()}_{counter}]"

    @property
    def mappings(self) -> Dict[str, str]:
        """Original→pseudonym mappings (forward direction)."""
        return dict(self._mappings)

    @property
    def reverse_mappings(self) -> Dict[str, str]:
        """Pseudonym→original mappings (for rehydration)."""
        return dict(self._reverse_mappings)

    @property
    def entity_count(self) -> int:
        """Total number of unique entities pseudonymised."""
        return len(self._mappings)


# =============================================================================
# MAIN SKILL CLASS
# =============================================================================


class AnonymisationSkill:
    """
    Anonymisation & Pseudonymisation Skill.

    Orchestrates Privacy Shield components for structured anonymisation
    workflows with persistent sessions and quality assessment.
    """

    def __init__(
        self,
        min_confidence: Confidence = Confidence.MEDIUM,
        target_types: Optional[Set[PIIType]] = None,
        scanner_layers: Optional[List[int]] = None,
        session_store_path: Optional[str] = None,
    ):
        self._min_confidence = min_confidence
        self._target_types = target_types
        self._scanner_layers = scanner_layers or [1, 2, 3, 4]
        self._session_store_path = session_store_path
        self._scanner = PrivacyScanner(
            layers=self._scanner_layers,
            min_confidence=min_confidence,
        )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def anonymise(
        self,
        text: str,
        target_types: Optional[Set[PIIType]] = None,
    ) -> AnonymisationResult:
        """
        Irreversibly anonymise text. No mappings are stored.

        Art. 9 data is always suppressed. Other types are generalised
        where possible, suppressed otherwise.
        """
        scan_result = self._scan(text)
        findings = self._filter_findings(scan_result.findings, target_types)

        processed = text
        transformations = 0
        pii_types_found: Set[str] = set()
        art9_detected = False

        # Process in reverse order to maintain positions
        for finding in sorted(findings, key=lambda f: f.start, reverse=True):
            pii_types_found.add(finding.pii_type.value)

            if finding.pii_type in ART9_TYPES:
                art9_detected = True
                replacement = f"[{finding.pii_type.value.upper()}_REDACTED]"
            else:
                replacement = self._generalise(finding)

            processed = processed[: finding.start] + replacement + processed[finding.end :]
            transformations += 1

        # Verify: re-scan for residual PII
        residual = self._count_residual_pii(processed)

        quality = self._calculate_quality_score(
            original_count=len(findings),
            residual_count=residual,
            art9_remaining=False,
        )

        return AnonymisationResult(
            processed_text=processed,
            mode=AnonymisationMode.ANONYMISE,
            findings_count=len(findings),
            transformations_applied=transformations,
            residual_pii=residual,
            quality_score=quality,
            pii_types_found=sorted(pii_types_found),
            art9_detected=art9_detected,
            warnings=self._generate_warnings(findings, residual),
        )

    def pseudonymise(
        self,
        text: str,
        session_id: Optional[str] = None,
        target_types: Optional[Set[PIIType]] = None,
    ) -> AnonymisationResult:
        """
        Pseudonymise text with consistent, session-scoped replacements.

        Mappings are stored separately for potential rehydration.
        """
        session = PseudonymisationSession(
            session_id=session_id,
            store_path=self._session_store_path,
        )

        scan_result = self._scan(text)
        findings = self._filter_findings(scan_result.findings, target_types)

        processed = text
        transformations = 0
        pii_types_found: Set[str] = set()
        art9_detected = False

        for finding in sorted(findings, key=lambda f: f.start, reverse=True):
            pii_types_found.add(finding.pii_type.value)
            if finding.pii_type in ART9_TYPES:
                art9_detected = True

            pseudo = session.get_or_create_pseudonym(finding.value, finding.pii_type)
            processed = processed[: finding.start] + pseudo + processed[finding.end :]
            transformations += 1

        # Persist session
        session.save()

        residual = self._count_residual_pii(processed)
        quality = self._calculate_quality_score(
            original_count=len(findings),
            residual_count=residual,
            art9_remaining=False,
        )

        return AnonymisationResult(
            processed_text=processed,
            mode=AnonymisationMode.PSEUDONYMISE,
            findings_count=len(findings),
            transformations_applied=transformations,
            residual_pii=residual,
            quality_score=quality,
            pii_types_found=sorted(pii_types_found),
            art9_detected=art9_detected,
            session_id=session.session_id,
            mappings_stored=True,
        )

    def assess(
        self,
        text: str,
        k_threshold: int = 5,
    ) -> AnonymisationResult:
        """
        Assess anonymisation quality of already-processed text.

        Checks for residual PII, estimates k-anonymity risk,
        and flags remaining quasi-identifiers.
        """
        scan_result = self._scan(text)
        findings = scan_result.findings

        # Classify residual findings
        direct_ids = [f for f in findings if f.layer == 1]
        quasi_ids = [f for f in findings if f.layer == 2]
        art9_findings = [f for f in findings if f.pii_type in ART9_TYPES]

        # Estimate k-anonymity from quasi-identifier diversity
        quasi_types = Counter(f.pii_type.value for f in quasi_ids)
        k_estimate = self._estimate_k_anonymity(quasi_ids)

        # Determine re-identification risk
        if direct_ids or art9_findings:
            risk = ReIdentificationRisk.HIGH
        elif len(quasi_ids) >= 3:
            risk = ReIdentificationRisk.MEDIUM
        elif quasi_ids:
            risk = ReIdentificationRisk.LOW
        else:
            risk = ReIdentificationRisk.LOW

        assessment = QualityAssessment(
            k_anonymity=k_estimate,
            re_identification_risk=risk,
            residual_quasi_identifiers=list(quasi_types.keys()),
            residual_direct_identifiers=len(direct_ids),
            art9_remaining=len(art9_findings) > 0,
        )

        if k_estimate is not None and k_estimate < k_threshold:
            assessment.notes.append(
                f"k-anonymity ({k_estimate}) below threshold ({k_threshold})"
            )
        if art9_findings:
            assessment.notes.append(
                f"Art. 9 special category data still present: "
                f"{', '.join(set(f.pii_type.value for f in art9_findings))}"
            )
        if direct_ids:
            assessment.notes.append(
                f"{len(direct_ids)} direct identifier(s) still present"
            )

        quality = self._calculate_quality_score(
            original_count=len(findings),
            residual_count=len(findings),
            art9_remaining=len(art9_findings) > 0,
        )
        # For assess mode, quality reflects how well the text is already anonymised
        if not findings:
            quality = 1.0
        else:
            quality = max(0.0, 1.0 - (len(findings) * 0.1))

        pii_types_found = sorted(set(f.pii_type.value for f in findings))

        return AnonymisationResult(
            processed_text=text,
            mode=AnonymisationMode.ASSESS,
            findings_count=len(findings),
            residual_pii=len(findings),
            quality_score=quality,
            pii_types_found=pii_types_found,
            art9_detected=len(art9_findings) > 0,
            assessment=assessment,
        )

    def rehydrate(
        self,
        text: str,
        session_id: Optional[str] = None,
        mappings: Optional[Dict[str, str]] = None,
    ) -> AnonymisationResult:
        """
        Restore original values from pseudonymised text.

        Requires either a session_id (to load stored mappings) or
        explicit mappings dict.
        """
        reverse_map: Dict[str, str] = {}

        if session_id:
            session = PseudonymisationSession(
                session_id=session_id,
                store_path=self._session_store_path,
            )
            reverse_map = session.reverse_mappings

        if mappings:
            # Explicit mappings override/supplement session
            reverse_map.update(mappings)

        if not reverse_map:
            return AnonymisationResult(
                processed_text=text,
                mode=AnonymisationMode.REHYDRATE,
                warnings=["No mappings provided — cannot rehydrate"],
            )

        # Apply reverse mappings (longest pseudonyms first to avoid partial matches)
        processed = text
        transformations = 0
        unresolved: List[str] = []

        for pseudo, original in sorted(
            reverse_map.items(), key=lambda x: len(x[0]), reverse=True
        ):
            if pseudo in processed:
                processed = processed.replace(pseudo, original)
                transformations += 1

        return AnonymisationResult(
            processed_text=processed,
            mode=AnonymisationMode.REHYDRATE,
            transformations_applied=transformations,
            session_id=session_id,
            warnings=[f"Unresolved pseudonyms: {unresolved}"] if unresolved else [],
        )

    def batch_process(
        self,
        texts: Dict[str, str],
        mode: AnonymisationMode = AnonymisationMode.PSEUDONYMISE,
        session_id: Optional[str] = None,
        target_types: Optional[Set[PIIType]] = None,
    ) -> AnonymisationResult:
        """
        Process multiple documents with consistent pseudonymisation.

        Args:
            texts: Dict of {identifier: text_content}
            mode: ANONYMISE or PSEUDONYMISE
            session_id: Shared session for cross-document consistency
            target_types: Restrict to specific PII types
        """
        if mode not in (AnonymisationMode.ANONYMISE, AnonymisationMode.PSEUDONYMISE):
            return AnonymisationResult(
                processed_text="",
                mode=AnonymisationMode.BATCH,
                warnings=[f"Batch mode only supports anonymise/pseudonymise, got {mode.value}"],
            )

        session = None
        if mode == AnonymisationMode.PSEUDONYMISE:
            session = PseudonymisationSession(
                session_id=session_id,
                store_path=self._session_store_path,
            )

        summary = BatchSummary(total_documents=len(texts))
        all_processed: Dict[str, str] = {}
        total_findings = 0
        total_transformations = 0
        all_pii_types: Set[str] = set()
        any_art9 = False

        for doc_id, text in texts.items():
            try:
                if mode == AnonymisationMode.ANONYMISE:
                    result = self.anonymise(text, target_types=target_types)
                else:
                    result = self._pseudonymise_with_session(
                        text, session, target_types=target_types  # type: ignore[arg-type]
                    )

                all_processed[doc_id] = result.processed_text
                total_findings += result.findings_count
                total_transformations += result.transformations_applied
                all_pii_types.update(result.pii_types_found)
                if result.art9_detected:
                    any_art9 = True

                summary.per_document_results.append(
                    BatchDocumentResult(
                        file_path=doc_id,
                        findings_count=result.findings_count,
                        transformations_applied=result.transformations_applied,
                        residual_pii=result.residual_pii,
                        quality_score=result.quality_score,
                    )
                )
                summary.documents_processed += 1

            except Exception as exc:
                logger.error("Batch processing failed for %s: %s", doc_id, exc)
                summary.per_document_results.append(
                    BatchDocumentResult(file_path=doc_id, error=str(exc))
                )
                summary.documents_failed += 1

        if session:
            summary.cross_document_entities = session.entity_count
            session.save()

        # Combine processed texts for output
        combined = "\n\n---\n\n".join(
            f"## {doc_id}\n\n{text}" for doc_id, text in all_processed.items()
        )

        return AnonymisationResult(
            processed_text=combined,
            mode=AnonymisationMode.BATCH,
            findings_count=total_findings,
            transformations_applied=total_transformations,
            pii_types_found=sorted(all_pii_types),
            art9_detected=any_art9,
            session_id=session.session_id if session else None,
            mappings_stored=session is not None,
            batch_summary=summary,
        )

    # -------------------------------------------------------------------------
    # Internal Methods
    # -------------------------------------------------------------------------

    def _scan(self, text: str) -> ScanResult:
        """Run PII scanner on text."""
        return self._scanner.scan(text)

    def _filter_findings(
        self,
        findings: List[Finding],
        target_types: Optional[Set[PIIType]] = None,
    ) -> List[Finding]:
        """Filter findings by target types if specified."""
        types = target_types or self._target_types
        if not types:
            return findings
        return [f for f in findings if f.pii_type in types]

    def _generalise(self, finding: Finding) -> str:
        """
        Apply generalisation to a finding for anonymisation.

        Returns a generalised value that reduces precision while
        preserving analytical utility.
        """
        pii_type = finding.pii_type
        value = finding.value

        if pii_type == PIIType.DATE_OF_BIRTH:
            # Extract year only: "15.03.1985" → "[YEAR:1985]"
            import re

            year_match = re.search(r"(19|20)\d{2}", value)
            if year_match:
                return f"[YEAR:{year_match.group()}]"
            return "[DATE_REDACTED]"

        elif pii_type == PIIType.AGE:
            # Age to decade range: "34" → "[AGE:30-39]"
            import re

            age_match = re.search(r"\d+", value)
            if age_match:
                age = int(age_match.group())
                decade = (age // 10) * 10
                return f"[AGE:{decade}-{decade + 9}]"
            return "[AGE_REDACTED]"

        elif pii_type == PIIType.PLZ_CITY:
            # PLZ to region: "80331 München" → "[REGION:Bayern (Süd)]"
            import re

            plz_match = re.search(r"(\d)", value)
            if plz_match:
                first_digit = plz_match.group(1)
                region = PLZ_REGION_MAP.get(first_digit, "Deutschland")
                return f"[REGION:{region}]"
            return "[LOCATION_REDACTED]"

        # Default: suppress (replace with type placeholder)
        return f"[{pii_type.value.upper()}_REDACTED]"

    def _pseudonymise_with_session(
        self,
        text: str,
        session: PseudonymisationSession,
        target_types: Optional[Set[PIIType]] = None,
    ) -> AnonymisationResult:
        """Pseudonymise using an existing session (for batch mode)."""
        scan_result = self._scan(text)
        findings = self._filter_findings(scan_result.findings, target_types)

        processed = text
        transformations = 0
        pii_types_found: Set[str] = set()
        art9_detected = False

        for finding in sorted(findings, key=lambda f: f.start, reverse=True):
            pii_types_found.add(finding.pii_type.value)
            if finding.pii_type in ART9_TYPES:
                art9_detected = True

            pseudo = session.get_or_create_pseudonym(finding.value, finding.pii_type)
            processed = processed[: finding.start] + pseudo + processed[finding.end :]
            transformations += 1

        residual = self._count_residual_pii(processed)

        return AnonymisationResult(
            processed_text=processed,
            mode=AnonymisationMode.PSEUDONYMISE,
            findings_count=len(findings),
            transformations_applied=transformations,
            residual_pii=residual,
            quality_score=self._calculate_quality_score(len(findings), residual, False),
            pii_types_found=sorted(pii_types_found),
            art9_detected=art9_detected,
            session_id=session.session_id,
            mappings_stored=True,
        )

    def _count_residual_pii(self, text: str) -> int:
        """Re-scan text to count residual PII after processing."""
        rescan = self._scanner.scan(text)
        # Exclude findings that match our own placeholders
        residual = [
            f for f in rescan.findings
            if not (f.value.startswith("[") and f.value.endswith("]"))
        ]
        return len(residual)

    def _estimate_k_anonymity(self, quasi_identifiers: List[Finding]) -> Optional[int]:
        """
        Estimate k-anonymity from quasi-identifier findings.

        k-anonymity means every combination of quasi-identifiers
        appears at least k times in the dataset. For a single document,
        we estimate based on uniqueness of quasi-identifier values.
        """
        if not quasi_identifiers:
            return None  # No quasi-identifiers = not applicable

        # Count unique values per quasi-identifier type
        values_by_type: Dict[str, Set[str]] = {}
        for f in quasi_identifiers:
            values_by_type.setdefault(f.pii_type.value, set()).add(f.value)

        # k = minimum group size across all quasi-identifier types
        # For single documents, k is effectively 1 per unique value
        total_unique = sum(len(v) for v in values_by_type.values())
        if total_unique == 0:
            return None
        return max(1, len(quasi_identifiers) // total_unique)

    def _calculate_quality_score(
        self,
        original_count: int,
        residual_count: int,
        art9_remaining: bool,
    ) -> float:
        """Calculate anonymisation quality score (0.0–1.0)."""
        if original_count == 0:
            return 1.0

        # Base score: proportion of PII removed
        removal_rate = 1.0 - (residual_count / max(original_count, 1))

        # Penalty for Art. 9 data remaining
        if art9_remaining:
            removal_rate *= 0.5

        return max(0.0, min(1.0, removal_rate))

    def _generate_warnings(
        self,
        findings: List[Finding],
        residual: int,
    ) -> List[str]:
        """Generate warnings based on processing results."""
        warnings: List[str] = []

        art9_types = {f.pii_type.value for f in findings if f.pii_type in ART9_TYPES}
        if art9_types:
            warnings.append(
                f"Art. 9 special category data detected and suppressed: {', '.join(art9_types)}"
            )

        if residual > 0:
            warnings.append(
                f"{residual} PII item(s) detected in output after processing — "
                "manual review recommended"
            )

        return warnings


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def anonymise_text(
    text: str,
    target_types: Optional[Set[PIIType]] = None,
    min_confidence: Confidence = Confidence.MEDIUM,
) -> AnonymisationResult:
    """Convenience: anonymise text in one call."""
    skill = AnonymisationSkill(min_confidence=min_confidence)
    return skill.anonymise(text, target_types=target_types)


def pseudonymise_text(
    text: str,
    session_id: Optional[str] = None,
    target_types: Optional[Set[PIIType]] = None,
    min_confidence: Confidence = Confidence.MEDIUM,
) -> AnonymisationResult:
    """Convenience: pseudonymise text in one call."""
    skill = AnonymisationSkill(min_confidence=min_confidence)
    return skill.pseudonymise(text, session_id=session_id, target_types=target_types)


def assess_anonymisation(
    text: str,
    k_threshold: int = 5,
    min_confidence: Confidence = Confidence.MEDIUM,
) -> AnonymisationResult:
    """Convenience: assess anonymisation quality in one call."""
    skill = AnonymisationSkill(min_confidence=min_confidence)
    return skill.assess(text, k_threshold=k_threshold)
