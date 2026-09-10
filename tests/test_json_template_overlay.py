from __future__ import annotations

from brain.audit_log import AuditEvent
from brain.helpers.json_template_overlay import maybe_apply_json_template_overlay


def _approved_review() -> dict:
    return {
        "all_resolved": True,
        "all_approved": True,
        "status": "approved",
    }


def test_contract_overlay_applies_at_or_above_threshold(monkeypatch) -> None:
    def _force_high(*args, **kwargs):
        return 0.95

    monkeypatch.setattr("brain.helpers.json_template_overlay._estimate_template_confidence", _force_high)
    record = {
        "filename": "service_agreement.txt",
        "text_preview": (
            "Service Agreement\n"
            "Parties: Example GmbH and Max Müller\n"
            "Email: max@example.com\n\n"
            "1 Scope\nThe supplier provides software support.\n\n"
            "2 Payment\nInvoice due within 14 days.\n"
        ),
        "privacy_review": {"status": "approved"},
    }

    out = maybe_apply_json_template_overlay(record, review=_approved_review())
    overlay = out.get("json_template_overlay", {})
    assert overlay.get("template_id") == "contract_clause_only"
    assert float(overlay.get("confidence", 0.0)) >= 0.9
    payload = overlay.get("payload", {})
    assert int(payload.get("clause_count", 0)) >= 2
    serialized = str(payload)
    assert "max@example.com" not in serialized


def test_contract_overlay_noop_below_threshold(monkeypatch) -> None:
    def _force_low(*args, **kwargs):
        return 0.89

    monkeypatch.setattr("brain.helpers.json_template_overlay._estimate_template_confidence", _force_low)
    record = {
        "filename": "service_agreement.txt",
        "text_preview": (
            "Service Agreement\n"
            "1 Scope\nThe supplier provides software support.\n"
        ),
        "privacy_review": {"status": "approved"},
    }

    out = maybe_apply_json_template_overlay(record, review=_approved_review())
    assert "json_template_overlay" not in out


def test_controlled_decision_event_logged_for_apply_and_fail(monkeypatch) -> None:
    events = []

    def _capture(event, user=None, ip=None, details=None, success=True, tenant_id=None):
        events.append(
            {
                "event": event,
                "user": user,
                "details": details or {},
                "success": success,
                "tenant_id": tenant_id,
            }
        )

    monkeypatch.setattr("brain.helpers.json_template_overlay.log_audit_event", _capture)

    def _force_high(*args, **kwargs):
        return 0.95

    monkeypatch.setattr("brain.helpers.json_template_overlay._estimate_template_confidence", _force_high)
    applied = maybe_apply_json_template_overlay(
        {
            "filename": "service_agreement.txt",
            "text_preview": "Service Agreement\n1 Scope\nWork\n2 Payment\nMonthly.\n",
            "source_kind": "upload",
        },
        review=_approved_review(),
        user="alice",
        scope="docs",
    )
    assert applied.get("json_template_overlay", {}).get("template_id") == "contract_clause_only"

    def _force_low(*args, **kwargs):
        return 0.4

    monkeypatch.setattr("brain.helpers.json_template_overlay._estimate_template_confidence", _force_low)
    not_applied = maybe_apply_json_template_overlay(
        {
            "filename": "service_agreement.txt",
            "text_preview": "Service Agreement\n1 Scope\nWork\n2 Payment\nMonthly.\n",
            "source_kind": "local_folder",
        },
        review=_approved_review(),
        user="bob",
        scope="folder",
    )
    assert "json_template_overlay" not in not_applied

    assert len(events) == 2
    first = events[0]
    second = events[1]
    assert first["event"] == AuditEvent.AI_PRIVACY_SHIELD_DECISION
    assert second["event"] == AuditEvent.AI_PRIVACY_SHIELD_DECISION
    assert first["details"]["scope"] == "docs"
    assert first["details"]["fail_reason"] == ""
    assert first["details"]["confidence_threshold"] == 0.9
    assert first["details"]["selected_template_id"] == "contract_clause_only"
    assert first["details"]["run_id"]
    assert first["details"]["approval_event_id"]
    assert first["details"]["input_hash"]
    assert first["details"]["output_hash"]
    assert second["details"]["scope"] == "folder"
    assert second["details"]["fail_reason"] == "below_threshold"
