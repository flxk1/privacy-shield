# ADR 0001 — RVND-optional: standalone core + optional enforcement/audit seam

Status: accepted

## Context

Privacy Shield is a local-first PII/PHI detection and clean-overlay pipeline. It
must run as a fully functional standalone artifact with **zero RVND present** —
no `import rvnd`, no RVND HTTP call, no MCP `workspace_*` call anywhere on the
core path (scanner, embeddings, local-model runtime, redactor, `anonymous_json`
overlay, egress guard, audit log). RVND governance (verdicts + a signed-chain
receipt) is a valuable *enrichment* for governed deployments, but it is
hands-off and must never become a dependency.

This mirrors the RVND-optional shape already adopted by `ctrl-desk`.

## Decision

1. **The standalone core is RVND-free** and is the default, complete product. A
   repo-wide scan for `rvnd` / `import rvnd` / RVND HTTP / MCP `workspace_*` on
   the core path found **no coupling** (the only `workspace`/`governance`
   strings are generic terms inside `compliance_evidence_export.py`, which is a
   Brain-coupled optional/enterprise export, not on the core path).

2. **One optional enforcement/audit seam** is defined, interface-only, in
   `brain.privacy_shield.enforcement`:
   - `EnforcementSink` — a `Protocol` (runtime-checkable) with
     `record_decision(decision)` and `gate(action, *, enforce=False)`.
   - `EnforcementDecision` / `EnforcementVerdict` — the typed payloads.
   - `NoOpEnforcementSink` (+ the `NOOP_SINK` singleton) — the inert default.
   - `RvndEnforcementAdapter` — an **interface-only stub** documenting the
     intended RVND bindings. It does **not** import or call `rvnd.*`; its methods
     raise `NotImplementedError` so an accidental attach fails loudly. A real
     adapter is built and owned **outside** this core.

3. **The egress guard is the hook.** `PrivacyGate` (`gate.py`) takes an optional
   sink via its constructor / `attach_enforcement_sink()`, gated by the
   `enforcement_enabled` capability flag. Every guard entry point behaves in
   both modes:
   - **Default (zero RVND):** the guard decides **locally** (privacy mode +
     classification tiers + Art. 9, over the scanner's regex/embeddings/local-LLM
     verdict) and records the decision to the standalone `audit_log`
     (`AI_PRIVACY_SHIELD_DECISION`). `require_privacy_check` raises
     `PermissionError` on an unsafe egress. Fully functional alone.
   - **Enriched (sink attached):** the **same** local decision is additionally
     surfaced to the sink via `record_decision` (governance verdict +
     signed-chain receipt). `PrivacyGate.plan_action()` optionally consults
     `gate()` for a prospective action. Enrichment is strictly additive and
     never overrides the local decision; a misbehaving sink can never change the
     egress outcome (calls are defensively wrapped).

4. **Audit:** the standalone `audit_log.py` is the **default** audit trail. The
   RVND signed-chain is the **optional** enrichment via the same seam. The
   Brain-coupled `compliance_evidence_export.py` (imports `brain.services.*`)
   stays off the core path — it is an optional/enterprise export, not a core
   dependency.

## Design consequence (advisory vs enforce)

Inherited from the `ctrl-desk` spec: RVND's `governance.decide_action`
**appends to the signed chain** — gating is itself a mutating, governed act. So
an adapter must distinguish an **advisory preview** (a pure, chain-reading gate,
`rvnd.action_gate.gate` → GO / CONDITIONAL / NO-GO, no chain write) from an
**enforce** call (`rvnd.governance.decide_action`, which writes the chain and
yields an `audit_id`). The `enforce` flag on `EnforcementSink.gate` carries that
distinction; `record_decision` is always advisory.

## Consequences

- The core ships and runs with no RVND and no governance import on any hot path.
- Governed deployments attach a real RVND-backed `EnforcementSink` from outside
  the core to gain verdicts + a signed-chain receipt, with no core changes.
- Tests prove both modes: the guard blocks/passes and records to `audit_log`
  with no sink attached, and a stub sink receives the same decision when
  attached (`tests/test_privacy_gate_rvnd_optional.py`).
