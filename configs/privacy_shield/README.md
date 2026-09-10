# Privacy Shield Detection Config

This config layer is designed for auditability and gradual adoption.

It does not replace the current scanner. It defines:

- `taxonomy.yaml`: canonical privacy entity taxonomy aligned to current `PIIType` values
- `patterns.yaml`: high-confidence regex and heuristic detector definitions
- `lexica/*.yaml`: jurisdiction and language specific labels, honorifics, context words, and weak-name cues
- `onnx_targets.yaml`: recommended ONNX tasks that should sit after regex and lexica

Recommended runtime order:

1. Regex and deterministic patterns
2. Lexicon and context boosts
3. ONNX classifiers or taggers
4. Policy decision
5. Preview and user override

Design rules:

- Keep direct identifiers deterministic wherever possible.
- Treat names and sensitive context as low or medium confidence unless corroborated.
- Keep jurisdiction-specific IDs and field labels in lexica or labelled regex rules.
- Use ONNX to improve context, not to replace deterministic redaction policy.

Important semantics:

- `field_labels` and rule `labels` are context cues only.
- A bare label such as `name`, `email`, or `telefon` must never be emitted as a finding by itself.
- Labels are only used to increase confidence for a nearby candidate value inside a bounded context window.
- Example:
  - `name` alone: no finding
  - `Name: Max Muller`: candidate value `Max Muller` may be marked
  - `the variable is called name`: no finding
