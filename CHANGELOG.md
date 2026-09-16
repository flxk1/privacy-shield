<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## 2.0.0

Breaking release: the import root, the console script and every environment
variable are renamed, and `AUDIT_LOG_PATH` changes semantics. Installs of
`1.0.0` and `2.0.0` are incompatible trees — pin the major version.

### Breaking changes

- Import root renamed `brain.privacy_shield` -> `privacy_shield`; every
  submodule moves with it (`brain.<module>` -> `privacy_shield.<module>`).
- Console script renamed `brain.privacy_shield.cli:main` -> `privacy_shield.cli:main`.
- All 27 `BRAIN_*` environment variables are renamed to the `PRIVACY_SHIELD_*`
  prefix (full table below). `reject_legacy_env()` tests **presence, not
  value** — an empty-valued legacy variable still raises. 1.0.0's readers
  `.strip()`-ed values, so an empty legacy variable was a silent no-op there;
  a `docker run -e BRAIN_PRIVACY_AUDIT_LOG` passthrough or a CI env block
  that exports one of these 27 names empty (common for optional passthrough)
  now hard-fails every scan on 2.0.0, where it was harmless on 1.0.0.
  Five call sites raise `LegacyEnvironmentError`, naming the replacement,
  while a pre-rename variable is set — the four egress/CLI decision points
  (`scan`, the CLI `main`, `PrivacyGate.check`, `is_safe_for_external_llm`)
  and the credential master-key derivation (`user_credentials._master_secret_bytes`,
  the one choke point every credential encrypt/decrypt call passes through).
  Importing the package never raises. Every other public function
  (`scan_text`, `scan_text_with_local_llm`, `extract_document`,
  `redact_text`, `PrivacyShield` and its lower-level methods, …) does not
  inspect legacy names at all: a legacy variable there is silently treated
  as unset, degrading to whatever default that function uses without
  raising or warning — for those, a caller who needs the guard should route
  through one of the five entry points above rather than the lower-level
  building blocks.
  The credential guard propagates all the way to the public functions
  (`add_credential`, `get_decrypted_key`, `revalidate_credential` — not
  `update_credential`, which only edits metadata and never touches key
  material) because the failure mode is irreversible: with a stale
  `BRAIN_CREDENTIALS_MASTER_KEY`, key derivation used to fall through to
  `secrets.token_hex(32)` and persist it, so every credential already
  encrypted under the operator's intended seed became permanently
  undecryptable while new ones were silently encrypted under material the
  operator never set. **There is no plaintext-fallback path left at all,
  for any reason** — a prior code shape swallowed `LegacyEnvironmentError`
  in a bare `except Exception` inside `_get_fernet` and wrote the key
  base64-encoded with `key_salt="fallback"` instead of failing; that swallow
  is gone, and so is the fallback write itself. `cryptography` is not a
  required dependency of this package (none are); if it is not installed,
  storing or reading a credential now raises `CredentialEncryptionUnavailable`
  instead of silently writing cleartext — BYOK credential storage needs it
  installed, same as `[semantic]`/`[extract]` need their own extras for
  their capabilities. `key_salt="fallback"` is still accepted on *read*,
  for any credential a pre-fix install already wrote insecurely.
  A third, undocumented seed also feeds the master-key derivation:
  `COCKPIT_SESSION_SECRET` (`user_credentials.py`), tried after
  `PRIVACY_SHIELD_CREDENTIALS_MASTER_KEY` and
  `PRIVACY_SHIELD_SKILL_INTAKE_MASTER_KEY`. It is not a `BRAIN_*` legacy
  name — nothing renamed it — it simply appeared in no table and no doc
  until now.
- The host-service import `brain.services.persistent_brain_objects.get_persistent_brain_object_service`
  is renamed `privacy_shield.services.persistent_objects.get_persistent_object_service`,
  and `PersistentBrainObjectSource` is renamed `PersistentObjectSource`
  (`compliance_evidence_export.py`). This one was undisclosed until now: a
  host that shimmed only the names this file previously listed got an
  uncaught `ImportError` out of `export_workspace_evidence` the moment it
  touched persistent-object evidence. `PersistentObjectSource._service()`
  now catches the missing shim and degrades that section to empty rather
  than crashing the export.
- `AUDIT_LOG_PATH` semantics changed: `from privacy_shield.audit_log import
  AUDIT_LOG_PATH` yields `None` unless a caller pinned it. The audit writer
  and reader resolve `AUDIT_LOG_PATH or audit_log_path()` at call time, so a
  stale pin handed back by a test harness no longer redirects the trail. One
  `_user_state_home` serves the audit trail and the privacy skill KG.
- The `brain_app` keyword parameter on ~15 helpers (e.g.
  `privacy_shield.helpers.documents.documents_store_path`) is renamed to
  `host_app`; calling with the old keyword now raises `TypeError`.
- `compliance_evidence_export`'s evidence-pack `section_id` values renamed:
  `persistent_brain_objects` -> `persistent_objects` and
  `persistent_brain_object_events` -> `persistent_object_events`. A downstream
  tool keyed on the old `section_id` finds no matching section and reports
  zero records rather than raising — check any consumer for the old strings.
- **The on-disk state root moved** (full paths in the migration table below):
  the encrypted BYOK credential store, `.credentials_master.key`, the
  pseudonymisation session maps and the breach log all lived under
  `<site-packages>/brain/...` on 1.0.0 and now live under
  `<site-packages>/privacy_shield/...`. Nothing reads the old location and
  nothing warns: **an operator upgrading in place must move these four
  paths by hand** (or re-derive credentials/keys fresh) before anything on
  disk there is found again.

### Other changes

- `tests/conftest.py` points `HOME`, `XDG_STATE_HOME`, `LOCALAPPDATA` and `USERPROFILE`
  at each test's `tmp_path` and clears every `PRIVACY_SHIELD_*` and legacy variable.
- Importing `privacy_shield.privacy_shield_embeddings` no longer creates `data/privacy_shield/`
  inside the installed package; the directory is made when the embeddings cache is written.
- Importing `privacy_shield.compliance_evidence_export` and `privacy_shield.breach`
  no longer create their evidence/log directories at import time; both are made
  on first write (same shape as the embeddings cache).
- NOTICE lists the optional third-party extras and states authorship.

### Migration

| 1.0.0 | 2.0.0 |
|---|---|
| `import brain.privacy_shield` | `import privacy_shield` |
| `brain.<module>`, e.g. `brain.audit_log` | `privacy_shield.<module>` |
| console script `brain.privacy_shield.cli:main` | `privacy_shield.cli:main` |
| `documents_store_path(brain_app=app)` (and ~15 other helpers) | `documents_store_path(host_app=app)` |
| `brain.services.persistent_brain_objects.get_persistent_brain_object_service` | `privacy_shield.services.persistent_objects.get_persistent_object_service` |
| `PersistentBrainObjectSource` | `PersistentObjectSource` |
| `<site-packages>/brain/user/credentials/*.json` | `<site-packages>/privacy_shield/user/credentials/*.json` |
| `<site-packages>/brain/user/.credentials_master.key` | `<site-packages>/privacy_shield/user/.credentials_master.key` |
| `<site-packages>/brain/user/pseudonymisation_sessions/` | `<site-packages>/privacy_shield/user/pseudonymisation_sessions/` |
| `<site-packages>/brain/data/breach_log/` | `<site-packages>/privacy_shield/data/breach_log/` |
| `BRAIN_CREDENTIALS_MASTER_KEY` | `PRIVACY_SHIELD_CREDENTIALS_MASTER_KEY` |
| `BRAIN_DEVICE_CLASS` | `PRIVACY_SHIELD_DEVICE_CLASS` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_API_KEY` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_API_KEY` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_AVAILABLE` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_AVAILABLE` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_COMMAND` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_COMMAND` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_ENDPOINT` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_ENDPOINT` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_ID` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_ID` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_NAME` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_NAME` |
| `BRAIN_EMBEDDED_LOCAL_MODEL_OPENAI_COMPAT` | `PRIVACY_SHIELD_EMBEDDED_LOCAL_MODEL_OPENAI_COMPAT` |
| `BRAIN_ENABLE_PYMUPDF` | `PRIVACY_SHIELD_ENABLE_PYMUPDF` |
| `BRAIN_NATIVE_LOCAL_MODEL_API_KEY` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_API_KEY` |
| `BRAIN_NATIVE_LOCAL_MODEL_AVAILABLE` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_AVAILABLE` |
| `BRAIN_NATIVE_LOCAL_MODEL_COMMAND` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_COMMAND` |
| `BRAIN_NATIVE_LOCAL_MODEL_ENDPOINT` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ENDPOINT` |
| `BRAIN_NATIVE_LOCAL_MODEL_ID` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_ID` |
| `BRAIN_NATIVE_LOCAL_MODEL_NAME` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_NAME` |
| `BRAIN_NATIVE_LOCAL_MODEL_OPENAI_COMPAT` | `PRIVACY_SHIELD_NATIVE_LOCAL_MODEL_OPENAI_COMPAT` |
| `BRAIN_PRIVACY_AUDIT_LOG` | `PRIVACY_SHIELD_AUDIT_LOG` |
| `BRAIN_PRIVACY_KG_DIR` | `PRIVACY_SHIELD_KG_DIR` |
| `BRAIN_PRIVACY_SHIELD_ONNX_AVAILABLE` | `PRIVACY_SHIELD_ONNX_AVAILABLE` |
| `BRAIN_PRIVACY_SHIELD_ONNX_MODE` | `PRIVACY_SHIELD_ONNX_MODE` |
| `BRAIN_PRIVACY_SHIELD_ONNX_MODEL_ID` | `PRIVACY_SHIELD_ONNX_MODEL_ID` |
| `BRAIN_PRIVACY_SHIELD_ONNX_MODEL_PATH` | `PRIVACY_SHIELD_ONNX_MODEL_PATH` |
| `BRAIN_PRIVACY_SHIELD_SEMANTIC_CHUNK_SIZE` | `PRIVACY_SHIELD_SEMANTIC_CHUNK_SIZE` |
| `BRAIN_PRIVACY_SHIELD_SEMANTIC_ENABLED` | `PRIVACY_SHIELD_SEMANTIC_ENABLED` |
| `BRAIN_PRIVACY_SHIELD_SEMANTIC_THRESHOLD` | `PRIVACY_SHIELD_SEMANTIC_THRESHOLD` |
| `BRAIN_SKILL_INTAKE_MASTER_KEY` | `PRIVACY_SHIELD_SKILL_INTAKE_MASTER_KEY` |

## 1.0.0

First release. Local-first PII/PHI detection and clean-overlay pipeline for governed folders.
