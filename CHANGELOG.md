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
  is gone, and so is the fallback write itself. `cryptography` is now
  declared explicitly as the new `credentials` extra
  (`pip install "privacy-shield[credentials]"`, `cryptography>=42`); if it
  is not installed, storing or reading a credential raises
  `CredentialEncryptionUnavailable` instead of silently writing cleartext.
  CI gained a dedicated `credentials` job installing `.[dev,credentials]`
  and running `tests/test_user_credentials.py` against real
  `cryptography.fernet.Fernet` (every other job's `_FakeFernet`-mocked
  cases don't exercise it), which is what catches bugs *inside* the real
  Fernet error surface (e.g. `ValueError` on a corrupted salt, below) —
  it is **not**, and would not have been, what catches the original
  plaintext-fallback defect, since it installs the exact opposite
  configuration (`cryptography` present) to the one that produced it
  (`cryptography` absent, the default). The `tests` job — no `credentials`
  extra, i.e. `cryptography` genuinely absent — is what actually asserts
  the write refuses, via `test_add_credential_raises_when_cryptography_is_unavailable`.
  `key_salt="fallback"` is still accepted on *read*, for any credential a
  pre-fix install already wrote insecurely — refusing it would lock out
  exactly the operators the bug harmed — but a successful read of one is
  now the one moment this system can know a secret sat in cleartext on
  disk, and it is no longer silent: `get_decrypted_key` and
  `revalidate_credential` both `logger.warning` the credential id and
  provider, and name `pip install "privacy-shield[credentials]"` as the
  remedy. **A fallback record can only exist because cryptography was
  absent when it was written, and cryptography is still absent by
  default** — an unconditional re-encrypt attempt would call
  `_encrypt_key` -> `_get_fernet`, which raises
  `CredentialEncryptionUnavailable` when `Fernet is None`, crashing
  `revalidate_credential` (typed `-> Tuple[bool, str]`) for exactly the
  operators the warning is trying to help; `get_decrypted_key`'s warning
  routed straight into that trap. `revalidate_credential` now only
  attempts the re-encrypt when `cryptography` is actually available in
  the *current* process (not merely "the CHANGELOG says to install it"),
  and even then round-trip verifies the new ciphertext decrypts back to
  the original secret before overwriting the record — `_master_secret_bytes`
  can silently (debug-level) mint a fresh random master key when the
  persisted one is unreadable or unwritable, which would otherwise turn a
  recoverable (base64) cleartext record into permanently lost ciphertext.
  An operator should run `pip install "privacy-shield[credentials]"` then
  call `revalidate_credential` for anything stored before this fix, and
  rotate the underlying provider key regardless, since it has been on disk
  unencrypted in the meantime.
  A third, undocumented seed also feeds the master-key derivation:
  `COCKPIT_SESSION_SECRET` (`user_credentials.py`), tried after
  `PRIVACY_SHIELD_CREDENTIALS_MASTER_KEY` and
  `PRIVACY_SHIELD_SKILL_INTAKE_MASTER_KEY`. It is not a `BRAIN_*` legacy
  name — nothing renamed it — it simply appeared in no table and no doc
  until now.
- **The rename touches the whole host-service shim surface, not just
  `persistent_objects`.** 1.0.0's shim contract was `brain.services.*` (six
  modules) plus `brain.app`; every one of those seven names changes on
  2.0.0 (full list in the migration table). Per module:
  - `governance_audit.GOVERNANCE_DIR`, `audit_documentation` (three
    functions), `human_control_service.get_human_control_service`,
    `conversation_delivery_records.get_conversation_delivery_record_service`
    and `persistent_objects.get_persistent_object_service` (renamed from
    `persistent_brain_objects`/`PersistentBrainObjectSource` ->
    `PersistentObjectSource`) all **degrade**: a host that has not shimmed
    the new name gets an empty evidence section and a `logger.warning`
    naming the missing module, not a crash. `governance_audit` was the
    worst of these — `GovernanceLogSource.__init__` imported it eagerly and
    unguarded, and since `ComplianceEvidenceExporter.__init__` constructs
    that source 4th, **any** host missing only that one shim got an
    uncaught `ModuleNotFoundError` out of `get_evidence_exporter()` itself,
    before ever reaching any of the other six — the exporter was
    unreachable on the exact path this fix claims to cover. All seven are
    lazy and guarded now.
  - `webhook_service.emit_webhook` already degraded correctly (logs the
    breach payload instead) and needed no change.
  - `app` (tenant/user resolution, `USER_ROOT`) **also degrades — it must,
    since compliance evidence cannot require every host to wire tenant
    resolution before this package will run at all — but it must not do so
    silently**: without it, `audit_log.py`'s tenant lookup, `llm_client.py`'s
    current-user resolution, and `compliance_evidence_export.py`'s
    `GovernanceLogSource`/`QueryAuditSource` tenant/directory resolution
    all fell back to `debug`-level logs or, in `QueryAuditSource`, no log
    at all — the resulting audit records are silently **wrong** (misattributed
    to no tenant, a real user read as anonymous, evidence read from this
    package's own unused `user/` directory instead of the host's), not
    merely **missing**, which is a materially worse failure to leave quiet.
    All four call sites now log at `warning`.
  - Beyond the seven: `PolicyEvaluationSource` also imports
    `privacy_shield.compliance_control_plane`, undisclosed and not part of
    this rename (it never shipped in this package on 1.0.0 either — a
    pre-existing host dependency, not a renamed one). It blocked
    `export_workspace_evidence` the same way; guarded the same way, but
    intentionally left out of the migration table below since nothing
    renamed it.
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
- **`PRIVACY_SHIELD_{NATIVE,EMBEDDED}_LOCAL_MODEL_ENDPOINT` must now resolve
  to a loopback address (`127.0.0.1`/`::1`/`localhost`, http or https) or a
  unix socket.** Nothing previously checked that a variable whose name
  contains "LOCAL" actually pointed at this machine — it was sent the raw,
  un-redacted scan text as an OpenAI-compatible `base_url`, the same class
  of gap as the enforcement seam this package otherwise guards: a
  local-first property asserted in the README that the mechanism did not
  enforce. **An operator who already points that variable at a remote host
  will find it stops working on 2.0.0** and the scan degrades to the
  regex/lexicon floor (same shape as any other absent detection layer,
  never a smaller finding set silently) with a `logger.error` naming the
  host and the variable. Set `PRIVACY_SHIELD_MODEL_ENDPOINT_ALLOW_REMOTE=1`
  to opt back in deliberately; every send then logs a `logger.warning`
  naming the destination. The resolution itself moved to one choke point,
  `resolve_embedded_endpoint()` (`services/local_model_runtime.py`) — it
  used to be read independently in two places, so a guard added to only one
  would not have covered the other. The `..._COMMAND` subprocess path is
  unaffected — it never leaves the machine by construction. The existing,
  separately-configurable `..._API_KEY` variables suggest remote use of
  this "local" layer was at least loosely anticipated by whoever built it;
  nothing else in the module assumes a remote provider (no TLS/proxy
  handling, no remote-specific retries).
  Two follow-on fixes to the same guard: `_embedded_provider_status()`
  used to still report `running: True, endpoint: None` for a refused
  endpoint with no `..._COMMAND` fallback — a ghost entry that
  `get_preferred_local_runtime()` preferred first (`embedded` leads the
  provider order), shadowing a genuinely running loopback provider (e.g.
  Ollama) found separately, so `is_local_model_available()` reported True
  for a layer that could never actually answer; it now correctly reports
  absent in that state. And the guard covered only the embedded path:
  `llm_client.get_local_client` takes an arbitrary `endpoint_url`
  parameter, overridden again by a stored BYOK credential's
  `endpoint_url` (user-writable via `add_credential`), with no loopback
  check of its own — both now go through the same shared check
  (`privacy_shield.utils.network.is_loopback_or_unix_endpoint`, factored
  out so `llm_client.py` and `services/local_model_runtime.py` — which
  imports *from* `llm_client.py` — can share it without a circular
  import) and fall back to the provider's default loopback endpoint,
  logged, rather than send. That check also now requires a `unix://` URL
  to have no host component (`unix:///path`, not `unix://host/path`):
  `unix://evil.example.com` previously passed as "local" on scheme alone
  — latent rather than live, since `httpx` happens to refuse that form,
  but not something to depend on.

### Other changes

- `tests/conftest.py` points `HOME`, `XDG_STATE_HOME`, `LOCALAPPDATA` and `USERPROFILE`
  at each test's `tmp_path` and clears every `PRIVACY_SHIELD_*` and legacy variable.
- Importing `privacy_shield.privacy_shield_embeddings` no longer creates `data/privacy_shield/`
  inside the installed package; the directory is made when the embeddings cache is written.
- Importing `privacy_shield.compliance_evidence_export` and `privacy_shield.breach`
  no longer create their evidence/log directories at import time; both are made
  on first write (same shape as the embeddings cache).
- NOTICE lists the optional third-party extras and states authorship.
- New `openai` extra (`openai>=1`) declares the dependency
  `services/local_model_runtime.py`'s embedded/native HTTP path already
  imported optionally; installed by CI's `tests` job so
  `tests/test_local_model_endpoint_guard.py`'s send-path assertions
  actually run instead of skipping in every leg (`openai` was previously
  required by no extra and no job). Its module-level `_DISCOVERY_CACHE`
  (2-second TTL, never reset) also made those tests order-dependent — run
  after another file exercising local-model discovery, a stale cached
  provider list let a tripwire's `assert constructed == []` pass
  vacuously, because the (cached) discovery never reached the send path
  at all. `tests/test_local_model_endpoint_guard.py` now resets it in an
  autouse fixture before and after every test.

### Migration

| 1.0.0 | 2.0.0 |
|---|---|
| `import brain.privacy_shield` | `import privacy_shield` |
| `brain.<module>`, e.g. `brain.audit_log` | `privacy_shield.<module>` |
| console script `brain.privacy_shield.cli:main` | `privacy_shield.cli:main` |
| `documents_store_path(brain_app=app)` (and ~15 other helpers) | `documents_store_path(host_app=app)` |
| `brain.services.persistent_brain_objects.get_persistent_brain_object_service` | `privacy_shield.services.persistent_objects.get_persistent_object_service` |
| `PersistentBrainObjectSource` | `PersistentObjectSource` |
| `brain.services.governance_audit.GOVERNANCE_DIR` | `privacy_shield.services.governance_audit.GOVERNANCE_DIR` |
| `brain.services.audit_documentation.{governance_documentation_inventory,workplane_monitoring_inventory,build_audit_documentation_summary}` | `privacy_shield.services.audit_documentation.*` (same three names) |
| `brain.services.human_control_service.get_human_control_service` | `privacy_shield.services.human_control_service.get_human_control_service` |
| `brain.services.conversation_delivery_records.get_conversation_delivery_record_service` | `privacy_shield.services.conversation_delivery_records.get_conversation_delivery_record_service` |
| `brain.services.webhook_service.emit_webhook` | `privacy_shield.services.webhook_service.emit_webhook` |
| `from brain import app` | `from privacy_shield import app` |
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
