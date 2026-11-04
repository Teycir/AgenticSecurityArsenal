# Changelog

## 1.2.0 — 2026-11-04

- Added explicit `scenario approve` and `scenario revoke` CLI commands; approval requires exact scenario IDs and is never inferred from generation.
- Strengthened scenario-pack validation for malformed rows, duplicate IDs, invalid status values, and mismatched approval flags.
- Assessment creation now snapshots the full approved scenario definitions and fingerprints the source scenario pack and scope manifest.
- Added canonical SHA-256 integrity verification; evidence runs refuse modified or malformed assessment manifests.
- Improved assessment regression classification for improved, regressed, degraded, changed, new, removed, and unchanged scenarios; malformed/duplicate result IDs are rejected.
- Fixed Python 3.10 compatibility by replacing the Python 3.11-only `typing.Self` import.
- Added adversarial tests for tampering, missing integrity metadata, invalid approvals, duplicate IDs, regression transitions, and CLI approval/revocation.
- Test suite: 51 passed on Python 3.13.5. Python 3.10 runtime and Ruff could not be run in the build environment; Python 3.10 import compatibility is addressed in source and remains to be confirmed in CI.

### Integrity boundary

The SHA-256 digest detects changes to the assessment payload when the digest is not also replaced. It is not a digital signature, does not prove who created or approved the assessment, and does not replace the original written authorization.


## 1.0.0 — 2026-11-04

- Added provenance-preserving knowledge import for local Markdown and GitHub README references.
- Added heuristic security taxonomy candidates, source SHA-256 fingerprints, and explicit untrusted-source markings.
- Added scenario draft generation and structural validation; human approval is explicit and defaults off.
- Added assessment manifests that require a valid, unexpired exact-origin scope.
- Added evidence-fixture assessment execution and scenario regression comparison.
- Added `knowledge`, `scenario`, and `assessment` CLI command groups.
- Updated README and release metadata to 1.0.0.
- Retained prior passive MCP inspection, catalog, planning, lab, finding analysis, SARIF and evaluation functionality.
- Test suite: 40 passed.

### Known limitations

- No live agent/model execution adapter is shipped in 1.0.0. Assessment runs consume evidence JSON only and never contact the target.
- Knowledge extraction is heuristic. Candidate categories are not confirmed findings.
- Scenario packs need expert review and explicit approval before inclusion in an assessment.
- Scope validation establishes declared origin authorization only; it is not proof of ownership or permission.
