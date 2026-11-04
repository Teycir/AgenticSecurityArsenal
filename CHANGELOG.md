# Changelog

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
