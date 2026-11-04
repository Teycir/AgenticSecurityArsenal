# Changelog

## 1.6.0 — 2026-11-04

- Added eight focused Agent Skills with agent-readable `SKILL.md` files and machine-readable metadata.
- Added CLI skill discovery and validation commands.
- Added MCP/Python skill discovery capabilities.
- Added documentation for agent and human workflows, architecture, permissions, parallel safety, evidence provenance, and result handoff.
- Kept agent reasoning and parallel scheduling in the host runtime; no orchestration engine was introduced.
- Retained all v1.5 capabilities and existing result shapes.

### Safety and validation boundary

Skill metadata does not grant authorization. Existing scope validation remains authoritative. Parallel-safe labels are operational guidance, not a guarantee about target capacity. Writes to one investigation session must be serialized.

## 1.5.0 — 2026-11-04

- Added a stateful investigation engine that creates scope-checked sessions from normalized evidence reports.
- Added deterministic queued review/benign-validation steps and next-action selection; queued steps are never auto-executed.
- Added result recording with explicit `observed`, `not_observed`, and `inconclusive` outcomes, evidence provenance, duplicate-record protection, and decision logs.
- Added low-confidence candidate attack-path correlation for observations sharing an explicit target context; correlations are explicitly non-causal and unverified.
- Exposed `investigation_create`, `investigation_next`, `investigation_record`, and `investigation_report` through MCP/Python capability APIs.
- Added CLI create/next/record/report workflows and regression tests.
- Retained all v1.4 HTTP/API, OpenAPI, Nmap, Nuclei, Burp and existing v1.3 capabilities.

### Safety and validation boundary

Investigation sessions perform offline planning and record externally supplied results. They do not execute validation actions, exploit targets, crawl, fuzz, invoke arbitrary commands, or mark vulnerabilities confirmed. Session JSON is operator-managed state and should be stored in a trusted workspace; it is not cryptographically signed.


## 1.4.0 — 2026-11-04

- Added a bounded, exact-origin scope-authorized HTTP GET probe; TLS verification is enabled, redirects are refused, response size and timeout are bounded, and no state-changing HTTP methods or payload execution are exposed.
- Added offline OpenAPI JSON endpoint analysis.
- Added offline Nmap XML, Nuclei JSONL and Burp XML result importers.
- Added evidence-led investigation hypothesis generation; outputs are explicitly unverified and include safe validation guidance.
- Exposed the new capabilities through the MCP agent interface and CLI.
- Added focused regression tests for parsers, hypothesis generation, scope enforcement and local HTTP probing.

### Safety and validation boundary

The HTTP adapter performs only one explicitly requested GET request against an exact origin in a valid, unexpired authorization manifest. It refuses redirects and does not automatically crawl, fuzz, authenticate, exploit, or follow links. Scan importers parse existing files only. Imported scanner output is treated as untrusted evidence and is not independently verified.

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


## [1.3.0] - 2026-11-04

### Added
- Agent-first capability registry exposed through a minimal MCP stdio server.
- Structured MCP tools for catalog search, scope authorization checks, synthetic labs, and offline MCP inventory analysis.
- Python capability API and machine-readable capability manifest.
- Strict rejection of undeclared tool arguments.
- Explicit execution constraints: no arbitrary shell, no automatic exploitation, and no target interaction by default.

### Notes
- v1.2 assessment governance, scope validation, evidence evaluation, and regression workflows are retained.
- This release establishes the agent integration foundation; active testing adapters and end-to-end challenge orchestration remain future work.
