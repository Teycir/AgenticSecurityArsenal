# Roadmap

## v0.1 — Foundation
- [x] 36-technique structured knowledge base
- [x] Authorization scope manifest and fail-closed validator
- [x] Assessment methodology and trust-boundary model
- [x] MCP assessment checklist
- [x] Evidence/reporting standard

## v0.2 — Passive inspection
- [x] MCP configuration and server manifest parser foundation
- [x] Tool-schema metadata observations
- [x] JSON inventory output

## v0.3 — MCP stdio inventory
- [x] MCP read-only discovery adapter
- [x] Legacy and modern protocol handling
- [x] Deterministic fixture tests

## v0.4 — Streamable HTTP and reporting
- [x] HTTP adapter with explicit exact-origin scope enforcement
- [x] Origin validation observation
- [x] Optional bearer token from environment variable
- [x] Manual principal-by-tool authorization review plan
- [x] SARIF 2.1.0 export

## v0.5 — Local vulnerable labs
- [ ] Deliberately vulnerable MCP server
- [ ] Mock agent with tool registry
- [ ] RAG and memory poisoning fixtures
- [ ] Authorization and tenant-isolation labs
- [ ] TOCTOU and transactional-invariant labs
- [ ] Containerized isolated execution profile

## v0.6 — Reporting and integrations
- [ ] SARIF 2.1.0
- [ ] HTML and Markdown reports
- [ ] CI regression tests
- [ ] Trace correlation and evidence bundles
- [ ] CWE / OWASP / ATLAS mapping version registry

## Non-goals
- Stealth, persistence, credential theft, real-world exfiltration, destructive exploitation, uncontrolled shell execution or automated attacks against arbitrary public targets.


## v0.2.0 delivery

- Added exact-origin scope validation with wildcard rejection and URL normalization.
- Added catalog structure/duplicate-ID validation and domain/ID filters.
- Added offline JSON/Markdown assessment-plan generation.
- Added tests for invalid URL forms, wildcard rejection, catalog integrity and plan structure.

## Next engineering milestones

1. Define adapter interfaces and a replayable evidence model before adding network checks.
2. Add MCP inventory against a local fixture, with read-only initialization and tool/resource listing only.
3. Add deterministic benign-canary evaluators for prompt injection and tool-boundary enforcement.
4. Add SARIF plus human-readable report export with stable finding IDs.
5. Add intentionally vulnerable local labs and CI integration; keep active tests opt-in and bounded by scope.


## MCP Inspector status (v0.4.0)

Implemented: stdio and Streamable HTTP metadata inventory; modern discovery and legacy initialization; exact-origin authorization gating; Origin rejection observation; optional bearer-token support through environment variables; manual principal-by-tool review planning; SARIF 2.1.0 export.

Next: richer JSON Schema analysis, explicit tool-risk classification, protocol conformance fixtures, HTML evidence reports, and isolated local labs. Automated tool invocation, resource reads, identity switching, and OAuth flows remain out of scope for the inspector.


## v0.5.0 — Local vulnerable labs

- Added five deterministic local scenarios: excessive tool permissions, tenant isolation, confused deputy, tool-description poisoning, and RAG/memory poisoning.
- Added `agentsec lab list` and `agentsec lab run`.
- Added JSON and SARIF export for lab findings.
- Added tests proving offline, synthetic-only execution.
- Lab results validate modeled fixtures, not live-target detection.
\n- [x] v0.7.0 deterministic agent evaluation suite with evidence-based checks and JSON/SARIF output\n- [ ] v0.8.0 authorized adapter-based evaluation and CI regression gates\n

## v1.2 — Scenario governance and reproducible evidence

- [x] Explicit per-scenario approval and revocation through the CLI
- [x] Strict scenario-pack approval-state validation
- [x] Approved scenario snapshots embedded in assessment manifests
- [x] Source-pack and scope fingerprints
- [x] Canonical assessment integrity verification before evidence runs
- [x] Regression classifications for improved, regressed, degraded, changed, new, removed, unchanged
- [x] Adversarial tests for approval, tampering and malformed regression inputs
- [x] Python 3.10-compatible MCP inspector typing


## v1.3.0 — Agent-first foundation

- [x] Stable capability registry and structured tool contracts
- [x] MCP stdio server (`initialize`, `tools/list`, `tools/call`, `ping`)
- [x] Python API for capability composition
- [x] Catalog search, scope authorization check, local synthetic labs, offline MCP inventory analysis
- [x] Machine-readable capability manifest and explicit execution constraints
- [ ] Adapter framework for external tools with per-adapter permission declarations
- [ ] HTTP request/response evidence capture and replay
- [ ] Scope-gated web/API passive discovery and bounded validation
- [ ] Attack-path graph and hypothesis/evidence tracking
- [ ] CTF benchmark harness with challenge fixtures, reproducibility and scoring
- [ ] Android/static-analysis adapters (JADX, apktool, Ghidra integration points)

## v1.3 design rule

Capabilities are composable and agent-discoverable. External tools are adapters,
not the product itself. Every active adapter must declare side effects, network
behavior, authorization requirements, limits, output schema and evidence format.
