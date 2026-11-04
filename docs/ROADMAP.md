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