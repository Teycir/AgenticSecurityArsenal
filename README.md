<!-- donation:eth:start -->
<div align="center">

## Support Development

If this project helps your work, support ongoing maintenance and new features.

**ETH Donation Wallet**
`0x11282eE5726B3370c8B480e321b3B2aA13686582`

<a href="https://etherscan.io/address/0x11282eE5726B3370c8B480e321b3B2aA13686582">
  <img src="publiceth.svg" alt="Ethereum donation QR code" width="220" />
</a>

_Scan the QR code or copy the wallet address above._

</div>
<!-- donation:eth:end -->

<div align="center">

# Agentic Security Arsenal

A modular security assessment knowledge base and safe testing scaffold for **LLM applications, AI agents, MCP servers, tool integrations, RAG systems, and A2A workflows**.

[![CI](https://img.shields.io/github/actions/workflow/status/Teycir/AgenticSecurityArsenal/ci.yml?branch=main&style=for-the-badge)](https://github.com/Teycir/AgenticSecurityArsenal/actions)
[![Tests](https://img.shields.io/badge/tests-73%20passed-2e8b57?style=for-the-badge)](https://github.com/Teycir/AgenticSecurityArsenal)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](https://github.com/Teycir/AgenticSecurityArsenal/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-%233776a2?style=for-the-badge)](https://www.python.org/)
[![PyPI](https://img.shields.io/badge/pypi-v1.6.0-%233776a2?style=for-the-badge)](https://pypi.org/project/agentic-security-arsenal/)

</div>

> **Status:** v1.6.0 — skills-first security toolkit for agent-native discovery and parallel use, retaining stateful investigation sessions with evidence-linked hypotheses, candidate attack-path correlation, next-action planning and result recording, alongside v1.4 HTTP/API and scanner-import capabilities. Investigation orchestration does not execute validation steps or perform automatic exploitation.

---

## What it covers

| Surface | Threats |
| --- | --- |
| Prompt & goal | Direct/indirect prompt injection, goal hijacking |
| Tools | Tool misuse, tool poisoning, excessive agency, confused-deputy |
| MCP | Discovery, resource exposure, authorization, session & transport |
| RAG & memory | Retrieval/context/memory poisoning |
| Identity | OAuth scopes, delegated authority, credential handling |
| Backend | SSRF, code/command injection, path traversal, IDOR, deserialization |
| Concurrency | Race conditions, TOCTOU, transaction invariants |
| A2A | Message authenticity, replay, delegation |
| Supply chain | Plugins, skills, configuration risks |
| Ops | Sandboxing, observability, audit trails, DoS controls |

## Design principles

1. **Authorization before interaction.** Every target must be declared in a scope file.
2. **Fail closed.** Missing, expired or mismatched scope means no test.
3. **Safe defaults.** No destructive actions, credential harvesting, persistence, arbitrary command execution, or external exfiltration.
4. **Evidence over claims.** Findings carry request/response evidence, confidence, impact and reproduction boundaries.
5. **Protocol-aware.** Treat the model UI, agent runtime, tool layer, MCP transport, backend and identity plane as separate surfaces.
6. **Framework mapping is versioned.** Taxonomy references are metadata, not a substitute for understanding root cause.

---

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

agentsec catalog --domain "Agent behavior"
agentsec scope-check examples/authorized-scope.example.json --target http://127.0.0.1:8000/health
agentsec plan examples/authorized-scope.example.json --format markdown --output assessment-plan.md
agentsec mcp-inspect --command 'python examples/my_mcp_server.py' --output mcp-inventory.json
agentsec mcp-http-inspect --url http://127.0.0.1:8000/mcp --scope examples/authorized-scope.example.json --output mcp-http.json --sarif mcp-http.sarif
pytest
```

The CLI supports deterministic local labs (`agentsec lab list` / `agentsec lab run`), catalog filtering, strict authorization-scope validation, manual assessment-plan generation, passive MCP stdio inventory, and scope-gated MCP Streamable HTTP inventory with SARIF output. The MCP Inspector negotiates modern (2026-07-28) or legacy protocol versions and lists tools, resources, resource templates and prompts without invoking tools or retrieving content. It is not a vulnerability scanner; see [docs/MCP_INSPECTOR.md](docs/MCP_INSPECTOR.md).

## Repository map

```text
.
├── catalog/
│   └── techniques.json          Structured technique knowledge base
├── skills/                      Portable Agent Skills (SKILL.md + metadata)
├── docs/
│   ├── METHODOLOGY.md           Assessment workflow
│   ├── ATTACK_SURFACES.md       System decomposition and trust boundaries
│   ├── TECHNIQUE_MATRIX.md      Coverage matrix
│   ├── MCP_ASSESSMENT.md        MCP-specific assessment guide
│   ├── LOCAL_LABS.md             Deterministic synthetic vulnerable scenarios
│   ├── MCP_INSPECTOR.md         MCP stdio and Streamable HTTP inspectors
│   ├── EVIDENCE_AND_REPORTING.md Finding and evidence standard
│   └── ROADMAP.md               Planned adapters and lab modules
├── examples/
│   └── authorized-scope.example.json
├── src/agentsec/
│   ├── skillpacks/               Packaged Agent Skills for CLI/MCP discovery
│   ├── skills.py                 Skill discovery and validation
│   ├── investigation.py         v1.4 importers, HTTP probe and hypotheses
│   ├── investigation_engine.py  Stateful investigation and evidence workflow
│   ├── mcp_http.py              Scope-gated Streamable HTTP inventory
│   ├── sarif.py                 SARIF 2.1.0 exporter
│   ├── cli.py
│   ├── scope.py
│   ├── catalog.py
│   └── planning.py
└── tests/
```

## Documentation map

- [Human user guide](docs/USER_GUIDE.md) — install, everyday CLI use, troubleshooting.
- [Quick start for AI agents](docs/QUICKSTART_AGENTS.md) — discover, select, and use skills.
- [Skills catalogue and parallel-use guidance](docs/SKILLS.md).
- [v1.6 architecture](docs/ARCHITECTURE_V1_6.md).
- [Result and evidence contract](docs/RESULT_CONTRACT.md).
- [v1.6 release notes](docs/V1_6.md).

## CLI capabilities

| Command | What it does |
| --- | --- |
| `agentsec catalog --domain "MCP"` | Filter the technique knowledge base by exact domain. |
| `agentsec scope-check scope.json --target https://host.example/path` | Check a target against declared origins (authorization-only, no network). |
| `agentsec plan scope.json --format json --output plan.json` | Create a structured manual test plan. `--format markdown` for a checklist. |
| `agentsec mcp-inspect --command 'python server.py' --output inventory.json` | Passively inventory a local stdio MCP server. |
| `agentsec mcp-http-inspect --url … --scope … --output … --sarif …` | Scope-gated Streamable HTTP inventory with SARIF output. |
| `agentsec lab list` / `agentsec lab run` | Deterministic in-process synthetic agent-security labs. |
| `agentsec skills list` / `show` / `validate` | Discover and validate portable Agent Skills. |
| `agentsec knowledge import …` | Import a local Markdown writeup or GitHub README URL as untrusted reference data. |
| `agentsec scenario generate|validate|approve|revoke` | Draft scenario governance; drafts are never executable by default. |
| `agentsec assessment create|run|compare` | Offline evidence evaluation bound to an unexpired scope manifest. |
| `agentsec http-probe --url … --scope …` | One bounded GET to an exact-origin target (no redirects, no payloads). |
| `agentsec openapi openapi.json` | Static OpenAPI JSON analysis (no network access). |
| `agentsec import-scan --format nmap_xml|nuclei_jsonl|burp_xml …` | Parse existing scanner exports without contacting targets. |
| `agentsec hypotheses …` | Turn imported evidence into explicitly unverified investigation hypotheses. |
| `agentsec investigation create|next|record|report` | Stateful investigation session with queued review steps and evidence log. |
| `agentsec mcp-serve` | Expose capabilities as an MCP stdio server for compatible agents. |
| `agentsec analyze … --sarif …` | Static analysis of a saved MCP inventory with SARIF output. |
| `agentsec compare …` | Regression comparison against a prior findings baseline. |

Scope matching normalizes host casing and default ports, but does not accept wildcard origins, URL credentials, non-HTTP schemes, or undeclared ports. A path on a requested URL is allowed because authorization is granted at the origin level; declare separate origins for separate schemes or ports.

## Example workflow

1. Draw the system boundary: user interface, model, orchestration, tools, MCP servers, data stores, identity provider and external services.
2. Obtain written authorization and create a narrow scope manifest.
3. Inventory tools, resources, prompts, identities, trust relationships and side effects.
4. Select techniques from `catalog/techniques.json`.
5. Run passive/configuration checks first; use benign canaries for runtime tests.
6. Reproduce high-impact behavior only in an isolated lab or with explicit written approval and safeguards.
7. Record raw evidence, determine root cause, validate remediation and produce a report.

## Safety boundary

This project is intended for systems you own or are explicitly authorized to assess. Do not point it at public agents, third-party MCP servers, production customer data or infrastructure without written authorization. The MCP adapters perform protocol discovery and metadata-list requests only; they do not invoke tools, read resource contents, or retrieve prompt contents. HTTP inspection is an active network interaction and requires an unexpired scope manifest with an exact endpoint origin. Redirects are refused, TLS verification remains enabled, and bearer tokens are read from environment variables. It launches the operator-supplied server process, so inspect that command and run it in an appropriately isolated environment. The project does not include exploit chains for credential theft, data exfiltration, destructive tool calls, persistence, or remote code execution. The `lab` command runs only deterministic in-process simulations using synthetic data.

See [AUTHORIZATION.md](AUTHORIZATION.md), [SECURITY.md](SECURITY.md), and [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## References

- [OWASP GenAI Security Project](https://genai.owasp.org/)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contributing and CI

See [CONTRIBUTING.md](CONTRIBUTING.md). GitHub Actions runs the test suite on Python 3.10–3.13 and checks style with Ruff. The JSON Schema for authorization manifests is in `schemas/scope.schema.json`; runtime validation remains authoritative.

## v1.6 — skills-first workflow

The arsenal now ships eight small, portable Agent Skills. Each folder contains an agent-readable `SKILL.md` and machine-readable `asa-skill.json` describing inputs, outputs, execution mode, permissions, interfaces, and parallel-safety boundaries. The host agent remains the planner; this project does not add a heavyweight orchestration engine.

```bash
agentsec skills list
agentsec skills show mcp-server-review
agentsec skills validate
```

Agents can also discover skills through MCP (`skills_list`, `skill_get`). See [Agent Skills guide](docs/SKILLS.md), [agent quick start](docs/QUICKSTART_AGENTS.md), and [human user guide](docs/USER_GUIDE.md).

## v1.5 — Stateful investigation and attack-path engine

v1.5 adds a closed-loop investigation workflow for AI agents. It turns imported evidence into a persistent session containing unverified hypotheses, queued review steps, candidate correlations and an evidence/decision log.

```bash
agentsec investigation create --scope scope.json --target https://lab.example \
  nmap-import.json nuclei-import.json --title "Initial API investigation" \
  --output session.json
agentsec investigation next session.json --output next-action.json
agentsec investigation record session.json --step-id step-IDENTIFIER \
  --outcome observed --note "Describe the exact observation" \
  --output session-updated.json
agentsec investigation report session-updated.json --output report.json
```

Candidate paths are grouped only when supplied observations share an explicit host/target context. This is a low-confidence correlation, not proof of causality, exploitability, or a working exploit chain. Hypotheses remain unverified. The engine does not run queued steps, crawl, fuzz, invoke external scanners, execute shell commands, or perform exploit actions. Each session update is returned as JSON; agents should persist the latest session document themselves.

## v1.4 — HTTP/API investigation and scan evidence

v1.4 extends the v1.3 agent interface with bounded investigation capabilities.

```bash
agentsec http-probe --url https://lab.example/health --scope scope.json --output probe.json
agentsec openapi openapi.json --output api-map.json
agentsec import-scan --format nmap_xml nmap.xml --output nmap-import.json
agentsec import-scan --format nuclei_jsonl nuclei.jsonl --output nuclei-import.json
agentsec import-scan --format burp_xml burp.xml --output burp-import.json
agentsec hypotheses nmap-import.json nuclei-import.json --output hypotheses.json
```

OpenAPI and scan import are offline. The HTTP probe verifies TLS, refuses redirects, caps response size, and exposes no arbitrary methods, payload execution, crawling or fuzzing. Findings/hypotheses remain unconfirmed until independently validated. See `docs/V1_4.md` for detailed contracts and limitations.

## v1.3 — Agent-first capability interface

v1.3 adds a machine-discoverable capability layer so compatible AI agents can use Agentic Security Arsenal as a security workbench rather than treating it as a standalone CTF application.

```bash
python -m pip install -e .
agentsec mcp-serve
agentsec mcp-serve --print-manifest
```

Configure the agent's MCP client to launch `agentsec mcp-serve` as a stdio server. Initial capabilities: `capability_manifest`, `catalog_search`, `scope_check`, `local_lab_list` / `local_lab_run`, `mcp_inventory_analyze`. The same functions are available to Python callers through `agentsec.agent_api`. Tool calls reject undeclared arguments and return structured JSON. The MCP server does not expose arbitrary shell execution, does not perform automatic exploitation, and does not contact targets by default. Existing CLI workflows remain available.

This is the first agent-integration milestone, not a claim of autonomous penetration testing. Active web/API testing, external tool adapters, replayable request/response capture, exploit-chain orchestration and a challenge benchmark are planned as subsequent capability modules.

## v1.2 — scenario governance and assessment integrity

- Scenario approval and revocation are explicit CLI operations; draft generation never implies approval.
- Assessment manifests snapshot approved scenario definitions rather than depending on a mutable source file at run time.
- SHA-256 fingerprints record the source scenario pack and scope manifest; a canonical manifest digest is verified before evidence evaluation.
- Regression comparison distinguishes improved, regressed, degraded, changed, new, removed and unchanged scenarios.
- Python 3.10 compatibility is retained by avoiding `typing.Self` (introduced in Python 3.11).

## v1.0 — knowledge → assessment workflow

```bash
agentsec knowledge import ./arkx-writeup.md --output knowledge.json
agentsec scenario generate --source knowledge.json --output scenarios.json
agentsec scenario validate scenarios.json
agentsec scenario approve scenarios.json --id prompt-injection
agentsec scenario revoke scenarios.json --id prompt-injection
agentsec assessment create --source scenarios.json --scope scope.json --target https://localhost:8443 --output assessment.json
agentsec assessment run --assessment assessment.json --evidence evidence.json --output results.json
agentsec assessment compare --baseline before.json --current results.json --output regression.json
```

Imported references are marked `UNTRUSTED_REFERENCE_ONLY`; taxonomy matches are heuristic candidates. Generated scenarios require explicit human approval (`status: approved` and `human_approval: true`) before they are included in an assessment. Assessment manifests embed the approved scenario definitions, source-pack and scope fingerprints, and a SHA-256 integrity digest; evidence runs reject modified manifests. This digest detects accidental or unsophisticated tampering, but is not a digital signature and does not authenticate the author. The runner consumes evidence fixtures and does **not** contact a target or execute agent/tool actions. Approved scenarios without a built-in evaluator are included as inconclusive, not silently dropped.

## v0.7.0 — agent evaluations

List synthetic evaluation scenarios with `agentsec eval list`. Evaluate a supplied evidence fixture using `agentsec eval run --evidence evidence.json --output evaluation.json`. The suite does not execute live agents or tools; missing evidence is marked inconclusive. See `docs/AGENT_EVALUATIONS.md`.

## v0.6.0 — static analysis and regression comparison

Analyze a previously saved MCP inventory without contacting the server or invoking tools:

```bash
agentsec analyze inventory.json --output findings.json --sarif findings.sarif
agentsec compare baseline-findings.json current-findings.json --output regression.json
```

The analyzer emits stable rule IDs, severity, confidence, evidence, remediation guidance, and a human-validation status. Results are heuristic metadata signals, not proof of exploitability. Review findings before treating them as confirmed vulnerabilities.
