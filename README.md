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

> **Status:** v1.0.0 — integrated knowledge ingestion, draft scenario generation/validation, explicit scope-bound assessment manifests, deterministic evidence evaluation, regression comparison, passive MCP inventory, and reports. Live agent execution is not included; assessment runs are evidence-fixture-only. High-impact exploit reproduction belongs in isolated, intentionally vulnerable labs.

## What it covers

- Prompt and goal hijacking, direct and indirect prompt injection
- Tool misuse, tool poisoning, excessive agency, confused-deputy paths
- MCP discovery, resource exposure, authorization, session and transport controls
- RAG, memory, context and retrieval poisoning
- Identity, OAuth scopes, delegated authority, credential handling
- Traditional vulnerabilities reachable through agent tools: SSRF, command/code injection, path traversal, unsafe deserialization, IDOR, error disclosure
- Race conditions, TOCTOU and transaction invariants
- A2A trust, message authenticity, replay and delegation
- Supply-chain, plugin, skill and configuration risks
- Sandboxing, observability, audit trails and denial-of-service controls

## Design principles

1. **Authorization before interaction.** Every target must be declared in a scope file.
2. **Fail closed.** Missing, expired or mismatched scope means no test.
3. **Safe defaults.** No destructive actions, credential harvesting, persistence, arbitrary command execution, or external exfiltration.
4. **Evidence over claims.** Findings carry request/response evidence, confidence, impact and reproduction boundaries.
5. **Protocol-aware.** Treat the model UI, agent runtime, tool layer, MCP transport, backend and identity plane as separate surfaces.
6. **Framework mapping is versioned.** Taxonomy references are metadata, not a substitute for understanding root cause.

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
├── docs/
│   ├── METHODOLOGY.md           Assessment workflow
│   ├── ATTACK_SURFACES.md       System decomposition and trust boundaries
│   ├── TECHNIQUE_MATRIX.md      Coverage matrix
│   ├── MCP_ASSESSMENT.md        MCP-specific assessment guide
│   ├── LOCAL_LABS.md             Deterministic synthetic vulnerable scenarios\n│   ├── MCP_INSPECTOR.md         MCP stdio and Streamable HTTP inspectors
│   ├── EVIDENCE_AND_REPORTING.md Finding and evidence standard
│   └── ROADMAP.md               Planned adapters and lab modules
├── examples/
│   └── authorized-scope.example.json
├── src/agentsec/
│   ├── mcp_http.py              Scope-gated Streamable HTTP inventory
│   ├── sarif.py                 SARIF 2.1.0 exporter
│   ├── cli.py
│   ├── scope.py
│   ├── catalog.py
│   └── planning.py
└── tests/
```

## CLI capabilities

- `agentsec catalog --domain "MCP"` filters the technique knowledge base by exact domain.
- `agentsec scope-check scope.json --target https://host.example/path` checks the target against explicitly declared origins.
- `agentsec plan scope.json --format json --output plan.json` creates a structured manual test plan. Use `--format markdown` for a review-friendly checklist.
- `agentsec mcp-inspect --command 'python server.py' --output inventory.json` passively inventories a local stdio MCP server.

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

## v0.6.0: static analysis and regression comparison

Analyze a previously saved MCP inventory without contacting the server or invoking tools:

```bash
agentsec analyze inventory.json --output findings.json --sarif findings.sarif
```

Compare normalized findings against a prior baseline:

```bash
agentsec compare baseline-findings.json current-findings.json --output regression.json
```

The analyzer emits stable rule IDs, severity, confidence, evidence, remediation guidance, and a human-validation status. Results are heuristic metadata signals, not proof of exploitability. Review findings before treating them as confirmed vulnerabilities.
## Agent evaluations (v0.7.0)

List synthetic evaluation scenarios with `agentsec eval list`. Evaluate a supplied evidence fixture using `agentsec eval run --evidence evidence.json --output evaluation.json`. The suite does not execute live agents or tools; missing evidence is marked inconclusive. See `docs/AGENT_EVALUATIONS.md`.

## v1.0 knowledge → assessment workflow

```bash
# Import a local Markdown writeup (or a GitHub README URL) as untrusted reference data
agentsec knowledge import ./arkx-writeup.md --output knowledge.json

# Generate draft scenarios; drafts are never executable by default
agentsec scenario generate --source knowledge.json --output scenarios.json
agentsec scenario validate scenarios.json

# Create an assessment bound to an unexpired exact-origin authorization manifest
agentsec assessment create --source scenarios.json --scope scope.json --target https://localhost:8443 --output assessment.json

# Evaluate supplied evidence offline (approved scenarios only)
agentsec assessment run --assessment assessment.json --evidence evidence.json --output results.json
agentsec assessment compare --baseline before.json --current results.json --output regression.json
```

Imported references are marked `UNTRUSTED_REFERENCE_ONLY`; taxonomy matches are heuristic candidates. Generated scenarios require explicit human approval (`status: approved` and `human_approval: true`) before they are included in an assessment. The current v1.0 runner consumes evidence fixtures and does **not** contact a target or execute agent/tool actions.
