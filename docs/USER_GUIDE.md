# Human user guide

## What v1.6 is

Agentic Security Arsenal is a security capability toolkit for AI agents and human security practitioners. It is not a standalone autonomous pentester. You can use its skill folders with compatible agent runtimes, call capabilities over MCP, use the Python API, or run the CLI directly.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Find a skill

```bash
agentsec skills list
agentsec skills show openapi-review
agentsec skills validate
```

Copy the selected skill folder into the skill directory supported by your agent. Keep the whole folder so `asa-skill.json` and future reference files travel with `SKILL.md`. Consult your agent's own documentation for its skill search path.

## Use the existing tools

```bash
# Offline technique discovery
agentsec catalog --domain "MCP"

# Validate scope without contacting a target
agentsec scope-check examples/authorized-scope.example.json

# Generate a manual review plan
agentsec plan examples/authorized-scope.example.json --format markdown --output plan.md

# Import an existing scan file (offline)
agentsec import-scan --format nmap_xml scan.xml --output normalized.json

# Inspect a supplied OpenAPI JSON file (offline)
agentsec openapi openapi.json --output openapi-review.json

# Run local synthetic scenarios
agentsec lab list
agentsec lab run
```

For active MCP HTTP metadata discovery or the bounded HTTP GET probe, first read the safety documentation and supply a valid scope manifest. Do not use the examples as authorization for real systems.

## MCP and Python API

Start the MCP server with `agentsec mcp-serve`. The server exposes stable capability tools and skill discovery (`skills_list`, `skill_get`). Python integrations can import `call_capability` and `capability_manifest` from `agentsec.agent_api`. See [MCP_ASSESSMENT.md](MCP_ASSESSMENT.md) and [QUICKSTART_AGENTS.md](QUICKSTART_AGENTS.md).

## Troubleshooting

- `Unknown or incomplete skill`: check that the complete skill directory is present.
- `DENIED` during scope validation: confirm scheme, host, port, expiration, and engagement metadata; do not widen scope to silence the error.
- Empty or partial results: read the tool's limitations and preserve the `partial` or `inconclusive` status.
- Import errors after installation: reinstall from the repository root with `pip install -e .` and verify Python version is 3.10+.
