# Findings engine (v0.6.0)

AgentSec normalizes static observations into a common finding shape: `id`, `title`, `severity`, `confidence`, `detail`, `target`, `evidence`, `remediation`, and `status`. The current MCP analyzer consumes saved inventory JSON and performs no network requests.

## Commands

- `agentsec analyze <inventory.json> --output <findings.json> [--sarif <findings.sarif>]`
- `agentsec compare <baseline.json> <current.json> --output <comparison.json>`

The comparison identity is `(id, target, title)`. It reports added and resolved findings plus severity changes. Keep baselines under version control and validate changes in context; title changes can appear as a resolved/new pair.

## Current rule families

- `ASA-MCP-001`: missing/uninspectable input schema
- `ASA-MCP-002`: non-object input schema
- `ASA-MCP-003`: `additionalProperties: true`
- `ASA-MCP-004`: missing tool description
- `ASA-MCP-005`: tool not declared read-only (informational, low confidence)
- `ASA-MCP-006`: duplicate tool name
- `ASA-MCP-007`: malformed tool definition

MCP annotations are hints, not authorization controls. Findings are needs-human-validation and should not be interpreted as exploitability claims.
