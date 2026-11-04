# Local Vulnerable Labs

Version: 0.5.0

These labs are deterministic, in-process simulations. They use synthetic identities,
records and policy fixtures. They make no network connections, start no MCP server,
call no external model, and perform no real data access or destructive operation.

They provide repeatable examples of security failure modes and validate the reporting
pipeline. They are **not** proof that the inspector detects the same issue in arbitrary
deployed MCP servers.

## Scenarios

| ID | Modeled weakness | Expected severity |
|---|---|---|
| `excessive-tool-permissions` | Low-privilege role receives a destructive capability | High |
| `tenant-isolation` | Tenant-scoped lookup returns another tenant's synthetic record | Critical |
| `confused-deputy` | Elevated service identity acts without caller-level resource authorization | High |
| `tool-description-poisoning` | Tool metadata contains policy-override instructions | Medium |
| `rag-memory-poisoning` | Untrusted retrieved memory attempts to override policy | High |

## Run

```bash
agentsec lab list
agentsec lab run
agentsec lab run --scenario tenant-isolation
agentsec lab run --output reports/labs.json --sarif reports/labs.sarif
```

## Interpretation

A finding means the deliberately flawed fixture contains the modeled condition. It does
not mean a real target has the same weakness. For real assessments, validate authorization
and data-flow behavior with approved test identities, synthetic records and a written plan.
Do not use customer data or attempt unauthorized cross-tenant access.

## Next step

A later lab generation can add opt-in containerized MCP server fixtures with documented
setup/teardown, disposable databases, and end-to-end tests. Keep those fixtures bound to
loopback or an isolated container network; never expose them publicly by default.
