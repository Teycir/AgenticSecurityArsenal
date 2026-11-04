# MCP Inspector

AgentSec v0.4.0 provides two metadata-only MCP inventory adapters:

- **stdio**: launches an operator-supplied local MCP server process.
- **Streamable HTTP**: connects to an explicitly authorized HTTP(S) MCP endpoint.

Neither adapter invokes tools, reads resource contents, or retrieves prompt contents. Both enumerate the tools, resources, resource templates, and prompt metadata advertised by the server. Metadata inventory is not proof that the server enforces authorization correctly.

## Remote Streamable HTTP

The HTTP adapter requires an unexpired authorization manifest and an exact declared origin. It refuses URL credentials, query strings, fragments, redirects, invalid ports, and undeclared origins. TLS certificate verification is not disabled. The adapter does not follow redirects because doing so could move a request outside the declared scope.

```bash
# Optional: place the authorized bearer token in the process environment.
export MCP_ASSESSMENT_TOKEN='...'

agentsec mcp-http-inspect \
  --url https://mcp.example.test/mcp \
  --scope scope.json \
  --auth-env MCP_ASSESSMENT_TOKEN \
  --output reports/mcp-http.json \
  --sarif reports/mcp-http.sarif
```

`--auth-env` names an environment variable; the token itself is never accepted as a command-line argument and is not included in the report. Do not place tokens in shell history or commit them to the scope manifest.

### Origin validation observation

The default initial discovery request includes the synthetic origin `https://agentsec.invalid`. If the endpoint returns HTTP 403, the adapter records a positive Origin-rejection signal and retries discovery without an Origin header to continue inventory. If it accepts the synthetic origin, the report records a medium-severity review finding. This is a narrow configuration signal, not a complete DNS-rebinding or CORS assessment. Use `--origin` to override the synthetic value when a specific controlled Origin test is required.

### Protocol compatibility

The adapter attempts the modern `2026-07-28` discovery flow first and falls back to the legacy `initialize` handshake for older Streamable HTTP servers. Legacy sessions are carried with `MCP-Session-Id`; modern stateless requests carry per-request metadata. The adapter does not implement the deprecated HTTP+SSE transport.

### Authentication observations

If discovery is rejected with HTTP 401, the adapter retries only when `--auth-env` was supplied. It does not perform OAuth authorization-code flows, token refresh, identity switching, privilege escalation, or authentication bypass tests. A successful inventory with a bearer token says nothing by itself about least privilege.

### Authorization review plan

If the scope manifest contains an `accounts` array, the report creates a manual principal-by-tool review matrix. Each row is marked `not_tested`; no account is impersonated and no tool is called. Review each principal's expected permissions with the system owner and validate them through a separately approved test procedure.

### SARIF

`--sarif` writes a SARIF 2.1.0 report. Findings are marked as requiring human validation. SARIF is an interchange format, not a claim that each metadata observation is a confirmed vulnerability.

## Local stdio

```bash
agentsec mcp-inspect \
  --command 'python examples/my_mcp_server.py' \
  --timeout 10 \
  --output reports/mcp-stdio.json
```

The stdio adapter launches the supplied process without a shell. Run unknown server code in a disposable container or VM with restricted filesystem and network access.

## Limitations and safe-use notes

- HTTP inspection sends protocol discovery and list requests; it is not zero-interaction or purely offline.
- Exact-origin scope checks do not replace network egress controls. Use a dedicated assessment host, firewall rules, and DNS controls to constrain where the process can connect.
- The inspector does not resolve or validate the security of server-side tool implementations.
- Tool annotations such as `readOnlyHint` are untrusted metadata hints, not authorization controls.
- Resource and prompt metadata can itself contain sensitive information. Protect inventory reports as assessment artifacts.
- Only inspect systems for which written authorization covers protocol discovery and metadata enumeration.

## Protocol references

- [Current Streamable HTTP transport specification](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http)
- [2025-11-25 transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
