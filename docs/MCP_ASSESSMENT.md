# MCP Security Assessment Guide

## Protocol and capability inventory
- Confirm protocol version and transport.
- Record authentication mechanism and session lifecycle.
- Enumerate tools, resources and prompts.
- Capture tool descriptions and JSON schemas.
- Identify server identity, publisher, package source and version.
- Determine which tools can read, write, delete, execute, send network requests or change permissions.

## Authorization
- Authentication is not authorization.
- Test each tool and resource using at least two synthetic principals with different permissions.
- Verify object-level authorization for every resource read and tool call.
- Confirm that authorization is enforced by the server, not by the model, UI, Origin header or client-side policy.
- Ensure a tool cannot grant the caller privileges that the caller is meant to lack.

## Session and transport
- Bind sessions to authenticated principals.
- Validate expiry, rotation, revocation and cross-session isolation.
- Do not treat CORS or Origin validation as authentication.
- Protect session identifiers and avoid logging them.
- Enforce transport security and appropriate request size/time limits.

## Tool safety
- Minimize tool capabilities and argument scope.
- Use strict schemas and reject unknown fields.
- Require confirmation for high-impact actions.
- Make operations idempotent where possible.
- Log principal, tool, arguments (redacted), decision and outcome.
- Ensure tool descriptions cannot silently expand authority.

## Resource safety
- Do not advertise secrets or protected data as broadly readable resources.
- Authorize every resource read.
- Enforce tenant and object boundaries.
- Avoid leaking data in error messages and metadata.

## Evidence template
For each MCP finding, retain:
- Redacted initialize exchange and negotiated protocol version.
- Redacted tools/list, resources/list and prompts/list results.
- Synthetic principal and scope used.
- Exact request/response pair.
- Authorization decision and server-side logs.
- Expected vs actual behavior.
- Remediation and retest result.


## Automated passive inventory

For a local stdio server, start with the [MCP Inspector](MCP_INSPECTOR.md): it inventories advertised tools, resources, templates and prompts without invoking them or reading their contents. Treat its output as an inventory, not as proof of access-control correctness.
