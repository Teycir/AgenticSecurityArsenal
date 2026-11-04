# AI Agent Attack Surface Model

An agentic system is not one attack surface. Assess each layer and the transitions between them.

| Layer | Assets / controls | Typical failure modes |
|---|---|---|
| User interface / API | Authentication, sessions, input validation | Auth bypass, injection, rate abuse |
| Model interface | System/developer instructions, context, output | Goal hijack, hidden context exposure, unsafe output handling |
| Orchestrator | Planning, routing, retries, state | Excessive agency, loops, confused deputy |
| Tool registry | Names, descriptions, schemas, permissions | Tool poisoning, overbroad tools, schema ambiguity |
| Tool runtime | Process, filesystem, network, code | Command/code injection, SSRF, sandbox escape |
| MCP client/server | JSON-RPC, resources, prompts, tools, sessions | Missing authorization, resource exposure, session confusion |
| RAG / memory | Ingestion, embeddings, retrieval, persistence | Poisoning, provenance failure, cross-tenant leakage |
| Identity plane | OAuth, API keys, service identities, delegation | Scope creep, token leakage, confused deputy |
| A2A | Peer identity, message integrity, delegation | Spoofing, replay, cascading trust |
| Data plane | Databases, object stores, caches | IDOR, cache poisoning, TOCTOU |
| Supply chain | Skills, plugins, packages, model artifacts | Typosquatting, untrusted updates, malicious metadata |
| Observability | Traces, logs, approvals | Missing evidence, secret leakage, audit tampering |

## Trust-boundary questions

For every transition, ask:
1. Who is the principal?
2. Which identity is being used: user, agent, tool or service?
3. What data crosses the boundary?
4. Is the content trusted, untrusted or unknown?
5. Which component authorizes the action?
6. Is authorization checked on the specific object and operation?
7. Can the caller influence the check and the checked state?
8. Is the action reversible, bounded and auditable?
