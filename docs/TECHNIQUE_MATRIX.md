# Technique Coverage Matrix

The canonical machine-readable catalog is [`../catalog/techniques.json`](../catalog/techniques.json).

| ID | Domain | Technique |
|---|---|---|
| AG-001 | Agent behavior | Agent goal hijack |
| AG-002 | Agent behavior | Indirect prompt injection |
| AG-003 | Agent behavior | System prompt/context disclosure |
| AG-004 | Tool layer | Tool misuse |
| AG-005 | Tool layer | Tool description poisoning |
| AG-006 | Identity / authorization | Confused deputy |
| AG-007 | MCP | MCP resource exposure |
| AG-008 | MCP | MCP tool authorization bypass |
| AG-009 | MCP | MCP session confusion |
| AG-010 | MCP | MCP transport and origin controls |
| AG-011 | MCP | MCP schema abuse |
| AG-012 | Backend / network | SSRF through tools |
| AG-013 | Backend / execution | Command injection through tools |
| AG-014 | Backend / execution | Code injection / unsafe evaluation |
| AG-015 | Backend / parsing | Unsafe deserialization |
| AG-016 | Backend / filesystem | Path traversal / file disclosure |
| AG-017 | Backend / errors | Error-based information disclosure |
| AG-018 | Identity | Credential and token exposure |
| AG-019 | Identity | OAuth scope and delegation abuse |
| AG-020 | Knowledge / retrieval | RAG poisoning |
| AG-021 | Knowledge / memory | Memory poisoning |
| AG-022 | Knowledge / retrieval | Context-window manipulation |
| AG-023 | Backend / authorization | IDOR via agent tools |
| AG-024 | Backend / state | Cache poisoning |
| AG-025 | Backend / concurrency | TOCTOU / race conditions |
| AG-026 | Multi-agent | A2A identity spoofing |
| AG-027 | Multi-agent | A2A replay and delegation confusion |
| AG-028 | Supply chain | Agent supply-chain compromise |
| AG-029 | Runtime isolation | Sandbox boundary weakness |
| AG-030 | Availability | Denial of service / resource exhaustion |
| AG-031 | Human-agent workflow | Human approval bypass |
| AG-032 | Observability | Audit and trace tampering |
| AG-033 | Model interface | Model/API data leakage |
| AG-034 | Model interface | Model extraction / inference abuse |
| AG-035 | Multimodal input | Multimodal instruction injection |
| AG-036 | Orchestration | Agent loop / cascading failure |

## How to extend the catalog

Every new entry must include:
- Stable ID and domain.
- Root-cause class and concise description.
- Safe validation method.
- Mitigation guidance.
- Evidence requirements.
- Optional mappings to current CWE, OWASP LLM/Agentic/MCP and MITRE ATLAS entries, with taxonomy version and rationale.

Do not add raw weaponized payloads as catalog entries. Keep test fixtures non-destructive and clearly label any lab-only reproduction.
