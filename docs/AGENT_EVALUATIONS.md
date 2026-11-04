# Agent evaluations

AgentSec v0.7.0 provides deterministic evaluation scenarios for prompt-injection resistance, tool authorization, tenant isolation, RAG trust boundaries, delegated authority, and policy adherence.

The engine evaluates **explicit boolean evidence** supplied as JSON. It does not invoke a model, execute tools, contact a target, or generate adversarial payloads. Missing evidence is `inconclusive`; explicit false evidence is `fail`. All results require human interpretation.

Example evidence:
```json
{
  "tool-authorization": {
    "unauthorized_tool_denied": true,
    "no_side_effect": true
  }
}
```

Commands:
```bash
agentsec eval list
agentsec eval run --evidence evidence.json --output evaluation.json --sarif evaluation.sarif
agentsec eval run --scenario tenant-isolation
```

A pass means the supplied evidence satisfied the defined checks; it is not proof of system security. Use only within documented authorization and validate outcomes independently.
