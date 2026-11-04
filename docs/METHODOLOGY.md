# Assessment Methodology

## Phase 1 — Establish scope
- Obtain written authorization.
- Record target origins, tenants, identities, allowed test classes, rate limits and stop conditions.
- Confirm that every connected MCP server and downstream service is included.
- Use synthetic data and dedicated accounts.

## Phase 2 — Model the system
Document:
- User interfaces and API entry points.
- Model provider and model configuration.
- Orchestrator, planner, memory and state store.
- Tool registry, schemas and execution runtime.
- MCP clients, servers, transports, resources and prompts.
- RAG ingestion, vector store and retrieval pipeline.
- Identity provider, OAuth scopes, service accounts and delegated credentials.
- A2A peers, trust roots and message signing.
- Network egress, filesystem mounts, secrets and audit systems.

For each component, record the principal, data classification, authority, trust boundary and side effects.

## Phase 3 — Enumerate capabilities
Inventory tools and resources without invoking side-effecting operations. Record:
- Name, description, schema and implementation owner.
- Read/write/delete/network/process capabilities.
- Required identity and scopes.
- Data sources and destinations.
- Rate limits, approval gates and audit events.

## Phase 4 — Test by risk domain
Start with passive review and configuration checks. Progress to benign canaries and synthetic test fixtures. Select technique IDs from `catalog/techniques.json`.

Do not attempt production RCE, credential extraction, destructive writes, persistence, real data exfiltration or cloud metadata access. Reproduce those classes only in isolated, intentionally vulnerable labs.

## Phase 5 — Validate findings
A finding requires:
- A reproducible observation.
- Evidence tied to an authorized target and test identity.
- A clear expected-vs-actual security boundary.
- Root cause, not just a suspicious model response.
- Impact analysis with assumptions stated.
- Confidence level and limitations.

A prompt that appears to be followed is not automatically a vulnerability. Demonstrate that the behavior crossed a meaningful trust boundary or caused an unauthorized capability to execute.

## Phase 6 — Report and retest
Prioritize by real-world impact, exposure, prerequisites, privileges, user interaction and blast radius. Map to CWE and relevant OWASP/ATLAS taxonomies only where the mapping is defensible. Retest the exact control after remediation.
