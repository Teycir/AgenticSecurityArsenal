# Authorization and Rules of Engagement

This toolkit is for authorized security assessment only.

Before testing, obtain written authorization that identifies:
- The legal owner and approving contact.
- Exact hostnames, IP ranges, applications, MCP endpoints and agent instances in scope.
- Allowed test windows and rate limits.
- Permitted accounts, roles and test data.
- Allowed techniques and explicitly prohibited actions.
- Data handling, retention, notification and stop conditions.
- Emergency contact and incident procedure.

## Default-deny rules

The framework must refuse active interaction when:
- No scope manifest is provided.
- Authorization is missing, expired or ambiguous.
- The requested target does not exactly match an allowed target.
- A test would cross into a third-party service or unapproved identity.
- A test requires destructive actions, real credential extraction, persistence, or exfiltration.

Use synthetic credentials, canary records, isolated networks and dedicated test tenants. Never use real customer data to prove a disclosure vulnerability.
