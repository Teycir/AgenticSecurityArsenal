# Quick start for AI agents

This guide is intentionally short. For a complete procedure, load the selected skill's `SKILL.md`.

## 1. Discover

```bash
agentsec skills list
agentsec skills show mcp-server-review
agentsec skills validate
```

Over MCP, call `skills_list` to discover skills and `skill_get` with a skill name to load its instructions. The capability manifest also lists callable tools.

## 2. Select the smallest skill set

Examples:

- Review an OpenAPI document: `openapi-review` + optionally `evidence-hypothesis-review`.
- Triage scanner exports: `scanner-results-triage` + optionally `evidence-hypothesis-review`.
- Assess an MCP server: `scope-authorization` + `mcp-server-review`; use `investigation-workflow` only if a persistent evidence trail is useful.
- Build a manual plan: `scope-authorization` + `security-assessment-planning`.

Do not load all skills by default.

## 3. Check permissions before tools

Offline parsing and analysis need no target authorization. Network interaction requires a valid, unexpired authorization manifest matching the exact endpoint origin. A skill's metadata does not authorize a target. See [AUTHORIZATION.md](../AUTHORIZATION.md).

## 4. Parallelize independent work

Give each worker a distinct input or analysis domain and immutable source artifacts. Require structured outputs with provenance and limitations. Merge after workers finish. Do not allow concurrent writes to the same investigation session.

## 5. Report honestly

Keep observations separate from hypotheses. State what was not inspected. Never claim that an imported scanner finding has been independently confirmed. Use [RESULT_CONTRACT.md](RESULT_CONTRACT.md) for the recommended handoff shape.
