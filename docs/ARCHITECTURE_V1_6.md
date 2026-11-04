# v1.6 architecture

## Design goal

Make the arsenal easy for existing AI agents to use as a library of specialist security skills. Do not build another agent runtime. The host agent owns planning, delegation, parallelism, and final reasoning. The arsenal supplies documented security procedures, bounded capabilities, authorization checks, and structured evidence.

## Layers

1. **Skills** — portable `SKILL.md` folders that explain when and how to use a capability.
2. **Capability API** — Python functions and stable MCP tools for operations already implemented in the library.
3. **CLI** — a human-friendly local interface and a simple skill discovery/validation surface.
4. **Knowledge and evidence** — technique catalog, schemas, local synthetic labs, imported reports, and investigation state.

These are interfaces to the same underlying capabilities where practical. Skills do not duplicate the implementation in Python, and the MCP server does not schedule or reason across skills.

## Source of truth

- `skills/<name>/SKILL.md`: agent-facing procedure and progressive-disclosure entry point.
- `skills/<name>/asa-skill.json`: execution mode, permission profile, inputs, outputs, interfaces, and parallel-safety declaration.
- `src/agentsec/`: executable implementation.
- `catalog/techniques.json`: technique knowledge.
- `schemas/`: machine-readable input schemas.
- `docs/`: human-readable architecture, operating model, safety, and examples.

The metadata is validated by `agentsec skills validate`; runtime scope checks remain authoritative.

## Parallelism model

Parallelism is a property of a task and its inputs, not a global scheduler. Independent offline reads can be delegated concurrently. Active operations need explicit scope and may have target-side effects even when they are read-only. Shared investigation state is single-writer. The agent must serialize writes and avoid duplicate concurrent requests against one target unless the operator confirms this is safe.

## Compatibility

The v1.6 release retains v1.5 Python, CLI, MCP, investigation, and scanner-import capabilities. New skill discovery tools are additive. Existing capability result shapes are not silently rewritten.

## Inspired-by note

The documentation approach takes inspiration from the public `Teycir/ArxivExplorer` repository: clear repository map, explicit source-of-truth files, practical quick-start paths, human-readable explanations, and discoverability-oriented documentation. This project adapts those documentation practices; it does not reuse ArxivExplorer code.
