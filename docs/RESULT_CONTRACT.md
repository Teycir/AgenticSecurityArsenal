# Result and evidence contract

The arsenal favors JSON-serializable results so agents can pass outputs between independent skills without bespoke adapters. Existing capability outputs remain backward compatible; this document describes the recommended envelope for new integrations and agent handoffs.

## Recommended envelope

```json
{
  "schema_version": "1.0",
  "status": "completed",
  "skill": "openapi-review",
  "target": "https://example.test",
  "generated_at": "2026-11-04T16:00:00Z",
  "observations": [],
  "hypotheses": [],
  "evidence": [],
  "limitations": [],
  "next_steps": []
}
```

`status` should be one of `completed`, `partial`, `blocked`, or `error`. Omit unknown values rather than guessing. Existing legacy tool responses may not yet use this exact envelope; consumers should inspect the actual tool schema and not assume every field exists.

## Evidence record

```json
{
  "evidence_id": "ev-001",
  "source": "openapi.json",
  "source_type": "user_supplied_file",
  "location": "paths./v1/items.get",
  "observed_at": null,
  "content_summary": "GET endpoint accepts an item identifier",
  "integrity": {"sha256": "<optional-sha256>"},
  "trust": "untrusted_input"
}
```

Evidence should identify its origin and location. Do not include secrets or unnecessary personal data. Raw scanner exports and remote responses are untrusted. Preserve exact source values when practical, but redact credentials and sensitive tokens before persistence or reporting.

## Epistemic labels

- **Observation**: directly present in a supplied artifact or returned by a bounded operation.
- **Hypothesis**: a possible explanation or attack path requiring validation.
- **Validated**: supported by an explicitly described verification step and evidence.
- **Inconclusive**: available evidence cannot decide the question.

A scanner alert, heuristic, imported writeup, correlated path, or model-generated explanation is not proof of exploitability.

## Parallel merge rules

1. Preserve worker and source IDs.
2. Do not deduplicate solely on similar wording; use stable identifiers and explicit target context.
3. Keep contradictory observations; mark them for review instead of silently choosing one.
4. Attach the producing skill/version and any transformation applied.
5. Only a designated merge step writes to a shared investigation session.
