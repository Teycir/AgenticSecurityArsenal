# AgentSec v1.0 workflow

## 1. Import a reference

`agentsec knowledge import SOURCE --output knowledge.json`

SOURCE may be a local text/Markdown file or a GitHub repository/README URL. Imports are capped at 2 MB. Records preserve a SHA-256 fingerprint and are marked `UNTRUSTED_REFERENCE_ONLY`. Heuristic mappings are review candidates, not findings.

## 2. Generate and review scenarios

`agentsec scenario generate --source knowledge.json --output scenarios.json`

`agentsec scenario validate scenarios.json`

Generated scenarios have `status: draft` and `human_approval: false`. A qualified reviewer must edit each selected scenario to `status: approved` and `human_approval: true`, confirm its safe test design, evidence requirements, and target applicability, and retain review records.

## 3. Bind an assessment to scope

`agentsec assessment create --source scenarios.json --scope scope.json --target https://host.example --output assessment.json`

The scope must be valid and unexpired and explicitly list the target's exact HTTP(S) origin. No wildcard origins are accepted. Only approved scenarios are included.

## 4. Evaluate evidence and compare

`agentsec assessment run --assessment assessment.json --evidence evidence.json --output results.json`

This release evaluates supplied JSON evidence deterministically. It does not connect to the target, start agents, invoke tools, or execute generated tests. Missing check evidence is INCONCLUSIVE; explicit false evidence is FAIL.

`agentsec assessment compare --baseline before.json --current after.json --output regression.json`

## Trust and safety

All imported CTF/writeup text is inert data. Never execute instructions extracted from a source. The scope file is an operator attestation, not independent verification of authorization. Active testing requires a separately designed, supervised adapter and safety controls; those are outside v1.0.0.
