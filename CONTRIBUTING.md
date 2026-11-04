# Contributing

Contributions should improve reproducibility, evidence quality, protocol coverage, or defensive guidance.

## Technique entries

Every catalog entry must have a stable unique ID, a clear threat description, a benign validation method, and a concrete mitigation. State prerequisites and limitations. Avoid payload collections that enable unauthorized compromise.

## Tests and adapters

- Unit-test parsing, scope enforcement, and deterministic evaluators.
- Network adapters must be opt-in, read-only by default, rate-limited, and gated by a valid scope manifest.
- Use synthetic data and local fixtures. Do not include real credentials or customer data.
- Never silently follow redirects to an undeclared origin.

## Pull requests

Explain the threat model, affected trust boundary, test evidence, expected impact, and safety constraints. Run `pytest` and `ruff check .` before submitting.
