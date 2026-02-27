# Contributing

Thanks for contributing to Skill Installer Guard.

## Development flow
1. Create a feature branch from `main`.
2. Make focused changes.
3. Add/update tests and example reports where relevant.
4. Open a PR (no direct pushes to `main`).

## Local checks
```bash
python3 src/guard_check_v3.py --manifest examples/manifest.example.json --candidate . --out /tmp/report.json
```

## PR expectations
- Clear scope and rationale
- Security impact note when scanner logic changes
- Backward compatibility note for rule IDs

## Rule ID stability
Rule identifiers are stable across MINOR and PATCH releases.
Renames/removals require MAJOR version increment.

## Security-sensitive changes
For scanner policy/risk model changes, include:
- before/after behavior summary
- false-positive/false-negative tradeoff note
- migration implications
