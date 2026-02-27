# Policy Profile Schema (Public Minimal)

File: `profiles_v3.json`

## Top-level
Object keyed by profile name (`default`, `telegram-bot`, `scraper`, `ci-helper`, ...).

Each profile object requires:
- `allowed_categories`: string[]
- `constrained_categories`: string[]
- `blocked_categories`: string[]
- `required_constraints`: object mapping category -> string[]

## Allowed categories enum (v3)
- `exec_chain`
- `command_exec`
- `dynamic_load`
- `network`
- `credentials`
- `supply_chain`
- `obfuscation`

## Override semantics
Overrides are not in `profiles_v3.json`; they are run-time inputs (`--override`).

Override object fields:
- `approved_rules`: string[] (rule IDs)
- `approved_files`: string[] (file paths)
- `justification`: string (required for public CI use)

## Constraint schema
Manifest `constraints` is an object where keys may include:
- `allowed_hosts`: string[]
- `allowed_env_prefixes`: string[]
- `allowed_commands`: string[]

A constrained category in a profile must list required constraint keys under `required_constraints`.
If those keys are absent in manifest constraints, decision must move toward REVIEW/BLOCK.
