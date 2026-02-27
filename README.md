# Skill Installer Guard

Intent-aware pre-merge security guard for OpenClaw skills.

## Why
Skill repos can contain expected automation behavior (network, credentials, command execution) and risky behavior (download+exec chains, unsafe hooks, credential harvesting). Skill Installer Guard evaluates candidates before merge with policy profiles and explicit decision outputs.

## Stages
- **Stage 1**: allowlist + basic signature checks (`src/guard_check_v1.py`)
- **Stage 2**: contextual weighted static scanner + override support (`src/guard_check_v2.py`)
- **Stage 3**: profile/intent-aware risk model (`src/guard_check_v3.py`)

## Quick start
```bash
python3 src/guard_check_v3.py \
  --manifest examples/manifest.example.json \
  --candidate /path/to/candidate-skill \
  --out /tmp/report_v3.json
```

## Assets
- 4K avatar: `assets/avatar-4k.png`
- 512 avatar: `assets/avatar-512.png`

## Public docs
- Pre-merge contract (PDF): `docs/PREMERGE_CONTRACT_public_v2_1.pdf`
- Pre-merge action design (PDF): `docs/PREMERGE_ACTION_DESIGN.pdf`
- Profile schema: `docs/PROFILE_SCHEMA.md`
- Rule manifest: `docs/rules_manifest.json`

## CI
GitHub Action workflow:
- `.github/workflows/skill-guard.yml`

This runs Skill Guard on pull requests and blocks merge on `BLOCK` (and `REVIEW` in strict mode).

## Governance & Security docs
- Contributing guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Safe candidate fixture: `examples/candidates/safe-docs-skill/`

## License
MIT
