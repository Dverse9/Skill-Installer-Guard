# Security Policy

## Reporting a vulnerability
Please open a private security advisory in GitHub (preferred) or contact the maintainer directly.
Do not post exploit details publicly before triage.

## Scope
This project provides static and intent-aware pre-merge scanning.
It does not guarantee complete detection of malicious behavior.

## Supported versions
- Main branch: supported
- Tagged releases: latest minor supported

## Security model highlights
- Immutable scan input snapshots
- Separate scan output domain
- Policy/profile versioning
- Audit artifacts and hash manifests

## Limitations
- Static analysis can produce false positives/false negatives
- Runtime-only behavior is out of scope without sandbox execution
