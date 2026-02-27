#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

ALLOWLIST_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "docs.openclaw.ai",
}

REQUIRED_FIELDS = {"name", "version", "source", "entry"}

DANGEROUS_PATTERNS = [
    r"curl\s+.*\|\s*bash",
    r"wget\s+.*\|\s*bash",
    r"os\.system\(",
    r"subprocess\..*shell\s*=\s*True",
    r"eval\(",
    r"rm\s+-rf\s+/",
]


def host_from_source(src: str) -> str:
    m = re.match(r"https?://([^/]+)", src.strip())
    return m.group(1).lower() if m else ""


def scan_files(root: Path):
    hits = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".pdf"}:
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat in DANGEROUS_PATTERNS:
            if re.search(pat, txt, flags=re.IGNORECASE):
                hits.append({"file": str(p), "pattern": pat})
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    reasons = []
    risk = 0

    mpath = Path(args.manifest)
    cpath = Path(args.candidate)

    if not mpath.exists():
        reasons.append("manifest_missing")
        risk += 5
        manifest = {}
    else:
        try:
            manifest = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}
            reasons.append("manifest_invalid_json")
            risk += 5

    missing = sorted(list(REQUIRED_FIELDS - set(manifest.keys())))
    if missing:
        reasons.append(f"manifest_missing_fields:{','.join(missing)}")
        risk += 4

    src = str(manifest.get("source", ""))
    host = host_from_source(src)
    if host not in ALLOWLIST_HOSTS:
        reasons.append(f"source_not_allowlisted:{host or 'unknown'}")
        risk += 4

    if not cpath.exists() or not cpath.is_dir():
        reasons.append("candidate_dir_missing")
        risk += 5
        hits = []
    else:
        hits = scan_files(cpath)

    if hits:
        reasons.append("dangerous_patterns_detected")
        risk += min(6, len(hits))

    status = "PASS" if not reasons else "BLOCK"
    next_step = "quarantine" if status == "PASS" else "reject"

    out = {
        "status": status,
        "risk_score": min(10, risk),
        "reasons": reasons,
        "host": host,
        "danger_hits": hits,
        "next_step": next_step,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
