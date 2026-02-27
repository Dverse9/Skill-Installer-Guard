#!/usr/bin/env python3
import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

ALLOWLIST_HOSTS = {"github.com", "raw.githubusercontent.com", "docs.openclaw.ai"}
EXCLUDED_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".pdf", ".ico", ".woff", ".woff2", ".ttf", ".lock", ".map"}
REQUIRED_FIELDS = {"name", "version", "source", "entry", "skill_type"}

RULES = {
    "shell_pipe_exec": {"category": "exec_chain", "severity": "critical", "weight": 5, "patterns": [r"curl\s+.*\|\s*(bash|sh)", r"wget\s+.*\|\s*(bash|sh)"]},
    "runtime_download_exec": {"category": "exec_chain", "severity": "high", "weight": 4, "patterns": [r"(curl|wget).*(chmod\s+\+x|python\s+|node\s+|bash\s+)"]},
    "js_child_process": {"category": "command_exec", "severity": "high", "weight": 3, "patterns": [r"child_process\.(exec|spawn|execSync|spawnSync)\s*\("]},
    "python_subprocess": {"category": "command_exec", "severity": "medium", "weight": 2, "patterns": [r"subprocess\.(run|Popen|call|check_output|check_call)\s*\("]},
    "js_dynamic_require_import": {"category": "dynamic_load", "severity": "low", "weight": 1, "patterns": [r"require\s*\(\s*[^\)\"\']", r"import\s*\(\s*[^\"\']"]},
    "network_refs": {"category": "network", "severity": "info", "weight": 0, "patterns": [r"https?://[^\s\"\']+", r"requests\.(post|get)\s*\(", r"fetch\s*\("]},
    "token_refs": {"category": "credentials", "severity": "medium", "weight": 2, "patterns": [r"(OPENAI|ANTHROPIC|GITHUB|OPENCLAW|TELEGRAM|DISCORD)_?(API_)?(KEY|TOKEN)", r"process\.env\.", r"os\.environ\["]},
    "install_hooks": {"category": "supply_chain", "severity": "high", "weight": 3, "patterns": []}
}


@dataclass
class Finding:
    file: str
    rule: str
    category: str
    severity: str
    weight: int
    pattern: str
    snippet: str


def host_from_source(src: str) -> str:
    m = re.match(r"https?://([^/]+)", src.strip())
    return m.group(1).lower() if m else ""


def should_scan_file(p: Path) -> bool:
    return p.is_file() and p.suffix.lower() not in EXCLUDED_EXT


def scan_file(path: Path, rel: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for rule, meta in RULES.items():
        for pat in meta["patterns"]:
            for m in re.finditer(pat, txt, re.IGNORECASE):
                snippet = txt[max(0, m.start() - 40): min(len(txt), m.end() + 120)].replace("\n", " ")
                findings.append(Finding(rel, rule, meta["category"], meta["severity"], meta["weight"], pat, snippet[:220]))
    return findings


def evaluate_intent(profile: dict, findings: List[Finding], constraints: dict):
    reasons = []
    score = 0

    blocked_cats = set(profile.get("blocked_categories", []))
    constrained_cats = set(profile.get("constrained_categories", []))
    allowed_cats = set(profile.get("allowed_categories", []))
    req = profile.get("required_constraints", {})

    by_cat: Dict[str, int] = {}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1

        if f.category in blocked_cats:
            reasons.append(f"blocked_category:{f.category}")
            score += 5
        elif f.category in constrained_cats:
            missing = [r for r in req.get(f.category, []) if r not in constraints or not constraints.get(r)]
            if missing:
                reasons.append(f"missing_constraints:{f.category}:{','.join(missing)}")
                score += max(2, f.weight)
            else:
                score += max(0, f.weight - 1)
        elif f.category in allowed_cats:
            score += max(0, f.weight - 2)
        else:
            reasons.append(f"unexpected_category:{f.category}")
            score += max(1, f.weight)

    # normalize and decision
    score = min(10, max(0, score))
    if any(r.startswith("blocked_category") for r in reasons) or score >= 8:
        status = "BLOCK"
    elif score >= 3:
        status = "REVIEW"
    else:
        status = "PASS"

    return status, score, sorted(set(reasons)), by_cat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--profiles", default=str(Path(__file__).with_name("profiles_v3.json")))
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    reasons = []
    mpath = Path(args.manifest)
    cpath = Path(args.candidate)
    profiles = json.loads(Path(args.profiles).read_text(encoding="utf-8"))

    manifest = {}
    if not mpath.exists():
        reasons.append("manifest_missing")
    else:
        try:
            manifest = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception:
            reasons.append("manifest_invalid_json")

    missing = sorted(list(REQUIRED_FIELDS - set(manifest.keys())))
    if missing:
        reasons.append(f"manifest_missing_fields:{','.join(missing)}")

    host = host_from_source(str(manifest.get("source", "")))
    if host not in ALLOWLIST_HOSTS:
        reasons.append(f"source_not_allowlisted:{host or 'unknown'}")

    skill_type = manifest.get("skill_type", "default")
    profile = profiles.get(skill_type, profiles["default"])
    constraints = manifest.get("constraints", {}) if isinstance(manifest.get("constraints"), dict) else {}

    findings: List[Finding] = []
    scanned = 0
    skipped: List[str] = []

    if not cpath.exists() or not cpath.is_dir():
        reasons.append("candidate_dir_missing")
    else:
        for p in cpath.rglob("*"):
            if not p.is_file():
                continue
            rel = str(p.relative_to(cpath))
            if not should_scan_file(p):
                skipped.append(rel)
                continue
            scanned += 1
            findings.extend(scan_file(p, rel))

        pkg = cpath / "package.json"
        if pkg.exists():
            try:
                pj = json.loads(pkg.read_text(encoding="utf-8"))
                scripts = pj.get("scripts") or {}
                hooks = [k for k in scripts if k in {"preinstall", "install", "postinstall", "prepare"}]
                if hooks:
                    findings.append(Finding("package.json", "install_hooks", "supply_chain", "high", 3, ",".join(hooks), "install scripts present"))
            except Exception:
                reasons.append("package_json_unreadable")

    status, risk_score, intent_reasons, by_category = evaluate_intent(profile, findings, constraints)
    reasons.extend(intent_reasons)

    if reasons and status == "PASS":
        status = "REVIEW"

    next_step = {"PASS": "quarantine", "REVIEW": "manual_review", "BLOCK": "reject"}[status]

    out = {
        "status": status,
        "risk_score": risk_score,
        "decision": status,
        "reasons": sorted(set(reasons)),
        "host": host,
        "skill_type": skill_type,
        "profile_used": skill_type if skill_type in profiles else "default",
        "files_scanned": scanned,
        "files_skipped": len(skipped),
        "skipped_sample": skipped[:100],
        "rules_checked": sorted(list(RULES.keys())),
        "findings_summary": {
            "count": len(findings),
            "by_category": by_category,
        },
        "findings": [f.__dict__ for f in findings[:300]],
        "constraints": constraints,
        "next_step": next_step,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
