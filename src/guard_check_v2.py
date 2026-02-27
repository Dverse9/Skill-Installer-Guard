#!/usr/bin/env python3
import argparse
import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

ALLOWLIST_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "docs.openclaw.ai",
}

REQUIRED_FIELDS = {"name", "version", "source", "entry"}

EXCLUDED_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".pdf",
    ".ico", ".woff", ".woff2", ".ttf", ".lock", ".map"
}

# Contextual rule model (severity + category + base weight)
RULES: Dict[str, Dict] = {
    "shell_pipe_exec": {
        "category": "exec_chain",
        "severity": "critical",
        "weight": 5,
        "patterns": [r"curl\s+.*\|\s*(bash|sh)", r"wget\s+.*\|\s*(bash|sh)"],
    },
    "runtime_download_exec": {
        "category": "exec_chain",
        "severity": "high",
        "weight": 4,
        "patterns": [r"(curl|wget).*(chmod\s+\+x|python\s+|node\s+|bash\s+)", r"Invoke-WebRequest.*(Start-Process|iex)"],
    },
    "js_child_process": {
        "category": "command_exec",
        "severity": "high",
        "weight": 3,
        "patterns": [r"child_process\.(exec|spawn|execSync|spawnSync)\s*\(", r"\bDeno\.run\s*\("],
    },
    "python_subprocess": {
        "category": "command_exec",
        "severity": "medium",
        "weight": 2,
        "patterns": [r"subprocess\.(run|Popen|call|check_output|check_call)\s*\("],
    },
    "python_os_system": {
        "category": "command_exec",
        "severity": "high",
        "weight": 3,
        "patterns": [r"os\.system\s*\("],
    },
    "python_eval_exec": {
        "category": "dynamic_exec",
        "severity": "high",
        "weight": 3,
        "patterns": [r"\beval\s*\(", r"\bexec\s*\("],
    },
    "js_dynamic_require_import": {
        "category": "dynamic_load",
        "severity": "low",
        "weight": 1,
        "patterns": [r"require\s*\(\s*[^\)\"\']", r"import\s*\(\s*[^\"\']"],
    },
    "js_backtick_shell": {
        "category": "command_exec",
        "severity": "medium",
        "weight": 2,
        "patterns": [r"`[^`]*(curl|wget|bash|sh|python)[^`]*`"],
    },
    "network_exfil": {
        "category": "network",
        "severity": "info",
        "weight": 0,
        "patterns": [r"https?://[^\s\"\']+", r"requests\.(post|get)\s*\(", r"fetch\s*\(", r"axios\.(post|get)\s*\("],
    },
    "token_harvest": {
        "category": "credentials",
        "severity": "medium",
        "weight": 2,
        "patterns": [r"(OPENAI|ANTHROPIC|GITHUB|OPENCLAW|TELEGRAM|DISCORD)_?(API_)?(KEY|TOKEN)", r"os\.environ\[", r"process\.env\."],
    },
    "credential_write": {
        "category": "credentials",
        "severity": "high",
        "weight": 3,
        "patterns": [r"\.write_text\(.*(token|key|secret)", r"fs\.writeFile\(.*(token|key|secret)"],
    },
    "base64_blob": {
        "category": "obfuscation",
        "severity": "low",
        "weight": 1,
        "patterns": [r"[A-Za-z0-9+/]{180,}={0,2}"],
    },
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SAFE_PATH_HINTS = ("docs/", "README", "readme", ".md")


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


def decode_base64_if_possible(token: str):
    try:
        raw = base64.b64decode(token + "===", validate=False)
        if not raw:
            return None
        txt = raw.decode("utf-8", errors="ignore")
        return txt if any(c.isalpha() for c in txt) else None
    except Exception:
        return None


def contextual_multiplier(file_rel: str, rule: str) -> float:
    # down-weight info-level and docs contexts to reduce false blocks
    if rule == "network_exfil":
        return 0.0
    if file_rel.startswith(SAFE_PATH_HINTS) or file_rel.endswith(".md"):
        return 0.3
    return 1.0


def scan_file(path: Path, rel: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for rule, meta in RULES.items():
        for pat in meta["patterns"]:
            for m in re.finditer(pat, text, flags=re.IGNORECASE):
                snippet = text[max(0, m.start() - 40): min(len(text), m.end() + 120)].replace("\n", " ")
                mult = contextual_multiplier(rel, rule)
                findings.append(
                    Finding(
                        file=rel,
                        rule=rule,
                        category=meta["category"],
                        severity=meta["severity"],
                        weight=int(round(meta["weight"] * mult)),
                        pattern=pat,
                        snippet=snippet[:240],
                    )
                )

    # base64 decoded payload heuristic
    for b in re.findall(RULES["base64_blob"]["patterns"][0], text):
        decoded = decode_base64_if_possible(b)
        if decoded and re.search(r"(curl|wget|bash|sh|subprocess|child_process|token|secret|apikey)", decoded, re.IGNORECASE):
            findings.append(
                Finding(
                    file=rel,
                    rule="base64_obfuscated_payload",
                    category="obfuscation",
                    severity="high",
                    weight=3,
                    pattern="decoded_risky_keywords",
                    snippet=decoded[:240].replace("\n", " "),
                )
            )

    return findings


def load_override(path_str: str | None):
    if not path_str:
        return {}
    p = Path(path_str)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def apply_overrides(findings: List[Finding], override: dict) -> Tuple[List[Finding], List[dict]]:
    approved = set(override.get("approved_rules", []))
    approved_files = set(override.get("approved_files", []))
    justification = override.get("justification", "")
    if not approved and not approved_files:
        return findings, []

    kept: List[Finding] = []
    overridden: List[dict] = []
    for f in findings:
        if f.rule in approved or f.file in approved_files:
            overridden.append({
                "file": f.file,
                "rule": f.rule,
                "severity": f.severity,
                "weight": f.weight,
                "justification": justification,
            })
            continue
        kept.append(f)
    return kept, overridden


def decision_from_score(score: int, has_critical: bool) -> str:
    if has_critical:
        return "BLOCK"
    if score >= 7:
        return "BLOCK"
    if score >= 3:
        return "REVIEW"
    return "PASS"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--override", required=False, help="JSON file with approved_rules/approved_files/justification")
    args = ap.parse_args()

    reasons: List[str] = []
    mpath = Path(args.manifest)
    cpath = Path(args.candidate)

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

    src = str(manifest.get("source", ""))
    host = host_from_source(src)
    if host not in ALLOWLIST_HOSTS:
        reasons.append(f"source_not_allowlisted:{host or 'unknown'}")

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

    # dependency/install hook checks
    pkg = cpath / "package.json"
    if pkg.exists():
        try:
            pj = json.loads(pkg.read_text(encoding="utf-8"))
            scripts = pj.get("scripts") or {}
            risky_hooks = [k for k in scripts.keys() if k in {"preinstall", "install", "postinstall", "prepare"}]
            if risky_hooks:
                reasons.append(f"install_hooks_present:{','.join(risky_hooks)}")
                findings.append(
                    Finding(
                        file="package.json",
                        rule="install_hooks",
                        category="supply_chain",
                        severity="high",
                        weight=3,
                        pattern=",".join(risky_hooks),
                        snippet="install scripts present",
                    )
                )
        except Exception:
            reasons.append("package_json_unreadable")

    # apply override (contextual model)
    override_data = load_override(args.override)
    findings, overridden = apply_overrides(findings, override_data)

    # score
    score = sum(max(0, f.weight) for f in findings)
    has_critical = any(SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER["critical"] for f in findings)

    # baseline penalties
    if any(r.startswith("manifest_missing") for r in reasons):
        score += 4
    if any(r.startswith("source_not_allowlisted") for r in reasons):
        score += 4
    if "candidate_dir_missing" in reasons:
        score += 5

    score = min(10, max(0, score))
    decision = decision_from_score(score, has_critical)

    # map decision to status/next-step
    if decision == "PASS":
        status, next_step = "PASS", "quarantine"
    elif decision == "REVIEW":
        status, next_step = "REVIEW", "manual_review"
        reasons.append("contextual_review_required")
    else:
        status, next_step = "BLOCK", "reject"
        if findings:
            reasons.append("advanced_risk_findings_detected")

    # categorized summary
    by_category: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    out = {
        "status": status,
        "risk_score": score,
        "decision": decision,
        "reasons": sorted(list(set(reasons))),
        "host": host,
        "files_scanned": scanned,
        "files_skipped": len(skipped),
        "skipped_sample": skipped[:100],
        "rules_checked": sorted(list(RULES.keys())),
        "findings_summary": {
            "count": len(findings),
            "by_category": by_category,
            "by_severity": by_severity,
        },
        "findings": [
            {
                "file": f.file,
                "rule": f.rule,
                "category": f.category,
                "severity": f.severity,
                "weight": f.weight,
                "pattern": f.pattern,
                "snippet": f.snippet,
            }
            for f in findings[:300]
        ],
        "override": {
            "used": bool(args.override),
            "overridden_findings": overridden[:200],
            "justification": override_data.get("justification") if isinstance(override_data, dict) else None,
        },
        "next_step": next_step,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
