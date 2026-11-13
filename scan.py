#!/usr/bin/env python3
"""Frontend security scan entrypoint (v1: SSRF rules for React web stacks).

One entrypoint, two callers: run it locally now, call the very same command from a
GitLab CI job later.

  python3 scan.py scan PATH [--batch] [--mode report|enforce] [--fail-on ERROR|WARNING|INFO]
                            [--baseline FILE] [--out DIR]
  python3 scan.py baseline PATH [--batch] --baseline FILE
  python3 scan.py self-test

PATH is one repo, or with --batch a folder whose sub-folders are repos.
Exit code: 0 ok | 1 findings at/above --fail-on (enforce mode only) | 2 scanner error.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RULES_DIR = ROOT / "config" / "semgrep"
SEVERITY_RANK = {"INFO": 1, "WARNING": 2, "ERROR": 3}
EXCLUDES = ["node_modules", "dist", "build", ".next", ".remix", ".turbo", "coverage", "*.min.js", "*.map"]
SKIP_REPO_DIRS = {"node_modules", ".git", "security-reports"}


def die(msg, code=2):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def semgrep_bin():
    exe = shutil.which("semgrep")
    if not exe:
        die("semgrep not found. Install it with: pip install semgrep")
    return exe


# ----------------------------------------------------------------------------- scanning
def list_repos(path: Path, batch: bool):
    if not path.is_dir():
        die(f"{path} is not a directory")
    if not batch:
        return [path]
    repos = sorted(p for p in path.iterdir() if p.is_dir() and p.name not in SKIP_REPO_DIRS and not p.name.startswith("."))
    if not repos:
        die(f"no sub-folders found in {path}")
    return repos


def run_semgrep(repo: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "semgrep.json"
    cmd = [
        semgrep_bin(), "scan",
        "--config", str(RULES_DIR),
        "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--quiet",
        "--json-output", str(json_path),
        "--sarif-output", str(out_dir / "semgrep.sarif"),
    ]
    for pattern in EXCLUDES:
        cmd += ["--exclude", pattern]
    cmd.append(str(repo))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1) or not json_path.exists():
        die(f"semgrep failed on {repo.name} (exit {proc.returncode}):\n{proc.stderr.strip()[-1500:]}")
    return json_path


def fingerprint(check_id: str, repo_name: str, rel_path: str, code: str) -> str:
    """Stable across line-number shifts: rule + file + normalized matched code."""
    norm = re.sub(r"\s+", " ", code).strip()
    return hashlib.sha1(f"{check_id}|{repo_name}/{rel_path}|{norm}".encode()).hexdigest()[:16]


def load_findings(repo: Path, json_path: Path):
    data = json.loads(json_path.read_text())
    findings = []
    for r in data.get("results", []):
        abs_path = Path(r["path"])
        if not abs_path.is_absolute():
            abs_path = Path.cwd() / abs_path
        rel = os.path.relpath(abs_path, repo)
        start, end = r["start"]["line"], r["end"]["line"]
        try:
            lines = abs_path.read_text(errors="replace").splitlines()[start - 1:end]
        except OSError:
            lines = []
        extra = r.get("extra", {})
        findings.append({
            "repo": repo.name,
            "rule": r["check_id"],
            "severity": extra.get("severity", "WARNING"),
            "path": rel,
            "line": start,
            "message": " ".join(extra.get("message", "").split()),
            "cwe": ", ".join(extra.get("metadata", {}).get("cwe", []) or []),
            "fingerprint": fingerprint(r["check_id"], repo.name, rel, "\n".join(lines)),
        })
    errors = [e.get("message", str(e)) for e in data.get("errors", []) if e.get("level") == "error"]
    return findings, errors


# ----------------------------------------------------------------------------- baseline
def load_baseline(path):
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        die(f"baseline file {p} not found (create it with the 'baseline' command)")
    return set(json.loads(p.read_text()).get("fingerprints", {}))


def write_baseline(path, findings):
    entries = {f["fingerprint"]: {"rule": f["rule"], "file": f"{f['repo']}/{f['path']}", "line": f["line"]} for f in findings}
    Path(path).write_text(json.dumps({"version": 1, "fingerprints": entries}, indent=2, sort_keys=True) + "\n")
    print(f"baseline written: {path} ({len(entries)} findings)")


# ----------------------------------------------------------------------------- reporting
def short(msg: str) -> str:
    first = re.split(r"(?<=[.!?])\s", msg, maxsplit=1)[0]
    return first if len(first) < 160 else first[:157] + "..."


def write_summary(out_root: Path, per_repo, mode, fail_on, failing):
    lines = [f"# Security scan summary", "", f"mode: **{mode}** | fail-on: **{fail_on}** | repos: **{len(per_repo)}**", ""]
    lines += ["| repo | new | baselined | ERROR | WARNING |", "|---|---:|---:|---:|---:|"]
    for repo, d in per_repo.items():
        sev = lambda s: sum(1 for f in d["new"] if f["severity"] == s)
        lines.append(f"| {repo} | {len(d['new'])} | {len(d['known'])} | {sev('ERROR')} | {sev('WARNING')} |")
    lines.append("")
    any_new = False
    for repo, d in per_repo.items():
        if not d["new"]:
            continue
        any_new = True
        lines += [f"## {repo}", ""]
        for f in sorted(d["new"], key=lambda x: (-SEVERITY_RANK.get(x["severity"], 0), x["path"], x["line"])):
            lines.append(f"- **{f['severity']}** `{f['path']}:{f['line']}` `{f['rule']}` {f['cwe'].split(':')[0]}: {short(f['message'])}")
        lines.append("")
    if not any_new:
        lines.append("No new findings.")
    lines += ["", f"Result: {'FAIL' if failing else 'PASS'} ({len(failing)} new finding(s) at or above {fail_on}"
                  f"{'' if mode == 'enforce' else ', not enforced in report mode'})"]
    (out_root / "summary.md").write_text("\n".join(lines) + "\n")
    (out_root / "summary.json").write_text(json.dumps(
        {repo: {"new": d["new"], "baselined": len(d["known"])} for repo, d in per_repo.items()}, indent=2) + "\n")


def print_console(per_repo, failing, mode, fail_on, out_root):
    width = max(len(r) for r in per_repo) + 2
    print(f"\n{'repo'.ljust(width)}{'new':>5}{'known':>7}{'ERROR':>7}{'WARN':>6}")
    for repo, d in per_repo.items():
        err = sum(1 for f in d["new"] if f["severity"] == "ERROR")
        warn = sum(1 for f in d["new"] if f["severity"] == "WARNING")
        print(f"{repo.ljust(width)}{len(d['new']):>5}{len(d['known']):>7}{err:>7}{warn:>6}")
    print(f"\nreports: {out_root}/summary.md (+ per-repo semgrep.json / semgrep.sarif)")
    verdict = "FAIL" if (failing and mode == "enforce") else "PASS"
    note = "" if mode == "enforce" else " [report mode: never fails the build]"
    print(f"result: {verdict} - {len(failing)} new finding(s) >= {fail_on}{note}")


# ----------------------------------------------------------------------------- commands
def cmd_scan(args):
    repos = list_repos(Path(args.path).resolve(), args.batch)
    out_root = Path(args.out).resolve()
    known_fps = load_baseline(args.baseline)
    per_repo, all_findings, scan_errors = {}, [], []
    for repo in repos:
        print(f"scanning {repo.name} ...", flush=True)
        json_path = run_semgrep(repo, out_root / repo.name)
        findings, errors = load_findings(repo, json_path)
        scan_errors += [f"{repo.name}: {e}" for e in errors]
        all_findings += findings
        per_repo[repo.name] = {
            "new": [f for f in findings if f["fingerprint"] not in known_fps],
            "known": [f for f in findings if f["fingerprint"] in known_fps],
        }
    threshold = SEVERITY_RANK[args.fail_on]
    failing = [f for d in per_repo.values() for f in d["new"] if SEVERITY_RANK.get(f["severity"], 0) >= threshold]
    write_summary(out_root, per_repo, args.mode, args.fail_on, failing)
    print_console(per_repo, failing, args.mode, args.fail_on, out_root)
    for e in scan_errors:
        print(f"scan warning: {e}", file=sys.stderr)
    return 1 if (failing and args.mode == "enforce") else 0


def cmd_baseline(args):
    repos = list_repos(Path(args.path).resolve(), args.batch)
    tmp = Path(args.out).resolve()
    findings = []
    for repo in repos:
        f, _ = load_findings(repo, run_semgrep(repo, tmp / repo.name))
        findings += f
    write_baseline(args.baseline, findings)
    return 0


def cmd_self_test(_args):
    proc = subprocess.run([semgrep_bin(), "--test", "--metrics=off", "--disable-version-check", str(RULES_DIR)],
                          capture_output=True, text=True)
    tail = "\n".join(proc.stdout.strip().splitlines()[-8:])
    print(tail or proc.stderr.strip()[-800:])
    return 0 if proc.returncode == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("path")
        p.add_argument("--batch", action="store_true", help="PATH holds many repos (one per sub-folder)")
        p.add_argument("--out", default="security-reports", help="output folder (default: security-reports)")

    s = sub.add_parser("scan", help="scan a repo, or many with --batch")
    common(s)
    s.add_argument("--mode", choices=["report", "enforce"], default="report")
    s.add_argument("--fail-on", choices=list(SEVERITY_RANK), default="ERROR")
    s.add_argument("--baseline", help="JSON file of accepted legacy findings; only NEW findings count")
    s.set_defaults(fn=cmd_scan)

    b = sub.add_parser("baseline", help="record current findings as accepted legacy debt")
    common(b)
    b.add_argument("--baseline", required=True, help="baseline file to write")
    b.set_defaults(fn=cmd_baseline)

    t = sub.add_parser("self-test", help="run the rule unit tests")
    t.set_defaults(fn=cmd_self_test)

    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
