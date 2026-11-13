#!/usr/bin/env python3
"""End-to-end check against dummy-projects.

  dummy-projects/vulnerable/ssrf/*           every VULN-EXPECTED line must be reported, only SSRF rules may fire
  dummy-projects/vulnerable/xss/*            every VULN-EXPECTED line must be reported, only xss-* rules may fire
  dummy-projects/vulnerable/secret-leaked/*  every VULN-EXPECTED line must be reported, only secret-* rules may fire
  dummy-projects/clean/*                     nothing may be reported (SAFE-EXPECTED lines are the tricky look-alikes)

*.tmpl fixtures (provider-shaped fake tokens) are rendered into a temp copy first, see scan.py render_tree.
Source lines containing `VULN-EXPECTED` / `SAFE-EXPECTED` (in a // or # comment) are the ground truth.

  python3 tests/verify_dummy.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scan import render_tree  # noqa: E402

DUMMY = ROOT / "dummy-projects"
EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs"}

# (folder, kind, allowed rule-id test). A finding outside the allowed family means the folder name lies.
def family(rule_id: str) -> str:
    return "secret" if rule_id.startswith("secret-") else "xss" if rule_id.startswith("xss-") else "ssrf"


GROUPS = [
    (DUMMY / "vulnerable" / "ssrf", "vulnerable", lambda rid: family(rid) == "ssrf"),
    (DUMMY / "vulnerable" / "xss", "vulnerable", lambda rid: family(rid) == "xss"),
    (DUMMY / "vulnerable" / "secret-leaked", "vulnerable", lambda rid: family(rid) == "secret"),
    (DUMMY / "clean", "clean", lambda rid: False),
]


def is_scannable(f: Path) -> bool:
    return f.suffix in EXTS or f.name.startswith(".env")


def markers(project: Path):
    vuln, safe = set(), set()
    for f in project.rglob("*"):
        if "node_modules" in f.parts or "dist" in f.parts or not f.is_file() or not is_scannable(f):
            continue
        rel = str(f.relative_to(project))
        for n, line in enumerate(f.read_text().splitlines(), 1):
            if "VULN-EXPECTED" in line:
                vuln.add((rel, n))
            if "SAFE-EXPECTED" in line:
                safe.add((rel, n))
    return vuln, safe


def main():
    failed = False
    tp_total = fn_total = fp_total = safe_total = clean_findings = 0
    by_family = {"ssrf": 0, "xss": 0, "secret": 0}
    print(f"{'project':<42}{'expected':>9}{'found':>7}{'missed':>8}{'false+':>8}")
    for src_dir, kind, rule_ok in GROUPS:
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "reports")
            group_dir = Path(tmp) / "fixtures" / src_dir.name
            render_tree(src_dir, group_dir)
            proc = subprocess.run([sys.executable, str(ROOT / "scan.py"), "scan", str(group_dir), "--batch", "--out", out],
                                  capture_output=True, text=True)
            if proc.returncode != 0:
                print(proc.stdout, proc.stderr)
                return 2
            for project in sorted(p for p in group_dir.iterdir() if p.is_dir()):
                name = f"{src_dir.relative_to(DUMMY)}/{project.name}"
                vuln, safe = markers(project)
                data = json.loads((Path(out) / project.name / "semgrep.json").read_text())
                found, wrong_family = set(), []
                for r in data["results"]:
                    rel = str(Path(r["path"]).resolve().relative_to(project.resolve()))
                    found.add((rel, r["start"]["line"]))
                    by_family[family(r["check_id"])] += 1
                    if kind == "vulnerable" and not rule_ok(r["check_id"]):
                        wrong_family.append((rel, r["start"]["line"], r["check_id"]))
                missed, extra = vuln - found, found - vuln
                tp_total += len(vuln & found)
                fn_total += len(missed)
                fp_total += len(extra)
                safe_total += len(safe)
                if kind == "clean":
                    clean_findings += len(found)
                print(f"{name:<42}{len(vuln):>9}{len(found):>7}{len(missed):>8}{len(extra):>8}")
                if kind == "vulnerable" and not vuln:
                    print("   BAD FIXTURE: vulnerable project has no VULN-EXPECTED marker")
                    failed = True
                for rel, n in sorted(missed):
                    print(f"   MISSED  {rel}:{n}")
                for rel, n in sorted(extra):
                    label = "SAFE case flagged" if (rel, n) in safe else "unexpected"
                    print(f"   FALSE+  {rel}:{n} ({label})")
                for rel, n, rid in wrong_family:
                    print(f"   WRONG FAMILY  {rel}:{n} {rid} (folder name does not match the finding)")
                failed |= bool(missed or extra or wrong_family)
    print(f"\nvulnerable cases caught: {tp_total}/{tp_total + fn_total} | "
          f"safe cases flagged: {fp_total}/{safe_total} | findings in clean/: {clean_findings}")
    print(f"findings by family (all scanned folders): ssrf={by_family['ssrf']} xss={by_family['xss']} secret={by_family['secret']}")
    print("RESULT:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
