#!/usr/bin/env python3
"""End-to-end check against dummy-projects.

Source lines ending in `// VULN-EXPECTED` must be reported, lines ending in
`// SAFE-EXPECTED` must not, and nothing else may be reported.

  python3 tests/verify_dummy.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECTS = ROOT / "dummy-projects"
EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs"}


def markers(project: Path):
    vuln, safe = set(), set()
    for f in project.rglob("*"):
        if "node_modules" in f.parts or f.suffix not in EXTS:
            continue
        for n, line in enumerate(f.read_text().splitlines(), 1):
            rel = str(f.relative_to(project))
            if "VULN-EXPECTED" in line:
                vuln.add((rel, n))
            if "SAFE-EXPECTED" in line:
                safe.add((rel, n))
    return vuln, safe


def main():
    with tempfile.TemporaryDirectory() as out:
        proc = subprocess.run([sys.executable, str(ROOT / "scan.py"), "scan", str(PROJECTS), "--batch", "--out", out],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout, proc.stderr)
            return 2
        failed = False
        tp_total = fn_total = fp_total = safe_total = 0
        print(f"{'project':<22}{'expected':>9}{'found':>7}{'missed':>8}{'false+':>8}")
        for project in sorted(p for p in PROJECTS.iterdir() if p.is_dir()):
            vuln, safe = markers(project)
            data = json.loads((Path(out) / project.name / "semgrep.json").read_text())
            found = set()
            for r in data["results"]:
                rel = str(Path(r["path"]).resolve().relative_to(project.resolve()))
                found.add((rel, r["start"]["line"]))
            missed, extra = vuln - found, found - vuln
            tp_total += len(vuln & found)
            fn_total += len(missed)
            fp_total += len(extra)
            safe_total += len(safe)
            print(f"{project.name:<22}{len(vuln):>9}{len(found):>7}{len(missed):>8}{len(extra):>8}")
            for rel, n in sorted(missed):
                print(f"   MISSED  {rel}:{n}")
            for rel, n in sorted(extra):
                kind = "SAFE case flagged" if (rel, n) in safe else "unexpected"
                print(f"   FALSE+  {rel}:{n} ({kind})")
            failed |= bool(missed or extra)
        print(f"\nvulnerable cases caught: {tp_total}/{tp_total + fn_total} | "
              f"safe cases flagged: {fp_total}/{safe_total}")
        print("RESULT:", "FAIL" if failed else "PASS")
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
