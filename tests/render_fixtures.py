#!/usr/bin/env python3
"""Render *.tmpl fixtures (provider-shaped fake tokens) into a folder you can scan by hand.

  python3 tests/render_fixtures.py dummy-projects/vulnerable/secret-leaked /tmp/rendered
  python3 scan.py scan /tmp/rendered --batch
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scan import render_tree  # noqa: E402

if len(sys.argv) != 3:
    sys.exit(__doc__)
render_tree(Path(sys.argv[1]), Path(sys.argv[2]))
print(f"rendered {sys.argv[1]} -> {sys.argv[2]}")
