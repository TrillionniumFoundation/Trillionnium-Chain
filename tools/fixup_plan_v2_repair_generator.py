#!/usr/bin/env python3
"""One-shot source fix for the deterministic Plan v2 repair generator."""
from __future__ import annotations

import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
path = root / "tools/repair_plan_v2_remaining_blockers.py"
source = path.read_text(encoding="utf-8")
old = '''            body = inline.group("body").strip()
            if body and not body.endswith(","):
                body += ","
            line = f'{inline.group("prefix")} version = "{version}", {body}{inline.group("suffix")}'
'''
new = '''            body = inline.group("body").strip()
            if body.endswith(","):
                body = body[:-1].rstrip()
            require(bool(body), f"{manifest.relative_to(ROOT)}: empty inline path dependency")
            line = f'{inline.group("prefix")} version = "{version}", {body}{inline.group("suffix")}'
'''
count = source.count(old)
if count != 1:
    raise SystemExit(f"repair generator source drift: expected one inline-table edge, found {count}")
path.write_text(source.replace(old, new, 1), encoding="utf-8")
