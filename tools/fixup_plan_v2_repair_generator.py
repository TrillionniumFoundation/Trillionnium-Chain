#!/usr/bin/env python3
"""One-shot source fixes applied after the immutable Plan v2 overlays."""
from __future__ import annotations

import pathlib

root = pathlib.Path(__file__).resolve().parents[1]

repair_path = root / "tools/repair_plan_v2_remaining_blockers.py"
source = repair_path.read_text(encoding="utf-8")
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
repair_path.write_text(source.replace(old, new, 1), encoding="utf-8")

control_path = root / "trillionnium/crates/trnm-control-plane-v0/src/lib.rs"
control = control_path.read_text(encoding="utf-8")
old_identifier = "fn forbidden_authority_is_explicitly rejected()"
new_identifier = "fn forbidden_authority_is_explicitly_rejected()"
count = control.count(old_identifier)
if count != 1:
    raise SystemExit(f"control-plane overlay drift: expected one malformed test identifier, found {count}")
control_path.write_text(control.replace(old_identifier, new_identifier, 1), encoding="utf-8")
