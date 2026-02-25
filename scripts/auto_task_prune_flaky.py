#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / 'scripts/auto_iterate.tasks'
FLAKY = ROOT / 'scripts/auto_iterate.flaky'

if not TASKS.exists() or not FLAKY.exists():
    raise SystemExit(0)

flaky = set()
for line in FLAKY.read_text().splitlines():
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    flaky.add(line)

text = TASKS.read_text().splitlines()
out = []
removed = 0
for ln in text:
    keep = True
    for f in flaky:
        if f in ln:
            keep = False
            break
    if keep:
        out.append(ln)
    else:
        removed += 1

if removed > 0:
    TASKS.write_text('\n'.join(out).rstrip() + '\n')
print(f'removed={removed}')