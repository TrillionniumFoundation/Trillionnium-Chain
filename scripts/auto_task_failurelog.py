#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / 'run/auto-iterate/daemon.log'
TASKS = ROOT / 'scripts/auto_iterate.tasks'
OUT = ROOT / 'run/auto-iterate/task-failurelog.json'
OUT.parent.mkdir(parents=True, exist_ok=True)

text = LOG.read_text() if LOG.exists() else ''
existing = TASKS.read_text() if TASKS.exists() else ''

# failure signal -> stable low-risk regression script to prioritize
MAP = [
    ('round-fail: rc=1', 'quick_gate_summary_path_guard_test.sh'),
    ('round-fail: rc=127', 'quick_gate_summary_json_escape_test.sh'),
    ('push-fail', 'rpc_query_hardcap_enforcement_test.sh'),
]

items = []
for sig, script in MAP:
    if sig not in text:
        continue
    run = f'./scripts/v2/{script}'
    if run in existing:
        continue
    p = ROOT / 'scripts/v2' / script
    if not p.exists():
        continue
    title = script.replace('.sh', '').replace('_', '-')
    items.append({
        'script': run,
        'step_name': f'Failurelog regression: {title}',
        'commit_msg': f'ci(gate): add failurelog-driven {title} regression to quick-check',
        'risk': 'low',
        'origin': 'failurelog-subagent'
    })

OUT.write_text(json.dumps({'count': len(items), 'candidates': items}, ensure_ascii=False, indent=2))
print(str(OUT))
print(f'count={len(items)}')