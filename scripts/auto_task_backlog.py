#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKLOG = ROOT / 'docs/archive/root-history/BACKLOG.md'
TASKS = ROOT / 'scripts/auto_iterate.tasks'
OUT = ROOT / 'run/auto-iterate/task-backlog.json'
OUT.parent.mkdir(parents=True, exist_ok=True)

text = BACKLOG.read_text() if BACKLOG.exists() else ''
existing = TASKS.read_text() if TASKS.exists() else ''

# backlog keyword -> v2 script mapping (low-risk, fast checks only)
MAPPING = [
    ('migration', 'pouw_commit_timeout_migration_test.sh'),
    ('migration', 'pouw_challenge_timeout_migration_test.sh'),
    ('challenge', 'pr4_challenge_fundflow_audit_gate.sh'),
    ('challenge', 'pr5_challenge_reconcile_gate.sh'),
    ('worker', 'worker_replay_guard_test.sh'),
    ('worker', 'worker_resume_no_duplicate_test.sh'),
    ('observ', 'rpc_node_events_resource_guard_test.sh'),
    ('经济参数', 'rpc_query_hardcap_enforcement_test.sh'),
]

items = []
lower = text.lower()
for kw, script in MAPPING:
    if kw.lower() not in lower:
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
        'step_name': f'Backlog regression: {title}',
        'commit_msg': f'ci(gate): add backlog-driven {title} regression to quick-check',
        'risk': 'low',
        'origin': 'backlog-subagent'
    })

OUT.write_text(json.dumps({'count': len(items), 'candidates': items}, ensure_ascii=False, indent=2))
print(str(OUT))
print(f'count={len(items)}')