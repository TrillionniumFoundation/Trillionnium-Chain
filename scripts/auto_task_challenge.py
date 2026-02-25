#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / 'scripts/auto_iterate.tasks'
OUT = ROOT / 'run/auto-iterate/task-challenges.json'
OUT.parent.mkdir(parents=True, exist_ok=True)

# Challenge templates for low-risk gate expansion.
# We only emit scripts that already exist under scripts/v2.
CANDIDATE_SCRIPTS = [
    'pr4_challenge_fundflow_audit_gate.sh',
    'pr5_challenge_reconcile_gate.sh',
    'pr6_alert_rules_gate.sh',
    'pr7_delivery_e2e_gate.sh',
    'quick_gate_summary_path_guard_test.sh',
    'quick_gate_summary_json_escape_test.sh',
    'rpc_query_hardcap_enforcement_test.sh',
]

existing_text = TASKS.read_text() if TASKS.exists() else ''

items = []
for s in CANDIDATE_SCRIPTS:
    script_path = ROOT / 'scripts/v2' / s
    if not script_path.exists() or not script_path.is_file():
        continue
    run = f'./scripts/v2/{s}'
    if run in existing_text:
        continue

    title = s.replace('.sh', '').replace('_', '-')
    items.append({
        'script': run,
        'step_name': f'Challenge regression: {title}',
        'commit_msg': f'ci(gate): add challenge-derived {title} regression to quick-check',
        'risk': 'low',
        'origin': 'challenge-subagent'
    })

OUT.write_text(json.dumps({'count': len(items), 'candidates': items}, ensure_ascii=False, indent=2))
print(str(OUT))
print(f'count={len(items)}')