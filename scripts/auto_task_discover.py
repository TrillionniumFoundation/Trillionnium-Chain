#!/usr/bin/env python3
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / '.github/workflows/trnm-gate-quick-check.yml'
V2 = ROOT / 'scripts/v2'
OUT = ROOT / 'run/auto-iterate/task-candidates.json'
FLAKY = ROOT / 'scripts/auto_iterate.flaky'
OUT.parent.mkdir(parents=True, exist_ok=True)

wf_text = WF.read_text() if WF.exists() else ''
existing = set(re.findall(r'\./scripts/v2/([\w\-]+\.sh)', wf_text))

HIGH_RISK_KEYS = (
    'e2e', 'soak', 'rollback', 'promote', 'emergency', 'dev_stack',
    'service_up', 'service_down', 'real_cli', 'worker_agent', 'onboard'
)

flaky = set()
if FLAKY.exists():
    for line in FLAKY.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        flaky.add(line)

candidates = []
for p in sorted(V2.glob('*.sh')):
    name = p.name
    if name in flaky:
        continue
    if name in existing:
        continue
    if name.startswith('auto_iterate_task_add_'):
        continue

    risk = 'high' if any(k in name for k in HIGH_RISK_KEYS) else 'low'
    title = name.replace('.sh','').replace('_','-')
    candidates.append({
        'script': f'./scripts/v2/{name}',
        'step_name': f'Auto regression: {title}',
        'commit_msg': f'ci(gate): add {title} regression to quick-check',
        'risk': risk
    })

OUT.write_text(json.dumps({'count': len(candidates), 'candidates': candidates}, ensure_ascii=False, indent=2))
print(str(OUT))
print(f'count={len(candidates)}')