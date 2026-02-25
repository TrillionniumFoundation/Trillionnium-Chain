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

allow_prefix = (
    'quick_gate_', 'pr5_', 'pr6_', 'pr7_', 'rpc_', 'governance_'
)
block_prefix = (
    'dev_stack_', 'rpc_service_', 'faucet_service_', 'explorer_service_',
    'run_reliability_soak', 'worker_agent_', 'trnm_tx_cli_'
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
    if not name.startswith(allow_prefix):
        continue
    if name.startswith(block_prefix):
        continue
    if 'e2e' in name or 'soak' in name:
        continue
    title = name.replace('.sh','').replace('_','-')
    candidates.append({
        'script': f'./scripts/v2/{name}',
        'step_name': f'Auto regression: {title}',
        'commit_msg': f'ci(gate): add {title} regression to quick-check',
        'risk': 'low'
    })

OUT.write_text(json.dumps({'count': len(candidates), 'candidates': candidates}, ensure_ascii=False, indent=2))
print(str(OUT))
print(f'count={len(candidates)}')