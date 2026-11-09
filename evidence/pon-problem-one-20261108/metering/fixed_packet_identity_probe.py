#!/usr/bin/env python3
"""Same-input report counterexamples; synthetic observations, no native workload."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path.cwd()
sys.path.insert(0, str(root / 'formal/pon-nakamoto-v1'))
from grouped_fresh_deployment_cost_v0 import topology_accounting
from test_grouped_fresh_deployment_cost_v0 import synthetic_worker
from test_grouped_fanout_reanalysis_v1 import synthetic_campaign, encode, sha
from experiments.reanalyze_grouped_fanout_v1 import reanalyze

def pins():
    names = (
        'formal/pon-nakamoto-v1/grouped_fresh_deployment_cost_v0.py',
        'formal/pon-nakamoto-v1/test_grouped_fresh_deployment_cost_v0.py',
        'formal/pon-nakamoto-v1/experiments/reanalyze_grouped_fanout_v1.py',
        'formal/pon-nakamoto-v1/test_grouped_fanout_reanalysis_v1.py',
        'formal/pon-nakamoto-v1/experiments/grouped_fresh_fanout_v0.py',
    )
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}

before = pins()
cases = []
def inspect(name, workers, planned):
    before_workers = copy.deepcopy(workers)
    result = topology_accounting(planned, workers)
    assert workers == before_workers
    assert result['completed_transport_attempts'] == planned * 6
    assert result['receiver_wait4_cpu_seconds'] == planned * 3.0
    assert result['chainwork_awarded'] == 0
    input_raw = json.dumps(dict(planned_receivers=planned, workers=workers),
                           sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    cases.append(dict(case=name, input_sha256=hashlib.sha256(input_raw).hexdigest(), status=result['status'],
        distinct_verified_work_ids=result['distinct_verified_work_ids'],
        observed_distinct_verified_work_ids_partial=result['observed_distinct_verified_work_ids_partial'],
        completed_transport_attempts=result['completed_transport_attempts'],
        receiver_wait4_cpu_seconds=result['receiver_wait4_cpu_seconds'], issues=result['issues']))

worker = synthetic_worker()
worker['worker_report']['transport_records'][1]['verification']['work_id'] = 'third'
inspect('carrier_replay_relabel', [worker], 1)
workers = [synthetic_worker(i) for i in range(2)]
for row in workers[1]['worker_report']['transport_records']:
    if row['case'] in ('valid', 'carrier_replay', 'discarded_response'):
        row['verification']['work_id'] = 'second' if row['verification']['work_id'] == 'first' else 'first'
inspect('cross_receiver_slot_swap', workers, 2)
worker = synthetic_worker()
worker['worker_report']['transport_records'][4]['verification']['work_id'] = 'first'
inspect('distinct_nonce_alias', [worker], 1)

for label in ('one_topology_renamed', 'all_topologies_swapped', 'producer_roster_missing'):
    original = synthetic_campaign()
    original['produced'] = [{'nonce': 1, 'work_id': 'first'}, {'nonce': 2, 'work_id': 'second'}]
    if label == 'producer_roster_missing':
        del original['produced']
    else:
        topologies = original['topologies'][1:2] if label == 'one_topology_renamed' else original['topologies']
        for topology in topologies:
            for worker in topology['workers']:
                for row in worker['worker_report']['transport_records']:
                    if row['case'] in ('valid', 'carrier_replay', 'discarded_response'):
                        current = row['verification']['work_id']
                        row['verification']['work_id'] = (current + '-renamed' if label == 'one_topology_renamed'
                            else 'second' if current == 'first' else 'first')
    raw = encode(original)
    result = reanalyze(raw, expected_sha256=sha(raw))
    assert result['planned_transport_attempts'] == 42
    assert result['chainwork_awarded'] == 0
    assert result['qualification_status'] == 'HOLD'
    cases.append(dict(case=label, input_sha256=sha(raw), status=result['status'],
        topology_statuses=[row['new_status'] for row in result['topologies']],
        issues=result['issues']))

after = pins()
assert before == after
mode = sys.argv[1]
assert mode in ('legacy', 'fixed')
expected = 'PASS' if mode == 'legacy' else 'FAIL'
assert all(row['status'] == expected for row in cases), cases
if mode == 'legacy':
    assert [row['distinct_verified_work_ids'] for row in cases[:3]] == [3, 2, 1]
else:
    assert all(row['distinct_verified_work_ids'] is None for row in cases[:3])
print(json.dumps(dict(schema='pon-fixed-packet-identity-counterexamples-v1',
    mode=mode, scope='six synthetic report-integrity controls; no new native workload',
    source_scope='listed working-tree bytes, not a complete-checkout qualification',
    probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    python=sys.version, source_before=before, source_after=after,
    source_unchanged=True, outcomes_verified=True, cases=cases), sort_keys=True, indent=2))

