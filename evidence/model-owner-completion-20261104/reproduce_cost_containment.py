#!/usr/bin/env python3
"""Retain six physical-containment counterexamples without model execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repository', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--label', required=True)
args = parser.parse_args()
repository = Path(args.repository).resolve()
sys.dont_write_bytecode = True
sys.path.insert(0, str(repository / 'scripts'))
import llm_runtime_assessment as assessment
import test_llm_runtime_assessment as fixtures

cases = (
    ('child-wall-exceeds-supervisor', 'process_wall_ns', 5000, None,
     'RUNTIME_COST_WALL_CONTAINMENT'),
    ('child-cpu-exceeds-wait4', 'process_cpu_ns', 5000, None,
     'RUNTIME_COST_CPU_CONTAINMENT'),
    ('stage-wall-exceeds-child', 'wall_ns', 5000, 0,
     'RUNTIME_COST_STAGE_WALL_CONTAINMENT'),
    ('stage-cpu-exceeds-child', 'cpu_ns', 5000, 0,
     'RUNTIME_COST_STAGE_CPU_CONTAINMENT'),
    ('stage-rss-exceeds-final-child', 'memory_peak_bytes', 1048576, 0,
     'RUNTIME_COST_STAGE_RSS_CONTAINMENT'),
    ('child-rss-exceeds-waited-final', 'process_peak_rss_bytes', 1048576, None,
     'RUNTIME_COST_RSS_CONTAINMENT'),
)
observations = []
for name, field, value, stage, expected in cases:
    inputs = fixtures.fixture()
    receipt = inputs[4]['evaluate-candidate']
    target = receipt if stage is None else receipt['cost_events'][stage]
    before = target[field]
    target[field] = value
    row = dict(name=name, phase='evaluate-candidate', field=field,
               stage_index=stage, original=before, injected=value,
               expected_rejection=expected)
    try:
        result = assessment.build_assessment(*inputs)
        row.update(outcome='ACCEPTED',
                   local_process_channels_complete=result['local_process_channels_complete'],
                   decision=result['decision'], adoption=result['adoption'],
                   reward=result['reward'], no_update=result['no_update'])
    except Exception as error:
        row.update(outcome='REFUSED', error_type=type(error).__name__, error=str(error),
                   expected_rejection_observed=isinstance(error, ValueError) and str(error) == expected)
    observations.append(row)

sources = ('scripts/llm_runtime_assessment.py', 'scripts/llm_runtime_pilot.py',
           'scripts/test_llm_runtime_assessment.py')
record = dict(schema='local-pilot-cost-containment-counterexamples-v1',
    label=args.label, observed_at_ns=time.time_ns(),
    source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'],
        cwd=repository, text=True).strip(),
    source_sha256={path: hashlib.sha256((repository / path).read_bytes()).hexdigest()
                   for path in sources},
    python=sys.version.split()[0],
    scope='synthetic-declared-receipt-controls-no-model-no-trial-no-release-qualification',
    model_executed=False, trial_initialized=False, trial_reserved=False,
    cases=observations)
output = Path(args.output)
with output.open('x', encoding='utf-8') as handle:
    json.dump(record, handle, sort_keys=True, indent=2)
    handle.write('\n')
print(json.dumps(dict(output=str(output),
    outcomes={row['name']: row['outcome'] for row in observations}), sort_keys=True))
