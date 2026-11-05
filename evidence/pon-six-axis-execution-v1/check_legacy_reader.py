#!/usr/bin/env python3
"""Synthetic parser controls only; not native execution or performance evidence."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types

root = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(root / 'scripts'))
sys.path.insert(0, str(root / 'scripts/ci'))
import pon_public_v3_phase_read as current
import test_pon_public_v3_phase_read as fixtures

base = 'a9b8602706b66adba82655c3c2ce90bde88620a2'
raw = subprocess.check_output(['git', 'show', base + ':scripts/pon_public_v3_phase_read.py'], cwd=root)
legacy = types.ModuleType('legacy_phase_reader')
legacy.__file__ = str(root / 'scripts/pon_public_v3_phase_read.py')
exec(compile(raw, legacy.__file__, 'exec'), legacy.__dict__)
results = []
for version in range(1, 5):
    row = fixtures.record_v4() if version == 4 else fixtures.record()
    phases = [fixtures.attribution_phase([], [], [], [copy.deepcopy(row)]) for _ in current.MODES]
    for phase, mode in zip(phases, current.MODES):
        phase['mode'] = mode
        observer = phase['receiver_observation']
        observer['schema'] = f'public-v3-local-request-resource-observation-v{version}'
        if version >= 3:
            observer.update(cpu_includes_reactor_authentication_or_response_signing=True,
                            cpu_includes_reactor_authentication=False,
                            dispatch_cpu_includes_paid_body_decode=True,
                            dispatch_cpu_includes_response_signing=True)
        if version == 4:
            observer.update(phase_parent_links_are_inclusive=True, cpu_wait_is_outside_dispatch=True,
                            monotonic_epoch_is_observer_local=True)
    report = dict(schema='native-public-v3-separate-process-campaign-v2', state_backend='authenticated-v1',
                  finite_experiment_criteria_met=False, economics_complete=False,
                  best_observed_cold_legal_method=None, preparation=dict(cpu_ns=None, wall_ns=None), phases=phases)
    for derivation in (1, 2, 3) if version <= 2 else (2, 3):
        schema = f'pon-public-v3-multiprocess-phase-derivation-v{derivation}'
        expected = json.dumps(legacy.analyze_for_retained_schema(report, schema), sort_keys=True,
                              separators=(',', ':')).encode()
        observed = json.dumps(current.analyze_for_retained_schema(report, schema), sort_keys=True,
                              separators=(',', ':')).encode()
        assert observed == expected, (version, derivation)
        results.append(dict(observer_version=version, derivation_version=derivation,
                            bytes_equal=True, sha256=hashlib.sha256(observed).hexdigest()))
print(json.dumps(dict(scope=__doc__, baseline_source_commit=base,
                      baseline_reader_sha256=hashlib.sha256(raw).hexdigest(),
                      cases=results, passed=True), indent=2))
