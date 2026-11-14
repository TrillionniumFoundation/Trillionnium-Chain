set -euo pipefail
python3 - <<'PY' 2>&1 | tee "$W1_CLOSURE_OUT/completion.log"
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, 'scripts/ci')
import w1_qrom_closure_current_controls as controls
out = Path(os.environ['W1_CLOSURE_OUT'])
required = ('observations', 'checkout', 'source_before', 'preflight',
            'named_controls', 'historical_refusal', 'reproduce', 'source_after')
steps = controls.strict_json(os.environ['W1_CLOSURE_STEPS'])
failed = [name for name in required if type(steps.get(name)) is not dict
          or steps[name].get('outcome') != 'success'
          or steps[name].get('conclusion') != 'success']
error = None
try:
    controls.check(Path.cwd(), out, os.environ['W1_CLOSURE_ROSTER_SHA256'])
    observed = controls.strict_json((out / 'lifetime-current.json').read_bytes())
    controls.require(observed['schema'] == 'TRNM-W1-LIFETIME-CURRENT-OBSERVATION2'
                     and observed['status'] == 'CURRENT_SELECTED_SOURCE_OBSERVED_SECURITY_HOLD', 'current lifetime scope differs')
    expected_qualification = {'production_activation': False, 'consensus_admission': False,
          'whole_chain_post_quantum_qualified': False, 'actual_lifetime_failure_bound': None,
          'coverage_exhaustiveness_proved': False, 'composition_theorem_instantiated': False}
    controls.require(type(observed['qualification']) is dict
                     and set(observed['qualification']) == set(expected_qualification)
                     and all(observed['qualification'][k] is v for k, v in expected_qualification.items()), 'current lifetime qualification differs')
    refusal = controls.strict_json((out / 'historical-refusal.json').read_bytes())
    controls.require(refusal['schema'] == 'TRNM-W1-LIFETIME-HISTORICAL-CURRENT-REFUSAL2'
                     and refusal['expected_source'] == os.environ['EXPECTED_SOURCE']
                     and type(refusal['exit_code']) is int and refusal['exit_code'] == 2
                     and refusal['historical_pins_relaxed'] is False
                     and refusal['historical_refusal']['status'] == 'REFUSED'
                     and refusal['historical_refusal']['error'].startswith('source identity mismatch: '), 'historical refusal record differs')
    before = controls.strict_json((out / 'source-before.json').read_bytes())
    after = controls.strict_json((out / 'source-after.json').read_bytes())
    controls.require(before == after, 'source observations differ')
    controls.require(before['schema'] == 'trnm-ci-source-v1', 'source schema differs')
    controls.require(before['tracked_worktree_verified'] is True, 'tracked source is unverified')
    controls.require(type(before['tracked_entries']) is int and before['tracked_entries'] > 0,
                     'tracked source count differs')
    controls.require(before['kind'] == os.environ['SOURCE_KIND'], 'source kind differs')
    controls.require(before['tested_commit'] == os.environ['EXPECTED_SOURCE'], 'source commit differs')
    controls.require(before['candidate'] == os.environ['EXPECTED_HEAD'], 'candidate differs')
    if os.environ['SOURCE_KIND'] == 'prospective-merge':
        controls.require(before['base'] == os.environ['EXPECTED_BASE'], 'base differs')
        controls.require(before['prospective_merge'] == os.environ['EXPECTED_SOURCE'], 'merge differs')
    else:
        controls.require(before['base'] is None and before['prospective_merge'] is None,
                         'head observation has merge fields')
except (Exception, SystemExit) as caught:
    error = type(caught).__name__ + ': ' + str(caught)
passed = not failed and error is None
status = {'schema': 'TRNM-W1-QROM-CLOSURE-CURRENT-CI2',
          'expected_source': os.environ['EXPECTED_SOURCE'],
          'expected_head': os.environ['EXPECTED_HEAD'],
          'expected_base': os.environ['EXPECTED_BASE'],
          'source_kind': os.environ['SOURCE_KIND'],
          'required_stages': list(required), 'steps': steps,
          'failed_or_skipped_stages': failed, 'completion_or_identity_error': error,
          'all_required_observations_passed': passed,
          'qualification': controls.QUALIFICATION}
with (out / 'ci-status.json').open('x') as stream:
    json.dump(status, stream, indent=2, sort_keys=True, allow_nan=False)
    stream.write('\n')
if not passed:
    raise SystemExit('required QROM continuation observations did not all complete')
print('All fixed named observations completed; complete QROM and chain qualification remain false.')
PY
