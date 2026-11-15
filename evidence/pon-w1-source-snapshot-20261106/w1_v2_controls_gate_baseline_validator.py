from pathlib import Path
import json, sys
sys.path.insert(0, 'scripts')
import w1_v2_receipt_controls as controls
out, proof, verifier = map(Path, sys.argv[1:])
report = controls.strict_json((out / 'result.json').read_bytes())
baseline = {key: (proof / name).read_bytes() for key, name in
            (('receipt', 'succinct.bin'), ('header', 'header.bin'), ('artifacts', 'expected-artifacts.bin'))}
location = controls.locate_journal(baseline['receipt'], baseline['header'], baseline['artifacts'])
plans = controls.plan_controls(baseline['receipt'], location)
retained = controls.strict_json((proof / 'controls-result.json').read_bytes())['controls']
cases = report['controls']
controls.require(len(plans) == len(retained) == len(cases) == 58, 'all 58 original controls are required')
observation_fields = {'passed', 'returncode', 'timed_out', 'panic_or_abort_detected',
                      'stdout_scan_truncated', 'stderr_scan_truncated', 'observed_rejection_layers',
                      'report_error', 'process', 'case_directory'}
controls.require(plans == [{key: value for key, value in row.items() if key not in observation_fields}
                           for row in retained], 'original control plan or required rejection text changed')
expected = {
    'schema': 'TRNM-W1-V2-RECEIPT-CONTROLS1', 'profile_id': 'trnm-w1-risc0-3.0.6-poseidon2-join-v2',
    'total_wall_budget_seconds': 120, 'termination_settlement_adds_acceptance_budget': False,
    'planned_controls': 58, 'completed_controls': 58, 'positive_controls_passed': 1,
    'negative_controls_passed': 57, 'unexpected_acceptances': 0, 'panic_or_abort_count': 0,
    'timeout_count': 0, 'all_controls_passed': True, 'error': None, 'uncompleted_controls': [],
    'new_proofs_generated': 0, 'additional_work_tickets': 0, 'independent_proof_trials': 1,
    'quantum_security_qualified': False, 'consensus_admission': False,
    'parent_eligibility_checked': False, 'production_activation': False,
    'runner_sha256': controls.sha(Path(controls.__file__)), 'verifier_sha256': controls.sha(verifier),
}
for key, value in expected.items():
    controls.require(type(report.get(key)) is type(value) and report[key] == value,
                     f'v2 controls summary differs: {key}')
elapsed = report['elapsed_wall_seconds']
controls.require(type(elapsed) in (int, float) and 0 < elapsed < 120, 'common 120-second deadline exceeded')
for plan, old, case in zip(plans, retained, cases):
    for row in (old, case):
        controls.require(all(type(row.get(key)) is type(value) and row[key] == value
                             for key, value in plan.items()), 'original ordered control or expectation changed')
    controls.require(case['passed'] is True and case['timed_out'] is False
                     and case['panic_or_abort_detected'] is False and case['report_error'] is None,
                     'control did not pass cleanly')
    code = case['returncode']
    controls.require(type(code) is int and (code == 0 if plan['expect'] == 'accept' else code > 0),
                     'control exit differs from expectation')
    process = case['process']
    controls.require(process['completion_observed_before_deadline'] is True
                     and process['termination_reasons'] == [], 'control did not complete before the deadline')
    layer = plan.get('required_rejection_layer')
    controls.require(layer is None or case['observed_rejection_layers'] == [layer], 'wrong rejection layer')
controls.validate_positive(json.dumps(report['positive_report']), baseline, location)
print('All 58 original saved-v2 controls passed; no new proof or qualification is claimed.')
