"""Finite independent checks; no native execution or cost lower bound claim."""
import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity_enumeration(root):
    from grouped_fresh_deployment_cost_v0 import topology_accounting
    from test_grouped_fresh_deployment_cost_v0 import synthetic_worker
    ids = ('first', 'second', 'third')
    rows = (0, 1, 4)
    base = [synthetic_worker(i) for i in range(2)]
    anchored_pass = unanchored_pass = 0
    for selected in itertools.product(ids, repeat=6):
        workers = copy.deepcopy(base)
        for worker, values in zip(workers, (selected[:3], selected[3:])):
            for index, value in zip(rows, values):
                worker['worker_report']['transport_records'][index]['verification']['work_id'] = value
        anchored = topology_accounting(2, workers, expected_work_ids={'1': 'first', '2': 'second'})
        unanchored = topology_accounting(2, workers)
        expect_anchor = selected == ('first', 'first', 'second', 'first', 'first', 'second')
        expect_structural = (selected[0] == selected[1] == selected[3] == selected[4]
                             and selected[2] == selected[5] and selected[0] != selected[2])
        assert (anchored['status'] == 'PASS') == expect_anchor, selected
        assert (unanchored['status'] == 'PASS') == expect_structural, selected
        assert anchored['producer_work_ids_bound'] == expect_anchor, selected
        assert not unanchored['producer_work_ids_bound'], selected
        for report, accepted in ((anchored, expect_anchor), (unanchored, expect_structural)):
            assert report['distinct_verified_work_ids'] == (2 if accepted else None), selected
            assert report['observed_distinct_verified_work_ids_partial'] == len(set(selected)), selected
            assert report['receiver_wait4_cpu_seconds'] == 6, selected
            assert report['completed_transport_attempts'] == 12, selected
            assert report['chainwork_awarded'] == 0, selected
        anchored_pass += expect_anchor
        unanchored_pass += expect_structural
    return {'assignments': 729, 'anchored_accepted': anchored_pass,
            'unanchored_structural_accepted': unanchored_pass,
            'all_independent_expectations_matched': True,
            'costs_attempts_and_zero_chainwork_preserved': True}


def service_probe(source):
    spec = importlib.util.spec_from_file_location('independently_reviewed_service', source)
    service = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(service)
    book, raw, expected, material = service.demo_case()
    book = service.reserve_contract(book, raw, expected, height=2)
    checkpoint = book.checkpoint()
    book, _ = service.settle_contract(book, raw, expected, height=3, outcome='complete',
        material=material, result=service.execute_service(raw, expected, material),
        base_consumed={'evaluation_cpu_ns': 30, 'evaluated_examples': 200},
        bonus_consumed={'training_cpu_ns': 20, 'parameter_bytes': 100})
    book.reorg(checkpoint)
    contract = json.loads(raw)
    for lane in ('base_budget', 'bonus_budget'):
        book.close(budget=contract[lane], height=50)
    observation = service.supply_observation(book, [(raw, expected)], height=50)
    row = observation['observations'][0]
    assert row['local_state'] == 'recorded-terminal'
    assert row['recorded_outcome'] == 'complete'
    assert row['branch_status'] == 'resolved'
    assert not observation['execution_dispatch_authorized']
    assert not observation['fresh_work_supply_verified']
    assert observation['additional_consensus_credit'] == 0
    return {'scenario': 'complete-reorg-generic-close',
        'branch_outcomes': [{'outcome': c.status, 'paid': c.paid} for c in book.branch.claims.values()],
        'original_local_outcome': row['recorded_outcome'],
        'reconciliation_reported': row['reconciliation_required'],
        'branch_resolution_matches_local': row.get('branch_resolution_matches_local'),
        'expected_reconciliation_required': True,
        'requirement_satisfied': row['reconciliation_required'] is True,
        'no_authority_promotion': True, 'observation': observation}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--service-source', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    code = root / 'formal/pon-nakamoto-v1'
    sys.path.insert(0, str(code))
    service = args.service_source or code / 'service_work_settlement_v1.py'
    paths = [code / 'grouped_fresh_deployment_cost_v0.py',
             code / 'test_grouped_fresh_deployment_cost_v0.py',
             code / 'reward_budget_oracle.py', service, Path(__file__).resolve()]
    before = {str(path): sha(path) for path in paths}
    report = {
        'schema': 'pon-independent-problem-one-review-v1',
        'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        'source_sha256': before,
        'identity_enumeration': identity_enumeration(root),
        'service_reconciliation': service_probe(service),
        'limitations': ['finite-synthetic-checks-only', 'no-new-native-campaign',
                       'no-general-cost-lower-bound', 'no-task-supply-liveness-qualification']}
    report['sources_unchanged_during_run'] = before == {str(path): sha(path) for path in paths}
    assert report['sources_unchanged_during_run']
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output), 'identity_cases': 729,
        'service_reconciliation_requirement_satisfied': report['service_reconciliation']['requirement_satisfied'],
        'sources_unchanged_during_run': True}))


if __name__ == '__main__':
    main()
