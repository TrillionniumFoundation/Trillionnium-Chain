#!/usr/bin/env python3
"""Validate this continuation's actual full regression, without repinning ML evidence."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
import statistics
import sys
import tempfile
from unittest.mock import patch
import os
from pathlib import Path
from check_invariant_evidence import ROOT, load, require, safe, source_bytes
from report_module_evidence import runtime_path, python_symbols, observed_selector

TEST_FILE = 'formal/pon-nakamoto-v1/test_client_confirmation.py'
RUNNER = 'scripts/run_evaluation_qualification.py'
HISTORICAL = {'evidence/' + name + '/manifest.json' for name in
              ['pon-v1', 'pon-v3', 'pon-v4', 'pon-evaluation-bundle-v1', 'pon-contract-authority-v1']}
FLAGS = ['ordinary_hepta_entry', 'independent_accepted', 'three_improving_generations',
         'physical_power_loss', 'public_network_ready', 'production_activation']
REQUIRED = {
    'preflight', 'source-contract', 'source-rejections', 'invariant-registry',
    'native-build', 'native-suite', 'native-doctests', 'native-ignored-helper',
    'native-lints', 'native-format', 'test_reference', 'test_contracts', 'test_invariants',
    'test_evaluation', 'test_evaluation_bundle', 'test_artifacts', 'test_model_contract',
    'test_inference_receipt', 'test_bounded_process', 'test_work_backend',
    'test_strict_signature', 'test_native_execution', 'test_interop',
    'test_client_confirmation', 'accepted-block', 'native-ledger',
    'historical-v1-rejections', 'historical-v4', 'historical-v4-rejections',
    'native-client-confirmation', 'historical-evaluation-components',
    'historical-evaluation-rejections', 'responsibility-evidence',
    'work-cost-rejections', 'whitespace',
}


def client_selectors(text):
    """Only direct unittest methods, not local callbacks nested inside those tests."""
    return [TEST_FILE + '::' + name for name in sorted(python_symbols(text))
            if name.startswith('VerifiedHistoryTests.test_') and name.count('.') == 1]



def require_tracked_evidence(root, folder, manifest):
    """Published inputs must survive checkout, including globally ignored raw logs.

    External historical/mutation packages are read-only supplied inputs, not a claim
    that the original measured source commit already contained its later evidence.
    """
    root, folder = Path(root).resolve(), Path(folder).resolve()
    if not folder.is_relative_to(root):
        return False
    prefix = folder.relative_to(root)
    tracked = set(subprocess.check_output(
        ['git', 'ls-files', '-z', '--', prefix.as_posix()], cwd=root
    ).decode().split('\0'))
    required = {(prefix / 'manifest.json').as_posix()}
    required.update(safe(folder, name).relative_to(root).as_posix()
                    for name in manifest['files'])
    missing = sorted(required - tracked)
    require(not missing, 'untracked evidence artifact: ' + ', '.join(missing[:3]))
    return True


def validate(root=ROOT, evidence=None):
    root = Path(root).resolve()
    folder = Path(evidence or root / 'evidence/pon-client-confirmation-v1').resolve()
    manifest = load(folder / 'manifest.json')
    session = manifest['schema'] == 'pon-native-session-evidence-v1'
    require(session or manifest['schema'] == 'pon-client-confirmation-evidence-v1', 'schema')
    require(manifest['source_clean'] is True and manifest['all_commands_passed'] is True, 'incomplete measurement')
    for flag in FLAGS:
        require(manifest[flag] is False, 'unsupported authority ' + flag)
    require('qualification.json' in manifest['files'], 'missing qualification')
    for relative, expected in manifest['files'].items():
        require(re.fullmatch('[0-9a-f]{64}', expected), 'digest shape')
        require(hashlib.sha256(safe(folder, relative).read_bytes()).hexdigest() == expected, 'changed artifact ' + relative)
    require_tracked_evidence(root, folder, manifest)
    q = load(folder / 'qualification.json')
    require(q['source_commit'] == manifest['implementation_commit']
            and q['source_tree'] == manifest['implementation_tree'], 'source identity')
    require(q['source_clean'] is True and q['source_clean_after'] is True
            and q['all_commands_passed'] is True, 'dirty or failed qualification')
    require(q['workstream'] == ('native-session' if session else 'client-confirmation')
            and q['model_experiments_rerun'] is False, 'wrong experiment scope')
    for flag in ['ordinary_hepta_entry', 'independent_accepted', 'future_window_accepted', 'production_activation']:
        require(q[flag] is False, 'qualification authority ' + flag)
    tree = subprocess.check_output(['git', 'rev-parse', q['source_commit'] + '^{tree}'], cwd=root, text=True).strip()
    require(tree == q['source_tree'], 'source tree')
    require(RUNNER in q['source_files_sha256'], 'missing measured qualification runner')
    history = HISTORICAL | ({'evidence/pon-client-confirmation-v1/manifest.json'} if session else set())
    require(set(q['historical_evidence_sha256']) == history, 'historical inventory')
    for relative, expected in q['historical_evidence_sha256'].items():
        require(hashlib.sha256(safe(root, relative).read_bytes()).hexdigest() == expected, 'historical evidence changed ' + relative)
    require(manifest['historical_v4_sha256'] == q['historical_evidence_sha256']['evidence/pon-v4/manifest.json'], 'historical manifest mismatch')
    measured_paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', q['source_commit']], cwd=root, text=True).splitlines()
    require({p for p in measured_paths if runtime_path(p)} ==
            {p for p in q['source_files_sha256'] if runtime_path(p)}, 'measured/current runtime inventory')
    originals = source_bytes(root, q['source_commit'], list(q['source_files_sha256']))
    for relative, raw in originals.items():
        require(hashlib.sha256(raw).hexdigest() == q['source_files_sha256'][relative], 'false source digest')
        require(safe(root, relative).read_bytes() == raw, 'current source differs ' + relative)
    tracked = set(subprocess.check_output(['git', 'ls-files'], cwd=root, text=True).splitlines())
    untracked = set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], cwd=root, text=True).splitlines())
    require({p for p in tracked | untracked if runtime_path(p)} == {p for p in originals if runtime_path(p)}, 'current runtime inventory')
    require(TEST_FILE in originals and 'formal/pon-nakamoto-v1/client_confirmation.py' in originals, 'missing client source')
    rows = q['results']
    required = REQUIRED | (SESSION_RUNS if session else set())
    require({r['name'] for r in rows} == required and len(rows) == len(required), 'execution matrix')
    records, native_count = [], 0
    by_name = {r['name']: r for r in rows}
    for row in rows:
        require(type(row['returncode']) is int and row['returncode'] == 0 and row['timed_out'] is False, 'failed execution')
        require(row['log'] in manifest['files'], 'unmanifested log')
        text = safe(folder, row['log']).read_text()
        require(row['vram_bytes'] is None and row['included_transactions'] is None
                and row['client_confirmed_transactions'] is None, 'unmeasured network metric')
        if row['name'].startswith('test_') or row['name'] in {'native-ledger', 'native-client-confirmation', 'accepted-block', 'source-rejections', 'invariant-registry', 'historical-v1-rejections', 'historical-v4-rejections', 'historical-evaluation-rejections', 'responsibility-evidence', 'work-cost-rejections'}:
            require('python_tests' in row, 'missing executed Python summary ' + row['name'])
        if row['name'].startswith('test_'):
            require(row['command'] == ['python3', 'formal/pon-nakamoto-v1/' + row['name'] + '.py'], 'wrong Python invocation ' + row['name'])
        if 'python_tests' in row:
            require(type(row['python_tests']) is int and row['python_tests'] > 0, 'test counter')
            require(re.search(r'(?m)^Ran ' + str(row['python_tests']) + r' tests?\b', text)
                    and re.search(r'(?m)^OK\s*$', text), 'Python log result')
        if row['name'] in {'native-suite', 'native-doctests', 'native-ignored-helper'}:
            require(row['command'][:2] == ['cargo', 'test'] and '--locked' in row['command'], 'native invocation')
            counts = []
            for part in re.split(r'(?m)^\s*(?:Running (?:unittests|tests/)|Doc-tests )', text):
                found = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored', part)
                if found:
                    counts.append(found[-1])
            require(counts and all(c[0] == 'ok' and int(c[2]) == 0 for c in counts), 'native failures')
            require(type(row['native_passed']) is int and sum(int(c[1]) for c in counts) == row['native_passed'], 'native result count')
            if row['name'] == 'native-suite':
                require({'--workspace', '--all-targets', '--all-features'} <= set(row['command']), 'incomplete native suite')
                native_count = row['native_passed']
        records.append(dict(row, _log_text=text))
    selectors = client_selectors(originals[TEST_FILE].decode())
    require(selectors, 'missing client assertions')
    for name in ['test_client_confirmation', 'native-client-confirmation']:
        row = by_name[name]
        require(row['command'] == ['python3', TEST_FILE], 'client invocation')
        exact = [r for r in records if r['name'] == name]
        require(all(observed_selector(s, exact) for s in selectors), 'unobserved client selector')
    build = by_name['native-build']['command']
    require(build[:2] == ['cargo', 'build'] and {'--offline', '--locked', '--release', '--examples'} <= set(build), 'native build invocation')
    require({'trnm-protocol', 'trnm-crypto-primitives', 'trnm-mvcc-fee', 'trnm-transport'} <= set(build), 'native build scope')
    overrides = by_name['native-client-confirmation']['environment_overrides']
    require(overrides.get('TRNM_EXECUTION_WORKERS') == '8'
            and overrides.get('TRNM_NATIVE_WORK', '').endswith('/release/examples/pon_work_io')
            and overrides.get('TRNM_NATIVE_EXECUTOR', '').endswith('/release/examples/pon_execute'), 'missing actual native client selection')
    for binary in ['pon_work_io', 'pon_execute']:
        require(re.fullmatch('[0-9a-f]{64}', q['native_binary_sha256'][binary]), 'native binary digest')
    require(q['environment']['cargo_locked'] is True and q['environment']['cargo_offline'] is True
            and q['environment']['physical_power_loss'] is False, 'environment scope')
    extra = validate_session(root, folder, manifest, q, records, originals) if session else {}
    return {**extra, 'measured_commit': q['source_commit'], 'runtime_matches': True,
            'native_tests': native_count, 'client_selectors_per_backend': len(selectors),
            'backends': ['reference', 'explicit-native-work-and-eight-worker-execution'] +
                        (['explicit-native-work-and-eight-worker-session'] if session else []),
            'model_experiments_rerun': False, 'public_confirmed_tps': None,
            'native_full_node': False, 'independent_accepted': False, 'production_activation': False}


SESSION_RUNS = {
    'test_native_session', 'test_work_precheck', 'session-ledger', 'session-invariants',
    'session-client-confirmation', 'historical-client', 'historical-client-rejections',
    'session-comparison', 'session-pipeline',
}


def validate_session(root, folder, manifest, q, records, originals):
    """The current receipt must actually cover the added runtime, not waive old checks."""
    by_name = {row['name']: row for row in records}
    session_file = 'formal/pon-nakamoto-v1/test_native_session.py'
    precheck_file = 'formal/pon-nakamoto-v1/test_work_precheck.py'
    for path in [session_file, precheck_file]:
        require(path in originals, 'missing session source')
        tests = [path + '::' + symbol for symbol in python_symbols(originals[path].decode())
                 if symbol.count('.') == 1 and symbol.split('.')[-1].startswith('test_')]
        require(tests and all(observed_selector(selector, records) for selector in tests),
                'unobserved session/precheck selector')
    for name, path in [('session-ledger','test_contracts'), ('session-invariants','test_invariants'),
                       ('session-client-confirmation','test_client_confirmation')]:
        row = by_name[name]
        require(row['command'] == ['python3', 'formal/pon-nakamoto-v1/' + path + '.py'], 'session test invocation')
        env = row['environment_overrides']
        require(env.get('TRNM_EXECUTION_WORKERS') == '8'
                and env.get('TRNM_NATIVE_WORK', '').endswith('/release/examples/pon_work_io')
                and env.get('TRNM_NATIVE_SESSION', '').endswith('/release/examples/pon_execute_session')
                and not env.get('TRNM_NATIVE_EXECUTOR'), 'explicit session backend')
        require(re.search(r'(?m)^Ran \d+ tests?\b', row['_log_text'])
                and re.search(r'(?m)^OK\s*$', row['_log_text']), 'session suite outcome')
    require(all(observed_selector(selector, [by_name['session-client-confirmation']])
                for selector in client_selectors(originals[TEST_FILE].decode())), 'session client coverage')
    invariants = json.loads(originals['config/pon/invariants-v2.json'])['invariants']
    for invariant in invariants:
        for selector in invariant['tests']:
            path, name = selector.split('::', 1)
            if path.endswith('.py'):
                require(observed_selector(selector, records), 'unobserved current invariant ' + selector)
            else:
                require(re.search(r'(?m)^test [\w:]*' + re.escape(name) + r' \.\.\. ok\s*$',
                                  by_name['native-suite']['_log_text']), 'unobserved native invariant ' + selector)
    require(by_name['historical-evaluation-components']['command'][-1] == '--historical'
            and by_name['historical-client']['command'][-1] == '--historical', 'historical claim scope')
    for name in ['session-comparison','session-pipeline']:
        script = 'formal/pon-nakamoto-v1/experiments/' + ('session_cost.py' if name.endswith('comparison') else 'session_pipeline.py')
        require(by_name[name]['command'][:2] == ['python3', script] and script in originals, 'measured campaign invocation')
    pipeline_env = by_name['session-pipeline']['environment_overrides']
    require(pipeline_env.get('TRNM_NATIVE_SESSION', '').endswith('/release/examples/pon_execute_session')
            and pipeline_env.get('TRNM_NATIVE_WORK', '').endswith('/release/examples/pon_work_io')
            and not pipeline_env.get('TRNM_NATIVE_EXECUTOR'), 'explicit pipeline backend')
    native_session_hash = q['native_binary_sha256'].get('pon_execute_session', '')
    require(re.fullmatch('[0-9a-f]{64}', native_session_hash), 'session binary identity')
    sys.path.insert(0, str(root / 'formal/pon-nakamoto-v1'))
    from contract_wire import H, NETWORK, PARAMETER_HASH, canonical, state_root, header_decode
    from ledger import execute_reference, public, key, Ledger, GENESIS, PARAMS
    from client_confirmation import confirmations, decode_page
    comparison = load(folder / 'comparison/report.json')
    require(comparison['source_commit'] == q['source_commit'] and comparison['source_clean'] is True, 'comparison source')
    require(comparison['context'] == {'network': NETWORK.hex(), 'parameters': PARAMETER_HASH.hex()}, 'comparison context')
    require(comparison['binary_sha256'] == {'full-state': q['native_binary_sha256']['pon_execute'],
                                           'delta-session': native_session_hash}, 'comparison binary')
    for flag in ['full_node', 'chain_tps_claimed', 'ordinary_hepta_entry', 'independent_operators', 'production_activation']:
        require(comparison[flag] is False, 'comparison overclaim')
    require(comparison['bootstrap_excluded_from_steady_state'] is True, 'bootstrap scope')
    requests = folder / 'comparison/requests.json'
    require(hashlib.sha256(requests.read_bytes()).hexdigest() == comparison['request_sha256'], 'comparison request hash')
    inputs = json.loads(requests.read_bytes())
    require(len(inputs) == 3 and {case['scenario'] for case in inputs} == {'independent','hot-recipient','hot-sender'}, 'workload coverage')
    n = comparison['samples_per_case']
    require(type(n) is int and 3 <= n <= 20, 'sample budget')
    expected = {}
    for case in inputs:
        state = case['initial']
        require(state_root(state).hex() == case['initial_root'] and len(case['blocks']) == n + 1, 'benchmark predecessor')
        for index, block in enumerate(case['blocks']):
            require(block['sample'] == index and block['warmup'] is (index == 0), 'benchmark sequence')
            txs = [bytes.fromhex(value) for value in block['transactions']]
            actual, receipts = execute_reference(state, txs, block['height'], bytes.fromhex(block['miner']), bytes.fromhex(block['parent']))
            require(actual == block['expected'] and [raw.hex() for raw in receipts] == block['receipts']
                    and state_root(actual).hex() == block['root'] and state_root(state).hex() == block['predecessor'], 'benchmark transition replay')
            for workers in [1,2,4,8]:
                request = dict(network=NETWORK.hex(), parameters=PARAMETER_HASH.hex(), state=state,
                               transactions=block['transactions'], height=block['height'], miner=block['miner'],
                               parent=block['parent'], workers=workers)
                expected[(case['scenario'],workers,index)] = (block, hashlib.sha256(canonical(request)).hexdigest())
            state = actual
    seen = set()
    for row in comparison['samples']:
        identity = (row['scenario'],row['workers'],row['sample'],row['variant'])
        require(identity not in seen and identity[-1] in {'full-state','delta-session'}, 'duplicate/unknown sample')
        seen.add(identity)
        require(identity[:3] in expected, 'unexpected sample')
        block, digest = expected[identity[:3]]
        require(row['warmup'] is block['warmup'] and row['root'] == block['root']
                and row['predecessor'] == block['predecessor'] and row['input_sha256'] == digest
                and row['receipt_digest'] == H('receipt-observation',canonical(block['receipts'])).hex(), 'sample outcome identity')
        require(row['transactions'] == row['application_executed'] == len(block['transactions']), 'sample execution count')
        require(all(row[field] is None for field in ['admitted_to_mempool','included','confirmed','proof_verification_ns','vram_bytes'])
                and row['gpu_used'] is False, 'unmeasured performance claim')
        for field in ['wall_ns','state_root_ns','state_transition_ns','request_bytes','response_bytes']:
            require(type(row[field]) is int and row[field] >= 0, 'sample metric')
        if row['variant'] == 'delta-session':
            require(row['metrics']['request_cache_hit'] is False, 'cache hit is not an execution sample')
    require(seen == {(*key,variant) for key in expected for variant in ['full-state','delta-session']}, 'missing paired samples')
    require(len(comparison['summary']) == 12 and {(row['scenario'],row['workers']) for row in comparison['summary']} ==
            {(case,w) for case in ['independent','hot-recipient','hot-sender'] for w in [1,2,4,8]}, 'summary coverage')
    for item in comparison['summary']:
        medians = {}
        for variant in ['full-state','delta-session']:
            rows = [row for row in comparison['samples'] if row['scenario'] == item['scenario'] and row['workers'] == item['workers']
                    and row['variant'] == variant and not row['warmup']]
            require(len(rows) == n, 'summary samples')
            medians[variant] = {field: statistics.median(row[field] for row in rows)
                                for field in ['wall_ns','state_root_ns','request_bytes','response_bytes']}
            require(item[variant] == medians[variant], 'false summary')
        require(item['wall_regression'] is (medians['delta-session']['wall_ns'] > medians['full-state']['wall_ns']), 'hidden regression')
    pipeline = load(folder / 'pipeline/report.json')
    require(pipeline['source_commit'] == q['source_commit'] and pipeline['source_tree'] == q['source_tree']
            and pipeline['source_clean'] is True, 'pipeline source')
    require(pipeline['network'] == NETWORK.hex() and pipeline['parameters'] == PARAMETER_HASH.hex(), 'pipeline context')
    require(pipeline['binaries'] == {'TRNM_NATIVE_WORK': q['native_binary_sha256']['pon_work_io'],
                                    'TRNM_NATIVE_SESSION': native_session_hash}, 'pipeline binaries')
    for flag in ['target_spacing_wall_paced','full_native_node','independent_operators','public_network_ready',
                 'physical_power_loss','ordinary_hepta_entry','production_activation']:
        require(pipeline[flag] is False, 'pipeline overclaim')
    require(pipeline['clock_scope'] == 'explicit-logical-test-clock' and pipeline['public_confirmed_tps'] is None
            and pipeline['transport_scope'] == 'bounded-pages-in-one-controller-with-separate-ledger-stores', 'pipeline transport/clock scope')
    for relative, digest in pipeline['files'].items():
        require(hashlib.sha256(safe(folder / 'pipeline', relative).read_bytes()).hexdigest() == digest, 'pipeline packet hash')
    samples, width = pipeline['samples_per_scenario'], pipeline['transactions_per_sample']
    require(type(samples) is int and 2 <= samples <= 8 and type(width) is int and 1 <= width <= 32, 'pipeline budget')
    require(len(pipeline['branches']) == 2 and {row['scenario'] for row in pipeline['branches']} == {'independent','hot-sender'}
            and len(pipeline['samples']) == 2*samples, 'pipeline coverage')
    replayed, confirmed = 0, 0
    for branch in pipeline['branches']:
        case = branch['scenario']
        require(case in {'independent','hot-sender'}, 'pipeline scenario')
        packets = load(folder / 'pipeline' / (case + '-packets.json'))
        pages = load(folder / 'pipeline' / (case + '-pages.json'))
        require(len(packets) == len(pages) == len(branch['blocks']) == 1 + samples*(1+PARAMS['confirmation_depth'])
                and branch['actual_work_verified_blocks'] == len(packets), 'pipeline block count')
        observed = [row for row in pipeline['samples'] if row['scenario'] == case]
        require(len(observed) == samples and [row['sample'] for row in observed] == list(range(samples)), 'pipeline sample sequence')
        with tempfile.TemporaryDirectory(prefix='pon-evidence-replay-') as directory, patch.dict(os.environ,
                {'TRNM_NATIVE_SESSION':'','TRNM_NATIVE_EXECUTOR':'','TRNM_NATIVE_WORK':''}):
            # Empty work selector must be absent; work_backend uses presence, not truthiness.
            os.environ.pop('TRNM_NATIVE_WORK', None)
            ledger = Ledger(directory)
            try:
                after, pending = GENESIS, None
                for index, (packet,page,stage) in enumerate(zip(packets,pages,branch['blocks'])):
                    hb, txs, proof = bytes.fromhex(packet['header']), [bytes.fromhex(tx) for tx in packet['transactions']], bytes.fromhex(packet['proof'])
                    bid = bytes.fromhex(packet['block'])
                    decoded, following, complete = decode_page(canonical(page), bid, after)
                    require(len(decoded) == 1 and decoded[0] == (hb,txs,proof,bid) and following == bid and complete, 'pipeline page binding')
                    require(ledger.admit(hb,txs,proof,PARAMS['genesis_timestamp']+100000) == bid, 'pipeline verified block')
                    ledger.recover();after=bid;replayed+=1
                    require(stage['block'] == bid.hex() and stage['height'] == header_decode(hb)['height']
                            and stage['transaction_count'] == len(txs) and stage['proof_bytes'] == len(proof), 'pipeline stage identity')
                    if index > 0 and (index-1) % (1+PARAMS['confirmation_depth']) == 0:
                        pending=(bid,txs)
                    if index > 0 and (index-1) % (1+PARAMS['confirmation_depth']) == PARAMS['confirmation_depth']:
                        row=observed[(index-1)//(1+PARAMS['confirmation_depth'])]
                        inclusion, transactions = pending
                        facts=confirmations(ledger, [(H('tx-id',tx),inclusion) for tx in transactions], observed_now=PARAMS['genesis_timestamp']+100000)
                        require(row['confirmations'] == facts and len(facts) == width and all(f['status']=='confirmed' for f in facts), 'pipeline confirmation replay')
                        require(row['submitted'] == row['source_included'] == row['receiver_verified'] == row['locally_policy_confirmed'] == width, 'pipeline stage counts')
                        require(row['public_confirmed_tps'] is None and row['vram_bytes'] is None
                                and row['hostile_network_availability'] is None and row['mempool_admitted'] is None, 'pipeline unmeasured claim')
                        confirmed+=len(facts)
                require(ledger.active()[0].hex() == branch['tip'] and state_root(ledger.read_active()[2]).hex() == branch['state_root'], 'pipeline final root')
            finally:
                ledger.close()
    return {'native_session_qualified_as': 'disposable-compute-cache', 'paired_samples': len(seen),
            'controlled_work_blocks_replayed': replayed, 'controlled_policy_confirmations_replayed': confirmed,
            'public_confirmed_tps': None, 'physical_power_loss': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence')
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--historical', action='store_true')
    parser.add_argument('--session', action='store_true')
    args = parser.parse_args()
    if args.session:
        if args.historical:
            parser.error('--session and --historical select different claims')
        args.evidence = args.evidence or args.root / 'evidence/pon-native-session-v1'
    if args.historical:
        from historical_evidence import validate_historical_cli
        value = validate_historical_cli(__file__, args.root, args.evidence or args.root / 'evidence/pon-client-confirmation-v1')
    else:
        value = validate(root=args.root, evidence=args.evidence)
    print(json.dumps(value, sort_keys=True))
