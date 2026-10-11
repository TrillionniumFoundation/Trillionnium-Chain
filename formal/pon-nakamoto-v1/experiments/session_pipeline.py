"""Controlled real-work -> persisted block -> receiver verification -> confirmation cost.

Uses the existing Ledger/client and explicit native work/session binaries. It is an
unpaced logical-clock experiment on one administrator's host, not public-network TPS,
an independent operator campaign, or a complete persistent native node.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract_wire import H, NETWORK, PARAMETER_HASH, PARAMS, canonical, header_decode, state_root
from ledger import GENESIS, Ledger, key, public, sign
from client_confirmation import confirmation, confirmations, history_pages, receive_page


def git(*args):
    return subprocess.check_output(['git', *args], cwd=Path(__file__).resolve().parents[3], text=True).strip()


def run(output, samples=3, width=16):
    if type(samples) is not int or not 2 <= samples <= 8 or type(width) is not int or not 1 <= width <= 32:
        raise ValueError('PIPELINE_BUDGET')
    if git('status', '--porcelain'):
        raise ValueError('DIRTY_SOURCE')
    binaries = {name: Path(os.environ[name]).resolve() for name in ('TRNM_NATIVE_WORK', 'TRNM_NATIVE_SESSION')}
    if not all(path.is_file() for path in binaries.values()) or os.environ.get('TRNM_NATIVE_EXECUTOR'):
        raise ValueError('EXPLICIT_NATIVE_COMPONENTS_REQUIRED')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows, branches = [], []
    now = PARAMS['genesis_timestamp'] + 100000
    for case in ('independent', 'hot-sender'):
        packets, pages, stage_rows = [], [], []
        with tempfile.TemporaryDirectory(prefix='pon-controlled-pipeline-') as private:
            source, receiver = Ledger(Path(private) / 'source'), Ledger(Path(private) / 'receiver')
            try:
                cursor = GENESIS
                def block(txs, phase):
                    nonlocal cursor
                    parent = source.active()[0]
                    start = time.perf_counter_ns()
                    header, transactions, proof = source.make(parent, txs)
                    constructed = time.perf_counter_ns()
                    tip = source.admit(header, transactions, proof, now)
                    source.recover()
                    persisted = time.perf_counter_ns()
                    delivered = []
                    for raw in history_pages(source, tip, cursor):
                        fact = receive_page(receiver, raw, expected_tip=tip, after=cursor, observed_now=now)
                        cursor = bytes.fromhex(fact['next_after'])
                        delivered.append(json.loads(raw))
                    end = time.perf_counter_ns()
                    if cursor != tip or receiver.active()[0] != tip:
                        raise ValueError('RECEIVER_NOT_ACTIVE')
                    if source.read_active()[2] != receiver.read_active()[2]:
                        raise ValueError('RECEIVER_STATE_PARITY')
                    packets.append({'header': header.hex(), 'transactions': [tx.hex() for tx in transactions],
                                    'proof': proof.hex(), 'block': tip.hex(), 'phase': phase})
                    pages.extend(delivered)
                    stage_rows.append({'phase': phase, 'height': header_decode(header)['height'],
                                       'block': tip.hex(), 'transaction_count': len(txs),
                                       'construction_search_ns': constructed-start,
                                       'source_admit_persist_ns': persisted-constructed,
                                       'receiver_delivery_validation_ns': end-persisted,
                                       'page_bytes': sum(len(canonical(page)) for page in delivered),
                                       'proof_bytes': len(proof)})
                    return tip
                # Actual signed and work-verified setup; not an imported state snapshot.
                setup = [sign(key(0), i+1, 'transfer', {'recipient': public(key(i+4)), 'amount': 250000}, expiry=100000)
                         for i in range(width)]
                block(setup, 'funding')
                for sample in range(samples):
                    txs = []
                    for index in range(width):
                        who = 4 if case == 'hot-sender' else index+4
                        nonce = sample*width+index+1 if case == 'hot-sender' else sample+1
                        txs.append(sign(key(who), nonce, 'transfer', {'recipient': public(key(100+index)) if case == 'independent' else public(key(1)), 'amount': 1}, expiry=100000))
                    start = time.perf_counter_ns()
                    included = block(txs, 'application')
                    inclusion_elapsed = time.perf_counter_ns()-start
                    for _ in range(PARAMS['confirmation_depth']):
                        block([], 'confirmation-fill')
                    confirmation_start = time.perf_counter_ns()
                    observed = confirmations(receiver, [(H('tx-id', tx), included) for tx in txs], observed_now=now)
                    completed = time.perf_counter_ns()
                    if any(row['status'] != 'confirmed' or row['finalized'] or row['execution_authority'] for row in observed):
                        raise ValueError('CONFIRMATION_NOT_VERIFIED')
                    rows.append({'scenario': case, 'sample': sample, 'submitted': len(txs),
                                 'source_included': len(txs), 'receiver_verified': len(txs),
                                 'locally_policy_confirmed': len(observed), 'included_block': included.hex(),
                                 'inclusion_pipeline_ns': inclusion_elapsed,
                                 'confirmation_query_ns': completed-confirmation_start,
                                 'submission_through_confirmation_ns': completed-start,
                                 'confirmations': observed, 'clock_scope': 'explicit-logical-test-clock',
                                 'mempool_admitted': None, 'public_confirmed_tps': None,
                                 'gpu_used': False, 'vram_bytes': None, 'hostile_network_availability': None})
                branches.append({'scenario': case, 'tip': source.active()[0].hex(),
                                 'state_root': state_root(receiver.read_active()[2]).hex(),
                                 'blocks': stage_rows, 'actual_work_verified_blocks': len(packets),
                                 'source_database_bytes': sum(p.stat().st_size for p in source.directory.iterdir() if p.is_file()),
                                 'receiver_database_bytes': sum(p.stat().st_size for p in receiver.directory.iterdir() if p.is_file())})
            finally:
                source.close()
                receiver.close()
        (output/(case+'-packets.json')).write_bytes(canonical(packets))
        (output/(case+'-pages.json')).write_bytes(canonical(pages))
    report = {'schema': 'pon-controlled-confirmation-pipeline-v1',
              'source_commit': git('rev-parse', 'HEAD'), 'source_tree': git('rev-parse', 'HEAD^{tree}'),
              'source_clean': not git('status', '--porcelain'),
              'network': NETWORK.hex(), 'parameters': PARAMETER_HASH.hex(),
              'binaries': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name,path in binaries.items()},
              'samples_per_scenario': samples, 'transactions_per_sample': width, 'samples': rows, 'branches': branches,
              'clock_scope': 'explicit-logical-test-clock', 'target_spacing_wall_paced': False,
              'transport_scope': 'bounded-pages-in-one-controller-with-separate-ledger-stores',
              'source_and_receiver_compute': 'separate-native-stdio-processes',
              'full_native_node': False, 'independent_operators': False, 'public_network_ready': False,
              'physical_power_loss': False, 'ordinary_hepta_entry': False, 'production_activation': False,
              'public_confirmed_tps': None,
              'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file()},
              'summary': [{'scenario': case, 'confirmed_transactions': sum(row['locally_policy_confirmed'] for row in rows if row['scenario']==case),
                           'median_submission_through_confirmation_ns': statistics.median(row['submission_through_confirmation_ns'] for row in rows if row['scenario']==case)}
                          for case in ('independent','hot-sender')]}
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'summary': report['summary'], 'work_verified_blocks': sum(row['actual_work_verified_blocks'] for row in branches),
                      'public_confirmed_tps': None, 'full_native_node': False}), flush=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',required=True)
    parser.add_argument('--samples',type=int,default=3)
    parser.add_argument('--width',type=int,default=16)
    args=parser.parse_args()
    run(args.out,args.samples,args.width)
