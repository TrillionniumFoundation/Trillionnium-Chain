#!/usr/bin/env python3
"""Review the frozen source-only change; does not execute or qualify Node."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = None
OLD = '7150d96a2112875b4afcf3023361a5cef4a0e4b1'
NEW = '7e044b65454f4c9ea505591727332acffb33e7e5'
STORE = 'trillionnium/crates/trnm-pon-node/src/store.rs'
WIRE = 'trillionnium/crates/trnm-protocol/src/pon_wire.rs'
CACHE = 'trillionnium/crates/trnm-crypto-primitives/src/pon_work/rejection_cache.rs'
OUT = None


def git_bytes(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=ROOT)


def blob(revision, path):
    return git_bytes('show', revision + ':' + path)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def method(value, signature):
    """Use the exact unique signature and Rustfmt's four-space method end.

    This is intentionally a bounded byte comparison, not a Rust parser or
    a proof of the method's semantics.
    """
    assert value.count(signature) == 1, signature
    start = value.index(signature)
    end = value.index(b'\n    }\n', start) + len(b'\n    }\n')
    return value[start:end]


def main():
    global ROOT, OUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    ROOT, OUT = args.root, args.output
    OUT.mkdir(parents=True, exist_ok=True)
    namespace = {}
    exec(compile(blob(NEW, 'scripts/w1_lifetime_ledger.py'),
                 'frozen-source-ledger', 'exec'),
         {'__file__': str(ROOT / 'scripts/w1_lifetime_ledger.py'),
          '__name__': 'source_review'}, namespace)
    rows = []
    for path, declared in namespace['SOURCE_PINS'].items():
        previous, current = blob(OLD, path), blob(NEW, path)
        assert sha(previous) == declared, path
        rows.append({'path': path, 'old_sha256': sha(previous),
                     'new_sha256': sha(current), 'unchanged': previous == current})
    assert [row['path'] for row in rows if not row['unchanged']] == [STORE]

    checks = []
    for path, signature, description in [
        (STORE, b'    pub(crate) fn verify(packet: Packet) -> Result<Self> {',
         'Complete native verifier keeps challenge, work_task, target and proof input expressions.'),
        (STORE, b'    pub(crate) fn verify_with_progress(',
         'Progress-aware complete native verifier and its exact inputs are unchanged.'),
        (STORE, b'    pub(crate) fn verify_with_arithmetic_facts(',
         'Arithmetic-fact path retains the same complete W1 input expressions.'),
        (CACHE, b'    fn key(challenge: Hash, task: Hash, target: Hash, bytes: &[u8]) -> Option<Hash> {',
         'Optional negative-cache hash retains its tag, profile and complete proof/context inputs.'),
        (WIRE, b'    pub fn encode(&self) -> Vec<u8> {',
         'PNH1 header byte grammar and field order are unchanged.'),
        (WIRE, b'    pub fn challenge(&self) -> Hash {',
         'W1 challenge still hashes the exact encoded PNH1 header.'),
    ]:
        old, new = method(blob(OLD, path), signature), method(blob(NEW, path), signature)
        assert old == new, (path, signature)
        checks.append({'path': path, 'signature': signature.decode(),
                       'unchanged': True, 'sha256': sha(new),
                       'exact_bytes_utf8': new.decode(), 'observation': description})

    credit = b'        let work = parent\n            .work\n            .checked_add(consensus::required_work(h.target)?)?;'
    for revision in (OLD, NEW):
        assert blob(revision, STORE).count(credit) == 1
    checks.append({'path': STORE, 'unchanged': True, 'sha256': sha(credit),
                   'exact_bytes_utf8': credit.decode(),
                   'observation': 'Admission still adds parent work and the complete header target required_work.'})

    diff = git_bytes('diff', '--no-ext-diff', '--no-textconv', OLD, NEW, '--', STORE, CACHE, WIRE)
    (OUT / 'reviewed-source.diff').write_bytes(diff)
    report = {
        'schema': 'trnm-w1-lifetime-source-review-v1',
        'old_selected_source': OLD, 'new_selected_source': NEW,
        'source_rows': rows, 'identical_selected_files': sum(row['unchanged'] for row in rows),
        'changed_selected_files': [row['path'] for row in rows if not row['unchanged']],
        'exact_byte_comparisons': checks,
        'reviewed_diff_sha256': sha(diff), 'reviewed_diff_bytes': len(diff),
        'observed_changes': [
            'Store gains task/demand/async observation modules and read-only reconciliation, with current admission and state-readback changes.',
            'Optional rejection-cache wrappers add bounded reservation/storage metadata and path observations; they cannot mint VerifiedWork on a cache hit.',
            'pon_wire payload_len accepts separately decoded funded-service task/decision payloads; Header encode/challenge bytes remain unchanged.',
        ],
        'scope': 'Only the selected source-survey statements and exact W1 call/input/credit expressions are reviewed; not all owner semantics or hash uses.',
        'native_tests_executed': False,
        'all_hash_calls_or_runtime_counts_preserved': False,
        'quantum_query_budget_instantiated': False,
        'whole_chain_pq_qualified': False,
        'production_activation': False,
    }
    (OUT / 'source-review.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'identical_selected_files': report['identical_selected_files'],
                      'changed_selected_files': report['changed_selected_files'],
                      'exact_byte_comparisons': len(checks),
                      'reviewed_diff_sha256': sha(diff)}))


if __name__ == '__main__':
    main()
