#!/usr/bin/env python3
"""Read original archived counters/rows; no native execution or benchmark."""
import datetime
import hashlib
import json
import pathlib
import sqlite3
import subprocess
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path('/workspace/scratch/b5a148b09b11/chain-six-axis')
ARCHIVE = pathlib.Path('/workspace/scratch/b5a148b09b11/next-hosted/c5dd7c-review/c5dd7c-original-campaign-13276003536.zip')
COMMIT = 'c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'
EXPECTED_ZIP = '78e1b41ced06d6b77568a132d60623a1a7b5059ef9791dd43cc8ed4110efaacb'
PREFIX = 'trillionnium/crates/trnm-pon-node/'
SOURCES = [
    'src/account_archive_prototype.rs',
    'src/account_archive_prototype/native_store.rs',
    'src/account_archive_prototype/native_node_reader.rs',
    'src/account_archive_prototype/native_node_decode.rs',
    'src/account_archive_prototype/native_scoped_readback.rs',
    'src/account_archive_execution/state_witness.rs',
    'src/store/native_authenticated.rs',
    'src/store/native_authenticated/arithmetic_cache.rs',
    'src/store/native_authenticated/arithmetic_cache/root_arithmetic/tests.rs',
    'src/store/native_authenticated/post_write_readback.rs',
    'src/store.rs',
    'src/store/reorg_cancellation.rs',
    'src/store/reorg_cancellation/tests.rs',
    'src/store/reorg_readback_tests.rs',
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def delta(before, after):
    assert before.keys() == after.keys()
    result = {key: after[key] - value for key, value in before.items()}
    assert all(value >= 0 for value in result.values())
    return result


def source_bindings():
    result = []
    for name in SOURCES:
        relative = PREFIX + name
        original = subprocess.check_output(['git', 'show', f'{COMMIT}:{relative}'], cwd=REPO)
        current = (REPO / relative).read_bytes()
        assert original == current, relative
        result.append({'commit': COMMIT, 'path': relative, 'bytes': len(original),
                       'sha256': digest(original), 'current_workspace_bytes_equal': True})
    return result


def sql_readback(zipped, run):
    member = f'run-{run}-raw/baseline/independent-client/native.sqlite'
    raw = zipped.read(member)
    assert member + '-wal' not in zipped.namelist()
    assert member + '-shm' not in zipped.namelist()
    with tempfile.TemporaryDirectory(prefix='exact-db-read-', dir=HERE) as temporary:
        db_file = pathlib.Path(temporary) / 'native.sqlite'
        db_file.write_bytes(raw)
        db_file.chmod(0o400)
        db = sqlite3.connect(db_file.as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            db.execute('PRAGMA query_only=ON')
            assert db.execute('PRAGMA query_only').fetchone() == (1,)
            rows = []
            for height, encoded in db.execute(
                    'SELECT b.height,c.data FROM native_state_commitments c '
                    'JOIN blocks b ON b.id=c.block WHERE b.height BETWEEN 4 AND 11 '
                    'ORDER BY b.height'):
                record = json.loads(encoded)
                state = record['state']
                counts = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(key LIKE 'account:%'),0) FROM deltas WHERE block=?",
                    (bytes(record['block']),),
                ).fetchone()
                rows.append({'height': height, 'record_sha256': digest(encoded),
                             'block': bytes(record['block']).hex(),
                             'account_root': bytes(record['accounts']['digest']).hex(),
                             'state_root': bytes(state['state_root']).hex(),
                             'non_account_root': bytes(state['non_account_root']).hex(),
                             'non_account_count': state['non_account_count'],
                             'delta_rows': counts[0], 'account_delta_rows': counts[1],
                             'non_account_delta_rows': counts[0] - counts[1]})
            assert [row['height'] for row in rows] == list(range(4, 12))
            assert len({row['account_root'] for row in rows[1:]}) == 1
            assert rows[0]['account_root'] != rows[1]['account_root']
        finally:
            db.close()
        assert db_file.read_bytes() == raw
        assert sorted(p.name for p in pathlib.Path(temporary).iterdir()) == ['native.sqlite']
    return {'member': member, 'bytes': len(raw), 'sha256': digest(raw), 'rows': rows,
            'reader': 'Exact disposable bytes; mode=ro&immutable=1, query_only=ON; SELECT only; no WAL/SHM; bytes rehashed unchanged',
            'semantic_native_verification_performed': False}


def main():
    zipped_bytes = ARCHIVE.read_bytes()
    assert digest(zipped_bytes) == EXPECTED_ZIP
    bindings = source_bindings()
    runs = []
    with zipfile.ZipFile(ARCHIVE) as zipped:
        for run in (1, 2, 3):
            member = f'run-{run}-raw/baseline.json'
            raw = zipped.read(member)
            phase = json.loads(raw)
            before = phase['client_native_history_arithmetic_before']
            after = phase['client_native_history_arithmetic_after']
            decoding = delta(before['account_node_decode_arithmetic']['counters'],
                             after['account_node_decode_arithmetic']['counters'])
            complete = delta(before['complete_root_arithmetic']['counters'],
                             after['complete_root_arithmetic']['counters'])
            before_stages = {entry['stage']: entry['totals'] for entry in before['stages']}
            stages = {entry['stage']: delta(before_stages[entry['stage']], entry['totals'])
                      for entry in after['stages']}
            runs.append({'run': run, 'member': member, 'member_bytes': len(raw),
                         'member_sha256': digest(raw),
                         'client_arithmetic_before': before,
                         'client_arithmetic_after': after,
                         'decode_delta': decoding,
                         'decode_exact_hit_percent': 100 * decoding['exact_hits'] / decoding['calls'],
                         'complete_arithmetic_delta': complete,
                         'stage_deltas': stages,
                         'all_signed_rounds_confirmed_in_window': phase['all_signed_rounds_confirmed_in_window'],
                         'state_backend': phase['state_backend'],
                         'sql_retained_complete_states': sql_readback(zipped, run)})
    output = {'schema': 'c5dd-account-graph-internal-source-readback-v1',
              'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'commit': COMMIT,
              'scope': 'Original client baseline before/after arithmetic observations; original final SQL structural facts. Not new runtime execution, per-call timing, benchmark or optimization acceptance.',
              'archive': {'path': str(ARCHIVE), 'bytes': len(zipped_bytes), 'sha256': EXPECTED_ZIP},
              'reader': {'path': str(pathlib.Path(__file__).resolve()),
                         'sha256': digest(pathlib.Path(__file__).read_bytes())},
              'source_bindings': bindings, 'runs': runs,
              'native_executions': 0, 'repository_or_target_mutations': False}
    path = HERE / 'raw-counters-and-state-shapes.json'
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'path': str(path), 'bytes': path.stat().st_size,
                      'sha256': digest(path.read_bytes())}))


if __name__ == '__main__':
    main()
