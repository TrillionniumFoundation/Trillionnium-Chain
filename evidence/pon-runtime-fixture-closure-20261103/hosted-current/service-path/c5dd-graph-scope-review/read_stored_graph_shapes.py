#!/usr/bin/env python3
"""Read original archived SQLite bytes in disposable immutable read-only copies.

This is structural evidence extraction, not native protocol verification or a
benchmark. No original database, source tree or target is opened for writing.
"""
import collections
import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
ZIP = Path('/workspace/scratch/b5a148b09b11/next-hosted/c5dd7c-review/c5dd7c-original-campaign-13276003536.zip')
ZIP_SHA = '78e1b41ced06d6b77568a132d60623a1a7b5059ef9791dd43cc8ed4110efaacb'
COMMIT = 'c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'
REPO = Path('/workspace/scratch/b5a148b09b11/fixture-committed-check')
PRIOR = HERE.parent / 'c5dd-baseline-critical-path' / 'critical-path-readback.json'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def root_summary(root):
    return {'node': bytes(root['node']).hex() if root['node'] is not None else None,
            'digest': bytes(root['digest']).hex(), 'count': root['count'], 'balance': root['balance']}


def inspect_graph(nodes, root):
    """Only inspect stored IDs/edges; do not claim native hash/grammar validation."""
    ids, frontier = set(), {}
    stack = [bytes(root['node'])] if root['node'] is not None else []
    while stack:
        node_id = stack.pop()
        assert node_id not in ids
        ids.add(node_id)
        raw = nodes[node_id]
        if raw[0] == 0:
            assert len(raw) == 49
            continue
        assert raw[0] == 1 and len(raw) == 163
        depth = int.from_bytes(raw[1:3], 'little')
        path = raw[3:35]
        if depth >= 4:
            frontier.setdefault(path[0] >> 4, node_id)
        stack.extend([raw[67:99], raw[35:67]])
    assert len(ids) == root['count'] * 2 - 1
    return ids, frontier


def exposed_shape(nodes, root, frontier):
    """Predict exposed node IDs for the existing16-prefix matching rule only."""
    hits, visited = [], []
    eligible = set(frontier.values())
    stack = [bytes(root['node'])] if root['node'] is not None else []
    while stack:
        node_id = stack.pop()
        visited.append(node_id)
        raw = nodes[node_id]
        if node_id in eligible:
            assert raw[0] == 1
            hits.append(node_id.hex())
            continue
        if raw[0] == 1:
            stack.extend([raw[67:99], raw[35:67]])
    return {'exact_frontier_ids_encountered': hits, 'frontier_hit_count_from_stored_shape': len(hits),
            'exposed_node_count_from_stored_shape': len(visited),
            'native_runtime_node_count_observed': False}


def main():
    assert sha(ZIP.read_bytes()) == ZIP_SHA
    prior_raw = PRIOR.read_bytes()
    assert sha(prior_raw) == '57ce0956d1927578cd5b4f1364ca38689a0256bbdba85c981358eb3c3c26e492'
    prior = json.loads(prior_raw)
    records = []
    with zipfile.ZipFile(ZIP) as archive:
        for run in range(1, 4):
            name = f'run-{run}-raw/baseline/independent-client/native.sqlite'
            raw = archive.read(name)
            assert not any(n in archive.namelist() for n in [name + '-wal', name + '-shm'])
            with tempfile.TemporaryDirectory(dir=HERE) as tmp:
                copy = Path(tmp) / 'native.sqlite'
                copy.write_bytes(raw)
                copy.chmod(0o400)
                db = sqlite3.connect(copy.as_uri() + '?mode=ro&immutable=1', uri=True)
                db.execute('PRAGMA query_only=ON')
                assert db.execute('PRAGMA query_only').fetchone() == (1,)
                active = db.execute('SELECT hex(tip),generation,state_slot FROM active').fetchone()
                rows = db.execute('SELECT b.height,hex(b.id),s.data FROM blocks b JOIN native_state_commitments s ON s.block=b.id ORDER BY b.height').fetchall()
                by_height = {h: json.loads(data) for h, _, data in rows}
                assert set(by_height) == set(range(13))
                assert active[0].lower() == prior['runs'][run - 1]['actual_result']['final_client_tip']
                assert active[1:] == (5, 5)
                assert len({json.dumps(by_height[h]['accounts'], sort_keys=True) for h in range(5, 12)}) == 1
                assert by_height[4]['accounts'] != by_height[5]['accounts'] != by_height[12]['accounts']
                nodes = dict(db.execute('SELECT id,data FROM archive_nodes'))
                shapes = []
                for source_height, targets in [(4, [0]), (5, [0, 4]), (12, [0, 11])]:
                    source = by_height[source_height]['accounts']
                    ids, frontier = inspect_graph(nodes, source)
                    assert len(frontier) == 16
                    target_shapes = []
                    for target_height in targets:
                        target = by_height[target_height]['accounts']
                        target_ids, _ = inspect_graph(nodes, target)
                        shaped = exposed_shape(nodes, target, frontier)
                        if target_height == 0:
                            assert not shaped['exact_frontier_ids_encountered']
                        else:
                            assert shaped['frontier_hit_count_from_stored_shape'] > 0
                        target_shapes.append({'height': target_height, 'full_node_count': len(target_ids), **shaped})
                    shapes.append({'source_height': source_height, 'full_node_count': len(ids),
                                   'frontier_slots': len(frontier), 'targets': target_shapes})
                steps = db.execute('SELECT ordinal,kind,b.height FROM steps JOIN blocks b ON b.id=steps.block ORDER BY ordinal').fetchall()
                events = db.execute('SELECT ordinal,kind,b.height FROM events JOIN blocks b ON b.id=events.block WHERE generation=5 ORDER BY ordinal').fetchall()
                assert steps == events == [(i, 1, i + 5) for i in range(7)]
                reorg = db.execute('SELECT hex(old_tip),hex(new_tip),generation,cursor,done FROM reorg').fetchone()
                assert reorg[2:] == (5, 7, 1)
                snapshots = [r[0] for r in db.execute('SELECT height FROM snapshots JOIN blocks ON snapshots.block=blocks.id ORDER BY height')]
                assert snapshots == list(range(13))
                deltas = dict(db.execute("SELECT b.height,count(*) FROM deltas d JOIN blocks b ON b.id=d.block WHERE d.key LIKE 'account:%' GROUP BY b.height"))
                assert deltas[5] == deltas[12] == 2 and all(deltas.get(h, 0) == 0 for h in range(6, 12))
                db.close()
                assert copy.read_bytes() == raw
                assert sorted(p.name for p in Path(tmp).iterdir()) == ['native.sqlite']
                records.append({'run': run, 'archive_member': name, 'bytes': len(raw), 'sha256': sha(raw),
                                'reader': 'SQLite immutable=1, mode=ro, query_only=ON on an exact disposable scratch copy; no retained WAL or SHM member; source and copy unchanged',
                                'sqlite_library_version_used_only_for_readback': sqlite3.sqlite_version,
                                'final_active': {'tip': active[0].lower(), 'generation': active[1], 'slot': active[2]},
                                'roots': [{'height': h, 'block': block.lower(), 'record_sha256': sha(data),
                                           'accounts': root_summary(by_height[h]['accounts'])} for h, block, data in rows],
                                'retained_snapshot_heights': snapshots,
                                'account_delta_rows_by_height': deltas,
                                'reorg': {'old': reorg[0].lower(), 'new': reorg[1].lower(), 'generation': reorg[2], 'cursor': reorg[3], 'done': reorg[4]},
                                'steps': steps, 'published_events': events,
                                'structural_frontier_comparisons': shapes,
                                'shape_is_runtime_measurement_or_protocol_acceptance': False})
    paths = [
        'trillionnium/crates/trnm-pon-node/src/store.rs',
        'trillionnium/crates/trnm-pon-node/src/store/historical_commitment.rs',
        'trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs',
        'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs',
        'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/history_arithmetic.rs',
        'trillionnium/crates/trnm-pon-node/src/account_archive_prototype.rs',
        'trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_scoped_readback.rs',
        'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/frontier_tests.rs',
        'trillionnium/crates/trnm-pon-node/src/store/reorg_readback_tests.rs',
    ]
    sources = []
    for path in paths:
        raw = subprocess.run(['git', '--no-replace-objects', 'show', COMMIT + ':' + path],
                             cwd=REPO, check=True, stdout=subprocess.PIPE).stdout
        sources.append({'commit': COMMIT, 'path': path, 'sha256': sha(raw), 'bytes': len(raw)})
    report = {'schema': 'trnm-c5dd-archived-graph-scope-shapes-v1',
              'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'commit': COMMIT, 'status': 'READ_ONLY_STRUCTURAL_EVIDENCE_NOT_NATIVE_VALIDATION',
              'archive': {'path': str(ZIP), 'sha256': ZIP_SHA},
              'prior_actor_readback': {'path': str(PRIOR), 'sha256': sha(prior_raw)},
              'reader': {'path': str(Path(__file__)), 'sha256': sha(Path(__file__).read_bytes())},
              'source_bindings': sources,
              'initial_read_attempt': 'A direct SQLite deserialize into memory could not open the original WAL-format header (OperationalError: unable to open database file). No byte/header alteration was made; subsequent exact disposable files were opened immutable/read-only.',
              'limits': ['Stored graph ID/edge/Root comparisons are posthoc structural readback, not native decode/hash/semantic verification.',
                         'Final database cannot reproduce aborted statement state or prove individual runtime frontier hits.',
                         'Native stage counters provide no full/partial/whole-root-hit outcomes by callsite; timing allocation to these roles remains unknown.'],
              'runs': records, 'native_code_executed': False, 'source_or_target_modified': False}
    with (HERE / 'stored-graph-shapes.json').open('x') as target:
        json.dump(report, target, indent=2)
        target.write('\n')
    print(json.dumps({'runs': len(records), 'all_final_sql_states_match_original_reports': True,
                      'stored_graph_shapes_sha256': sha((HERE / 'stored-graph-shapes.json').read_bytes()),
                      'structural_shapes': records[0]['structural_frontier_comparisons']}))


if __name__ == '__main__':
    main()
