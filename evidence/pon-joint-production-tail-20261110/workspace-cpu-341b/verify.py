"""Reconcile retained original CI bytes; never execute archived commands."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / name).read_text())


def check(raw, row):
    assert len(raw) == row['bytes']
    assert hashlib.sha256(raw).hexdigest() == row['sha256']


def verify():
    assert __debug__, 'run without -O'
    for row in read('MANIFEST.json')['files']:
        check((ROOT / row['path']).read_bytes(), row)
    jobs = read('jobs.json')['jobs']
    assert len(jobs) == 4 and all(j['conclusion'] == 'success' for j in jobs)
    declarations = {a['id']: a for a in read('artifacts.json')['artifacts']}
    identities = []
    for row in read('archive-index.json'):
        raw = (ROOT / row['path']).read_bytes()
        check(raw, row)
        assert declarations[row['id']]['size_in_bytes'] == len(raw)
        assert declarations[row['id']]['digest'] == 'sha256:' + row['sha256']
        with zipfile.ZipFile(ROOT / row['path']) as z:
            infos = z.infolist()
            assert len(infos) == len({i.filename for i in infos}) == len(row['members']) == 391
            assert sum(i.file_size for i in infos) < 128 * 1024 * 1024
            assert all(i.file_size < 32 * 1024 * 1024 for i in infos)
            for member in row['members']:
                check(z.read(member['path']), member)
            before = json.loads(z.read('source-before.json'))
            assert before == json.loads(z.read('source-after.json'))
            assert before['tested_tree'] == 'eb37d4499ca92121a81ef9c0af1e7b221d5f85b1'
            expected = ('341b7b6195a44d3f4a758c98f846457567ac1de3' if before['kind'] == 'head'
                        else 'a040a36e5a16822e56cbed29a6dce31b8c265f67')
            assert before['tested_commit'] == expected
            hashes = {}
            for prefix, name in [('', 'node'), ('m06-', 'm06')]:
                sha = json.loads(z.read(prefix + 'binary.json'))['sha256']
                before_path = ('semantic-controls/m06-binary-before.sha256' if prefix else 'binary-before.sha256')
                assert z.read(before_path).decode().split()[0] == sha
                assert z.read(prefix + 'binary-after.sha256').decode().split()[0] == sha
                hashes[name] = sha
            executions = [json.loads(z.read(n)) for n in z.namelist()
                          if n.startswith('semantic-controls/') and n.endswith('.execution.json')]
            assert len(executions) == 60
            assert all(e['result'] == 'PASS' and e['executed_tests'] == 1 for e in executions)
            assert len({e['test'] for e in executions}) == 60
            for n in ['build.exit', 'test-step.exit', 'semantic-controls/semantic-step.exit']:
                assert z.read(n).strip() == b'0'
            rows = z.read('test-exits.tsv').decode().splitlines()[1:]
            assert len(rows) == 4 and all(r.split('\t')[1:] == ['0', '0', '0'] for r in rows)
            identities.append({'artifact_id': row['id'], 'source': expected, 'kind': before['kind'], **hashes})
    assert identities == read('binary-identities.json')
    return {'evidence_consistency': 'PASS', 'original_jobs_success': 4,
            'selected_semantic_controls_per_lane': 60, 'actual_joint_obligations_closed': 0,
            'native_cp_cg_cq': None, 'six_successor_bound': None, 'lifetime_bound': None,
            'qualification': 'HOLD_NO_GO', 'activation': False}


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
