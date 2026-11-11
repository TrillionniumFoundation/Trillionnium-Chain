"""Verify original compact CI receipts without executing their scripts."""
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
    assert __debug__
    for row in read('MANIFEST.json')['files']:
        check((ROOT / row['path']).read_bytes(), row)
    declarations = {a['id']: a for a in read('artifacts.json')['artifacts']}
    rows = read('archive-index.json')
    assert len(rows) == 6
    for row in rows:
        raw = (ROOT / row['path']).read_bytes()
        check(raw, row)
        assert len(raw) == declarations[row['id']]['size_in_bytes']
        assert declarations[row['id']]['digest'] == 'sha256:' + row['sha256']
        with zipfile.ZipFile(ROOT / row['path']) as z:
            assert len(z.namelist()) == len(set(z.namelist())) == len(row['members'])
            assert sum(i.file_size for i in z.infolist()) < 1024 * 1024
            for member in row['members']:
                check(z.read(member['path']), member)
            if 'rust-shard.json' in z.namelist():
                receipt = json.loads(z.read('rust-shard.json'))
                assert receipt['before'] == receipt['after']
                source = receipt['before']
                assert hashlib.sha256(z.read('rust-shard.sh')).hexdigest() == receipt['command_sha256']
                assert receipt['run']['GITHUB_RUN_ID'] == '42815422254'
                assert receipt['status'] == ('passed' if receipt['shard'] == 'runtime' else 'failed')
                assert receipt['exit_code'] == (0 if receipt['shard'] == 'runtime' else 1)
            else:
                source = json.loads(z.read('source.json'))
            expected = ('341b7b6195a44d3f4a758c98f846457567ac1de3' if source['kind'] == 'head'
                        else 'a040a36e5a16822e56cbed29a6dce31b8c265f67')
            assert source['tested_commit'] == expected
            assert source['tested_tree'] == 'eb37d4499ca92121a81ef9c0af1e7b221d5f85b1'
    jobs = {j['id']: j for j in read('jobs.json')['jobs']}
    for job in [129854464801, 129854465039, 129854464809, 129854465016]:
        assert jobs[job]['conclusion'] == 'success'
    for job in [129854464730, 129854464770]:
        assert jobs[job]['conclusion'] == 'failure'
    return {'receipt_consistency': 'PASS', 'source341b_runtime_lanes': 'success',
            'source341b_repository_lanes': 'success', 'source341b_quality_lanes': 'failure',
            'whole_ci_pass': False, 'actual_joint_obligations_closed': 0,
            'native_risk_bounds': None, 'qualification': 'HOLD_NO_GO'}


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
