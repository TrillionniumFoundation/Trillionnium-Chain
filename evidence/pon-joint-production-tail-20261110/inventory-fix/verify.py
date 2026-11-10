import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parent


def verify():
    assert __debug__
    before = json.loads((ROOT / 'source-before.report.json').read_text())
    after = json.loads((ROOT / 'source-after.report.json').read_text())
    assert before == after and before['tracked_worktree_verified'] is True
    assert before['tested_commit'] == 'db9991c537e3469f1b7b6e1fa6f8466ac62edc4f'
    assert before['tested_tree'] == '64f5c864417aa567239dd67d3113eb8a0cef795e'
    expected = {'tail': 27, 'dynamic': 28, 'qualification': 34, 'ci-tests': 167, 'integrity': 43}
    for name, count in expected.items():
        row = json.loads((ROOT / (name + '.json')).read_text())
        assert row['source_commit'] == before['tested_commit'] and row['exit_code'] == 0
        log = (ROOT / (name + '.stderr.log')).read_bytes()
        assert hashlib.sha256(log).hexdigest() == row['stderr_sha256']
        assert re.findall(rb'Ran (\d+) tests?', log)[-1] == str(count).encode()
        assert not re.search(rb'OK \(skipped=', log)
    assert sum(expected.values()) == 299
    assert json.loads((ROOT / 'inventory-before.json').read_text())['exit_code'] == 1
    for name in ('inventory-after', 'inventory', 'ci', 'repository', 'qualification-check'):
        assert json.loads((ROOT / (name + '.json')).read_text())['exit_code'] == 0
    assert json.loads((ROOT / 'promotion-refusal.json').read_text())['exit_code'] == 3
    for row in json.loads((ROOT / 'original-runtime-shards.json').read_text()):
        raw = base64.b64decode(row['zip_base64'], validate=True)
        assert raw == (ROOT / ('original-shard-' + str(row['artifact_id']) + '.zip')).read_bytes()
        assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            assert sorted(z.namelist()) == ['rust-shard.json', 'rust-shard.sh']
            r = json.loads(z.read('rust-shard.json'))
            assert r['before'] == r['after'] and r['exit_code'] == 0 and r['status'] == 'passed'
            assert r['before']['tested_tree'] == 'bbc0278f87282d9bcf4e22b167040233516da310'
            assert hashlib.sha256(z.read('rust-shard.sh')).hexdigest() == r['command_sha256'] == 'c2369d386856e03a4e6566b4232ccdfb43f2672ca49d2a7070ebd2bfe7d0e9ae'
    for row in json.loads((ROOT / 'original-runtime-summary.json').read_text()):
        log = gzip.decompress((ROOT / ('original-runtime-' + str(row['job_id']) + '.log.gz')).read_bytes()).decode()
        roster = [line for line in log.splitlines() if 'test consensus::tests::' in line]
        assert roster == row['consensus_roster'] and len(roster) == 10
        assert len(set(line.split('test consensus::tests::', 1)[1].split(' ... ')[0] for line in roster)) == 10
        assert all(line.endswith(' ... ok') for line in roster)
        summaries = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', log)
        assert len(summaries) == row['summary_count'] == 430
        assert sum(int(s[0]) for s in summaries) == row['reported_passed'] == 5069
        assert sum(int(s[2]) for s in summaries) == row['reported_ignored'] == 83
    return {'packet_consistency': 'PASS', 'fresh_python_methods': 299, 'repaired_source_native_execution': False, 'actual_joint_obligations_closed': 0, 'qualification': 'HOLD_NO_GO'}


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
