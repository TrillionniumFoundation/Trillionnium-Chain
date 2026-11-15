"""Read-only reconciliation of retained original CI artifacts."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent


def verify():
    assert __debug__
    artifacts = json.loads(json.loads((ROOT / 'artifacts-api.json').read_text())['structuredContent']['content'])
    ids = {a['id']: a for a in artifacts['artifacts']}
    for row in json.loads((ROOT / 'archive-index.json').read_text()):
        data = (ROOT / row['path']).read_bytes()
        assert len(data) == row['bytes'] == ids[row['id']]['size_in_bytes']
        assert hashlib.sha256(data).hexdigest() == row['sha256']
        assert 'sha256:' + row['sha256'] == ids[row['id']]['digest']
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            assert len(set(names)) == len(names) == len(row['members'])
            for member in row['members']:
                raw = archive.read(member['path'])
                assert len(raw) == member['bytes']
                assert hashlib.sha256(raw).hexdigest() == member['sha256']
    for row in json.loads((ROOT / 'logs-index.json').read_text()):
        stored = (ROOT / row['path']).read_bytes()
        assert hashlib.sha256(stored).hexdigest() == row['stored_sha256']
        raw = gzip.decompress(stored)
        assert len(raw) == row['decoded_bytes'] and hashlib.sha256(raw).hexdigest() == row['decoded_sha256']
    with zipfile.ZipFile(ROOT / '13752345156.zip') as archive:
        m = json.loads(archive.read('from-zero-native/manifest.json'))
        for path, sha in m['files'].items():
            assert hashlib.sha256(archive.read('from-zero-native/' + path)).hexdigest() == sha
        assert m['source_before'] == m['source_after']
        assert m['source_before']['commit'] == '4716bade250f327b012a098418f4eece6b73fcaa'
        assert m['source_before']['tree'] == 'bbc0278f87282d9bcf4e22b167040233516da310'
        assert m['binary_sha256_before'] == m['binary_sha256_after'] == '68a31cc8b95aee51e6202c275807ee48b0fab8ffd4498d30e30f1a6dbac374e1'
        assert len(m['runs']) == 5 and all(r['process']['exit_code'] == 0 and not r['process']['timed_out'] for r in m['runs'])
        assert m['terminal']['native_execution_completed'] is True
        assert m['terminal']['acceptance_passed'] is False and m['failures'] == ['CONFIRMATION_TARGET']
        assert [p['business']['reported_independently_confirmed_in_window'] for p in m['confirmation_observation']['phases']] == [1, 0]
    return {'packet_consistency': 'PASS', 'original_acceptance': False, 'actual_joint_obligations_closed': 0, 'qualification': 'HOLD_NO_GO'}


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
