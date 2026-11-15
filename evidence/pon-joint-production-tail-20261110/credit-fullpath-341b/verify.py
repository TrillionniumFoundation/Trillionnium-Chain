"""Read-only reconciliation of original artifacts, not execution or qualification."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / name).read_text())


def digest(raw, row):
    assert len(raw) == row['bytes']
    assert hashlib.sha256(raw).hexdigest() == row['sha256']


def verify():
    assert __debug__
    for row in read('MANIFEST.json')['files']:
        digest((ROOT / row['path']).read_bytes(), row)
    for row in read('archive-index.json'):
        raw = (ROOT / row['path']).read_bytes()
        digest(raw, row)
        declaration = next(a for a in read(row['api'])['artifacts'] if a['id'] == row['id'])
        assert declaration['size_in_bytes'] == len(raw)
        assert declaration['digest'] == 'sha256:' + row['sha256']
        with zipfile.ZipFile(ROOT / row['path']) as z:
            infos = z.infolist()
            assert len(infos) == len({i.filename for i in infos}) == len(row['members'])
            assert sum(i.file_size for i in infos) < 128 * 1024 * 1024
            for member in row['members']:
                digest(z.read(member['path']), member)
            before = json.loads(z.read('source-before.json'))
            assert before == json.loads(z.read('source-after.json'))
            assert before['tested_tree'] == 'eb37d4499ca92121a81ef9c0af1e7b221d5f85b1'
            assert before['tested_commit'] == row['source']
            if row['id'] != 13778293257:
                completion = json.loads(z.read('finite-math/completion.json'))
                assert completion['finite_math_checks'] == 'PASS'
                assert completion['overall'] == 'HOLD'
                assert completion['distinct_named_tests_passed'] == 77
                assert completion['actual_w1_minimum_cost'] == completion['mixed_consensus_bound'] == completion['stateful_portfolio_bound'] == 'UNPROVED'
                assert completion['production_activation'] is False
                tests = json.loads(z.read('finite-math/test-outcomes.json'))
                assert tests['passed'] is True and tests['distinct_tests'] == 77
                assert not tests['failures'] and not tests['errors']
                assert z.read('finite-math/sources-before.json') == z.read('finite-math/sources-after.json')
            else:
                collector = json.loads(z.read('collector-output.json'))
                assert hashlib.sha256(z.read('processes/preregistration.json')).hexdigest() == collector['manifest_sha256']
                assert hashlib.sha256(z.read('processes/process-observations.json')).hexdigest() == collector['observations_sha256']
                context = json.loads(z.read('processes/context.json'))
                assert context['source_commit'] == row['source']
                assert context['binary_sha256'] == 'f8eeb2ddce66949e11c433f34389f75966ec127a20beb9dcad3baddcf5acb4e4'
                gate = json.loads(z.read('processes/gate-readback.json'))
                manifest = json.loads(z.read('processes/gate-manifest.json'))
                assert gate['overall_gate'] == gate['security_gate'] == 'HOLD'
                assert gate['recorded_unique_new_native_blocks'] == 1
                valid = next(a for a in gate['attempts'] if a['id'] == 'valid')
                assert valid['status'] == 'accepted' and valid['last_canonical_depth'] == 0
                assert valid['timely_accepted_progress'] is False
                assert manifest['required_depth'] == 6
                assert gate['resources']['cpu_ns'] == 2448578000 > manifest['maximum_total_cpu_ns'] == 1000000000
                assert gate['observation_window_covered'] is False
                assert gate['recorded_resource_thresholds_met'] is False
                assert gate['security_qualification_verified'] is False
                assert gate['production_activation'] is False
    assert all(j['conclusion'] == 'success' for j in read('credit-jobs.json')['jobs'])
    assert read('native-jobs.json')['jobs'][0]['conclusion'] == 'success'
    assert read('campaign-jobs.json')['jobs'][0]['conclusion'] == 'failure'
    return {'packet_consistency': 'PASS', 'native_gate': 'HOLD',
            'finite_credit_controls_per_lane': 77, 'actual_joint_obligations_closed': 0,
            'native_cp_cg_cq': None, 'six_successor_bound': None, 'lifetime_bound': None,
            'qualification': 'HOLD_NO_GO', 'activation': False}


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
