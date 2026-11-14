"""Read and reconcile retained evidence only; execute no archived payloads."""
import gzip
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
HEAD = '341b7b6195a44d3f4a758c98f846457567ac1de3'
PREVIEW = 'a040a36e5a16822e56cbed29a6dce31b8c265f67'
TREE = 'eb37d4499ca92121a81ef9c0af1e7b221d5f85b1'


def read(name):
    return json.loads((ROOT / name).read_text())


def check(data, row):
    assert len(data) == row['bytes']
    assert hashlib.sha256(data).hexdigest() == row['sha256']


def verify():
    assert __debug__, 'run without Python -O'
    for row in read('MANIFEST.json')['files']:
        check((ROOT / row['path']).read_bytes(), row)
    for row in read('archive-index.json'):
        declared = next(a for a in read(row['api'])['artifacts'] if a['id'] == row['id'])
        raw = (ROOT / row['path']).read_bytes()
        check(raw, row)
        assert len(raw) == declared['size_in_bytes']
        assert 'sha256:' + row['sha256'] == declared['digest']
        with zipfile.ZipFile(ROOT / row['path']) as archive:
            assert len(archive.namelist()) == len(set(archive.namelist())) == len(row['members'])
            for member in row['members']:
                check(archive.read(member['path']), member)
    for row in read('logs-index.json'):
        raw = (ROOT / row['path']).read_bytes()
        check(raw, row['stored'])
        check(gzip.decompress(raw), row['decoded'])
    work_jobs = read('work-time-jobs.json')['jobs']
    assert len(work_jobs) == 2 and all(j['conclusion'] == 'success' for j in work_jobs)
    assert {j['id'] for j in work_jobs} == {129827163245, 129827163342}
    for artifact, source in [(13772381773, HEAD), (13772825234, PREVIEW)]:
        with zipfile.ZipFile(ROOT / f'{artifact}.zip') as archive:
            execution = json.loads(archive.read('work-time-contract/execution.json'))
            assert execution['head_at_execution'] == source and execution['head_tree_at_execution'] == TREE
            assert execution['passed_research_controls'] is True and execution['status'] == 'HOLD_NO_GO'
            assert execution['current_native_cost_qualified'] is False
            reference = execution['reference']
            assert reference['source_commit'] == 'b16bae2824e6c8236ef2011fc93a74df3ac7f039'
            assert reference['native_binary_executed'] is False
            assert execution['qualification']['joint_cp_cq_cg_proof'] is False
            assert execution['qualification']['lifetime_security_bound'] is None
            assert execution['original_current_contract']['matched'] is False
            assert execution['original_current_contract']['error']['message'] == 'SOURCE_BYTES:config/pon/pq-cross-branch-corpus-v1.json'
            for row in execution['artifacts']:
                check(archive.read('work-time-contract/' + row['path']), row)
            for prefix in ['work-time-contract/contract-', 'work-time-contract/research-source-', 'work-time-source-']:
                assert archive.read(prefix + 'before.json') == archive.read(prefix + 'after.json')
    with zipfile.ZipFile(ROOT / '13773101574.zip') as archive:
        command = json.loads(archive.read('pq-source.json'))
        assert command['before'] == command['after']
        assert command['before']['tested_commit'] == HEAD and command['before']['tested_tree'] == TREE
        assert command['exit_code'] == 1 and command['status'] == 'command_failed'
        assert archive.read('pq-source.log') == b'HOLD_NO_GO: changed source: scripts/ci/check_ci_contract.py\n'
        assert command['whole_chain_quantum_security_qualified'] is False
        for name in ['test_ci_source_integrity', 'test_record_pq_native_command', 'test_pq_research_integration',
                     'test_pq_chain_claim_guard', 'test_pq_authority_surface_scan']:
            control = json.loads(archive.read(name + '.json'))
            assert control['exit_code'] == 0
    original = read('original-final-run.json')
    assert original['id'] == 42778406804 and original['run_attempt'] == 1
    assert original['head_sha'] == '4716bade250f327b012a098418f4eece6b73fcaa'
    assert original['status'] == 'completed' and original['conclusion'] == 'failure'
    original_jobs = read('original-final-jobs.json')
    assert original_jobs['total_count'] == len(original_jobs['jobs']) == 21
    assert all(j['status'] == 'completed' for j in original_jobs['jobs'])
    assert {j['id']: j['conclusion'] for j in original_jobs['jobs']}[129787197177] == 'failure'
    pq_jobs = read('pq-jobs.json')['jobs']
    assert len(pq_jobs) == 16 and sum(j['conclusion'] == 'failure' for j in pq_jobs) == 4
    assert all(any(s['name'] == 'Require retained source and claim controls' and s['conclusion'] == 'failure'
                   for s in j['steps']) for j in pq_jobs if j['conclusion'] == 'failure')
    cleanup = read('cleanup-jobs.json')['jobs']
    assert len(cleanup) == 8 and sum(j['conclusion'] == 'cancelled' for j in cleanup) == 2
    assert sum(j['conclusion'] == 'success' for j in cleanup) == 6
    model = read('parent-model-jobs.json')['jobs']
    assert len(model) == 4 and all(j['conclusion'] == 'success' for j in model)
    result = read('RESULT.json')
    assert result['actual_joint_obligations_closed'] == 0
    assert result['native_cp_cg_cq'] is result['native_six_successor_bound'] is result['native_lifetime_bound'] is None
    assert result['production_activation'] is False and result['qualification'] == 'HOLD_NO_GO'
    return {'packet_consistency': 'PASS', 'original_run_conclusion': 'failure',
            'work_time_research_controls': 'PASS', 'current_native_cost_qualified': False,
            'pq_source_guard': 'failed_exit_1', 'actual_joint_obligations_closed': 0,
            'qualification': 'HOLD_NO_GO'}


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
