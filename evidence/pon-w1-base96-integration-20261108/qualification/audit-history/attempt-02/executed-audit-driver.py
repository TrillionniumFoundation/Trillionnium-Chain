#!/usr/bin/env python3
"""Audit completed C7 component records; no tests, source mutation or operation.

Creates a new external package. Reads only explicit manifests, bound logs and
provenance; copies no executable, database, state tree or process environment.
"""
import collections
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path

REPO = Path('/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b')
ROOT = Path('/home/qian-qi/work/chain-w1-c7-root-validation-20261108-ec265b')
TOOLS = Path('/home/qian-qi/work/chain-w1-c7-root-tools-20261108-ec265b')
MTOOLS = Path('/home/qian-qi/work/chain-w1-base96-m12-tools-20261108-ec265b')
DEST = Path('/home/qian-qi/work/chain-w1-c7-adversarial-components-20261108-ec265b-02')
SOURCE = {'commit': '40a3a45d6b8afc5c4706c5235fec47634f4aabbe', 'tree': '4b25e3194a0682adff40bb476f2e7c0a395639fe'}
SOURCE_SHA = '538a1a4fc74182b322eb823d908898acee7041fedc122ea4f441e7cb21303835'
MAX_FILE = 24 * 1024 * 1024

def sha(b):
    return hashlib.sha256(b).hexdigest()

def stable(path, limit=MAX_FILE):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        assert stat.S_ISREG(a.st_mode) and a.st_size <= limit, str(path)
        chunks = []
        remaining = limit + 1
        while remaining:
            b = os.read(fd, min(1048576, remaining))
            if not b:
                break
            chunks.append(b)
            remaining -= len(b)
        b = b''.join(chunks)
        z = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        assert fields(a) == fields(z) and len(b) == z.st_size <= limit, str(path)
        return b
    finally:
        os.close(fd)

def binary_pin(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        assert stat.S_ISREG(a.st_mode)
        h = hashlib.sha256()
        n = 0
        while True:
            b = os.read(fd, 1048576)
            if not b:
                break
            n += len(b)
            h.update(b)
        z = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        assert fields(a) == fields(z) and n == z.st_size
        return {'path': str(path), 'bytes': n, 'sha256': h.hexdigest(), 'current_nlink': z.st_nlink}
    finally:
        os.close(fd)

def load(b):
    def pairs(items):
        d = {}
        for k, v in items:
            assert k not in d, k
            d[k] = v
        return d
    return json.loads(b.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def dump(v):
    return (json.dumps(v, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()

def write(p, b):
    p.parent.mkdir(exist_ok=True, parents=True)
    with p.open('xb') as f:
        f.write(b)

PY = re.compile(r'^Ran ([0-9]+) tests? in ([^\n]+)\n\n(OK(?: \([^\n]*\))?|FAILED \([^\n]*\))$', re.M)
RUST = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([^\n]+)$', re.M)

def outcomes(text):
    py = []
    for m in PY.finditer(text):
        fields = {k: int(v) for k, v in re.findall(r'([A-Za-z ]+)=(\d+)', m[3])}
        assert not set(fields) - {'failures', 'errors', 'skipped', 'expected failures', 'unexpected successes'}
        assert fields.get('expected failures', 0) == fields.get('unexpected successes', 0) == 0
        n, fail, err, skip = int(m[1]), fields.get('failures', 0), fields.get('errors', 0), fields.get('skipped', 0)
        assert n >= fail + err + skip
        py.append({'methods': n, 'passed': n-fail-err-skip, 'failed': fail, 'errors': err,
                   'skipped': skip, 'terminal': m[3], 'reported_duration': m[2]})
    assert [str(x['methods']) for x in py] == re.findall(r'^Ran ([0-9]+) tests? in ', text, re.M)
    rust = [dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'), map(int, m.group(2, 3, 4, 5, 6))))
            | {'terminal': m[1], 'reported_duration': m[7]} for m in RUST.finditer(text)]
    named = [{'name': m[1], 'outcome': m[2]} for m in re.finditer(r'^test (\S+) \.\.\. (ok|FAILED|ignored(?:[^\n]*))$', text, re.M)]
    if rust:
        assert len(rust) == 1
        count = collections.Counter('ignored' if x['outcome'].startswith('ignored') else x['outcome'] for x in named)
        assert [count['ok'], count['FAILED'], count['ignored']] == [rust[0][k] for k in ('passed', 'failed', 'ignored')]
    return {'python': py, 'rust': rust, 'named_rust': named}

def finish_package(dest, raw, index, summary):
    archive = io.BytesIO()
    with gzip.GzipFile(fileobj=archive, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w') as tf:
            for name, b in sorted(raw.items()):
                assert not name.startswith('/') and '..' not in Path(name).parts
                ti = tarfile.TarInfo(name)
                ti.size, ti.mode, ti.mtime = len(b), 0o644, 0
                tf.addfile(ti, io.BytesIO(b))
    archive_bytes = archive.getvalue()
    assert len(archive_bytes) < MAX_FILE
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as tf:
        assert sorted(tf.getnames()) == sorted(raw)
        for name, b in raw.items():
            assert tf.extractfile(name).read() == b
    write(dest/'raw-logs.tar.gz', archive_bytes)
    write(dest/'raw-output-index.json', dump(index))
    write(dest/'summary.json', dump(summary))
    write(dest/'README.md', (f"# C7 {summary['component']} independent review\n\n"
        f"Source `{SOURCE['commit']}` / tree `{SOURCE['tree']}`. This review recomputed every original command output hash and parsed its raw terminal test summaries. It ran no tests, builds, source guards or operation.\n\n"
        "`raw-output-index.json` maps each explicitly selected original file to the byte-identical tar member. The archive was read back member by member. Executables, databases, state directories, credentials and process environments are excluded.\n\n"
        "This package is a filesystem-verified publication candidate. Its manifest does not claim Git staging or commit completeness; the publishing owner must verify every manifest member in the index and published commit.\n\n"
        "Counts and component-specific provenance limits are in `summary.json`. No new complete proof, positive provider payment, original business-budget qualification, winning W1 Node admission or full cryptographic/protocol security qualification follows from these controls.\n").encode())
    members = []
    for p in sorted(dest.iterdir()):
        if p.is_file():
            b = stable(p)
            members.append({'path': p.name, 'bytes': len(b), 'sha256': sha(b)})
    write(dest/'manifest.json', dump({'schema': 'TRNM-W1-C7-COMPONENT-PUBLICATION1',
        'component': summary['component'], 'source': SOURCE, 'files': members,
        'raw_tar_members': len(raw), 'raw_tar_readback_verified': True,
        'filesystem_members_verified': True, 'git_index_or_commit_verified_by_this_audit': False}))
    return {'component': summary['component'], 'manifest_sha256': sha(stable(dest/'manifest.json')),
            'raw_members': len(raw), 'raw_archive_sha256': sha(archive_bytes), 'raw_archive_bytes': len(archive_bytes)}

def audit(spec, inputs):
    name = spec['component']
    directory = Path(spec['path']).parent
    dest = DEST/name
    dest.mkdir()
    raw, index = {}, []
    def add(path, rel=None, pin=None):
        path = Path(path)
        b = stable(path)
        if pin:
            assert sha(b) == pin['sha256'], str(path)
            if 'bytes' in pin:
                assert len(b) == pin['bytes'], str(path)
        rel = rel or path.name
        assert rel not in raw, rel
        raw[rel] = b
        index.append({'archive_member': rel, 'original_path': str(path), 'bytes': len(b), 'sha256': sha(b)})
        return b
    manifest = load(add(directory/'manifest.json', pin=spec))
    commands = manifest['commands']
    expected_counts = {'core': 20, 'owner': 19, 'receiver': 4, 'backend': 7, 'native': 10}
    assert len(commands) == expected_counts[name]
    assert manifest.get('actual_command_count', len(commands)) == len(commands)
    source = manifest.get('source', {'commit': manifest.get('source_commit'), 'tree': manifest.get('source_tree')})
    assert source == SOURCE and manifest['repo'] == str(REPO)
    assert manifest['qualification_complete'] is True
    before = add(directory/'source-before.json', pin={'sha256': SOURCE_SHA})
    after = add(directory/'source-after.json', pin={'sha256': SOURCE_SHA})
    assert before == after
    sg = load(before)
    assert sg['tested_commit'] == SOURCE['commit'] and sg['tested_tree'] == SOURCE['tree']
    assert sg['tracked_worktree_verified'] is True and sg['tests_executed_by_identity_check'] is False
    if name in ('core', 'owner', 'receiver'):
        plan = load(add(TOOLS/(name+'-plan.json'), 'provenance/plan.json', {'sha256': manifest['plan_sha256']}))
        add(TOOLS/'qualify_source.py', 'provenance/qualify_source.py', {'sha256': manifest['driver_sha256']})
        assert plan['source_commit'] == SOURCE['commit'] and plan['source_tree'] == SOURCE['tree']
        expanded = [{'label': f'{i:02d}-'+item['label'],
            'argv': [v.replace('@REPO@', str(REPO)).replace('@OUT@', str(directory)).replace('@HEAD@', SOURCE['commit']) for v in item['argv']],
            'cwd': str(REPO/item.get('cwd', ''))} for i, item in enumerate(plan['commands'], 2)]
        assert len(expanded) == len(commands)-3
        for a, b in zip(expanded, commands[2:-1]):
            assert all(a[k] == b[k] for k in a), a['label']
    py, rust, rows = collections.Counter(), collections.Counter(), []
    labels = set()
    for c in commands:
        label = c['label']
        assert label not in labels
        labels.add(label)
        expected = 1 if name == 'backend' and label == 'source-probe' else 0
        assert type(c['exit']) is int and c['exit'] == expected
        assert c.get('timed_out', False) is False
        if 'expected_exit' in c:
            assert type(c['expected_exit']) is int and c['expected_exit'] == expected and c['passed'] is True
        if 'started_monotonic_ns' in c:
            assert type(c['started_monotonic_ns']) is int and type(c['finished_monotonic_ns']) is int
            assert c['finished_monotonic_ns'] >= c['started_monotonic_ns']
        streams = []
        for stream in ('stdout', 'stderr'):
            pin = c[stream]
            p = Path(pin['path'])
            assert p.parent == directory and p.name == label+'.'+stream
            streams.append(add(p, pin=pin))
        result = outcomes(b'\n'.join(streams).decode('utf-8'))
        assert c.get('python_test_counts', [r['methods'] for r in result['python']]) == [r['methods'] for r in result['python']]
        assert c.get('rust_test_outcomes', [{k: r[k] for k in ('passed','failed','ignored')} for r in result['rust']]) == [{k: r[k] for k in ('passed','failed','ignored')} for r in result['rust']]
        for r in result['python']:
            assert r['terminal'] == 'OK' and r['failed'] == r['errors'] == r['skipped'] == 0
            for k in ('methods','passed','failed','errors','skipped'):
                py[k] += r[k]
        for r in result['rust']:
            assert r['terminal'] == 'ok' and r['failed'] == r['measured'] == 0
            for k in ('passed','failed','ignored'):
                rust[k] += r[k]
        rows.append({'label': label, 'argv': c['argv'], 'cwd': c['cwd'], 'exit': c['exit'], 'outcomes': result})
    expected_py = {'core':571,'receiver':11}.get(name,0)
    expected_rust = {'owner':37,'native':4}.get(name,0)
    assert py['passed'] == expected_py and rust['passed'] == expected_rust
    assert rust['ignored'] == (4 if name == 'owner' else 0)
    extra = {}
    if name == 'core':
        add(directory/'w1-current-command-block.sh', pin={'sha256': manifest['ci_command_block_sha256']})
        for leaf in ('cancellation-handoff','coordinator-contract','provider-contract','generation-target',
                     'owner-cancellation','source-builder','owned-runtime-reader','kaggle-worker-contract',
                     'winner-identity','deployment-evidence-binding','deployment-comparison-audit','owned-process-collector'):
            add(directory/'ci-receipts'/'w1-postwin-contracts'/(leaf+'.log'), 'retained-logs/'+leaf+'.log')
        extra = {'w1_retained_suites_methods': [22,20,11,13,8,8,7,12,4,12,20,14],
                 'history_control_methods': 6, 'host_helper_control_methods': 79,
                 'staged32_included': False, 'history_workload_executed': False}
    elif name == 'owner':
        prep = load(add(ROOT/'preparation-01/owner-empty-preparation.json', 'provenance/owner-empty-preparation.json',
                        {'sha256':'d9e66a4ee1cb9cdbe0a1399b7e347f53866f6a5c0b8739711bbebfb0a6fe49a1'}))
        launch = load(add(ROOT/'owner-launch-binding.json', 'provenance/owner-launch-binding.json',
                          {'sha256':'157a0124359a37e8278a118da11ac0dd6581e3fdc75560e05cfbf2dee98b0df3'}))
        add(TOOLS/'launch_owner.py', 'provenance/launch_owner.py', {'sha256':'8631bd49109c0b0d0f3562751946d0d229836e0cc532e67b52fe0467877d789b'})
        a = load(add(MTOOLS/'owner-import-c7-01/extracted-owner-artifact.json', 'provenance/extracted-owner-artifact.json',
                     {'sha256':'79bb1357e284dbab706886d4420fd7c549b59a06ccb773cb52f191dd2a28cf46'}))
        assert prep['entries_at_creation'] == launch['observed_entries'] == 0
        assert launch['empty_checked_before_exec'] is True and prep['copied_cache'] is False
        assert prep['target'] == launch['target'] == manifest['cargo_target']
        assert prep['device'] == launch['device'] and prep['inode'] == launch['inode']
        assert launch['preparation_sha256'] == sha(raw['provenance/owner-empty-preparation.json'])
        assert launch['plan_sha256'] == manifest['plan_sha256'] and launch['driver_sha256'] == manifest['driver_sha256']
        assert prep['source_commit'] == launch['source_commit'] == a['source_commit'] == SOURCE['commit']
        assert prep['source_tree'] == a['source_tree'] == SOURCE['tree']
        assert a['derived_extraction'] is True and a['original_root_owner_artifact_file_claimed'] is False
        assert a['qualification_manifest']['sha256'] == spec['sha256']
        build = raw['13-owner-no-run-json.stdout']
        assert a['compiler_artifact_stdout']['sha256'] == sha(build)
        selected = [load(x) for x in build.splitlines() if x and load(x).get('reason') == 'compiler-artifact' and load(x).get('executable') == a['owner_executable']['path']]
        assert len(selected) == 1 and selected[0] == a['cargo_artifact']
        assert selected[0]['profile']['test'] is True and selected[0]['target']['name'] == 'trnm_pon_node'
        assert Path(selected[0]['manifest_path']).is_relative_to(REPO) and Path(selected[0]['target']['src_path']).is_relative_to(REPO)
        st = Path(a['owner_executable']['path']).stat()
        assert st.st_size == a['owner_executable']['bytes'] and st.st_nlink == 1
        extra = {'empty_target_preparation_and_launch_bytes_match': True,
                 'compiler_artifact_matches_derived_extraction': True,
                 'owner_elf_size_and_nlink_independently_observed': {'bytes':st.st_size,'nlink':st.st_nlink},
                 'owner_elf_sha256_from_pinned_extraction': a['owner_executable']['sha256'],
                 'owner_elf_sha256_recomputed_by_this_audit': False,
                 'limitation':'The 467950280-byte owner ELF was not reread in this audit. Pinned separate owner import rehashed it. Cargo JSON and raw command outputs were independently checked here. Fresh target is supported by the original prep/launch chain; registry/toolchain reuse means no independent cleanroom claim.'}
    elif name == 'receiver':
        binding = load(add(ROOT/'receiver-launch-binding.json', 'provenance/receiver-launch-binding.json',
                           {'sha256':'8b1ba7162b4166769a1690d3a60bec54aa590c865b93ac59badc5517c752fbd6'}))
        add(TOOLS/'launch_receiver.py','provenance/launch_receiver.py', {'sha256':'b999d4a3a858c8b6642c82fcfe866a1cad851cfdac33bc6d6176497709d98301'})
        n_spec = next(x for x in inputs['manifests'] if x['component']=='native')
        native = load(add(Path(n_spec['path']), 'provenance/native-manifest.json', n_spec))
        assert binding['native_manifest_sha256'] == n_spec['sha256'] and binding['plan_sha256'] == manifest['plan_sha256']
        assert binding['source_commit'] == SOURCE['commit'] and binding['source_tree'] == SOURCE['tree']
        for nc in native['commands']:
            for s in ('stdout','stderr'):
                pin = nc[s]
                assert binding['actual_native_logs_checked'][pin['path']] == pin['sha256']
                b = stable(pin['path'])
                assert len(b) == pin['bytes'] and sha(b) == pin['sha256']
        assert len(binding['actual_native_logs_checked']) == 20
        argv = commands[2]['argv']
        verifier = native['binaries']['verifier']['file']
        assert argv[argv.index('--verifier')+1] == verifier['path']
        assert argv[argv.index('--verifier-sha256')+1] == binding['verifier_sha256'] == verifier['sha256']
        control = load(add(directory/'real-receiver-controls/summary.json','real-receiver-controls/summary.json'))
        assert control['tests_run']==11 and control['failures']==control['errors']==control['skipped']==0 and control['result']=='PASS'
        extra = {'native_binding_and_20_actual_logs_rechecked':True,'actual_original_nov5_receipt_used':True,
                 'new_receipts_generated':0,'winning_w1_node_admission_established':False}
    else:
        declaration = load(add(directory/'declaration.json'))
        assert declaration['source'] == SOURCE and declaration['cache_copy'] == manifest['cache_copy']
        add(Path(declaration['driver']['path']), 'provenance/'+Path(declaration['driver']['path']).name, declaration['driver'])
        cache = load(add(Path(manifest['cache_copy']['path']), 'provenance/cache-copy.json', manifest['cache_copy']))
        origin = manifest['cache_origin']
        assert declaration['cache_origin'] == origin and origin['kind']=='copied-from-qualified-target'
        assert manifest['fresh_cargo_target'] is False and manifest['independent_cleanroom_build'] is False
        assert cache['copy_complete'] is True and cache['copy_exit_code'] == 0
        assert cache['destination'] == manifest['target'] and cache['source_target'] != cache['destination']
        assert cache['shared_source_inode_count']==cache['destination_hardlink_count']==cache['destination_duplicate_inode_count']==0
        assert cache['source_target_written'] is False and cache['source_regular_metadata_unchanged'] is True
        assert cache['source_stat_inventory_before_sha256']==cache['source_stat_inventory_after_sha256']
        assert cache['source_binaries_before']==cache['source_binaries_after']
        for key in ('source_qualification','declaration','source_inventory'):
            pin = cache[key]
            add(Path(pin['path']), 'provenance/cache-'+key+Path(pin['path']).suffix, pin)
        if name == 'backend':
            bindings = {'runner':{'file':manifest['runner'],'cargo_artifact':manifest['cargo_artifact'],'build_label':'build'}}
            probe = [load(x)['identity'] for x in raw['source-probe.stdout'].splitlines() if x.startswith(b'{') and load(x).get('stage')=='RAW_COMMITTED_SOURCE_VERIFIED']
            assert len(probe)==1 and probe[0]==manifest['runner_actual_source_identity']==sg
            assert raw['source-probe.stderr'].decode().strip()=='Error: unknown stage'
            assert not (directory/'source-probe-must-remain-absent').exists()
        else:
            bindings = {k:{**v,'build_label':'build-'+('native' if k=='native_winner' else 'verifier')} for k,v in manifest['binaries'].items()}
        binary_results = {}
        for role, v in bindings.items():
            log = raw[v['build_label']+'.stdout']
            records = [load(x) for x in log.splitlines() if x]
            selected = [x for x in records if x.get('reason')=='compiler-artifact' and x.get('executable')==v['file']['path']]
            assert len(selected)==1 and selected[0]==v['cargo_artifact']
            assert any(x.get('reason')=='build-finished' and x.get('success') is True for x in records)
            assert selected[0]['profile']['test'] is False
            assert Path(selected[0]['manifest_path']).resolve().is_relative_to(REPO)
            assert Path(selected[0]['target']['src_path']).resolve().is_relative_to(REPO)
            actual = binary_pin(v['file']['path'])
            assert {k:actual[k] for k in ('path','bytes','sha256')} == v['file']
            binary_results[role] = actual | {'independently_rehashed':True,'copied_into_publication':False,'cargo_reported_fresh':selected[0]['fresh']}
        extra = {'copied_c6_cache_provenance_checked':True,'fresh_target':False,'independent_cleanroom_build':False,
                 'qualification_budget_seconds':manifest['qualification_budget_seconds'],
                 'cache_copy_outer_budget_seconds':cache['outer_hepta_timeout_seconds'],
                 'binary_bindings':binary_results,'expensive_proof_started':False,
                 'probe_exit1_expected_unknown_stage':name=='backend',
                 'historic_native243_rerun':False}
    terminal_bytes = inputs['terminals'][name].encode()
    terminal = load(terminal_bytes)
    assert terminal['state']=='succeeded' and terminal['exit_code']==0 and terminal['timed_out'] is False
    assert terminal['output_complete'] is True and terminal['output_durable'] is True
    assert terminal['cancelled'] is False and not any(terminal['log_truncated'].values())
    raw['durable-job-terminal.json']=terminal_bytes
    index.append({'archive_member':'durable-job-terminal.json','original_path':'hepta-runtime authoritative process_status',
                  'bytes':len(terminal_bytes),'sha256':sha(terminal_bytes)})
    result = {'schema':'TRNM-W1-C7-INDEPENDENT-COMPONENT-REVIEW1','component':name,'source':SOURCE,
              'actual_command_count':len(commands),'actual_nonzero_commands':[c['label'] for c in commands if c['exit']!=0],
              'original_manifest_sha256':spec['sha256'],'durable_job_id':terminal['job_id'],'durable_exit':0,
              'python':dict(py),'rust':dict(rust),'command_reviews':rows,'provenance':extra,
              'all_bound_outputs_match':True,'source_guards_before_after_exact_equal':True,
              'audit_reran_tests':False,'audit_reran_source_guard':False,'audit_started_operation':False,
              'new_complete_proofs':0,'full_source_qualification_aggregate_claimed':False}
    receipt = finish_package(dest,raw,index,result)
    print(json.dumps(receipt | {'python':dict(py),'rust':dict(rust),'commands':len(commands)}),flush=True)
    return result,receipt

if __name__ == '__main__':
    inputs_bytes=stable(Path(sys.argv[1]))
    inputs=load(inputs_bytes)
    assert inputs['source']==SOURCE
    DEST.mkdir()
    results=[]
    receipts=[]
    for spec in inputs['manifests']:
        if spec['component'] not in ('backend','native'):
            continue
        result,receipt=audit(spec,inputs)
        results.append(result)
        receipts.append(receipt)
    total={'commands':sum(r['actual_command_count'] for r in results),
           'python_passed':sum(r['python'].get('passed',0) for r in results),
           'rust_passed':sum(r['rust'].get('passed',0) for r in results),
           'rust_ignored':sum(r['rust'].get('ignored',0) for r in results)}
    assert total=={'commands':17,'python_passed':0,'rust_passed':4,'rust_ignored':0}
    write(DEST/'audit-inputs.json',inputs_bytes)
    write(DEST/'audit-driver.py',stable(Path(__file__)))
    write(DEST/'completed-components.json',dump({'schema':'TRNM-W1-C7-COMPLETED-COMPONENTS1','source':SOURCE,
        'components':receipts,'counts':total,'ordinary_passes':4,'other_completed_components':'Core, owner and receiver were already independently audited and sealed in attempt01; not rerun here.', 'audit_attempt01_limit':'An unnecessary current-ELF nlink==1 assertion stopped the first audit before ELF hashing; initial cache-copy inode isolation remains verified. This continuation permits regular Cargo outputs with multiple hard links and records their current link counts.', 'pending_components':['history-local-compile-list','staged32'],
        'qualification_aggregate_complete_claimed':False,'new_complete_proofs':0,
        'publication_state':'filesystem verified; index and committed publication completeness not claimed by this audit'}))
    print(json.dumps({'complete':True,'out':str(DEST),'counts':total,'ordinary_passes':4}),flush=True)
