"""Verify original native command records and exact full registry without executing code."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--directory', type=Path, required=True)
parser.add_argument('--candidate', required=True)
parser.add_argument('--run-id', type=int, required=True)
parser.add_argument('--job-id', type=int, required=True)
parser.add_argument('--artifact-id', type=int, required=True)
parser.add_argument('--zip', type=Path, required=True)
parser.add_argument('--lane', choices=['x64-head','x64-merge','arm64-head','arm64-merge'], required=True)
args = parser.parse_args()
P = args.directory
ROOT = Path('/workspace/scratch/b5a148b09b11')
plan_path = ROOT / 'next-validation/full-node-fixture-diagnostics/plan.json'
plan = json.loads(plan_path.read_bytes())
registered = plan['registered']
ignored_original = plan['original_ignored']
assert len(registered) == len(set(registered)) == 974
assert len(ignored_original) == len(set(ignored_original)) == 23
assert plan['original_registry_count'] == 971 and len(plan['candidate_additions']) == 3
binding = json.loads((P / 'source-binding.json').read_bytes())
HEAD = args.candidate
assert binding['candidate'] == HEAD
MERGE = binding['actual_merge']
TREE = binding.get('tree', binding.get('head_tree', binding.get('tested_tree', binding.get('expected_tree'))))
kind = 'prospective-merge' if args.lane.endswith('merge') else 'head'
commit = MERGE if kind == 'prospective-merge' else HEAD
arch = 'ARM64' if args.lane.startswith('arm64') else 'X64'
tracked = { 'c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1':(7723,882506480),
            'b4bdf142f513081715ecc8d1f9674291e85302cc':(7757,884109821)}[HEAD]

def digest(value):
    return hashlib.sha256(value).hexdigest()

def write_new(path, value):
    raw = (json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)
    return {'path':str(path),'bytes':len(raw),'sha256':digest(raw)}

receipt = json.loads((P / f'{args.artifact_id}-download-receipt.json').read_bytes())
meta = receipt['metadata']
raw = args.zip.read_bytes()
assert meta['id'] == args.artifact_id and meta['workflow_run']['id'] == args.run_id
assert meta['workflow_run']['head_sha'] == HEAD
assert len(raw) == meta['size_in_bytes'] and 'sha256:'+digest(raw) == meta['digest']
with zipfile.ZipFile(args.zip) as z:
    names = z.namelist()
    assert len(names) == len(set(names))
    source = json.loads(z.read('source.json'))
    assert source['candidate'] == HEAD and source['tested_commit'] == commit
    assert source['kind'] == kind and source['tested_tree'] == TREE
    assert source['tracked_worktree_verified'] and (source['tracked_entries'],source['tracked_bytes']) == tracked
    if kind == 'prospective-merge':
        assert source['base'] == 'dd6e1c3cbeacbdc532b0679297835b3a0aac78f0' and source['prospective_merge'] == MERGE
    commands = []
    command_map = {}
    for name in names:
        if not name.endswith('.json'):
            continue
        d = json.loads(z.read(name))
        if not isinstance(d,dict) or d.get('schema') != 'trnm-pq-native-command-v1':
            continue
        content = z.read(d['log_file'])
        assert len(content) == d['log_bytes'] and digest(content) == d['log_sha256'], name
        assert d['before'] == d['after'] == source, name
        assert d['environment']['GITHUB_RUN_ID'] == str(args.run_id)
        assert d['environment']['GITHUB_RUN_ATTEMPT'] == '1'
        assert d['environment']['RUNNER_ARCH'] == arch
        assert d['exit_code'] == 0 and d['status'] == 'command_succeeded', name
        command_map[name] = d
        commands.append({'record':name,'argv':d['argv'],'exit_code':d['exit_code'],'log_file':d['log_file'],
                         'log_bytes':d['log_bytes'],'log_sha256':d['log_sha256'],'elapsed_ns':d['elapsed_ns'],
                         'source_before_after_identical':True})
    node = command_map['node-lib.json']
    log = z.read(node['log_file']).decode()
    expected_argv = ['cargo','+1.95.0','test','--locked','--manifest-path','trillionnium/Cargo.toml','-p',
                     'trnm-pon-node','--lib','--all-features','--','--show-output','--test-threads=1']
    assert node['argv'] == expected_argv
    starts = re.findall(r'^running (\d+) tests?$',log,re.M)
    assert starts and starts[0] == '974'
    summaries = re.findall(r'^test result: (?:ok|FAILED)\..*$',log,re.M)
    terminal = summaries[-1]
    match = re.fullmatch(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s',terminal)
    assert match and tuple(map(int,match.groups()[:5])) == (951,0,23,0,0)
    success_block = log.rsplit('\nsuccesses:\n',1)[1].split('\ntest result:',1)[0]
    successes = [line.strip() for line in success_block.splitlines() if line.strip()]
    ignored = re.findall(r'^test (.+?) \.\.\. ignored(?:, (.*))?$',log,re.M)
    ignored_names = [name for name,reason in ignored]
    assert len(successes) == len(set(successes)) == 951
    assert len(ignored_names) == len(set(ignored_names)) == 23
    assert set(successes).isdisjoint(ignored_names)
    assert set(successes)|set(ignored_names) == set(registered)
    assert set(ignored_names) == set(ignored_original)
    assert set(plan['candidate_additions']) <= set(successes)
    controls = []
    for row in z.read('required-tests.tsv').decode().splitlines():
        key,name = row.split('\t')
        execution = json.loads(z.read(key+'-execution.json'))
        command = command_map[key+'.json']
        assert execution['test'] == name and execution['executed_tests'] == 1 and execution['result'] == 'PASS'
        assert name in successes and '--exact' in command['argv'] and name in command['argv']
        text = z.read(command['log_file']).decode()
        assert re.search(r'^test '+re.escape(name)+r' \.\.\. ok$',text,re.M), key
        assert re.findall(r'^test result: .*$',text,re.M)[-1].startswith('test result: ok. 1 passed; 0 failed; 0 ignored;')
        controls.append({'id':key,'test':name,'executed_tests':1,'result':'PASS','raw_log_sha256':command['log_sha256']})
    assert len(controls) == len({x['test'] for x in controls}) == 43
    clippy = command_map['clippy.json']
    assert clippy['argv'] == ['cargo','+1.95.0','clippy','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--lib','--tests','--all-features','--','-D','warnings']
    artifacts = []
    for line in z.read(command_map['build.json']['log_file']).decode().splitlines():
        if not line.startswith('{'):
            continue
        d = json.loads(line)
        if d.get('reason') == 'compiler-artifact' and d.get('target',{}).get('name') == 'trnm_pon_node' and d.get('profile',{}).get('test'):
            artifacts.append(d)
    assert len(artifacts) == 1
    compiler = artifacts[0]
    assert compiler['profile'] == {'opt_level':'3','debuginfo':2,'debug_assertions':True,'overflow_checks':True,'test':True}
    assert compiler['features'] == ['default','pq-native-openssl']
    history = [name for name in successes if name.startswith('ingress::history_import::tests::')]
    history_ignored = [name for name in ignored_names if name.startswith('ingress::history_import::tests::')]
    assert len(history) == 25 and len(history_ignored) == 1
    out = {
        'schema':'exact-candidate-full-node-974-one-lane-readback-v1',
        'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'candidate':HEAD,'actual_merge':MERGE,'tree':TREE,'lane':args.lane,'job_id':args.job_id,
        'run_id':args.run_id,'attempt':1,'artifact_id':args.artifact_id,'artifact_bytes':len(raw),
        'artifact_sha256':digest(raw),'artifact_metadata':meta,'source':source,
        'frozen_registry':{'path':str(plan_path),'sha256':digest(plan_path.read_bytes()),'registered':registered,
                           'original_ignored':ignored_original,'candidate_additions':plan['candidate_additions']},
        'node_command':node,'outer_summary':terminal,'counts':{'pass':951,'fail':0,'original_ignored':23,'measured':0,'filtered':0},
        'unique_pass_names':sorted(successes),'ignored_names_and_reasons':[{'name':n,'reason':r} for n,r in ignored],
        'complete_974_registry_matched':True,'child_summaries_retained_not_added':summaries[:-1],
        'original43_named_controls':controls,'strict_clippy':clippy,'verified_command_records':commands,
        'compiler_artifact':compiler,'binary_sha256':None,
        'binary_hash_scope':'This artifact retains compiler executable path and profile, but no ELF bytes or independently recorded ELF SHA; no hash is inferred.',
        'profile_scope':'Actual compiler artifact has opt_level3,debuginfo2,debug_assertions=true,overflow_checks=true,test=true. Original cargo test profile and all-feature invocation retained; banner is not used to infer package optimization.',
        'counts_scope':'951 unique PASS plus23 original ignored from974 registry for this one lane.43 selectors overlap the full suite; child harnesses are not added. No other lane/candidate/workspace/9Host/business/performance qualification.',
        'reader':{'path':str(Path(__file__).resolve()),'sha256':digest(Path(__file__).read_bytes()),'executes_native':False}
    }
    stem = f'pq-node-{args.lane}-{args.artifact_id}'
    print(json.dumps(write_new(P/(stem+'-readback.json'),out)))
    member_path = P/(stem+'-original-members.json')
    meta_path = P/(stem+'-metadata.json')
    write_new(member_path,names)
    write_new(meta_path,meta)
subprocess.run([sys.executable,str(Path(__file__).with_name('collect_readback.py')),'artifact',
    '--candidate',HEAD,'--run-id',str(args.run_id),'--metadata',str(meta_path),'--zip',str(args.zip),
    '--members',str(member_path),'--output',str(P/(stem+'-original-records.json.gz')),'--gzip'],check=True)
