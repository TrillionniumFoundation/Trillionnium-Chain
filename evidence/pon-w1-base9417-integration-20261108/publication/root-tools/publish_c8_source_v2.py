#!/usr/bin/env python3
import pathlib,subprocess,json,hashlib,time
r=pathlib.Path('/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b')
v=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b')
out=v/'source-publication-01';out.mkdir(exist_ok=False)
head='4e007a87ceecbec8d265f6a70cfd71d512a514b5';tree='19a4f1a6e1cec5c27e595fa555b97cddc4717a3c';previous='40a3a45d6b8afc5c4706c5235fec47634f4aabbe'
branch='fix/chain-w1-runtime-integrated-20261107';base='fix/chain-six-axis-performance-20261103';records=[]
def run(n,args,allowed=(0,)):
 p=subprocess.run(args,cwd=r,capture_output=True);(out/(n+'.stdout')).write_bytes(p.stdout);(out/(n+'.stderr')).write_bytes(p.stderr);records.append({'label':n,'argv':args,'exit':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');assert p.returncode in allowed,(n,p.returncode,p.stderr[-1500:]);return p.stdout.decode()
assert run('00-head',['git','rev-parse','HEAD']).strip()==head
assert run('01-tree',['git','rev-parse','HEAD^{tree}']).strip()==tree
assert not run('02-clean',['git','status','--porcelain']).strip()
run('03-preflight',['bash','scripts/project-preflight.sh','--dev'])
run('04-source-identity',['python3','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',head,'--output',str(out/'prepush-source.json')])
assert run('05-actor',['gh','api','user','--jq','.login']).strip()=='ProfHepta'
specs=[('core',v/'exact-ci-core-01/manifest.json'),('owner',v/'exact-owner-02/manifest.json'),('receiver',v/'exact-receiver-01/manifest.json'),('history-local',v/'exact-history-local-01/manifest.json'),('historical-regressions',v/'exact-historical-regressions-01/manifest.json'),('staged',v/'exact-staged-02/manifest.json'),('backend',pathlib.Path('/home/qian-qi/work/chain-w1-c8-backend-qualification-20261108-ec265b-01/manifest.json')),('native',pathlib.Path('/home/qian-qi/work/chain-w1-c8-native-qualification-20261108-ec265b-01/manifest.json'))]
components=[];command_count=0;methods=0;ignored=0;expected_nonzero=0
for name,path in specs:
 b=path.read_bytes();m=json.loads(b);src=m.get('source',{'commit':m.get('source_commit'),'tree':m.get('source_tree')});assert src=={'commit':head,'tree':tree}
 assert m['qualification_complete'] is True
 for c in m['commands']:
  assert c['exit']==c.get('expected_exit',0)
  expected_nonzero+=int(c.get('expected_exit',0)!=0)
 command_count+=len(m['commands']);methods+=m.get('python_test_methods_reported',0)
 rust=m.get('rust_test_outcomes',{});assert rust.get('failed',0)==0;methods+=rust.get('passed',0);ignored+=rust.get('ignored',0)
 if name=='native':methods+=m['test_counts']['native_example']+m['test_counts']['verifier']
 components.append({'name':name,'manifest':str(path),'sha256':hashlib.sha256(b).hexdigest(),'commands':len(m['commands'])})
assert (command_count,methods,ignored,expected_nonzero)==(73,665,4,1),(command_count,methods,ignored,expected_nonzero)

original_path=v/'exact-staged-01/manifest.json';original_bytes=original_path.read_bytes()
assert hashlib.sha256(original_bytes).hexdigest()=='a6e8363bfa6a157fc1b414b64e4af59bb11211166fe06f1b0962460253e89e25'
original=json.loads(original_bytes)
assert original['source_commit']==head and original['source_tree']==tree and original['qualification_complete'] is False
assert len(original['commands'])==4 and [c['exit'] for c in original['commands']]==[0,0,1,0]
for c in original['commands']:
 for stream in ('stdout','stderr'):
  rec=c[stream];raw=pathlib.Path(rec['path']).read_bytes()
  assert len(raw)==rec['bytes'] and hashlib.sha256(raw).hexdigest()==rec['sha256']
oldstderr=pathlib.Path(original['commands'][2]['stderr']['path']).read_text()
assert hashlib.sha256(oldstderr.encode()).hexdigest()=='6523776cafbcfcb998f508af0a9a890ef1714adfc5a06aadd59a952baf4bca4c'
assert sum(line.endswith(' ... ok') for line in oldstderr.splitlines())==31 and 'FAILED (failures=1)' in oldstderr and 'Ran 32 tests in ' in oldstderr
repeat_path=v/'exact-staged-02/manifest.json';repeat_bytes=repeat_path.read_bytes()
assert hashlib.sha256(repeat_bytes).hexdigest()=='f7c7527fb00f542021f0c7ab0469b2c0f2905e0f71b9b55f5e577b8f94c3104f'
repeat=json.loads(repeat_bytes);assert repeat['qualification_complete'] is True
assert repeat['commands'][2]['argv']==original['commands'][2]['argv']
assert repeat['commands'][2]['cwd']==original['commands'][2]['cwd']
repeatstderr=pathlib.Path(repeat['commands'][2]['stderr']['path']).read_text()
assert hashlib.sha256(repeatstderr.encode()).hexdigest()=='e8d2eb49b607f969d4c137d70ab50073f7c6add5f4325cd36d76d275e82604c2'
assert sum(line.endswith(' ... ok') for line in repeatstderr.splitlines())==32 and repeatstderr.splitlines()[-1]=='OK'
declpath=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b/staged-one-repeat-declaration.json')
declbytes=declpath.read_bytes();assert hashlib.sha256(declbytes).hexdigest()=='7b51a7dee784b9375eb1c1dcc9b8f54869538810c763ee1514208ba42912ce95'
decl=json.loads(declbytes);assert decl['maximum_additional_attempts']==1 and decl['test_argv_changed'] is False and decl['test_parameters_changed'] is False
assert sorted(p.name for p in v.glob('exact-staged-*'))==['exact-staged-01','exact-staged-02']
all_attempts={'commands':command_count+4,'method_executions':methods+32,'passed_methods':methods+31,'failed_methods':1,'ignored_methods':ignored,'exit_zero_commands':75,'expected_nonzero_commands':1,'unexpected_nonzero_commands':1,'all_first_attempts_passed':False,'source_guard_failures':0,'original_staged_failure_manifest_sha256':hashlib.sha256(original_bytes).hexdigest(),'unique_repeat_manifest_sha256':hashlib.sha256(repeat_bytes).hexdigest(),'repeat_declaration_sha256':hashlib.sha256(declbytes).hexdigest(),'causal_explanation_established':False}
assert (all_attempts['commands'],all_attempts['method_executions'],all_attempts['passed_methods'],all_attempts['failed_methods'])==(77,697,696,1)

run('06-fast-forward',['git','merge-base','--is-ancestor',previous,head])
refs=['refs/heads/'+branch,'refs/heads/'+base,'refs/pull/782/merge']
def readrefs(n):
 s=run(n,['git','ls-remote','origin']+refs);return {line.split()[1]:line.split()[0] for line in s.splitlines()}
before=readrefs('07-remote-before');assert before['refs/heads/'+branch]==previous
prbefore=json.loads(run('08-pr-before',['gh','api','repos/TrillionniumFoundation/Trillionnium-Chain/pulls/782']));assert prbefore['draft'] is True and prbefore['head']['sha']==previous
run('09-source-push',['git','push','origin','HEAD:refs/heads/'+branch])
after=readrefs('10-remote-after');assert after['refs/heads/'+branch]==head
prafter=json.loads(run('11-pr-after',['gh','api','repos/TrillionniumFoundation/Trillionnium-Chain/pulls/782']));assert prafter['draft'] is True and prafter['head']['sha']==head
result={'schema':'TRNM-W1-C8-SOURCE-PUBLICATION2','source_commit':head,'source_tree':tree,'source_parents':[previous,'9417e495165865ef6c1288b39084856e31020634'],'actor':'ProfHepta','push_kind':'ordinary-fast-forward','components':components,'selected_coverage_command_count':command_count,'selected_coverage_passed_methods':methods,'ordinary_ignored':ignored,'all_declared_qualification_attempts':all_attempts,'expected_negative_exit_commands':expected_nonzero,'before_refs':before,'after_refs':after,'api_base_before':prbefore['base']['sha'],'api_base_after':prafter['base']['sha'],'api_head_after':prafter['head']['sha'],'api_merge_after':prafter.get('merge_commit_sha'),'pr_draft':prafter['draft'],'url':prafter['html_url'],'new_ci_not_yet_qualified':True,'tested_base_parent_matches_current_remote_base':after['refs/heads/'+base]=='9417e495165865ef6c1288b39084856e31020634','observed_unix_ns':time.time_ns()}
(out/'readback.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
