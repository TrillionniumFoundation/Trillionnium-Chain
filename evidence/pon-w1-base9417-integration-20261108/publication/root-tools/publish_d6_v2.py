#!/usr/bin/env python3
import pathlib,subprocess,json,hashlib,time,base64,argparse,re
ap=argparse.ArgumentParser();ap.add_argument('--inventory-sha256',required=True);a=ap.parse_args()
ish=a.inventory_sha256;assert re.fullmatch('[0-9a-f]{64}',ish)
r=pathlib.Path('/home/qian-qi/work/chain-w1-c8-attestation-20261108-ec265b')
v=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b')
out=v/'docs-publication-01';out.mkdir(exist_ok=False);records=[]
c8='4e007a87ceecbec8d265f6a70cfd71d512a514b5';d5='41d717cc9608153dec0daa26ad68ebf8129ed215';branch='docs/chain-w1-base9417-qualification-20261108-ec265b'
prefix='evidence/pon-w1-base9417-integration-20261108'
def run(n,args):
 p=subprocess.run(args,cwd=r,capture_output=True);(out/(n+'.stdout')).write_bytes(p.stdout);(out/(n+'.stderr')).write_bytes(p.stderr);records.append({'label':n,'argv':args,'exit':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');assert p.returncode==0,(n,p.returncode,p.stderr[-2000:]);return p.stdout.decode()
assert run('00-head',['git','rev-parse','HEAD']).strip()==d5
assert run('01-merge',['git','rev-parse','MERGE_HEAD']).strip()==c8
assert run('02-branch',['git','branch','--show-current']).strip()==branch
run('03-preflight',['bash','scripts/project-preflight.sh','--dev'])
assert run('04-actor',['gh','api','user','--jq','.login']).strip()=='ProfHepta'
run('05-no-unstaged',['git','diff','--exit-code'])
assert not run('06-no-untracked',['git','ls-files','--others','--exclude-standard']).strip()
assert hashlib.sha256((r/prefix/'publication-inventory.json').read_bytes()).hexdigest()==ish
qa=json.loads((v/'docs-validation-02/manifest.json').read_text())
assert qa['inventory_sha256']==ish and qa['all_old_and_new_git_index_blobs_verified'] is True and qa['runtime_index_equal_c8'] is True and qa['old_paths_git_index_verified']==2138
summary=json.loads((r/prefix/'summary.json').read_text())
assert summary['tested_source']=='4e007a87ceecbec8d265f6a70cfd71d512a514b5'
assert summary['four_gate_status']==['HOLD','HOLD','HOLD','HOLD']
assert not run('07-remote-before',['git','ls-remote','origin','refs/heads/'+branch]).strip()
pr=json.loads(run('07-pr-head',['gh','api','repos/TrillionniumFoundation/Trillionnium-Chain/pulls/782']))
assert pr['head']['sha']==c8 and pr['draft'] is True
run('08-commit',['git','commit','-m','docs(w1): publish exact C8 qualification and retained runtime evidence'])
head=run('09-head',['git','rev-parse','HEAD']).strip();parents=run('10-parents',['git','show','-s','--format=%P','HEAD']).strip().split();assert parents==[d5,c8]
tree=run('11-tree',['git','rev-parse','HEAD^{tree}']).strip()
assert not run('12-clean',['git','status','--porcelain']).strip()
run('13-verify-committed-bytes',['python3',str(r/prefix/'verify_git_publication.py'),'--rev',head,'--expected-new-inventory-sha256',ish,'--output',str(out/'git-commit-verification.json')])
local=json.loads((out/'git-commit-verification.json').read_text());assert local['file_count']==2138+qa['new_files_including_inventory']
run('14-pre-push-preflight',['bash','scripts/project-preflight.sh','--dev'])
run('15-push',['git','push','origin','HEAD:refs/heads/'+branch])
remote_ref=run('16-remote-after',['git','ls-remote','origin','refs/heads/'+branch]).strip();assert remote_ref.split()[0]==head
remote_commit=json.loads(run('17-remote-commit',['gh','api','repos/TrillionniumFoundation/Trillionnium-Chain/git/commits/'+head]));assert remote_commit['sha']==head and remote_commit['tree']['sha']==tree
assert [p['sha'] for p in remote_commit['parents']]==parents
groups=[]
for i,g in enumerate(local['groups'],start=1):
 pfx=g['prefix'];oid=run('18-subtree-'+str(i),['git','rev-parse',head+':'+pfx]).strip()
 rt=json.loads(run('19-remote-tree-'+str(i),['gh','api','repos/TrillionniumFoundation/Trillionnium-Chain/git/trees/'+oid+'?recursive=1']))
 assert rt['sha']==oid and rt['truncated'] is False
 got={pfx+'/'+x['path']:x['sha'] for x in rt['tree'] if x['type']=='blob'}
 expected={p:d['git_blob'] for p,d in local['blobs'].items() if p.startswith(pfx+'/')}
 assert got==expected,{'prefix':pfx,'remote_count':len(got),'expected_count':len(expected)}
 assert all(x['type'] in ('tree','blob') for x in rt['tree'])
 groups.append({'prefix':pfx,'tree':oid,'remote_blob_count':len(got),'all_blob_oids_match_byte_verified_commit':True})
api=json.loads(run('20-readme',['gh','api','repos/TrillionniumFoundation/Trillionnium-Chain/contents/'+prefix+'/README.md?ref='+head]));b=base64.b64decode(api['content']);assert b==(r/prefix/'README.md').read_bytes()
result={'schema':'TRNM-W1-C8-D6-PUBLICATION1','commit':head,'tree':tree,'parents':parents,'tested_source':c8,'actor':'ProfHepta','branch':branch,'push_kind':'ordinary-new-branch','inventory_sha256':ish,'new_package_files':qa['new_files_including_inventory'],'old_package_files':2138,'all_committed_files_verified':local['file_count'],'remote_groups':groups,'readme_api_exact_bytes':True,'prior_104_log_correction_retained':True,'old_inventory_hashes_unchanged':True,'four_gate_status':['HOLD']*4,'documentation_commit_executed_as_source':False,'observed_unix_ns':time.time_ns()}
(out/'readback.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
