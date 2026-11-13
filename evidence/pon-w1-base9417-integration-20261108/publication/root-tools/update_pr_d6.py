#!/usr/bin/env python3
import pathlib,subprocess,json,hashlib,time,argparse,re
ap=argparse.ArgumentParser();ap.add_argument('--body-template-sha256',required=True);a=ap.parse_args()
r=pathlib.Path('/home/qian-qi/work/chain-w1-c8-attestation-20261108-ec265b')
v=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b')
t=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b/d6-pr-body-template.md')
out=v/'pr-d6-publication-01';out.mkdir(exist_ok=False);records=[]
pub=json.loads((v/'docs-publication-01/readback.json').read_text())
head='4e007a87ceecbec8d265f6a70cfd71d512a514b5'
assert pub['tested_source']==head and re.fullmatch('[0-9a-f]{40}',pub['commit'])
assert pub['all_committed_files_verified']>2138 and pub['readme_api_exact_bytes'] is True
assert pub['four_gate_status']==['HOLD']*4
template=t.read_bytes();assert hashlib.sha256(template).hexdigest()==a.body_template_sha256
body=template.decode().replace('{{D6_COMMIT}}',pub['commit'])
assert '{{' not in body and '}}' not in body and pub['commit'] in body
endpoint='repos/TrillionniumFoundation/Trillionnium-Chain/pulls/782'
def run(n,args):
 p=subprocess.run(args,cwd=r,capture_output=True);(out/(n+'.stdout')).write_bytes(p.stdout);(out/(n+'.stderr')).write_bytes(p.stderr);records.append({'label':n,'argv':args,'exit':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()});(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');assert p.returncode==0,(n,p.returncode,p.stderr[-2000:]);return p.stdout
assert run('00-actor',['gh','api','user','--jq','.login']).decode().strip()=='ProfHepta'
before=json.loads(run('01-before',['gh','api',endpoint]))
assert before['head']['sha']==head and before['draft'] is True
assert hashlib.sha256(before['body'].encode()).hexdigest()=='33550dcbedb0f3c8d62dcaf15855bc3ce8dae815a4a60730cc7b207d0cbd3cb1','PR body changed since the last verified root update'
(out/'body.md').write_text(body)
request=out/'request.json';request.write_text(json.dumps({'body':body},ensure_ascii=False)+'\n')
run('02-patch',['gh','api','--method','PATCH',endpoint,'--input',str(request)])
after=json.loads(run('03-after',['gh','api',endpoint]))
assert after['body']==body and after['head']['sha']==head and after['draft'] is True
result={'schema':'TRNM-W1-C8-D6-PR-BODY-PUBLICATION1','head':head,'evidence_commit':pub['commit'],'draft':True,'actor':'ProfHepta','body_template_sha256':a.body_template_sha256,'body_sha256':hashlib.sha256(body.encode()).hexdigest(),'body_exact_readback':True,'all_attempts_commands':77,'ordinary_executions':697,'ordinary_passed':696,'ordinary_failed':1,'ignored':4,'all_first_attempts_passed':False,'four_gate_status':['HOLD']*4,'url':after['html_url'],'observed_unix_ns':time.time_ns()}
(out/'readback.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
