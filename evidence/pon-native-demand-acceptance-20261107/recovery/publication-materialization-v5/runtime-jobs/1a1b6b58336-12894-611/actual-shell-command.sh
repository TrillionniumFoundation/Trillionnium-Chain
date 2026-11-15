/usr/bin/python3 - <<'PY'
import os,json,pathlib,subprocess,hashlib,time
r=pathlib.Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2');out=r/'publication-materialization-v5';inv=json.loads((out/'missing-before.json').read_text());oid='d1b9788bf1cd2ec9f8450aafb9c10fd41f0ae96c';row=next(x for x in inv['missing'] if x['oid']==oid)
p=out/'raw-blobs';p.mkdir(exist_ok=True);raw=p/(oid+'.raw');err=p/(oid+'.stderr');args=['/usr/bin/gh','api','-H','Accept: application/vnd.github.raw+json','repos/TrillionniumFoundation/Trillionnium-Chain/git/blobs/'+oid];start=time.time();code=None;timed_out=False
with raw.open('xb') as f,err.open('xb') as e:
 try: code=subprocess.run(args,stdout=f,stderr=e,timeout=150).returncode
 except subprocess.TimeoutExpired: code=124;timed_out=True
b=raw.read_bytes();actual=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest();record={'command':args,'expected_blob':oid,'expected_bytes':row['github_size'],'actual_bytes':len(b),'actual_git_blob_sha1':actual,'raw_sha256':hashlib.sha256(b).hexdigest(),'exit_code':code,'timed_out':timed_out,'elapsed_seconds':time.time()-start,'path':row['path'],'imported':False}
if code==0 and len(b)==row['github_size'] and actual==oid:
 q=subprocess.run(['/usr/bin/git','--no-replace-objects','--git-dir='+str(r/'chain.git'),'hash-object','-w','--stdin'],input=b,capture_output=True,env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0'))
 record.update(import_exit_code=q.returncode,import_stdout=q.stdout.decode(),import_stderr=q.stderr.decode());record['imported']=q.returncode==0 and q.stdout.decode().strip()==oid
with (p/(oid+'.receipt.json')).open('x') as f: json.dump(record,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps(record),flush=True)
raise SystemExit(0 if record['imported'] else 1)
PY