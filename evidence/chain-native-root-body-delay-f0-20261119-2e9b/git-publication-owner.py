from pathlib import Path
import subprocess,json,base64,hashlib,time,resource,sys
root=Path('/home/qian-qi/work/chain-native-root-delay-f0-publication-20261119-2e9b')
p=root/'git-publication-1'
p.mkdir(exist_ok=False)
inputs=json.loads(sys.argv[1])
(root/'README.md').write_text(inputs['readme'])
(root/'SOURCE_PREFLIGHT.json').write_text(json.dumps(inputs['preflight'],indent=2)+'\n')
(p/'publish-owner.py').write_text(inputs['driver'])
def gitsha(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
with (p/'account.stdout').open('wb') as out,(p/'account.stderr').open('wb') as err:
 r=subprocess.run(['/usr/bin/gh','api','user','--jq','.login'],stdout=out,stderr=err)
assert r.returncode==0 and (p/'account.stdout').read_text().strip()=='ProfHepta', 'original normal account unavailable'
items=[]
for f in sorted(root.iterdir()):
 if not f.is_file():continue
 b=f.read_bytes(); expected=gitsha(b)
 request=p/(f.name+'.request.json')
 request.write_text(json.dumps({'encoding':'base64','content':base64.b64encode(b).decode()}))
 out=p/(f.name+'.stdout.json');err=p/(f.name+'.stderr')
 start=time.monotonic();before=resource.getrusage(resource.RUSAGE_CHILDREN)
 with out.open('wb') as o,err.open('wb') as e:
  child=subprocess.Popen(['/usr/bin/gh','api','--method','POST','/repos/TrillionniumFoundation/Trillionnium-Chain/git/blobs','--input',str(request)],stdout=o,stderr=e)
  pid=child.pid;rc=child.wait()
 after=resource.getrusage(resource.RUSAGE_CHILDREN)
 receipt={'file':f.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'expected_git_blob':expected,'pid':pid,'exit_code':rc,'wall_seconds':time.monotonic()-start,'child_user_cpu_seconds':after.ru_utime-before.ru_utime,'child_system_cpu_seconds':after.ru_stime-before.ru_stime}
 if rc==0:
  response=json.loads(out.read_text());receipt['actual_git_blob']=response['sha'];receipt['hash_matches']=response['sha']==expected
 else:receipt['stderr']=err.read_text()
 items.append(receipt)
 (p/'PROGRESS.json').write_text(json.dumps(items,indent=2)+'\n')
 print(json.dumps(receipt),flush=True)
 assert rc==0 and receipt['hash_matches'], 'uncertain/failed mutation: stop without retry'
result={'schema':'chain-original-f0-git-blob-publication-v1','files':items,'all_actual_exits_zero':True,'all_git_blob_hashes_verified':True,'one_post_per_file':True,'business_requests':0,'full_physical_cost_closed':False}
(p/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'complete':True,'files':len(items),'receipt':str(p/'RESULT.json')}),flush=True)
