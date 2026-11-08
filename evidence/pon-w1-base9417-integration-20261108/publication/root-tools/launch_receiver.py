#!/usr/bin/env python3
import hashlib,json,os,pathlib,subprocess,sys,time
repo=pathlib.Path('/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b')
tool=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b')
v=pathlib.Path('/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b')
head='4e007a87ceecbec8d265f6a70cfd71d512a514b5';tree='19a4f1a6e1cec5c27e595fa555b97cddc4717a3c'
mp=pathlib.Path('/home/qian-qi/work/chain-w1-c8-native-qualification-20261108-ec265b-01/manifest.json')
mb=mp.read_bytes();ms=hashlib.sha256(mb).hexdigest()
assert ms=='0fcf604c56d415907fc721f9262d7b6a843b1db49cd62246d706ccf8d319f310'
m=json.loads(mb);assert m['source']=={'commit':head,'tree':tree}
assert m['qualification_complete'] is True and m['source_clean_before'] is True and m['source_clean_after'] is True
assert len(m['commands'])==10 and all(c['passed'] is True and c['exit']==c['expected_exit']==0 for c in m['commands'])
logs={}
for c in m['commands']:
 for stream in ('stdout','stderr'):
  rec=c[stream];p=pathlib.Path(rec['path']);b=p.read_bytes()
  assert len(b)==rec['bytes'] and hashlib.sha256(b).hexdigest()==rec['sha256'],str(p)
  logs[str(p)]=rec['sha256']
binfo=m['binaries']['verifier'];f=binfo['file'];elf=pathlib.Path(f['path']).resolve(strict=True);eb=elf.read_bytes()
assert len(eb)==f['bytes']==19346216 and hashlib.sha256(eb).hexdigest()==f['sha256']=='c667ec4cff650909734c4343fc814d0b3dd8bdb68b5c85085b11bd9c2d68cd2f'
assert eb[:4]==b'\x7fELF'
art=binfo['cargo_artifact'];assert pathlib.Path(art['manifest_path']).resolve()==repo/'formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml'
assert pathlib.Path(art['target']['src_path']).resolve()==repo/'formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs'
rawlog=pathlib.Path(binfo['build_log']['path']).read_bytes();assert hashlib.sha256(rawlog).hexdigest()==binfo['build_log']['sha256']
actual=[json.loads(line) for line in rawlog.decode().splitlines() if line.strip()]
matched=[x for x in actual if x.get('reason')=='compiler-artifact' and x.get('target',{}).get('name')=='w1-verify-v2' and x.get('executable')]
assert len(matched)==1 and matched[0]==art
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()==head
assert subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=repo,text=True).strip()==tree
assert not subprocess.check_output(['git','status','--porcelain'],cwd=repo,text=True).strip()
plan=json.loads(pathlib.Path('/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b/receiver-plan.json').read_text())
argv=plan['commands'][0]['argv']
argv[argv.index('--verifier')+1]=str(elf);argv[argv.index('--verifier-sha256')+1]=f['sha256']
plan.update(native_build_manifest={'path':str(mp),'sha256':ms},source_commit=head,source_tree=tree,cache_basis='No Cargo in receiver controls; verifier is from independently completed C8 copied-cache native build; no new proof',declared_command_count=4,declared_python_methods=11,new_receipts_generated=0)
pp=tool/'receiver-plan.json'
with pp.open('x') as w:w.write(json.dumps(plan,indent=2)+'\n')
driver=tool/'qualify_source.py'
assert hashlib.sha256(driver.read_bytes()).hexdigest()=='d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f'
runargv=[sys.executable,str(driver),'--repo',str(repo),'--head',head,'--out',str(v/'exact-receiver-01'),'--plan',str(pp)]
binding={'schema':'TRNM-W1-C8-RECEIVER-LAUNCH-BINDING1','source_commit':head,'source_tree':tree,'native_manifest_sha256':ms,'actual_native_logs_checked':logs,'actual_cargo_artifact_matched':True,'verifier_sha256':f['sha256'],'plan_sha256':hashlib.sha256(pp.read_bytes()).hexdigest(),'new_proofs':0,'argv':runargv,'observed_monotonic_ns':time.monotonic_ns()}
with (v/'receiver-launch-binding.json').open('x') as w:w.write(json.dumps(binding,indent=2)+'\n')
print(json.dumps({k:binding[k] for k in ('schema','source_commit','native_manifest_sha256','verifier_sha256','plan_sha256','new_proofs')}),flush=True)
os.execv(sys.executable,runargv)
