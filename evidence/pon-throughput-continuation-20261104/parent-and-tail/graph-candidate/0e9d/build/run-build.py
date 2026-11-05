from pathlib import Path
import hashlib,json,subprocess,time,resource,shutil
root=Path('/workspace/scratch/7318d5f890d1/chain-throughput')
out=Path('/workspace/scratch/7318d5f890d1/throughput-readback/prewrite-73ab-trimmed-schema-build-attempt-1')
prior=json.loads(Path('/workspace/scratch/7318d5f890d1/throughput-readback/tail-native-73ab-attempt-2/source-before.json').read_text())
def manifest():
 files={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in sorted(prior['native_input_files'])}
 return {'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'native_input_files':files,'manifest_sha256':hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'scope':prior['scope']}
before=manifest();(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
changes=set(subprocess.check_output(['git','diff','--name-only','HEAD'],cwd=root,text=True).splitlines())|set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],cwd=root,text=True).splitlines())
snapshot={}
for path in sorted(changes & before['native_input_files'].keys()):
 destination=out/'source-snapshot'/path;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/path,destination);snapshot[path]=before['native_input_files'][path]
(out/'source-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
command=['bash','/workspace/scratch/7318d5f890d1/run-throughput.sh','cargo','test','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--lib','--all-features','--no-run','--message-format=json']
(out/'command.json').write_text(json.dumps({'cwd':str(root),'argv':command},indent=2)+'\n')
print(json.dumps({'build_started':True,'source_manifest_sha256':before['manifest_sha256'],'source_files':len(before['native_input_files']),'snapshot_files':len(snapshot)}),flush=True)
started=time.monotonic_ns();usage=resource.getrusage(resource.RUSAGE_CHILDREN)
with (out/'stdout.txt').open('w') as stdout,(out/'stderr.txt').open('w') as stderr: result=subprocess.run(command,cwd=root,stdout=stdout,stderr=stderr)
after_usage=resource.getrusage(resource.RUSAGE_CHILDREN);after=manifest();(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
report={'exit_code':result.returncode,'wall_ns':time.monotonic_ns()-started,'source_manifest_sha256':before['manifest_sha256'],'source_unchanged':before==after,'child_user_seconds':after_usage.ru_utime-usage.ru_utime,'child_system_seconds':after_usage.ru_stime-usage.ru_stime,'max_child_rss_kib':after_usage.ru_maxrss}
if result.returncode==0:
 artifacts=[]
 for line in (out/'stdout.txt').read_text().splitlines():
  try: row=json.loads(line)
  except json.JSONDecodeError: continue
  if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='trnm_pon_node' and row.get('executable'):artifacts.append(row['executable'])
 assert len(artifacts)==1,artifacts
 binary=Path(artifacts[0]);report.update({'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'binary_bytes':binary.stat().st_size})
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True);print((out/'stderr.txt').read_text()[-3500:],flush=True)
assert before==after,'source changed during build'
raise SystemExit(result.returncode)
