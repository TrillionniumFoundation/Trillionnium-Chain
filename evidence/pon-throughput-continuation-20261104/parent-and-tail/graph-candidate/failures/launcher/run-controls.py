from pathlib import Path
import hashlib,json,subprocess,time,resource
root=Path('/workspace/scratch/7318d5f890d1/chain-throughput')
out=Path('/workspace/scratch/7318d5f890d1/throughput-readback/prewrite-73ab-native-attempt-1')
binary=Path('/workspace/scratch/7318d5f890d1/target-throughput/debug/deps/trnm_pon_node-05b4ed99663833c1')
source=json.loads(Path('/workspace/scratch/7318d5f890d1/throughput-readback/tail-native-73ab-attempt-2/source-before.json').read_text())
expected='dd6a1dee07568ba26022ccd690933af13788696e1925e442fe3ba471927f856f'
def verify(stage):
 mismatches=[p for p,h in source['native_input_files'].items() if not (root/p).is_file() or hashlib.sha256((root/p).read_bytes()).hexdigest()!=h]
 digest=hashlib.sha256(binary.read_bytes()).hexdigest()
 report={'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'binary_sha256':digest,'binary_expected_sha256':expected,'source_manifest_sha256':source['manifest_sha256'],'source_files_verified':len(source['native_input_files']),'mismatches':mismatches,'source_and_binary_unchanged':not mismatches and digest==expected}
 (out/(stage+'.json')).write_text(json.dumps(report,indent=2)+'\n')
 assert report['source_and_binary_unchanged'],report
 return report
(out/'source-manifest.json').write_text(json.dumps(source,indent=2)+'\n')
verify('before')
command=['/workspace/scratch/7318d5f890d1/run-throughput.sh',str(binary),'store::native_authenticated::post_write_readback::tests::','--nocapture','--test-threads=1']
(out/'command.json').write_text(json.dumps({'cwd':str(root/'trillionnium/crates/trnm-pon-node'),'argv':command},indent=2)+'\n')
start=time.monotonic_ns();usage=resource.getrusage(resource.RUSAGE_CHILDREN)
with (out/'stdout.txt').open('w') as stdout, (out/'stderr.txt').open('w') as stderr:
 result=subprocess.run(command,cwd=root/'trillionnium/crates/trnm-pon-node',stdout=stdout,stderr=stderr)
after=resource.getrusage(resource.RUSAGE_CHILDREN)
report={'exit_code':result.returncode,'wall_ns':time.monotonic_ns()-start,'child_user_seconds':after.ru_utime-usage.ru_utime,'child_system_seconds':after.ru_stime-usage.ru_stime,'max_child_rss_kib':after.ru_maxrss}
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n');verify('after')
print(json.dumps(report),flush=True)
print((out/'stdout.txt').read_text()[-4500:],flush=True)
print((out/'stderr.txt').read_text()[-2500:],flush=True)
raise SystemExit(result.returncode)
