#!/usr/bin/env python3
import argparse,hashlib,json,pathlib,subprocess,time
ap=argparse.ArgumentParser()
for k in ('cargo-log','repo','head','output'):ap.add_argument('--'+k,required=True)
a=ap.parse_args(); repo=pathlib.Path(a.repo).resolve(strict=True); log=pathlib.Path(a.cargo_log)
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()==a.head
assert not subprocess.check_output(['git','status','--porcelain'],cwd=repo,text=True).strip()
rows=[json.loads(x) for x in log.read_text().splitlines() if x.strip()]
assert any(x.get('reason')=='build-finished' and x.get('success') is True for x in rows)
arts=[x for x in rows if x.get('reason')=='compiler-artifact' and x.get('target',{}).get('name')=='history_stage_diagnostic' and x.get('executable')]
assert len(arts)==1, len(arts)
art=arts[0]; target=art['target']; profile=art['profile']
expected_src=repo/'trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs'
expected_manifest=repo/'trillionnium/crates/trnm-pon-node/Cargo.toml'
assert pathlib.Path(target['src_path']).resolve(strict=True)==expected_src
assert pathlib.Path(art['manifest_path']).resolve(strict=True)==expected_manifest
assert target['kind']==['test'] and profile['test'] is True and str(profile['opt_level'])=='3', (target,profile)
elf=pathlib.Path(art['executable']).resolve(strict=True)
expected_target=pathlib.Path('/home/qian-qi/work/chain-w1-base9417-owner-target-20261108-ec265b').resolve(strict=True)
assert elf.is_relative_to(expected_target/'release/deps')
b=elf.read_bytes();assert b[:4]==b'\x7fELF'
name='actual_v3_long_chain_public_full_sync_reopen_and_corrupt_index_refusal'
argv=[str(elf),name,'--exact','--ignored','--list']
start=time.monotonic_ns();p=subprocess.run(argv,cwd=repo,capture_output=True,timeout=60);end=time.monotonic_ns()
out=pathlib.Path(a.output)
out.with_suffix('.list.stdout').write_bytes(p.stdout);out.with_suffix('.list.stderr').write_bytes(p.stderr)
assert p.returncode==0,(p.returncode,p.stderr)
assert p.stdout.decode().strip()==name+': test\n\n1 test, 0 benchmarks',p.stdout
record={'schema':'TRNM-W1-C8-HISTORY-COMPILE-AND-LIST1','source_commit':a.head,'cargo_log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'compiler_artifact':art,'elf':str(elf),'elf_bytes':len(b),'elf_sha256':hashlib.sha256(b).hexdigest(),'list_argv':argv,'list_exit':p.returncode,'list_stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'list_stderr_sha256':hashlib.sha256(p.stderr).hexdigest(),'started_monotonic_ns':start,'finished_monotonic_ns':end,'listed_test_count':1,'full_history_executed':False,'test_passes_claimed':0,'production_qualified':False,'resource_qualified':False}
out.write_text(json.dumps(record,indent=2)+'\n')
print(p.stdout.decode(),end='');print(json.dumps({k:record[k] for k in ('schema','source_commit','elf_sha256','listed_test_count','full_history_executed','test_passes_claimed')}))
