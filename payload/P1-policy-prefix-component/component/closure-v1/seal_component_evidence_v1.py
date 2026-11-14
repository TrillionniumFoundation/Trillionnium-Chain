#!/usr/bin/env python3
"""Seal closed component evidence; access neither source worktrees nor Git."""
import hashlib,json,os,stat,sys,time,traceback
from pathlib import Path,PurePosixPath
E=Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1');C=E/'closure-v1'
MAX_FILE=16*1024*1024;MAX_TOTAL=32*1024*1024
DF=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
RF=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
def sha(b):return hashlib.sha256(b).hexdigest()
def js(x):return (json.dumps(x,indent=2,sort_keys=True)+'\n').encode()
def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def parentfd(p):
 p=Path(p)
 if not p.is_absolute() or str(p)!=os.path.normpath(str(p)):raise ValueError('noncanonical spelling')
 fd=os.open('/',DF)
 try:
  for part in p.parts[1:-1]:
   n=os.open(part,DF,dir_fd=fd);os.close(fd);fd=n
  return fd,p.name
 except BaseException:os.close(fd);raise
def read(p):
 d,name=parentfd(p);fd=None
 try:
  fd=os.open(name,RF,dir_fd=d);a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>MAX_FILE:raise ValueError('regular/cap')
  chunks=[];left=a.st_size
  while left:
   b=os.read(fd,min(left,262144))
   if not b:raise ValueError('short read')
   chunks.append(b);left-=len(b)
  if os.read(fd,1)or ident(a)!=ident(os.fstat(fd))or ident(a)!=ident(os.stat(name,dir_fd=d,follow_symlinks=False)):raise ValueError('unstable read')
  b=b''.join(chunks);return b,ident(a)
 finally:
  if fd is not None:os.close(fd)
  os.close(d)
def meta(p,b):return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def put(p,b):
 d,name=parentfd(p);fd=None
 try:
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600,dir_fd=d)
  v=memoryview(b)
  while v:
   n=os.write(fd,v);v=v[n:]
  os.fsync(fd)
 finally:
  if fd is not None:os.close(fd)
  os.close(d)
 if read(p)[0]!=b:raise ValueError('readback')
 return meta(p,b)
data=json.loads(sys.argv[1])
if sys.flags.optimize or E.resolve()!=E or C.resolve()!=C:raise ValueError('runtime/root')
put(C/'seal_component_evidence_v1.py',sys.argv[2].encode())
put(C/'packager-terminal.json',js(data['packager_terminal']))
put(C/'prepackaging-evidence-inventory-terminal.json',js(data['inventory_terminal']))
expected={
 'commit-v1/summary.json':'8d69be2772c79b881c0005968d986c548b4f118f3f78392c1d01819dcf638375',
 'commit-v1/final-patch.stdout':'1a4dcea6c65abaa8ecfffec5cebba1e1dd7327608f90f0095527de0b9c4b1356',
 'implementation-v1/source-diff.stdout':'519f7b6950743386f53e655edf5e31d3f198de581c7125461a08b28d81211a37',
 'validation-v1/summary.json':'2447c1d7d7300e3a1b8d0d2591ad362c294b261510ef493511496d0a8bfcdcdf',
 'static-and-python-validation-v1/summary.json':'6464a84fa41517c4d41b0ff4a03032009347c079a904e363a291ed7c4ad8a27a',
 'current-consumer-validation-v1/summary.json':'13cbab826109d2441cea16313f0b68be2a7cba561200f13d053427b0bc05a458',
 'current-consumer-validation-v2/summary.json':'ec1a745291e4ec3f4cda2eb9769d7196490edabc49e92587a17f2dca43b0f9be',
 'current-metadata-update-v1/summary.json':'61e2634360a2cee6bf44577b0797f5d8a9b2e3155c7cc0c387e7d7de4b1e66e9',
 'final-contract-validation-v1/summary.json':'66674134ce77d1340ea670b53cd12a93895b6e46b5acc20c997383410a6e8585',
 'linux-closed-originals-v1/payloads/serial/execution-v1/summary.json':'bf16496bd43d61e935e84748177d8add0ef5cc661be35f77ddb2ec11f94448f4',
 'linux-closed-originals-v1/payloads/default/summary.json':'0be788fea02aa1a59869c7610f42002c39954f52a63b4f4a76bfdf78f038780a',
 'linux-closed-originals-v1/packager-summary.json':'249dd56db615c3bf7e67770cd3a2ef1d6d1c312524bdecbc5c3839a785ddc0d1',
}
verified={}
for rel,digest in expected.items():
 b,_=read(E/rel)
 if sha(b)!=digest:raise ValueError('fixed receipt mismatch '+rel)
 verified[rel]=meta(E/rel,b)
summary={
 'schema':'trnm-policy-prefix-component-closure-v1','status':'CLOSED_COMPONENT_EVIDENCE_ONLY',
 'commit':'6a8cd55573065ceb50cdb65a7834615f79b521ae','tree':'cbd6b4552c87af27c72c0189806baeb33ecb8bf5',
 'parent':'ed0d35487f2a67239e4d646fd41c2c7acb5cc740','changed_paths':10,
 'original_rust_sha256':'1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70',
 'candidate_rust_sha256':'0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a',
 'verified_original_receipts':verified,
 'outcomes':{
  'Mac_native':'HOLD: 11 preexisting Darwin test-fixture compilation errors, zero Rust test executions',
  'Linux_serial_harness':'3 prefix controls + 1 original golden passed; RUST_TEST_THREADS=1 preserved',
  'Linux_default_harness_followup':'same 3 + 1 controls passed, zero ignored; inherited RUST_TEST_* removed, exact original commands retained',
  'strict_Clippy':'one actual all-target/all-feature run passed; not repeated with default harness',
  'policy_and_hash_use':'7 + 33 original tests passed; actual fixed-inventory inspector HOLD_NO_GO, 19 uses/31 sources, no complete-callgraph claim',
  'first_Mac_frozen_budget':'original Ran 58; failures=1, errors=4. ERROR entries include subtest errors, so a top-level pass count is not inferred by subtraction',
  'canonical_TMPDIR_current_consumers':'58 frozen + 25 current + 60 composition + 57 claim guard = 200 passed; no source/test alteration for temporary-directory issue',
  'final_actual_source_contracts':'actual corpus/repository/CI contract and diff checks passed; not hosted qualification',
 },
 'preserved_failures':['Mac Rust platform compilation','Mac original temporary-directory symlink rejection','orchestration JavaScript parse errors before operator calls','attempt to invoke nonexistent corpus helper after source/doc preparation'],
 'frozen_json_sha256':{
  'config/pon/pq128-lifetime-budget-v1.json':'0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd',
  'config/pon/pq128-source-lock-v1.json':'094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2',
  'config/pon/pq128-lifetime-composition-v2.json':'5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052',
 },
 'scope_boundaries':{'no_nonce_optimization':True,'no_fresh_Host_or_budget_or_deadline_change':True,'hosted_four_second_performance_proved':False,'SQLite_native_qualification_granted':False,'global_policy_call_count_proved':False,'simultaneous_cold_OnceLock_contention_proved':False,'historical_M8_readbacks_relabelled_as_current':False},
 'exclusions':data['excluded']+[
  {'path':'/home/qian-qi/chain-final-consolidation-20261114-root/source','reason':'live root source excluded'},
  {'path':'/home/qian-qi/chain-final-consolidation-20261114-root/target','reason':'compiled target excluded'},
  {'path':'/private/tmp/chain-public-policy-P1-independent-closure-review-20261114-v1','reason':'separate later metadata review; root will archive independently'},
  {'path':'root P1 full repository-truth/external execution directories','reason':'not part of this closed component selection; running results excluded'},
 ],
 'artifact_packaging_only':True,'tests_or_Git_or_network_or_source_worktree_operations':False,
}
put(C/'component-summary.json',js(summary))
readme="""# P1 policy-prefix component evidence

This closure preserves the complete existing component evidence and the completed Linux original-file transfer. P1 is commit 6a8cd55573065ceb50cdb65a7834615f79b521ae, tree cbd6b4552c87af27c72c0189806baeb33ecb8bf5, with one M8 parent and ten changed paths. The source change caches only the unfinalized SHA256 state for the exact immutable 5,105-byte public-policy prefix; each call clones it and appends the original six framed suffixes.

The first Linux run was serial (RUST_TEST_THREADS=1), with three new controls plus the original golden and strict Clippy passing. A distinct follow-up repeated the same four tests under the default harness, with no ignored tests. The first Mac native attempt remains a compilation HOLD. The initial Mac budget test attempt remains Ran 58, failures=1, errors=4; errors include subtests, so no top-level pass total is inferred by subtracting these figures. Original logs and the committed P1 document remain unchanged. The successful canonical-TMPDIR consumer closure is separately recorded as 200 tests. Original policy and Hash-use suites add 7 and 33 tests.

The compiler-path warning does not establish SQLite native qualification. No hosted four-second performance result is inferred. The 1,099 fresh-Host observations and the separate policy-counter lower-bound value 1,099 belong to different scopes. Concurrent clone controls do not establish simultaneous cold-cache initialization contention. Current source mappings changed only their exact reviewed hash correspondence; all three frozen JSON identities and qualification denials remain fixed.

The complete Linux ZIP has 115 members under originals/, and its separate index supplies exact member names and original ROG origins. All original payloads also remain individually available. Executed orchestration code is saved as the exact strings used by actual terminal calls, with the timing of preservation stated explicitly.

The evidence index excludes itself and its final seal to avoid self-reference. The seal binds the index, and all three are archived by the later stage manifest. Provider transfer bookkeeping is explicitly excluded; no validation output, known failure, or timeout is cleaned up. The running root P1 full lanes and the separate later P1 metadata review are outside this selection.
"""
put(C/'README.md',readme.encode())
excluded={x['path']:x for x in data['excluded']}
files=[];identities={};inodes=set();total=0
raw_roster=json.loads(read(E/'linux-closed-originals-v1/source-roster.json')[0])['files']
raw_origins={'linux-closed-originals-v1/payloads/'+x['path']:x['origin']for x in raw_roster}
def walk(root):
 for entry in sorted(os.scandir(root),key=lambda x:x.name):
  p=Path(entry.path);s=entry.stat(follow_symlinks=False)
  if stat.S_ISDIR(s.st_mode):
   if p.resolve()!=p:raise ValueError('directory alias')
   yield from walk(p)
  elif stat.S_ISREG(s.st_mode):yield p
  else:raise ValueError('special file in component')
for p in walk(E):
 rel=p.relative_to(E).as_posix()
 if rel in excluded:
  if p.stat().st_size!=excluded[rel]['bytes']:raise ValueError('excluded bookkeeping identity changed')
  continue
 if rel in {'closure-v1/EVIDENCE_INDEX.json','closure-v1/seal.json'}:raise ValueError('seal outputs already exist')
 b,s=read(p)
 if s[:2]in inodes:raise ValueError('duplicate component inode')
 inodes.add(s[:2]);total+=len(b)
 if total>MAX_TOTAL or len(files)>=2000:raise ValueError('component count/total cap')
 origin=raw_origins.get(rel,{'host':'mac','path':str(p)})
 files.append({'path':rel,'bytes':len(b),'sha256':sha(b),'origin':origin});identities[rel]=s
index={'schema':'trnm-policy-prefix-component-evidence-index-v1','evidence_root':str(E),'file_count':len(files),'total_bytes':total,'files':files,'explicit_excluded_provider_bookkeeping':data['excluded'],'index_and_seal_not_self_listed':True,'source_or_Git_or_tests_executed':False}
im=put(C/'EVIDENCE_INDEX.json',js(index))
for row in files:
 b,s=read(E/row['path'])
 if s!=identities[row['path']]or len(b)!=row['bytes']or sha(b)!=row['sha256']:raise ValueError('closed component changed')
seal={'schema':'trnm-policy-prefix-component-evidence-seal-v1','status':'SEALED','index':im,'indexed_files':len(files),'indexed_bytes':total,'all_indexed_originals_rechecked':True,'known_failures_preserved':True,'source_Git_network_tests_executed':False,'scope':'complete closed component E; original later independent review is a separate fixed selection'}
sm=put(C/'seal.json',js(seal))
print(json.dumps({'status':'SEALED','index':im,'seal':sm,'selected_files_including_index_and_seal':len(files)+2,'selected_bytes_including_index_and_seal':total+im['bytes']+sm['bytes'],'excluded':data['excluded']}),flush=True)
