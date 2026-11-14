#!/usr/bin/env python3
"""Seal already completed immutable metadata review; no repository operations."""
import difflib,hashlib,json,os,stat,sys
from pathlib import Path
B=Path('/private/tmp/chain-N2-metadata-integration-review-20261114-v1');O=B/'final-review-v1'
if os.path.lexists(O):raise ValueError('create-only final review')
O.mkdir(mode=0o700)
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def js(x):return (json.dumps(x,indent=2,sort_keys=True)+'\n').encode()
def read(p):
 p=Path(p)
 if p.resolve()!=p:raise ValueError('alias')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1 or s.st_size>16*1024*1024:raise ValueError('regular/cap')
  b=b''
  while len(b)<s.st_size:
   chunk=os.read(fd,min(262144,s.st_size-len(b)))
   if not chunk:raise ValueError('short read')
   b+=chunk
  sig=lambda a:(a.st_dev,a.st_ino,a.st_mode,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns)
  if os.read(fd,1)or sig(s)!=sig(os.fstat(fd))or sig(s)!=sig(p.lstat()):raise ValueError('changed read')
  return b
 finally:os.close(fd)
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  v=memoryview(b)
  while v:
   n=os.write(fd,v);v=v[n:]
  os.fsync(fd)
 finally:os.close(fd)
 if read(p)!=b:raise ValueError('readback')
 return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
put(O/'seal_readonly_review_v1.py',sys.argv[2].encode())
data=json.loads(sys.argv[1])
for i,x in enumerate(data['terminals']):put(O/('actual-terminal-'+str(i)+'.json'),js(x))
table=json.loads(read(B/'source-table.json'))
report=json.loads(read(B/'static-review-v1/review.json'))
if sha(read(B/'static-review-v1/review.json'))!='151c8365f7304a7191632c6cd0b5d673d030422a94741f91795d38d1fcd73f68':raise ValueError('fixed completed report')
for row in table['files']:
 raw=read(Path(row['capture']['path']))
 if len(raw)!=row['bytes']or sha(raw)!=row['sha256']or blob(raw)!=row['oid']:raise ValueError('captured input changed')
path='config/pon/pq-cross-branch-corpus-v1.json'
old=read(B/'sources'/('P2--'+path.replace('/','--')+'.original'));new=old
pins=report['recommendation']['conditional_3_pin_updates']
for row in pins:
 a=('"'+row['path']+'": "'+row['old_P2_corpus_oid']+'"').encode()
 b=('"'+row['path']+'": "'+row['incoming_N2_corpus_oid']+'"').encode()
 if new.count(a)!=1:raise ValueError('exact pin line')
 new=new.replace(a,b,1)
before=json.loads(old);after=json.loads(new)
if set(before)!=set(after)or before['required_paths']!=after['required_paths']or set(before['pinned_blobs'])!=set(after['pinned_blobs']):raise ValueError('corpus preservation')
changed={p for p in before['pinned_blobs']if before['pinned_blobs'][p]!=after['pinned_blobs'][p]}
if changed!=set(x['path']for x in pins):raise ValueError('three pins only')
for k in before:
 if k!='pinned_blobs'and before[k]!=after[k]:raise ValueError('unselected corpus field')
patch=''.join(difflib.unified_diff(old.decode().splitlines(keepends=True),new.decode().splitlines(keepends=True),fromfile='a/'+path,tofile='b/'+path))
pm=put(O/'conditional-P2-corpus-three-W1-pins.patch',patch.encode())
selection={
 'schema':'trnm-N2-readonly-metadata-integration-recommendation-v1',
 'fixed_heads':table['heads'],'fixed_trees':table['identities'],
 'status':'NO_STATIC_METADATA_BLOCKER_FOR_REVIEWED_SELECTION',
 'decisions':[
 {'path':'config/pon/hash-use-contract-v1.json','disposition':'retain P2 exact blob','oid':'986a94eaf6b1c44a11595cc98ac4f9925e7c943e','reason':'all31 bindings match selected P2 source; incoming differs only at store.rs whose N implementation was explicitly not selected'},
 {'path':'scripts/ci/hash_use_contract.py','disposition':'retain P2 exact blob','oid':'cf55d45678bfb27d9ad9fcf2863a05aa1bc0540b','reason':'H1 source-map commitment binds selected actual31; all other AST nodes identical across N/N2/P2'},
 {'path':'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs','disposition':'already exact in both P2 and N2','oid':'a13590cbefab86636e12a83f4eaf58b8d69aaf8e','reason':'1740 identical entries; two current PQ JSON entries already included in P2'},
 {'path':path,'disposition':'retain P2 all2606 pins/all2510 required entries; conditional three reviewed W1 pin updates only','P2_oid':blob(old),'conditional_new_oid':blob(new),'conditional_new_sha256':sha(new),'conditional_new_bytes':len(new),'patch':pm,'reason':'incoming wholesale corpus would remove B1 carrier requirement and roll back40 current pins; no such replacement is selected'}
 ],
 'conditional_three_updates':pins,
 'conditional_patch_not_applied':True,
 'soleplan_or_audit_report_future_changes_not_in_this_patch':True,
 'actual_blob_proof':report['actual_31_source_proof'],
 'exact_semantics':{'purposes':19,'paths':31,'review_base':'e4abb172147e941b62483652b0ceabaae4317624','semantics_sha256':'29189f8e96a255472577479d46204b2b403a1f8e27806da6aa616e417ced0b5b','all_typed_semantics_and_qualifications_equal':True,'reader_AST_except_one_map_literal_equal':True,'MAX_BYTES':1048576,'MAX_SOURCE_BYTES':2097152,'MAX_DEPTH':64},
 'actual_source_map_matches':{'N':25,'N2':31,'P2':31},
 'runtime_source_mutation':False,'tests_run':False,'source_worktree_stage_Git_refs_network_writes':False,
 'qualification_granted':False,
 'advisory_path_query_note':'The actual protected-path rows list only six existing returned entries. Two guessed collector paths in the raw static producer did not resolve; no read or coverage claim was made for them. Canonical collector paths are identified directly by existing P2 corpus entries and are not in the complete seven-path N-to-N2 changed set.',
 'actual_collector_corpus_paths':{x:before['pinned_blobs'][x]for x in ['scripts/w1_owned_process_collector_v1.py','scripts/test_w1_owned_process_collector_v1.py']},
}
sm=put(O/'review.json',js(selection))
readme="""# N2 metadata integration review

The immutable inputs are N=5a4b7fe8de1adce803184f262fd9f704ead1930c, N2=096c6b5f9b952c49389fd975515744074ba61317, and P2=1e54c4ff66a92827c83bea8715f59f6b299e98cf. N2 has exactly N as its parent and changes seven paths. This review owns four metadata paths; the three W1 workflow/control files are reviewed separately.

## Selected integration

Keep the complete P2 Hash-use JSON and reader. N2 fixes six stale inputs in its own inherited mapping. Five of those are already the same as P2; the sixth is store.rs, for which P2 deliberately retains the reviewed 391,470-byte implementation (SHA256 591827...), while N2 binds its different 391,556-byte implementation (ae54...). The selected P2 source map and the incoming N2 source map each match all 31 of their own actual immutable Git blobs. Retaining P2 keeps its selected source implementation and corresponding H1 identity together.

All 19 use semantics, all 31 paths, the original review-base context, qualification denials, and strict reader checks remain typed-identical. The three reader ASTs are identical after replacing only the one reviewed map-digest literal. No function, mathematical parameter, byte ceiling, source ceiling, nesting ceiling, or qualification flag changes. This is a closed declared-use inventory and does not claim complete-callgraph review.

The distributed-source inventory is already byte-identical in N2 and P2: 1,740 entries, including both current PQ JSON files. No additional inventory edit is needed for these inputs.

Use P2 as the corpus baseline. It has 2,606 pinned blobs and 2,510 required paths. N2's complete corpus would remove the B1 original collector carrier and substitute 40 existing pin values, including the P1 policy-prefix source and current21 correspondence. The supplied external patch changes only the three W1 pins, conditional on selecting those exact independently reviewed N2 blobs. It preserves every other pin, required path, ordering and typed field. It is not applied to a worktree; any later root plan/report edit needs its normal final pin refresh.

## Evidence and limits

The captures include all four full source files at all three commits, exact bounded diffs, typed deltas, source-mode/OID/size/SHA tables, and a content-address-checked batch of 32 unique blobs (1,336,463 bytes) covering the two actual 31-source sets. The old N map matches 25/31 of its actual inputs; N2 and P2 each match 31/31.

All operations were fixed local Git reads and external evidence writes. No fetch, source/worktree modification, refs/config mutation, stage write, repository helper import, test execution or qualification occurred. Full original gates must run on the eventual selected merge, independently of this static conclusion.
"""
put(O/'README.md',readme.encode())
files=[];total=0
for root,dirs,names in os.walk(B,followlinks=False):
 for name in dirs:
  p=Path(root)/name
  if p.resolve()!=p or not stat.S_ISDIR(p.lstat().st_mode):raise ValueError('directory alias')
 for name in sorted(names):
  p=Path(root)/name
  if p in [O/'EVIDENCE_INDEX.json',O/'seal.json']:raise ValueError('index already exists')
  b=read(p);total+=len(b)
  if total>24*1024*1024:raise ValueError('bounded evidence closure')
  files.append({'path':p.relative_to(B).as_posix(),'bytes':len(b),'sha256':sha(b),'origin':{'host':'mac','path':str(p)}})
files.sort(key=lambda x:x['path'])
im=put(O/'EVIDENCE_INDEX.json',js({'schema':'trnm-N2-metadata-evidence-index-v1','evidence_root':str(B),'file_count':len(files),'total_bytes':total,'files':files,'index_and_seal_excluded_from_self_roster':True,'tests_or_source_refs_stage_network_mutated':False}))
for row in files:
 b=read(B/row['path'])
 if len(b)!=row['bytes']or sha(b)!=row['sha256']:raise ValueError('final raw evidence change')
seal=put(O/'seal.json',js({'schema':'trnm-N2-metadata-evidence-seal-v1','status':'SEALED_STATIC_READONLY_REVIEW','index':im,'review':sm,'all_selected_originals_rechecked':True,'tests_run':False,'source_Git_stage_network_mutation':False}))
print(json.dumps({'status':'SEALED_STATIC_READONLY_REVIEW','review':sm,'patch':pm,'index':im,'seal':seal,'selected_files_including_index_and_seal':len(files)+2,'selected_bytes_including_index_and_seal':total+im['bytes']+seal['bytes']}),flush=True)
