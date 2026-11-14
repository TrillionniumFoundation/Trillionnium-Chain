import os,sys,stat,json,hashlib,re,datetime
from pathlib import Path
assert sys.flags.optimize==0
I=json.loads(sys.argv[1]);BASE=Path("/private/tmp/chain-prci-remote-head-5df7ae6-commit-review-20261114-v1");OUT=BASE/"scope-and-patches-v1"
R1="2a86462a1ab20c68151719ba4635e3c294391e64";NEW="5df7ae6f482157c5f7fdcbcd52222117a965053f"
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
reads={}
def read(p,n,h):
 p=Path(p);assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==n and n<8*1024*1024
  chunks=[]
  while True:
   b=os.read(fd,65536)
   if not b:break
   chunks.append(b)
  raw=b"".join(chunks);assert fp(s)==fp(os.fstat(fd))==fp(p.lstat())
 finally:os.close(fd)
 assert len(raw)==n and hashlib.sha256(raw).hexdigest()==h
 pin={"path":str(p),"bytes":n,"sha256":h};reads[str(p)]=(pin,fp(s));return raw,pin
def rd(p,n,h):
 raw,pin=read(p,n,h);return json.loads(raw),pin
s,sp=rd(BASE/"summary.json",1380671,"3a6c6a8ded04c094d23b1d2218f2222041766602c47b86e0a6aef09913576c95")
c,cp=rd(BASE/"new-commit.stdout",1355264,"f2ca4cecadb5a4b465b5b5eb4d7348b02f41fe21a9059d56fa47e0c08f7e6611")
q,qp=rd(BASE/"R1-compare-new.stdout",175282,"fc777c5004b2995f8154b34a36966d88c91d7edd461fc9fcd6fe866494ef917d")
ix,ip=rd(BASE/"EVIDENCE_INDEX.json",1762,"9133f1661263b7701e99b6655582e6fffa8af40a5dedf9d55ee59e8c87aedc82")
for x in ix["files"]:read(x["path"],x["bytes"],x["sha256"])
producer,pin=read(s["producer"]["path"],s["producer"]["bytes"],s["producer"]["sha256"])
assert c["sha"]==NEW and [x["sha"]for x in c["parents"]]==["abfcff23d4e2aab7dfd92dfb34937ec7d6021ead",R1]
assert q["base_commit"]["sha"]==q["merge_base_commit"]["sha"]==R1 and q["status"]=="ahead"and q["behind_by"]==0 and q["ahead_by"]==q["total_commits"]==len(q["commits"])==6
assert len(q["files"])==12 and len({x["filename"]for x in q["files"]})==12
pos=0;terminal=[]
for page in I["pages"]:
 assert page["offset"]==pos and not page["truncated_before_offset"]and not page["text_is_lossy"]
 raw=bytes.fromhex(page["bytes_hex"]);assert len(raw)==page["next_offset"]-pos and hashlib.sha256(raw).hexdigest()==page["chunk_sha256"]
 terminal.append(raw);pos=page["next_offset"]
last=I["pages"][-1];assert last["status"]["state"]=="exited"and last["status"]["exit_code"]==0 and last["output_complete"]is True and pos==last["available_end"]==78331
OUT.mkdir(exist_ok=False);(OUT/"patches").mkdir();(OUT/"terminal").mkdir();made=[]
def put(name,raw):
 p=OUT/name
 with p.open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 pin={"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
 assert p.read_bytes()==raw;made.append(pin);return pin
def js(name,v):return put(name,(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n").encode())
put("scope-producer.py",sys.argv[2].encode());put("original-acquisition-producer.py",producer);put("original-acquisition-launcher.py",I["launcher"].encode())
js("actual-acquisition-launch.json",I["launch"])
pagepins=[js("terminal/page-%03d.json"%i,p)for i,p in enumerate(I["pages"])]
tp=put("terminal/actual-complete-output.log",b"".join(terminal))
tr=js("terminal/actual-terminal-index.json",{"schema":"trnm-actual-pty-page-index-v1","session_id":last["session_id"],"archive_path":last["archive_path"],"actual_status":last["status"],"available_end":pos,"pages":pagepins,"complete_output":tp})
files=[]
for i,x in enumerate(q["files"],1):
 raw=x.get("patch","").encode();parts=[]
 if"patch"in x:
  rem=raw;num=1
  while rem:
   limit=min(len(rem),48000);cut=limit
   if cut<len(rem):
    nl=rem.rfind(b"\n",0,cut)
    if nl>0:cut=nl+1
    else:
     while cut and(rem[cut]&0xc0)==0x80:cut-=1
   part=rem[:cut];part.decode("utf-8");assert len(part)<65536
   parts.append(put("patches/%02d-part-%02d.patch"%(i,num),part));rem=rem[cut:];num+=1
  assert b"".join(Path(p["path"]).read_bytes()for p in parts)==raw
 lines=x.get("patch","").splitlines()
 adds=sum(v.startswith("+")for v in lines);dels=sum(v.startswith("-")for v in lines)
 hunk_valid=True;expected=None;seen=[0,0]
 for line in lines:
  if line.startswith("@@"):
   if expected is not None and tuple(seen)!=expected:hunk_valid=False
   mt=re.match(r"^@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@",line)
   if mt is None:hunk_valid=False;expected=None
   else:expected=(int(mt.group(1)or"1"),int(mt.group(2)or"1"));seen=[0,0]
  elif line.startswith("+"):seen[1]+=1
  elif line.startswith("-"):seen[0]+=1
  elif line.startswith(" "):seen[0]+=1;seen[1]+=1
  elif line.startswith("\\ No newline"):pass
  else:hunk_valid=False
 if expected is not None and tuple(seen)!=expected:hunk_valid=False
 row={k:x.get(k)for k in ("filename","sha","status","additions","deletions","changes","previous_filename")}
 row.update(api_patch_present="patch"in x,api_patch_bytes=len(raw),api_patch_sha256=hashlib.sha256(raw).hexdigest()if"patch"in x else None,actual_patch_additions=adds,actual_patch_deletions=dels,patch_line_counts_match_reported=("patch"in x and adds==x["additions"]and dels==x["deletions"]),hunk_old_new_line_counts_match=hunk_valid if"patch"in x else False,parts=parts)
 files.append(row)
def cv(v):
 d=v["commit"];return{"sha":v["sha"],"tree":d["tree"]["sha"],"parents":[p["sha"]for p in v["parents"]],"author":d["author"],"committer":d["committer"],"message":d["message"]}
commits=js("six-returned-commit-metadata.json",[cv(v)for v in q["commits"]])
summary={"schema":"trnm-R1-to-5df-scope-readonly-v1","status":"CLOSED_UNACCEPTED_NEW_HEAD_SCOPE","created_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"observed_from":s["started_at"],"observed_to":s["finished_at"],"repository":"TrillionniumFoundation/Trillionnium-Chain","new_commit":cv(c),"author_account":None if c.get("author")is None else{k:c["author"].get(k)for k in("login","id")},"committer_account":None if c.get("committer")is None else{k:c["committer"].get(k)for k in("login","id")},"comparison":{"base":q["base_commit"]["sha"],"merge_base":q["merge_base_commit"]["sha"],"status":q["status"],"ahead_by":q["ahead_by"],"behind_by":q["behind_by"],"total_commits":q["total_commits"],"actual_commits_returned":len(q["commits"]),"all_commit_rows_returned":True,"R1_direct_second_parent":True,"local_Git_ancestry_or_new_source_blobs_not_read":True},"files":files,"changed_file_count":len(files),"patches_absent":[x["filename"]for x in files if not x["api_patch_present"]],"patches_counts_or_hunks_incomplete":[x["filename"]for x in files if not x["patch_line_counts_match_reported"]or not x["hunk_old_new_line_counts_match"]],"all_returned_patches_line_counts_and_hunks_match":all(x["patch_line_counts_match_reported"]and x["hunk_old_new_line_counts_match"]for x in files),"all_patch_bytes":sum(x["api_patch_bytes"]for x in files),"all_patch_parts":sum(len(x["parts"])for x in files),"part_max_bytes":max((p["bytes"]for x in files for p in x["parts"]),default=0),"scope_basis":"The R1...5df compare response, not the merge commit's first-parent file list","first_parent_commit_response":{"pin":cp,"files_returned":len(c.get("files",[])),"listing_at_API_300_cap":len(c.get("files",[]))==300,"full_first_parent_file_list_proven":False},"compare_response":qp,"original_acquisition":sp,"actual_terminal":tr,"returned_commits":commits,"source_scope":{"production":["trillionnium/crates/trnm-pon-node/src/ingress/public_v2.rs"],"test_files":["scripts/ci/test_pq_authority_effect_register.py","scripts/test_w1_owned_process_collector_v1.py"],"corpus":"config/pon/pq-cross-branch-corpus-v1.json","documentation_or_evidence_files":8},"observed_intent_not_verified_outcome":"Commit message explicitly describes deadline/ownership fixes, retained historical failure and open business qualification; it is not proof that CI or 4s acceptance is fixed.","new_head_accepted_as_R1":False,"newhead_CI_or_native_tests_examined":False,"source_refs_stage_changes":False,"extra_network_GETs_for_review":0,"qualification":False}
scopepin=js("scope-summary.json",summary)
assert scopepin["bytes"]<65536
for p,ident in list(reads.values()):
 read(p["path"],p["bytes"],p["sha256"]);assert fp(Path(p["path"]).lstat())==ident
union=ix["files"]+[ip]+made
assert len({x["path"]for x in union})==len(union)
indexpin=js("EVIDENCE_INDEX.json",{"files":union,"self_excluded":True,"scope":"Original two GETs plus exact compare patch parts and actual terminal; no source acceptance"})
seal=js("seal-summary.json",{"schema":"trnm-evidence-seal-v1","status":"CLOSED","scope":scopepin,"index":indexpin,"files":len(union),"bytes":sum(x["bytes"]for x in union),"original_terminal_exit":0,"original_terminal_complete":True,"no_new_network_or_Git_or_test":True})
print(json.dumps({"status":"CLOSED","scope":scopepin,"index":indexpin,"seal":seal,"patches_absent":summary["patches_absent"],"patches_counts_or_hunks_incomplete":summary["patches_counts_or_hunks_incomplete"],"parts":[{"file":x["filename"],"parts":x["parts"]}for x in files]},sort_keys=True))
