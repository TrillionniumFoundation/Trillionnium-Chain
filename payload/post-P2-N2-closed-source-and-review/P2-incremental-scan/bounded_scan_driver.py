import ast, collections, datetime, hashlib, json, os, pathlib, re, stat, subprocess, sys, time
sys.dont_write_bytecode=True
W=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
E=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/incremental-1e54c4-after-6a8cd5-v1")
HEAD="1e54c4ff66a92827c83bea8715f59f6b299e98cf"
TREE="2c0716f9165f7cbc31ce8eae17f17bf2643d30cb"
BASE="6a8cd55573065ceb50cdb65a7834615f79b521ae"
env=dict(os.environ,PATH="/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0")
steps=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def put(name,b):
 p=E/name
 with p.open("xb") as f:f.write(b)
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def dump(name,v):return put(name,(json.dumps(v,indent=2,sort_keys=True)+"\n").encode())
def run(label,args,inp=None):
 t=time.monotonic();r=subprocess.run(["/usr/bin/git","-C",str(W),*args],input=inp,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=60)
 steps.append({"label":label,"argv":["/usr/bin/git","-C",str(W),*args],"exit_code":r.returncode,"seconds":round(time.monotonic()-t,3),"stdout":put(label+".stdout",r.stdout),"stderr":put(label+".stderr",r.stderr)})
 if r.returncode!=0:raise RuntimeError("git read failed: "+label)
 return r.stdout
def fence(label):
 h=run(label+"-head",["rev-parse","HEAD"]).decode().strip()
 tr=run(label+"-tree",["rev-parse","HEAD^{tree}"]).decode().strip()
 br=run(label+"-branch",["symbolic-ref","HEAD"]).decode().strip()
 st=run(label+"-status",["status","--porcelain=v1","--untracked-files=all"])
 assert h==HEAD and tr==TREE and not st
 return {"head":h,"tree":tr,"branch":br,"clean":True,"status_sha256":sha(st)}
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
stage="producer binding"
try:
 prior=(E/"prior-scan_driver.py").read_bytes()
 assert sha(prior)=="5c292f6554bbf1345d6e58a3c64cf9099230223fc9c70f217a575f6f20ee7368"
 assignments=[n for n in ast.parse(prior).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="PATTERNS" for t in n.targets)]
 assert len(assignments)==1
 PATTERNS=ast.literal_eval(assignments[0].value)
 assert len(PATTERNS)==5 and all(isinstance(k,str) and isinstance(v,bytes) for k,v in PATTERNS.items())
 prior_scope=json.loads((E/"prior-patterns-and-scope.json").read_bytes())
 patterns=[{"id":k,"bytes_regex_ascii":v.decode("ascii"),"flags":[]} for k,v in PATTERNS.items()]
 assert prior_scope["patterns"]==patterns
 compiled={k:re.compile(v) for k,v in PATTERNS.items()}
 dump("patterns-and-scope.json",{"schema":"bounded-commit-delta-credential-patterns-v1","patterns":patterns,"same_regex_bytes_as_prior_producer":True,"prior_producer_sha256":sha(prior),"scope":"Only raw bytes of blobs enumerated by git rev-list --objects --no-object-names HEAD ^BASE for the fixed commits below; binary and text treated identically.","head":HEAD,"excluded_base":BASE,"recursive_archive_decompression":False,"all_secret_types_excluded":False,"full_database_inventory_or_fsck_run":False,"original_8gb_scanner_regex_equivalence_claimed":False})
 before=fence("source-before")
 commit=run("head-commit",["cat-file","commit",HEAD])
 assert hashlib.sha1(b"commit "+str(len(commit)).encode()+b"\0"+commit).hexdigest()==HEAD
 headers=commit.split(b"\n\n",1)[0].splitlines()
 assert [x.split(b" ",1)[1].decode() for x in headers if x.startswith(b"parent ")]==["6a8cd55573065ceb50cdb65a7834615f79b521ae"]
 run("base-is-ancestor",["merge-base","--is-ancestor",BASE,HEAD])
 stage="bounded enumeration"
 raw=run("new-objects",["rev-list","--objects","--no-object-names",HEAD,"^"+BASE])
 oids=raw.decode("ascii").splitlines()
 assert oids and len(oids)==len(set(oids)) and len(oids)<=4096
 assert all(re.fullmatch("[0-9a-f]{40}",oid) for oid in oids)
 meta=run("new-object-metadata",["cat-file","--batch-check=%(objectname) %(objecttype) %(objectsize)"],raw)
 inv={}
 for line in meta.decode().splitlines():
  oid,kind,size=line.split();assert oid in oids and oid not in inv and kind in ("blob","tree","commit","tag")
  inv[oid]=(kind,int(size));assert int(size)>=0
 assert set(inv)==set(oids)
 blobs=[(oid,size) for oid,(kind,size) in inv.items() if kind=="blob"]
 assert sum(n for _,n in blobs)<=64*1024*1024
 paths_raw=run("delta-paths",["diff-tree","--no-commit-id","--no-renames","--raw","-r","--no-abbrev","-z",BASE,HEAD])
 items=paths_raw.split(b"\0");assert items[-1]==b"";items=items[:-1];assert len(items)%2==0
 paths={}
 for i in range(0,len(items),2):
  fields=items[i].decode("ascii").split()
  assert len(fields)==5 and fields[0].startswith(":")
  paths.setdefault(fields[3],[]).append({"path":items[i+1].decode("utf-8"),"old_mode":fields[0][1:],"new_mode":fields[1],"old_blob":fields[2],"new_blob":fields[3],"status":fields[4]})
 counts={k:0 for k in compiled};hits=[];coverage=[];total=0
 stage="bounded raw blob scan"
 batcherr=(E/"blob-batch.stderr").open("xb")
 proc=subprocess.Popen(["/usr/bin/git","-C",str(W),"cat-file","--batch"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=batcherr,env=env)
 try:
  for oid,size in blobs:
   proc.stdin.write((oid+"\n").encode());proc.stdin.flush()
   header=proc.stdout.readline().decode("ascii").strip().split()
   assert header==[oid,"blob",str(size)]
   chunks=[];remaining=size
   while remaining:
    data=proc.stdout.read(min(1024*1024,remaining));assert data
    chunks.append(data);remaining-=len(data)
   data=b"".join(chunks);assert len(data)==size and proc.stdout.read(1)==b"\n"
   assert hashlib.sha1(b"blob "+str(size).encode()+b"\0"+data).hexdigest()==oid
   matches={}
   for name,pattern in compiled.items():
    offsets=[m.start() for m in pattern.finditer(data)]
    if offsets:
     counts[name]+=len(offsets);matches[name]={"count":len(offsets),"offsets":offsets}
   row={"oid":oid,"bytes":size,"sha256":sha(data),"content_address_verified":True,"raw_bytes_scanned":size,"pattern_categories_checked":list(compiled),"changed_paths":paths.get(oid,[])}
   coverage.append(row);total+=size
   if matches:
    hit={**row,"matches":matches,"raw_secret_values_retained":False,"classification":"REVIEW_REQUIRED"}
    if set(matches)=={"private_key_header"} and size<=2*1024*1024:
     try:
      syntax=ast.parse(data.decode("utf-8"));literals=[]
      for node in ast.walk(syntax):
       if isinstance(node,ast.Constant) and isinstance(node.value,(str,bytes)):
        value=node.value.encode() if isinstance(node.value,str) else node.value
        if compiled["private_key_header"].search(value):
         lines=[s for s in value.splitlines() if s.strip() and not s.startswith(b"-----")]
         literals.append({"line":node.lineno,"literal_bytes":len(value),"has_end_private_marker":b"-----END " in value,"non_marker_lines":len(lines)})
      hit["python_marker_literal_metadata"]=literals
      if literals and all(not x["has_end_private_marker"] and x["non_marker_lines"]==0 for x in literals):hit["classification"]="MARKER_ONLY_PYTHON_LITERAL_REQUIRES_CONTEXT_REVIEW"
     except (UnicodeError,SyntaxError,ValueError,MemoryError):hit["marker_AST_unavailable"]=True
    hits.append(hit)
  proc.stdin.close();assert proc.wait(timeout=60)==0
 finally:
  if proc.poll() is None:proc.kill();proc.wait()
  batcherr.close()
 assert len(coverage)==len(blobs) and total==sum(n for _,n in blobs)
 dump("blob-coverage.json",coverage);dump("hits-redacted.json",hits)
 after=fence("source-after");assert before==after
 dump("steps.json",steps)
 summary={"schema":"bounded-new-blobs-1e54c4-after-6a8cd5-v1","started_utc":started,"finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source_before":before,"source_after":after,"head":HEAD,"tree":TREE,"excluded_base":BASE,"enumerated_objects":len(inv),"object_types":dict(collections.Counter(kind for kind,size in inv.values())),"new_blobs":len(blobs),"new_blob_raw_bytes":total,"all_new_blob_content_addresses_verified":True,"all_new_blob_raw_bytes_scanned":True,"same_five_regex_bytes_as_reviewed_prior_producer":True,"match_counts":counts,"hit_blob_count":len(hits),"hits_require_context_review":bool(hits),"credential_values_disclosed":False,"only_external_evidence_written":True,"source_head_tree_status_unchanged":True,"no_git_object_ref_or_network_writes":True,"tests_run":False,"full_history_scanned":False,"fsck_run":False,"recursive_archive_decompression":False,"all_secret_types_excluded":False,"prior_8gb_scanner_regex_equivalence_claimed":False,"limitations":["Five exact explicit patterns only; absence is not proof that every secret type is absent.","No recursive archive decompression.","Only fixed commit difference; no future object or outside-range claim."],"status":"REVIEW_REQUIRED" if hits else "PASS_FOR_DECLARED_SCOPE"}
 s=dump("summary.json",summary)
 entries=[]
 for f in sorted(E.iterdir()):
  if f.is_file():
   st=f.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1
   b=f.read_bytes();entries.append({"name":f.name,"bytes":len(b),"sha256":sha(b)})
 idx=dump("EVIDENCE_INDEX.json",{"schema":"bounded-incremental-scan-evidence-index-v1","files":entries})
 print(json.dumps({"summary":s,"index":idx,"objects":len(inv),"blobs":len(blobs),"raw_bytes":total,"match_counts":counts,"hit_blob_count":len(hits),"source_unchanged":before==after,"status":summary["status"]}),flush=True)
except BaseException as ex:
 dump("failure.json",{"stage":stage,"type":type(ex).__name__,"message":str(ex),"steps":steps})
 raise
