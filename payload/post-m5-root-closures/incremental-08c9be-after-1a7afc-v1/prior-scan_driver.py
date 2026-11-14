import ast,collections,datetime,hashlib,json,mmap,os,re,subprocess,sys,tempfile,time
from pathlib import Path
E=Path("/private/tmp/chain-audit-20261114-branch-graph/final-object-delta-review-v1")
G=Path("/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git")
OLD=Path("/private/tmp/chain-consolidation-20261114-root/all-object-secret-inventory-v1/object-inventory.txt")
EXPECTED_OLD="ec74ecf3a402fdc790d4649a2829e7f4995b724ad157b849e73d4ff94aab0648"
CANDIDATE=sys.argv[1]
assert re.fullmatch("[0-9a-f]{40}",CANDIDATE)
RUN=E/"run-v1";RUN.mkdir()
env=dict(os.environ,GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0")
started=datetime.datetime.now(datetime.timezone.utc).isoformat();t0=time.monotonic();stage="initialization"
def sh(b):return hashlib.sha256(b).hexdigest()
def filehash(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for c in iter(lambda:f.read(1024*1024),b""):h.update(c)
 return h.hexdigest()
def write(name,v):
 p=RUN/name
 with p.open("x",encoding="utf-8") as f:json.dump(v,f,indent=2,sort_keys=True);f.write("\n")
 return p
def command(args,stdout=None,stderr=None):
 return subprocess.run(["/usr/bin/git","--git-dir="+str(G),*args],env=env,stdout=stdout if stdout is not None else subprocess.PIPE,stderr=stderr if stderr is not None else subprocess.PIPE,check=False)
def capture(args):
 r=command(args);assert r.returncode==0,"git read command failed";return r.stdout
def parse_inventory(raw):
 result={}
 for line in raw.splitlines():
  oid,kind,size=line.decode("ascii").split();assert re.fullmatch("[0-9a-f]{40}",oid) and kind in ("blob","commit","tree","tag") and oid not in result
  result[oid]=(kind,int(size))
 return result
PATTERNS={
 "github_classic_token":rb"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
 "github_fine_grained_token":rb"\bgithub_pat_[A-Za-z0-9_]{20,255}\b",
 "aws_access_key_id":rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
 "slack_token":rb"\b(?:xox[baprs]-[A-Za-z0-9-]{10,255}|xapp-[A-Za-z0-9-]{10,255})\b",
 "private_key_header":rb"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----",
}
try:
 write("started.json",{"started_at":started,"pid":os.getpid(),"git_dir":str(G),"expected_candidate":CANDIDATE})
 assert capture(["cat-file","-t",CANDIDATE]).strip()==b"commit"
 tree=capture(["rev-parse",CANDIDATE+"^{tree}"]).decode().strip()
 before_refs=capture(["for-each-ref","--format=%(refname) %(objectname)"])
 (RUN/"refs-before.txt").write_bytes(before_refs)
 old_raw=OLD.read_bytes();assert sh(old_raw)==EXPECTED_OLD
 old=parse_inventory(old_raw)
 patterns=[{"id":k,"bytes_regex_ascii":v.decode("ascii"),"flags":[]} for k,v in PATTERNS.items()]
 write("patterns-and-scope.json",{"schema":"explicit-new-delta-credential-patterns-v1","patterns":patterns,"previous_scanner_driver_available":False,"previous_regex_equivalence_claimed":False,"reason":"Original summary records category names only; original driver not found by coordinator. These are explicitly new regular expressions.","scope":"All new Git blob raw bytes from frozen local enumeration; no recursive archive decompression; binary and text blobs treated identically.","all_secret_types_excluded":False})
 stage="object enumeration"
 with (RUN/"object-inventory-after.txt").open("xb") as out,(RUN/"inventory.stderr.log").open("xb") as err:
  r=command(["cat-file","--batch-all-objects","--batch-check=%(objectname) %(objecttype) %(objectsize)"],out,err)
 assert r.returncode==0
 raw=(RUN/"object-inventory-after.txt").read_bytes();current=parse_inventory(raw)
 missing=sorted(set(old)-set(current));changed=[p for p in old.keys()&current.keys() if old[p]!=current[p]]
 assert not missing and not changed,"prior frozen objects absent or metadata differs"
 delta={p:current[p] for p in sorted(set(current)-set(old))}
 (RUN/"new-object-inventory.txt").write_text("".join(p+" "+v[0]+" "+str(v[1])+"\n" for p,v in delta.items()))
 blobs=[(p,n) for p,(kind,n) in delta.items() if kind=="blob"]
 compiled={k:re.compile(v) for k,v in PATTERNS.items()}
 counts={k:0 for k in compiled};hits=[];scanned=0;totalbytes=0
 stage="new raw blob pattern scan"
 with (RUN/"batch-stderr.log").open("xb") as batcherr,(RUN/"blob-coverage.jsonl").open("x",encoding="utf-8") as coverage:
  proc=subprocess.Popen(["/usr/bin/git","--git-dir="+str(G),"cat-file","--batch"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=batcherr,env=env)
  for oid,size in blobs:
   proc.stdin.write((oid+"\n").encode());proc.stdin.flush()
   header=proc.stdout.readline().decode("ascii").strip().split()
   assert header==[oid,"blob",str(size)],"batch object header mismatch"
   digest=hashlib.sha256();object_digest=hashlib.sha1(b"blob "+str(size).encode()+b"\0")
   with tempfile.TemporaryFile(dir=RUN) as temp:
    remaining=size
    while remaining:
     data=proc.stdout.read(min(1024*1024,remaining));assert data,"truncated blob"
     temp.write(data);digest.update(data);object_digest.update(data);remaining-=len(data)
    assert proc.stdout.read(1)==b"\n"
    assert object_digest.hexdigest()==oid,"blob content address differs"
    temp.flush();matches={}
    if size:
     with mmap.mmap(temp.fileno(),0,access=mmap.ACCESS_READ) as view:
      for name,pattern in compiled.items():
       offsets=[]
       for match in pattern.finditer(view):offsets.append(match.start())
       if offsets:
        counts[name]+=len(offsets);matches[name]={"count":len(offsets),"offsets":offsets}
      if matches:
       hit={"oid":oid,"bytes":size,"source_sha256":digest.hexdigest(),"matches":matches,"raw_secret_values_retained":False,"classification":"REVIEW_REQUIRED"}
       if set(matches)=={"private_key_header"} and size<=2*1024*1024:
        try:
         syntax=ast.parse(view[:].decode("utf-8"))
         literals=[]
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
   scanned+=1;totalbytes+=size
   coverage.write(json.dumps({"oid":oid,"bytes":size,"sha256":digest.hexdigest(),"content_address_verified":True,"raw_bytes_scanned":size,"pattern_categories_checked":list(compiled)},sort_keys=True)+"\n")
   if scanned%250==0:coverage.flush()
  proc.stdin.close();exitcode=proc.wait(timeout=60);assert exitcode==0,"cat-file failed"
 assert scanned==len(blobs) and totalbytes==sum(n for _,n in blobs)
 if hits:
  needed={h["oid"] for h in hits};names={}
  r=capture(["rev-list","--objects","--all"])
  for line in r.decode("utf-8",errors="replace").splitlines():
   oid,sep,name=line.partition(" ")
   if oid in needed and sep:names.setdefault(oid,[]).append(name)
  for h in hits:h["reachable_path_hints"]=names.get(h["oid"],[])
 write("hits-redacted.json",hits)
 stage="full fsck"
 fsckstart=time.monotonic()
 with (RUN/"git-fsck.log").open("xb") as out:
  r=command(["fsck","--full","--no-reflogs"],out,subprocess.STDOUT)
 fsck={"exit":r.returncode,"seconds":round(time.monotonic()-fsckstart,3),"bytes":(RUN/"git-fsck.log").stat().st_size,"sha256":filehash(RUN/"git-fsck.log"),"command":["git","fsck","--full","--no-reflogs"],"repository_object_view_not_atomic_with_enumeration":True}
 write("git-fsck-summary.json",fsck)
 after_refs=capture(["for-each-ref","--format=%(refname) %(objectname)"]);(RUN/"refs-after.txt").write_bytes(after_refs)
 summary={"schema":"final-new-git-object-delta-integrity-and-pattern-review-v1","started_at":started,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"seconds":round(time.monotonic()-t0,3),"git_dir":str(G),"expected_code_commit":CANDIDATE,"expected_code_tree":tree,"baseline_inventory":{"path":str(OLD),"sha256":EXPECTED_OLD,"bytes":len(old_raw),"objects":len(old)},"current_inventory":{"path":"object-inventory-after.txt","sha256":sh(raw),"bytes":len(raw),"objects":len(current),"types":dict(collections.Counter(k for k,n in current.values()))},"new_objects":{"count":len(delta),"types":dict(collections.Counter(k for k,n in delta.values())),"new_blob_count":len(blobs),"new_uncompressed_blob_bytes":sum(n for _,n in blobs)},"coverage":{"scanned_new_blobs":scanned,"scanned_new_raw_bytes":totalbytes,"all_new_blob_bytes_scanned":True,"all_new_blob_content_addresses_verified":True,"all_prior_OIDs_present":True,"prior_OID_metadata_unchanged":True,"pattern_categories":list(PATTERNS),"recursive_archive_decompression":False,"all_secret_types_excluded":False,"original_regex_reproduced":False},"match_counts":counts,"hit_blob_count":len(hits),"unclassified_hit_count":sum(h["classification"]=="REVIEW_REQUIRED" for h in hits),"credential_values_disclosed":False,"fsck":fsck,"refs_before_sha256":sh(before_refs),"refs_after_sha256":sh(after_refs),"refs_changed_during_run":before_refs!=after_refs,"scope_exclusions":["Objects created after frozen enumeration, including final report/evidence/docs and future archive objects, are outside this delta. They require a separate execution receipt.","Regex absence is not evidence that all credentials or secret types are absent.","Original full-store scan and this new-regex delta are separate results."],"no_remote_write":True,"no_checkout_or_refs_modified":True}
 p=write("summary.json",summary)
 write("terminal.json",{"exit":0 if fsck["exit"]==0 else 1,"stage":"completed","summary_sha256":filehash(p)})
 print(json.dumps({"summary":str(p),"summary_sha256":filehash(p),"summary_bytes":p.stat().st_size,"new_objects":summary["new_objects"],"match_counts":counts,"hit_blob_count":len(hits),"fsck":fsck,"seconds":summary["seconds"]}))
 if fsck["exit"]!=0:sys.exit(1)
except BaseException as error:
 if isinstance(error,SystemExit):raise
 try:write("failed.json",{"stage":stage,"error_type":type(error).__name__,"raw_error_or_secret_values_disclosed":False})
 finally:print(json.dumps({"status":"FAILED","stage":stage,"error_type":type(error).__name__}));sys.exit(1)
