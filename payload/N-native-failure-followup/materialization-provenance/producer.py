import os,sys,pathlib,stat,json,hashlib,datetime
D=json.loads(sys.argv[1]);SELF=sys.argv[2]
S=pathlib.Path(D["stage"]);O=pathlib.Path(D["output"]);P=D["prefix"]
assert not O.exists() and S.resolve(strict=True)==S and not (S/P).exists()
assert P=="N-native-failure-followup" and D["expected_stage_files"]==3594 and D["expected_stage_bytes"]==187247568
def js(x):return(json.dumps(x,indent=2)+"\n").encode()
def sg(x):return [x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def rd(p,limit=24*1024*1024):
 p=pathlib.Path(p);assert p.is_absolute() and ".."not in p.parts
 fdparent=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for n in p.parts[1:-1]:
   q=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fdparent);os.close(fdparent);fdparent=q
  fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fdparent)
 finally:os.close(fdparent)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=limit,str(p)
  with os.fdopen(fd,"rb",closefd=False)as f:b=f.read(a.st_size+1)
  assert len(b)==a.st_size and sg(a)==sg(os.fstat(fd)),str(p)
  return b,sg(a)
 finally:os.close(fd)
def save(p,b):
 p=pathlib.Path(p);p.parent.mkdir(parents=True,exist_ok=True);assert p.parent.resolve(strict=True)==p.parent
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  view=memoryview(b);done=0
  while done<len(view):
   n=os.write(fd,view[done:]);assert n>0;done+=n
  os.fsync(fd)
 finally:os.close(fd)
 raw,v=rd(p);assert raw==b
 return {"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"version":v}
def inv(root):
 assert root.resolve(strict=True)==root
 files={};dirs={".":sg(root.lstat())}
 for b,ds,fs in os.walk(root,followlinks=False):
  ds.sort();fs.sort()
  for n in ds:
   p=pathlib.Path(b)/n;a=p.lstat();assert stat.S_ISDIR(a.st_mode) and not stat.S_ISLNK(a.st_mode)
   dirs[str(p.relative_to(root))]=sg(a)
  for n in fs:
   p=pathlib.Path(b)/n;a=p.lstat();assert stat.S_ISREG(a.st_mode) and a.st_nlink==1,str(p)
   files[str(p.relative_to(root))]={"bytes":a.st_size,"version":sg(a)}
 return {"files":files,"directories":dirs}
def sha(b):return hashlib.sha256(b).hexdigest()
start=datetime.datetime.now(datetime.timezone.utc).isoformat()
before=inv(S);old=before["files"]
assert len(old)==D["expected_stage_files"] and sum(r["bytes"]for r in old.values())==D["expected_stage_bytes"]
O.mkdir(mode=0o700)
saved=[]
saved.append(save(O/"producer.py",SELF.encode()))
saved.append(save(O/"inputs.json",js(D)))
saved.append(save(O/"stage-before.json",js({"schema":"trnm-N-followup-stage-stat-baseline-v1","captured_at":start,"stage":str(S),**before,"hash_rescan_of_old_payload":False})))
pages=D["completion_seal_terminal"]["reads"];assert len(pages)==1
t=pages[0];raw=bytes.fromhex(t["bytes_hex"])
assert t["offset"]==0 and t["next_offset"]==t["available_end"]==len(raw) and t["output_complete"]is True and t["status"]["exit_code"]==0 and sha(raw)==t["chunk_sha256"] and raw.decode()==t["text"]
saved.append(save(O/"completion-seal-terminal.json",js(D["completion_seal_terminal"])))
saved.append(save(O/"completion-seal-terminal.log",raw))
sources={};versions={};source_rosters={};source_rows=[];group_counts=[]
for spec in D["source_roots"]:
 root=pathlib.Path(spec["path"]);assert not (root==O or O in root.parents or root in O.parents)
 snap=inv(root);source_rosters[str(root)]=snap;count=0;size=0
 for rel,record in sorted(snap["files"].items()):
  pp=pathlib.PurePosixPath(rel);assert not pp.is_absolute() and ".."not in pp.parts and "\\"not in rel and "\x00"not in rel
  originpath=root/rel;data,version=rd(originpath);assert version==record["version"]
  target=P+"/"+spec["target"]+"/"+rel
  assert target not in sources and target not in old
  row={"path":target,"bytes":len(data),"sha256":sha(data),"origin":{"host":"mac","path":str(originpath)},"source_path":str(originpath),"source_version":version,"role":spec["role"]}
  if rel.startswith("selected-read-v1/originals/"):
   row["upstream_original"]={"provider":"github-actions","repository":"TrillionniumFoundation/Trillionnium-Chain","run_id":43582713392,"job_id":132415017426,"artifact_id":14109658844,"member":rel[len("selected-read-v1/originals/"):],"zip_sha256":"10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4"}
  if rel=="N-cost-x64-14109658844.zip":
   row["upstream_original"]={"provider":"github-actions","artifact_api":"https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/14109658844","artifact_id":14109658844,"run_id":43582713392,"head":D["fixed_identities"]["head"]}
  if rel=="x64-job132415017426.log":
   row["upstream_original"]={"provider":"github-actions","job_logs_api":"https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/actions/jobs/132415017426/logs","one_official_gh_GET":True}
  source_rows.append(row);sources[target]=data;versions[str(originpath)]=version;count+=1;size+=len(data)
 assert inv(root)==snap,str(root)
 group_counts.append({"source_root":str(root),"target":spec["target"],"files":count,"bytes":size})
by_source={r["source_path"]:r for r in source_rows}
for p in D["pins"]:
 row=by_source[p["path"]];assert row["bytes"]==p["bytes"] and row["sha256"]==p["sha256"],p["path"]
assert sum(len(v)for v in sources.values())<D["cap_bytes"]
selection={"schema":"trnm-N-native-failure-closed-selection-v1","prepared_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"stage":str(S),"prefix":P,"baseline":{"files":len(old),"bytes":sum(r["bytes"]for r in old.values())},"files":source_rows,"source_rosters":source_rosters,"groups":group_counts,"all_selected_sources_preverified":True,"originals_preserved_without_relabeling":True,"source_scope":{"N_head":D["fixed_identities"]["head"],"N_tree":D["fixed_identities"]["tree"],"original_business_confirmation_failed":True,"native_test_passes_are_not_business_pass":True,"M8_publication_or_hosted_result_not_claimed":True},"upstream_origin_chain":"strict origins name actual immutable Mac custody files; per-row upstream_original and original API/transport/member receipts identify the original GitHub bytes"}
saved.append(save(O/"selection.json",js(selection)))
readme="""# N native failure follow-up archive group

This create-only group retains the fresh 10:53 UTC complete refs/PR/N checks-and-jobs observation, one complete original N x64 job log, its unchanged outer-only UNKNOWN report, the one approved complete artifact 14109658844, the complete 161-member custody index, the 17 approved original manifest/source/process/stdout/stderr members, and the separate final diagnostic overlay.

The tested source is N 5a4b7fe8de1adce803184f262fd9f704ead1930c / tree 4bc5ade0813ba3172eeb0ad7425358469a1b1edd. All five native tests returned normally and passed their test assertions; the original four-second, 16-worker pressure business confirmation failed with CONFIRMATION_TARGET. This evidence does not describe an M8 hosted result or authorize a deadline change.

Every selected regular, single-link source was read with a stable no-follow FD and checked before stage writes. Exact SHA readback validates all new targets. Every old stage file and subdirectory identity must remain unchanged; only the existing stage-root directory metadata may reflect the new child. Existing reports are never edited. Sources retain actual Mac custody origin; selection.json and original API/transport/member receipts provide the upstream GitHub origin chain. No network, native test, source, Git or PR action occurs in this materializer. The materializer's own final outcome is an external receipt and is not self-referentially included.
"""
saved.append(save(O/"README.md",readme.encode()))
provenance_rows=[]
for r in saved:
 data,v=rd(r["path"]);assert sha(data)==r["sha256"] and v==r["version"]
 target=P+"/materialization-provenance/"+pathlib.Path(r["path"]).name
 assert target not in sources and target not in old
 sources[target]=data;versions[r["path"]]=v
 provenance_rows.append({"path":target,"bytes":len(data),"sha256":sha(data),"origin":{"host":"mac","path":r["path"]},"source_path":r["path"],"source_version":v,"role":"frozen selection, baseline, actual seal terminal and materialization producer"})
planned=source_rows+provenance_rows
assert len(sources)==len(planned) and sum(len(b)for b in sources.values())<=D["cap_bytes"]
for row in planned:
 raw,v=rd(row["source_path"]);assert raw==sources[row["path"]] and v==row["source_version"]
for root,snap in source_rosters.items():assert inv(pathlib.Path(root))==snap,root
assert inv(S)==before and not (S/P).exists()
for row in planned:
 f=save(S/row["path"],sources[row["path"]]);assert f["bytes"]==row["bytes"] and f["sha256"]==row["sha256"]
for row in planned:
 raw,v=rd(row["source_path"]);assert raw==sources[row["path"]] and v==row["source_version"]
for root,snap in source_rosters.items():assert inv(pathlib.Path(root))==snap,root
after=inv(S);assert set(after["files"])==set(old)|set(sources)
for rel,oldrow in old.items():assert after["files"][rel]==oldrow,rel
for rel,v in before["directories"].items():
 if rel==".":assert after["directories"][rel][:3]==v[:3]
 else:assert after["directories"][rel]==v,rel
for rel in set(after["directories"])-set(before["directories"]):
 assert rel==P or rel.startswith(P+"/"),rel
for row in planned:
 raw,v=rd(S/row["path"]);assert raw==sources[row["path"]] and sha(raw)==row["sha256"]
strict=sorted([{k:r[k]for k in ("path","bytes","sha256","origin")}for r in planned],key=lambda r:r["path"])
fr=save(O/"files.json",js({"files":strict}));fr={k:fr[k]for k in ("path","bytes","sha256")}
summary={"schema":"trnm-N-native-failure-followup-materialization-v1","status":"materialized_verified","started_at":start,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"prefix":P,"strict_files":fr,"groups":group_counts,"provenance_files":len(provenance_rows),"new_files":len(strict),"new_bytes":sum(r["bytes"]for r in strict),"baseline_files":len(old),"baseline_bytes":sum(r["bytes"]for r in old.values()),"final_stage_files":len(after["files"]),"final_stage_bytes":sum(r["bytes"]for r in after["files"].values()),"old_files_and_subdirectory_identities_unchanged":True,"old_stage_root_inode_and_mode_unchanged":True,"old_stage_root_directory_metadata_changed_for_new_child_only":True,"all_sources_stable_and_sha_preverified":True,"all_new_target_sha_readback":True,"exact_union_verified":True,"source_cap_bytes":D["cap_bytes"],"no_network_source_git_native_actions":True,"original_outer_unknown_preserved":True,"artifact_business_failure_preserved":True,"hosted_or_M8_qualification_claimed":False,"writer_released":True}
sr=save(O/"summary.json",js(summary))
print(json.dumps({"files":fr,"summary":{k:sr[k]for k in ("path","bytes","sha256")},"groups":group_counts,"new_files":summary["new_files"],"new_bytes":summary["new_bytes"],"final_stage_files":summary["final_stage_files"],"final_stage_bytes":summary["final_stage_bytes"],"writer_released":True}),flush=True)
