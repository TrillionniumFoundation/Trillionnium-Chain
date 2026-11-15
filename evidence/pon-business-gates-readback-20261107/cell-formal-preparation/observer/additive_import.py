import ast,datetime,hashlib,json,os,pathlib,subprocess,sys,time,traceback
ROOT=pathlib.Path("/home/qian-qi/chain-throughput-local-admin-20261107/work-final-business-20261107")
OUT=pathlib.Path("/home/qian-qi/throughput-ci-observation-20261107/cell-formal-preparation-v1")
ISO=OUT/"isolated-original-object-pack.git";VIEW=OUT/"original-objects-readonly-view.git"
SOURCE="9fedf7ecbbe07177069c030592b4e03dcffebb81"
ENV=dict(os.environ,GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1")
commands=[];imported=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def run(name,args,cwd=ROOT,input=None,env=None,required=True,retain=True):
 start=time.time_ns()
 try:p=subprocess.run(args,cwd=cwd,env=env or ENV,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
 except BaseException as e:
  commands.append({"name":name,"argv":args,"cwd":str(cwd),"started_ns":start,"ended_ns":time.time_ns(),"exception":repr(e)})
  (OUT/"additive-import-commands.json").write_text(json.dumps(commands,indent=2)+"\n");raise
 row={"name":name,"argv":args,"cwd":str(cwd),"started_ns":start,"ended_ns":time.time_ns(),"exit_code":p.returncode,"stdin_bytes":len(input) if input is not None else None,"stdin_sha256":sha(input) if input is not None else None,"stdout_bytes":len(p.stdout),"stdout_sha256":sha(p.stdout),"stderr_bytes":len(p.stderr),"stderr_sha256":sha(p.stderr),"streams_retained":retain}
 if retain:
  for s,b in (("stdout",p.stdout),("stderr",p.stderr)):(OUT/(name+"."+s)).write_bytes(b)
 elif len(p.stdout)<1024 and len(p.stderr)<4096:row.update(stdout=p.stdout.decode(errors="replace"),stderr=p.stderr.decode(errors="replace"))
 commands.append(row);(OUT/"additive-import-commands.json").write_text(json.dumps(commands,indent=2)+"\n")
 if required and p.returncode:raise RuntimeError(name+" failed: "+str(p.returncode))
 return p
def git(name,*args,cwd=ROOT,**kw):return run(name,["/usr/bin/git","--no-optional-locks",*args],cwd=cwd,**kw)
try:
 assert json.loads((OUT/"commands.json").read_text())[0]["exit_code"]==0
 inspection=json.loads((OUT/"inspection.json").read_text())
 entries=[]
 for raw in (OUT/"historical-all-trees-and-blobs.stdout").read_bytes().split(b"\0"):
  if not raw:continue
  a,b=raw.split(b"\t",1);mode,typ,oid=a.decode().split();entries.append({"path":b.decode(),"mode":mode,"type":typ,"oid":oid})
 by_path={x["path"]:x for x in entries};assert len(by_path)==len(entries)
 inv=by_path["config/portability-inventory-v1.json"]
 invraw=(OUT/"inventory-from-retained-pack.stdout").read_bytes()
 assert hashlib.sha1(b"blob "+str(len(invraw)).encode()+b"\0"+invraw).hexdigest()==inv["oid"]
 inventory=json.loads(invraw)
 classes=None
 for n in ast.parse((OUT/"model-contract-head.stdout").read_bytes()).body:
  if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="CLASSES" for t in n.targets):classes=ast.literal_eval(n.value)
 assert classes==["M00","M04","M10"]
 grouped={x:[] for x in classes}
 for row in inventory["packages"]:
  if row["module"] not in grouped:continue
  for e in entries:
   f=e["path"]
   if e["type"]!="tree" and f.startswith(row["path"]+"/src/") and f.endswith(".rs") and "/tests/" not in f and not f.endswith("/tests.rs"):grouped[row["module"]].append(f)
 selection=[{"module":module,**by_path[f]} for module,ps in grouped.items() for f in sorted(ps,key=lambda p:hashlib.sha256(p.encode()).digest())]
 assert all(x["type"]=="blob" for x in selection)
 blob_oids={x["oid"] for x in selection}|{inv["oid"]}
 pack_map={}
 for line in (OUT/"isolated-object-list.stdout").read_text().splitlines():
  oid,typ,size=line.split();assert typ=="blob";pack_map[oid]={"type":typ,"bytes":int(size)}
 assert blob_oids==set(pack_map)
 commitraw=(OUT/"historical-commit.stdout").read_bytes();assert hashlib.sha1(b"commit "+str(len(commitraw)).encode()+b"\0"+commitraw).hexdigest()==SOURCE
 root_tree=commitraw.splitlines()[0].decode().removeprefix("tree ")
 tree_oids={root_tree}|{x["oid"] for x in entries if x["type"]=="tree"}
 needed={SOURCE:"commit",**{x:"tree" for x in tree_oids},**{x:"blob" for x in blob_oids}}
 git("availability-git-init","init","--bare",str(VIEW))
 common=git("original-common-dir","rev-parse","--path-format=absolute","--git-common-dir").stdout.decode().strip()
 objects=pathlib.Path(common)/"objects";assert objects.is_dir()
 view_env=dict(ENV,GIT_ALTERNATE_OBJECT_DIRECTORIES=str(objects))
 batch=("\n".join(sorted(needed))+"\n").encode()
 p=git("required-object-presence-view-before","cat-file","--batch-check=%(objectname) %(objecttype) %(objectsize)",cwd=VIEW,input=batch,env=view_env)
 lines=p.stdout.decode().splitlines();assert len(lines)==len(needed)
 missing=[];present=[]
 for line in lines:
  f=line.split()
  if len(f)==2 and f[1]=="missing":missing.append({"oid":f[0],"expected_type":needed[f[0]]})
  else:
   oid,typ,n=f;assert typ==needed[oid];present.append({"oid":oid,"type":typ,"bytes":int(n)})
 assert all(x["expected_type"]=="blob" and x["oid"] in pack_map for x in missing)
 before={"schema":"trnm-cell-required-historical-objects-before-v1","source":SOURCE,"root_tree":root_tree,"classes":classes,"selected_source_paths":len(selection),"selected_unique_source_blob_oids":len({x["oid"] for x in selection}),"inventory":inv,"source_files_in_exact_iteration_order":selection,"required_tree_oids":sorted(tree_oids),"required_unique_objects":len(needed),"required_unique_source_and_inventory_blobs":len(blob_oids),"present":present,"missing":missing,"availability_view":{"path":str(VIEW),"read_only_alternate_objects":str(objects),"has_remote":False},"original_direct_batch_failure_retained":"required-object-presence-before.stderr","git_no_lazy_fetch":"1","git_no_replace_objects":"1"}
 (OUT/"required-objects-before.json").write_text(json.dumps(before,indent=2)+"\n")
 print(json.dumps({"stage":"full-missing-denominator","selected_source_paths":len(selection),"source_and_inventory_unique_blobs":len(blob_oids),"tree_objects":len(tree_oids),"commit_objects":1,"required_unique_objects":len(needed),"present_before":len(present),"missing_before":len(missing),"selected_per_module":{k:len(v) for k,v in grouped.items()}}),flush=True)
 git_version=git("preparation-git-version","--version").stdout.decode().strip()
 run("pre-import-project-preflight",["bash","scripts/project-preflight.sh"])
 head_before=git("import-head-before","rev-parse","HEAD").stdout.decode().strip()
 refs_before=git("import-refs-before","for-each-ref","--format=%(refname) %(objectname)").stdout
 status_before=git("import-tracked-status-before","status","--porcelain=v1","--untracked-files=no").stdout
 for i,x in enumerate(missing,1):
  oid=x["oid"]
  raw=git("read-missing-"+str(i),"cat-file","blob",oid,cwd=ISO,retain=False).stdout
  assert hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==oid and len(raw)==pack_map[oid]["bytes"]
  receipt=git("write-missing-"+str(i),"hash-object","-w","--no-filters","-t","blob","--stdin",input=raw,retain=False)
  assert receipt.stdout.decode().strip()==oid
  imported.append({"oid":oid,"type":"blob","bytes":len(raw),"sha256":sha(raw)})
  (OUT/"imported-objects.json").write_text(json.dumps(imported,indent=2)+"\n")
 after_batch=git("required-original-object-content-after","cat-file","--batch",input=batch,retain=False).stdout
 pos=0;verified=[]
 for expected in sorted(needed):
  end=after_batch.index(b"\n",pos);header=after_batch[pos:end].decode().split();assert len(header)==3
  oid,typ,size=header;size=int(size);assert oid==expected and typ==needed[expected]
  pos=end+1;raw=after_batch[pos:pos+size];assert len(raw)==size;pos+=size;assert after_batch[pos:pos+1]==b"\n";pos+=1
  assert hashlib.sha1(typ.encode()+b" "+str(size).encode()+b"\0"+raw).hexdigest()==oid
  verified.append({"oid":oid,"type":typ,"bytes":size,"sha256":sha(raw),"git_object_sha1_verified":True})
 assert pos==len(after_batch)
 (OUT/"verified-objects-after.json").write_text(json.dumps({"source":SOURCE,"objects":verified,"all_expected_objects_read":True,"git_no_lazy_fetch":"1","git_no_replace_objects":"1"},indent=2)+"\n")
 inv_after=git("historical-inventory-after","show",SOURCE+":config/portability-inventory-v1.json").stdout
 assert inv_after==invraw
 names_after=git("historical-names-after","ls-tree","-r","--name-only",SOURCE).stdout.decode().splitlines()
 assert names_after==[x["path"] for x in entries if x["type"]!="tree"]
 fixtures=[]
 for old in inspection["fixtures"]:
  p=ROOT/old["path"];assert p.is_file() and not p.is_symlink()
  raw=p.read_bytes();assert len(raw)==old["expected_bytes"] and sha(raw)==old["expected_sha256"]
  fixtures.append({k:old[k] for k in ("path","actual_bytes","actual_sha256","expected_git_blob","bytes_equal_HEAD")})
 selector=(ROOT/"formal/pon-nakamoto-v1/experiments/model_loop.py").read_bytes()
 assert sha(selector)==inspection["selector"]["sha256"]
 assert (ROOT/"formal/pon-nakamoto-v1/model_contract.py").read_bytes()==(OUT/"model-contract-head.stdout").read_bytes()
 head_after=git("import-head-after","rev-parse","HEAD").stdout.decode().strip()
 refs_after=git("import-refs-after","for-each-ref","--format=%(refname) %(objectname)").stdout
 status_after=git("import-tracked-status-after","status","--porcelain=v1","--untracked-files=no").stdout
 archive_rel="evidence/pon-cell-integration-v1-20261107"
 archive=json.loads((ROOT/archive_rel/"ARCHIVE.json").read_bytes())
 members=json.loads((ROOT/archive_rel/"MANIFEST.json").read_bytes())["files"]
 pack_entry=next(x for x in members if x["path"]=="raw/remote-prior/original-source-blobs-9fed.pack")
 core={"schema":"trnm-cell-formal-preparation-core-v1","status":"PREPARATION_COMPLETE","observed_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"historical_source":SOURCE,"historical_root_tree":root_tree,"working_head_before":head_before,"working_head_after":head_after,"root_refs_equal_before_after":refs_before==refs_after,"tracked_status_equal_before_after":status_before==status_after,"root_had_concurrent_untracked_evidence":bool(inspection["dirty_porcelain"]),"full_tree_clean_claim":False,"git_version":git_version,"runtime":inspection["runtime"],"classes":classes,"selected_source_paths":len(selection),"selected_per_module":{k:len(v) for k,v in grouped.items()},"required_unique_source_and_inventory_blobs":len(blob_oids),"required_tree_objects":len(tree_oids),"required_commit_objects":1,"required_unique_objects":len(needed),"missing_before":len(missing),"missing_after":0,"imported_blob_count":len(imported),"imported_raw_bytes":sum(x["bytes"] for x in imported),"all_required_objects_full_content_hash_verified_in_original_repository":True,"no_lazy_fetch":"1","no_replace_objects":"1","source_replay_timeout_seconds_unchanged":30,"fixtures":fixtures,"selector":inspection["selector"],"original_pack":{"archive":archive_rel+"/retained-runs.tar.gz","archive_bytes":archive["bytes"],"archive_sha256":archive["sha256"],"member":pack_entry,"isolated_strict_index_pack_exit":0,"pack_objects":len(pack_map)},"preparation_failures_retained":[{"command":"historical-inventory","exit":128,"stderr":"historical-inventory.stderr"},{"command":"required-object-presence-before","exit":128,"stderr":"required-object-presence-before.stderr","note":"Original promisor batch stops at first unavailable object; complete denominator was then read through an isolated no-remote object view."}],"mutations":{"only_missing_git_blobs_written":True,"source_files_changed":False,"working_fixtures_changed":False,"refs_commands_used":False,"FETCH_HEAD_used_or_written":False,"runtime_or_deadline_changed":False,"global_Host_configuration_changed":False},"network_or_GitHub_used":False,"formal_tests_executed":0,"native_or_benchmark_executed":False,"formal_202_pass_claim":False}
 raw=(json.dumps(core,indent=2)+"\n").encode();assert len(raw)<=16384
 (OUT/"PREPARATION_CORE.json").write_bytes(raw)
 print(json.dumps(core),flush=True)
except BaseException as e:
 failure={"schema":"trnm-cell-formal-preparation-failure-v1","error":repr(e),"traceback":traceback.format_exc(),"completed_imports":imported,"commands_record":"additive-import-commands.json","source_files_modified":False,"refs_written":False}
 (OUT/"PREPARATION_FAILURE.json").write_text(json.dumps(failure,indent=2)+"\n")
 print(json.dumps(failure),flush=True);raise
