import ast,hashlib,json,os,pathlib,subprocess,tarfile,time
ROOT=pathlib.Path("/home/qian-qi/chain-throughput-local-admin-20261107/work-final-business-20261107")
OUT=pathlib.Path("/home/qian-qi/throughput-ci-observation-20261107/cell-formal-preparation-v1")
SOURCE="9fedf7ecbbe07177069c030592b4e03dcffebb81"
ENV=dict(os.environ,GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1")
def sha(b):return hashlib.sha256(b).hexdigest()
commands=[]
def run(name,args,cwd=ROOT,input=None,required=True):
 start=time.time_ns();p=subprocess.run(args,cwd=cwd,env=ENV,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
 for s,b in (("stdout",p.stdout),("stderr",p.stderr)):(OUT/(name+"."+s)).write_bytes(b)
 commands.append({"name":name,"argv":args,"cwd":str(cwd),"started_ns":start,"ended_ns":time.time_ns(),"exit_code":p.returncode,"stdout_bytes":len(p.stdout),"stdout_sha256":sha(p.stdout),"stderr_bytes":len(p.stderr),"stderr_sha256":sha(p.stderr)})
 (OUT/"pack-inspection-commands.json").write_text(json.dumps(commands,indent=2)+"\n")
 if required and p.returncode:raise RuntimeError(name+" failed")
 return p
head=run("pack-head-before",["/usr/bin/git","--no-optional-locks","rev-parse","HEAD"]).stdout.decode().strip()
rel="evidence/pon-cell-integration-v1-20261107"
d=ROOT/rel
for name in ("ARCHIVE.json","MANIFEST.json","retained-runs.tar.gz"):
 expected_oid=run("pin-"+name,["/usr/bin/git","--no-optional-locks","rev-parse",head+":"+rel+"/"+name]).stdout.decode().strip()
 raw=(d/name).read_bytes()
 assert hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==expected_oid
archive=json.loads((d/"ARCHIVE.json").read_bytes());manifest=json.loads((d/"MANIFEST.json").read_bytes())
raw=(d/"retained-runs.tar.gz").read_bytes()
assert len(raw)==archive["bytes"] and sha(raw)==archive["sha256"]
manifest_by_path={x["path"]:x for x in manifest["files"]}
wanted=("raw/remote-prior/original-source-blobs-9fed.pack","raw/remote-prior/validation-prior-public/source-preparation/objects.json")
member_records=[]
with tarfile.open(d/"retained-runs.tar.gz","r:gz") as tf:
 members=tf.getmembers();names=[m.name for m in members]
 assert len(names)==len(set(names)) and all(not pathlib.PurePosixPath(n).is_absolute() and ".." not in pathlib.PurePosixPath(n).parts for n in names)
 assert sum(m.isfile() for m in members)==archive["regular_members"] and not any(m.issym() or m.islnk() for m in members)
 for name in wanted:
  m=tf.getmember(name);assert m.isfile() and m.size<8*1024*1024
  b=tf.extractfile(m).read();pin=manifest_by_path[name]
  assert len(b)==pin["bytes"] and sha(b)==pin["sha256"]
  out=OUT/("retained-"+pathlib.PurePosixPath(name).name);out.write_bytes(b)
  member_records.append({"archive_member":name,"bytes":len(b),"sha256":sha(b),"extracted_path":str(out)})
iso=OUT/"isolated-original-object-pack.git"
run("isolated-git-init",["/usr/bin/git","init","--bare",str(iso)])
pack=OUT/"retained-original-source-blobs-9fed.pack"
run("isolated-index-pack",["/usr/bin/git","--no-optional-locks","index-pack","--stdin","--strict"],cwd=iso,input=pack.read_bytes())
pack_objects=run("isolated-object-list",["/usr/bin/git","--no-optional-locks","cat-file","--batch-all-objects","--batch-check=%(objectname) %(objecttype) %(objectsize)"],cwd=iso).stdout.decode().splitlines()
pack_map={}
for line in pack_objects:
 oid,kind,size=line.split();assert kind=="blob";pack_map[oid]={"type":kind,"bytes":int(size)}
entries=[]
for record in (OUT/"historical-all-trees-and-blobs.stdout").read_bytes().split(b"\0"):
 if not record:continue
 mode_kind_sha,path=record.split(b"\t",1);mode,kind,oid=mode_kind_sha.decode().split()
 entries.append({"path":path.decode(),"mode":mode,"type":kind,"oid":oid})
by_path={x["path"]:x for x in entries};assert len(by_path)==len(entries)
inventory_entry=by_path["config/portability-inventory-v1.json"];assert inventory_entry["type"]=="blob"
invraw=run("inventory-from-retained-pack",["/usr/bin/git","--no-optional-locks","cat-file","blob",inventory_entry["oid"]],cwd=iso).stdout
assert hashlib.sha1(b"blob "+str(len(invraw)).encode()+b"\0"+invraw).hexdigest()==inventory_entry["oid"]
inventory=json.loads(invraw)
model_source=(OUT/"model-contract-head.stdout").read_bytes();node=ast.parse(model_source)
classes=None
for stmt in node.body:
 if isinstance(stmt,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="CLASSES" for t in stmt.targets):classes=ast.literal_eval(stmt.value)
assert classes==["M00","M04","M10"]
paths=[x["path"] for x in entries if x["type"]!="tree"]
grouped={m:[] for m in classes}
for row in inventory["packages"]:
 if row["module"] not in grouped:continue
 for f in paths:
  if f.startswith(row["path"]+"/src/") and f.endswith(".rs") and "/tests/" not in f and not f.endswith("/tests.rs"):
   grouped[row["module"]].append(f)
selection=[]
for module,ps in grouped.items():
 for path in sorted(ps,key=lambda p:hashlib.sha256(p.encode()).digest()):
  e=by_path[path];assert e["type"]=="blob"
  selection.append({"module":module,**e})
blob_oids={x["oid"] for x in selection}|{inventory_entry["oid"]}
assert blob_oids<=set(pack_map),sorted(blob_oids-set(pack_map))
commitraw=(OUT/"historical-commit.stdout").read_bytes()
assert hashlib.sha1(b"commit "+str(len(commitraw)).encode()+b"\0"+commitraw).hexdigest()==SOURCE
root_tree=commitraw.decode().splitlines()[0].removeprefix("tree ")
tree_oids={root_tree}|{x["oid"] for x in entries if x["type"]=="tree"}
needed={SOURCE:"commit",**{x:"tree" for x in tree_oids},**{x:"blob" for x in blob_oids}}
batch=("\n".join(sorted(needed))+"\n").encode()
presence=run("required-object-presence-before",["/usr/bin/git","--no-optional-locks","cat-file","--batch-check=%(objectname) %(objecttype) %(objectsize)"],input=batch).stdout.decode().splitlines()
assert len(presence)==len(needed)
found=[];missing=[]
for line in presence:
 fields=line.split()
 if len(fields)==2 and fields[1]=="missing":missing.append({"oid":fields[0],"expected_type":needed[fields[0]]})
 else:
  oid,kind,size=fields;assert kind==needed[oid];found.append({"oid":oid,"type":kind,"bytes":int(size)})
assert all(x["expected_type"]=="blob" and x["oid"] in pack_map for x in missing)
result={"schema":"trnm-cell-formal-historical-object-preparation-before-v1","head_at_stage":head,"historical_source":SOURCE,"historical_root_tree":root_tree,"classes":classes,"source_files_in_exact_iteration_order":selection,"inventory":inventory_entry,"tree_oids":sorted(tree_oids),"required_unique_objects":len(needed),"required_unique_source_and_inventory_blobs":len(blob_oids),"selected_source_paths":len(selection),"trees":len(tree_oids),"commit_objects":1,"present_before":len(found),"missing_before":missing,"archive":{"path":str(d/"retained-runs.tar.gz"),**archive},"extracted_members":member_records,"isolated_pack":str(iso),"retained_pack_objects":len(pack_map),"retained_pack_extra_object_count":len(set(pack_map)-blob_oids),"full_corpus_selector_source_sha256":sha((OUT/"selector-head.stdout").read_bytes()),"source_or_fixture_modified":False,"original_repository_objects_written":False,"github_or_network_used":False}
(OUT/"required-objects-before.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps({k:v for k,v in result.items() if k not in ("source_files_in_exact_iteration_order","tree_oids","missing_before")}|{"missing_before_count":len(missing),"missing_before_types":sorted({x["expected_type"] for x in missing}),"selected_per_module":{k:len(v) for k,v in grouped.items()},"original_objects_record":str(OUT/"retained-objects.json")}),flush=True)
