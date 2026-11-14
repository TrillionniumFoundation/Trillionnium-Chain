import collections, datetime, hashlib, json, os, pathlib, stat, sys

def need(c,m):
    if not c: raise ValueError(m)
def sha(b): return hashlib.sha256(b).hexdigest()
def enc(v): return (json.dumps(v,indent=2,sort_keys=True)+"\n").encode()
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def fp(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def safe_rel(v):
    need(type(v)is str and v and "\0"not in v and "\\"not in v,"unsafe relative path")
    p=pathlib.PurePosixPath(v)
    need(not p.is_absolute() and all(x not in ("",".","..")for x in p.parts)
         and str(p)==v,"noncanonical relative path")
    return p
def read_fixed(path,expected_bytes=None,expected_sha=None):
    p=pathlib.Path(path)
    need(p.is_absolute()and p.parent.resolve(strict=True)==p.parent,"canonical source path")
    s=p.lstat()
    need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=8*1024*1024,
         "bounded regular single-link source")
    if expected_bytes is not None:need(s.st_size==expected_bytes,"source size differs")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb")as f:
        need(fp(os.fstat(f.fileno()))==fp(s),"source open changed")
        raw=f.read(s.st_size+1)
        need(fp(os.fstat(f.fileno()))==fp(s),"source changed during read")
    need(fp(p.lstat())==fp(s)and len(raw)==s.st_size,"source path/bytes changed")
    digest=sha(raw)
    if expected_sha is not None:need(digest==expected_sha,"source SHA differs: "+str(p))
    return raw,{"path":str(p),"bytes":len(raw),"sha256":digest,"fingerprint":list(fp(s))}
def tree_inventory(root):
    root=pathlib.Path(root)
    need(root.resolve(strict=True)==root and stat.S_ISDIR(root.lstat().st_mode),"canonical tree")
    found={}
    for d,dirs,files in os.walk(root,followlinks=False):
        for name in dirs:
            p=pathlib.Path(d)/name
            need(stat.S_ISDIR(p.lstat().st_mode)and not p.is_symlink(),"non-directory in tree")
        for name in files:
            p=pathlib.Path(d)/name;s=p.lstat();rel=p.relative_to(root).as_posix();safe_rel(rel)
            need(stat.S_ISREG(s.st_mode)and s.st_nlink==1,"non-regular/single-link tree member")
            need(rel not in found,"duplicate tree path")
            found[rel]={"bytes":s.st_size,"fingerprint":list(fp(s))}
    return dict(sorted(found.items()))
def write_new(path,raw):
    path=pathlib.Path(path)
    need(path.parent.resolve(strict=True)==path.parent,"canonical target parent")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb")as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    got,info=read_fixed(path,len(raw),sha(raw))
    need(got==raw,"target readback differs")
    return info
def pin(data,info):
    need(len(data)==info["bytes"]and sha(data)==info["sha256"],"held bytes changed")

p=json.loads(sys.argv[1]);producer=sys.argv[2].encode();started=now()
need(p["schema"]=="trnm-concurrent-reconciliation-materialization-inputs-v1","input schema")
root=pathlib.Path(p["root"]);stage=pathlib.Path(p["stage"]);out=pathlib.Path(p["output_directory"])
need(root==pathlib.Path("/private/tmp/chain-consolidation-20261114-root"),"ROOT")
need(stage==root/"execution-receipts-followup-v1","stage")
need(out==pathlib.Path("/private/tmp/chain-prci-concurrent-reconciliation-materialization-20261114-v1"),"output")
prefix=safe_rel(p["prefix"])
need(str(prefix)=="concurrent-head-prepublication-reconciliation","owned prefix")
target_root=stage.joinpath(*prefix.parts)
need(not target_root.exists()and not target_root.is_symlink(),"target prefix already exists")
need(not out.exists()and not out.is_symlink(),"output directory already exists")
baseline=tree_inventory(stage)
need(len(baseline)==p["expected_stage_files"]==2285
     and sum(v["bytes"]for v in baseline.values())==p["expected_stage_bytes"]==154688299,
     "stage baseline differs")
rows=p["selected_sources"];need(len(rows)==166,"fixed source roster")
expected_rosters=collections.defaultdict(set)
held=[];by_origin={};paths=set();total=0
for row in rows:
    need(set(row)=={"group","source_path","relative","bytes","expected_sha256"},"source row fields")
    rel=safe_rel(row["relative"]);group=safe_rel(row["group"]);need(len(group.parts)==1,"group")
    target=str(prefix/group/rel)
    need(target not in paths and target not in baseline,"target collision");paths.add(target)
    origin={"host":"mac","path":row["source_path"]}
    need(origin["path"]not in by_origin,"duplicate source origin")
    data,info=read_fixed(origin["path"],row["bytes"],row["expected_sha256"])
    total+=len(data);need(total<=p["max_group_bytes"],"source bound exceeded")
    entry={"path":target,"bytes":len(data),"sha256":sha(data),"origin":origin}
    held.append({"entry":entry,"data":data,"source":info,"group":row["group"]})
    by_origin[origin["path"]]=held[-1]
    if row["group"]in p["closed_source_directories"]:
        parent=pathlib.Path(p["closed_source_directories"][row["group"]])
        need(pathlib.Path(row["source_path"])==parent.joinpath(*rel.parts),"closed source membership")
        expected_rosters[row["group"]].add(str(rel))
for group,directory in p["closed_source_directories"].items():
    actual=tree_inventory(pathlib.Path(directory))
    need(set(actual)==expected_rosters[group],"closed source directory roster drift: "+group)
    for rel,value in actual.items():
        info=by_origin[str(pathlib.Path(directory)/rel)]["source"]
        need(value["fingerprint"]==info["fingerprint"],"closed source changed: "+rel)
# Verify all original captured streams against their existing summaries. No command is executed.
stream_closures={}
for group,dirname in (
    ("publication-hold","publish-followup-candidate-execution-2a6206-v1"),
    ("local-reconciliation","remote-head-drift-local-reconciliation-v1"),
    ("graph","remote-head-drift-5a4b7f-graph-v1")):
    data=by_origin[str(root/dirname/"summary.json")]["data"];summary=json.loads(data)
    checks=0
    for step in summary["steps"]:
        for channel in("stdout","stderr"):
            source_pin=(step[channel]if isinstance(step.get(channel),dict)else
                        {"path":step[channel+"_path"],"bytes":step[channel+"_bytes"],
                         "sha256":step[channel+"_sha256"]})
            original=by_origin[source_pin["path"]]
            need(original["entry"]["bytes"]==source_pin["bytes"]
                 and original["entry"]["sha256"]==source_pin["sha256"],"original stream pin differs")
            checks+=1
    stream_closures[group]={"steps":len(summary["steps"]),"original_streams":checks,
                            "summary_sha256":sha(data)}
hold=json.loads(by_origin[str(root/"publish-followup-candidate-execution-2a6206-v1/summary.json")]["data"])
need(hold["status"]=="HOLD"and hold["push_started"]is False and hold["push_exit"]is None
     and hold["archive"]is None and hold["head"]=="2a62061177852dc3ebd200fa8d7c66c661a119a1"
     and hold["tree"]=="f8d170ff75990e879e93888a95e5408f36b36f6c","original HOLD outcome differs")
need(by_origin[str(root/"followup-publication-spec-2a6206-v1.json")]["data"]==
     by_origin[str(root/"publish-followup-candidate-execution-2a6206-v1/spec.json")]["data"],
     "actual invoked spec differs from retained spec")
# The first closure attempt mislabeled cached JSON as producer.py. Preserve bytes as data.
first_bad=by_origin[str(root/"concurrent-head-root-closure-v1/producer.py")]["data"]
json.loads(first_bad)
scope={
"status":"FROZEN_CLOSED_OBSERVATIONS_AND_PREPARED_ADAPTERS",
"publication_v1":"Actual pre-push HOLD. push_started=false, push_exit=null, archive=null. No publication success is claimed.",
"remote_observation":"Historical N observation and initial parser error preserved; correction is a separate overlay. Not a fresh remote check.",
"preparation":"Publisher V2, preparer V5 and apply V3 were prepared and statically compared only. No candidate program execution is claimed.",
"root_closure":"Actual cached publisher exit1, local reconciliation exit0 and graph exit0 tool originals are retained.",
"first_closure_attempt":"The preserved root-closure-first-attempt/producer.py contains cached JSON input, not executable Python. The actual failed producer and terminal are in root-closure/.",
"worker_artifact_plan":"Source inspection and validation/lint plans only; no tests or native execution.",
"coverage":"All selected source bytes were read with stable descriptors and verified before any stage target was written.",
"existing_stage":"All 2285 prior file stat identities are protected. Their contents are not re-scanned or re-qualified.",
"qualification_granted":False,"network_git_or_source_actions_performed":False}
os.umask(0o077);out.mkdir(mode=0o700,exist_ok=False)
source_manifest={"schema":"trnm-concurrent-reconciliation-selected-sources-v1","created_at":now(),
"selected_count":len(held),"selected_bytes":total,"stream_closures":stream_closures,"scope":scope,
"files":[{"entry":h["entry"],"source_identity":h["source"],"group":h["group"]}for h in held]}
metadata={}
metadata["materializer-producer.py"]=producer
metadata["materializer-inputs.json"]=enc(p)
metadata["source-manifest.json"]=enc(source_manifest)
metadata["baseline-identities.json"]=enc({"schema":"trnm-stage-prior-stat-identities-v1","stage":str(stage),
"file_count":len(baseline),"total_bytes":sum(v["bytes"]for v in baseline.values()),
"content_rescan_performed":False,"files":baseline})
readme=(
"# Concurrent remote advance and prepublication reconciliation\n\n"
"These are closed original observations and prepared programs. The retained V1 publisher stopped "
"before push with HOLD; its outcome has not been rewritten. The original attempted M6 candidate "
"is distinct from the remote N advance. All original stdout/stderr, spec, summary, actual cached "
"PTY outputs and the original launch producer are retained.\n\n"
"The initial remote parser error remains in its original summary; a separate overlay corrects "
"the frozen-map comparison. Publisher V2 / preparer V5 / apply V3 are prepared source files, "
"not execution receipts. The old and new versions, exact diffs, identity proofs, unchanged body "
"template and original capture/resume helpers are stored separately with original paths.\n\n"
"The root-closure-first-attempt/producer.py file is cached JSON input that was initially saved "
"under a misleading .py name. Treat it only as data; it was not executed as Python. The real "
"first failed producer and terminal are preserved under root-closure. Worker artifact/lint "
"plans are preparation-only and make no test or performance claim.\n\n"
"All selected sources are ordinary single-link files, read through stable descriptors and "
"SHA-verified before stage writes. Targets are create-only and read back for exact bytes/SHA. "
"The 2285 pre-existing stage files are checked by their complete before/after stat fingerprints; "
"their contents were not scanned again. This copy grants no hosted or protocol qualification.\n\n"
"metadata/source-manifest.json lists every selected source and exact original identity. "
"The final strict four-field files.json and materialization summary are external to this "
"payload, avoiding a self-referential result. This frozen group does not include future "
"publication or PR-ready results.\n")
metadata["README.md"]=readme.encode()
for name,data in metadata.items():
    path=out/name
    info=write_new(path,data)
    rel=(prefix/pathlib.PurePosixPath("metadata")/name)if name!="README.md"else prefix/name
    held.append({"entry":{"path":str(rel),"bytes":len(data),"sha256":sha(data),
                         "origin":{"host":"mac","path":str(path)}},
                 "data":data,"source":info,"group":"metadata"})
prewrite={"schema":"trnm-concurrent-reconciliation-prewrite-seal-v1","sealed_at":now(),
"selected_source_count":len(rows),"selected_source_bytes":total,
"selected_manifest_sha256":sha(metadata["source-manifest.json"]),
"baseline_count":len(baseline),"baseline_bytes":sum(v["bytes"]for v in baseline.values()),
"baseline_identities_sha256":sha(metadata["baseline-identities.json"]),
"all_selected_sources_preverified_before_stage_write":True,
"metadata_before_seal":[{"path":name,"bytes":len(data),"sha256":sha(data)}for name,data in metadata.items()],
"self_excluded":True,"publication_or_qualification_success_asserted":False}
prewrite_raw=enc(prewrite);prewrite_info=write_new(out/"prewrite-seal.json",prewrite_raw)
held.append({"entry":{"path":str(prefix/"metadata"/"prewrite-seal.json"),"bytes":len(prewrite_raw),
"sha256":sha(prewrite_raw),"origin":{"host":"mac","path":str(out/"prewrite-seal.json")}},
"data":prewrite_raw,"source":prewrite_info,"group":"metadata"})
need(sum(len(h["data"])for h in held)<=p["max_group_bytes"],"complete group exceeds 8MiB")
for h in held:
    path=pathlib.Path(h["source"]["path"])
    need(fp(path.lstat())==tuple(h["source"]["fingerprint"]),"source changed after prevalidation")
    pin(h["data"],h["source"])
need(tree_inventory(stage)==baseline,"stage drift before write")
target_root.mkdir(mode=0o700,exist_ok=False)
target_records=[]
for h in sorted(held,key=lambda x:x["entry"]["path"]):
    rel=safe_rel(h["entry"]["path"]);target=stage.joinpath(*rel.parts)
    need(target.is_relative_to(target_root),"target escaped prefix")
    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=write_new(target,h["data"])
    need(info["bytes"]==h["entry"]["bytes"]and info["sha256"]==h["entry"]["sha256"],"target pin differs")
    target_records.append(info)
after=tree_inventory(stage)
old_after={name:value for name,value in after.items()if not name.startswith(str(prefix)+"/")}
need(old_after==baseline,"prior stage file identity changed")
wanted={h["entry"]["path"]:h for h in held}
need(set(after)==set(baseline)|set(wanted),"unexpected stage membership after write")
for h in held:
    need(fp(pathlib.Path(h["source"]["path"]).lstat())==tuple(h["source"]["fingerprint"]),
         "source changed during materialization")
strict=[h["entry"]for h in sorted(held,key=lambda x:x["entry"]["path"])]
need(all(set(x)=={"path","bytes","sha256","origin"}for x in strict),"strict schema")
file_raw=enc(strict);files_info=write_new(out/"files.json",file_raw)
groups={}
for h in held:
    g=groups.setdefault(h["group"],{"files":0,"bytes":0});g["files"]+=1;g["bytes"]+=len(h["data"])
summary={
"schema":"trnm-concurrent-reconciliation-materialization-summary-v1","status":"MATERIALIZED_AND_READBACK_VERIFIED",
"started_at":started,"finished_at":now(),"stage":str(stage),"prefix":str(prefix),
"source_files":len(rows),"source_bytes":total,"group_files":len(strict),
"group_bytes":sum(x["bytes"]for x in strict),"groups":groups,
"files":{"path":files_info["path"],"bytes":files_info["bytes"],"sha256":files_info["sha256"]},
"before":{"files":len(baseline),"bytes":sum(x["bytes"]for x in baseline.values())},
"after":{"files":len(after),"bytes":sum(x["bytes"]for x in after.values())},
"prior_stage_all_file_stat_identities_unchanged":True,
"all_sources_stable_regular_single_link_before_stage_write":True,
"all_targets_create_only_and_sha_readback_verified":True,
"all_source_identities_unchanged_after_materialization":True,
"original_hold_summary_sha256":sha(by_origin[str(root/"publish-followup-candidate-execution-2a6206-v1/summary.json")]["data"]),
"hold_status":"HOLD","hold_push_started":False,"scope":scope,"stage_writer_released":True,
"source_git_network_tests_or_ref_mutations":False,
"final_receipt_not_self_included":True}
summary_info=write_new(out/"summary.json",enc(summary))
print(json.dumps({"status":summary["status"],"files":summary["files"],
"summary":{"path":summary_info["path"],"bytes":summary_info["bytes"],"sha256":summary_info["sha256"]},
"group_files":summary["group_files"],"group_bytes":summary["group_bytes"],
"stage":summary["after"],"groups":groups,"stage_writer_released":True},sort_keys=True),flush=True)
