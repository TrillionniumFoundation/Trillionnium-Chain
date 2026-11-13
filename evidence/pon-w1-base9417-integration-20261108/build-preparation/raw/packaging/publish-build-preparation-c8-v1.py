#!/usr/bin/env python3
"""Publish only the allowlisted C8 build-preparation bundle; never runs an operation."""
import gzip,hashlib,io,json,os,shutil,subprocess,tarfile
from pathlib import Path
TOOLS=Path("/home/qian-qi/work/chain-w1-base9417-m12-tools-20261108-ec265b")
SPEC=TOOLS/"build-preparation-allowlist-01.json"
SPEC_SHA="2e82d20505d5af603295c643553a61ed75f2d7327a44b6252d668e5f6834215a"
DOCS=Path("/home/qian-qi/work/chain-w1-c8-attestation-20261108-ec265b")
EVIDENCE=DOCS/"evidence/pon-w1-base9417-integration-20261108"
DEST=EVIDENCE/"build-preparation"
SOURCE={"commit":"4e007a87ceecbec8d265f6a70cfd71d512a514b5","tree":"19a4f1a6e1cec5c27e595fa555b97cddc4717a3c"}
JOB_ROOT=Path("/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs")
def pin(path):
    assert path.is_absolute() and path.is_file() and not path.is_symlink() and path.resolve()==path
    h=hashlib.sha256()
    with path.open("rb") as f:
        before=os.fstat(f.fileno());assert before.st_nlink==1
        for b in iter(lambda:f.read(1048576),b""):h.update(b)
        after=os.fstat(f.fileno())
    assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(path),"bytes":after.st_size,"sha256":h.hexdigest()}
def verify(record):
    observed=pin(Path(record["path"]))
    assert all(observed[k]==record[k] for k in ("path","bytes","sha256"))
    return observed
def write(path,value):
    with path.open("x") as f:
        json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def copied(src,dst,expected=None):
    before=pin(src)
    assert src.name!="request.json" and src.suffix not in (".db",".sqlite",".sqlite3",".bin",".elf",".env")
    data=src.read_bytes();assert data[:4]!=b"\x7fELF";data.decode("utf-8")
    assert len(data)==before["bytes"] and hashlib.sha256(data).hexdigest()==before["sha256"]
    if expected is not None:assert before["sha256"]==expected
    dst.parent.mkdir(parents=True,exist_ok=True);assert not dst.exists()
    with dst.open("xb") as f:f.write(data);f.flush();os.fsync(f.fileno())
    dst.chmod(0o644)
    after=pin(src);actual=pin(dst)
    assert before==after and actual["bytes"]==before["bytes"] and actual["sha256"]==before["sha256"]
    assert (src.stat().st_dev,src.stat().st_ino)!=(dst.stat().st_dev,dst.stat().st_ino)
    return {"original":before,"copied":actual}
spec_pin=pin(SPEC);assert spec_pin["sha256"]==SPEC_SHA
spec=json.loads(SPEC.read_text())
assert spec["schema"]=="TRNM-W1-C8-BUILD-PREPARATION-ALLOWLIST1"
assert spec["source"]==SOURCE and spec["docs_repo"]==str(DOCS) and spec["evidence_root"]==str(EVIDENCE)
assert spec["bundle"]=="build-preparation" and not DEST.exists()
assert spec["summary"]["current_runtime_readiness"]["qualified"] is False
original_stage=spec["summary"]["current_runtime_readiness"]["manifest"]
verify(original_stage)
original_stage_manifest=json.loads(Path(original_stage["path"]).read_text())
assert original_stage_manifest["source_commit"]==SOURCE["commit"] and original_stage_manifest["source_tree"]==SOURCE["tree"]
assert original_stage_manifest["qualification_complete"] is False
assert [r["exit"] for r in original_stage_manifest["commands"]]==[0,0,1,0]
failed_stage_row=original_stage_manifest["commands"][2]
raw_failure=Path(failed_stage_row["stderr"]["path"]).read_text()
assert sum(line.endswith(" ... ok") for line in raw_failure.splitlines())==31
assert "Ran 32 tests" in raw_failure and "FAILED (failures=1)" in raw_failure
assert "'SIGKILL_DURING_SETTLEMENT' not found in ['DEADLINE_EXHAUSTED_BEFORE_SPAWN']" in raw_failure
items=list(spec["items"])
for item in items:
    record=pin(Path(item["source"]))
    if "sha256" in item:assert record["sha256"]==item["sha256"]
    item["sha256"]=record["sha256"]
jobs=[]
for job in spec["jobs"]:
    root=JOB_ROOT/job["id"]
    terminal=json.loads((root/"exit.json").read_text());witness=json.loads((root/"exit.witness.json").read_text())
    assert terminal["job_id"]==witness["job_id"]==job["id"]
    assert terminal["exit_code"]==job["expected_exit"]
    assert terminal["cancelled"] is False and terminal["timed_out"] is False
    assert terminal["output_complete"] is True and terminal["output_durable"] is True
    assert terminal["log_errors"]=={"stdout":None,"stderr":None}
    assert terminal["log_synced"]=={"stdout":True,"stderr":True}
    assert terminal["log_truncated"]=={"stdout":False,"stderr":False}
    assert witness["exit_sha256"]==pin(root/"exit.json")["sha256"]
    assert witness["launch_nonce"]==terminal["launch_nonce"]
    for stream in ("stdout","stderr"):
        assert (root/(stream+".log")).stat().st_size==terminal["log_bytes"][stream]["seen"]==terminal["log_bytes"][stream]["stored"]
    pins={}
    for leaf in ("started.json","child.json","exit.json","exit.witness.json","stdout.log","stderr.log"):
        source=root/leaf;pins[leaf]=pin(source)
        items.append({"source":str(source),"relative":"jobs/"+job["role"]+"/"+leaf,"sha256":pins[leaf]["sha256"]})
    jobs.append({**job,"terminal":terminal,"raw_files":pins})
import_pin=verify(spec["owner_import"]);binding_pin=verify(spec["owner_import_artifact"])
import_root=Path(import_pin["path"]).parent
assert import_root==TOOLS/"owner-import-c8-01"
q=json.loads(Path(import_pin["path"]).read_text())
assert q["source"]==SOURCE and q["qualification_complete"] is True and q["fresh_cargo_target"] is False
assert q["actual_command_count"]==19 and q["raw_log_files_verified"]==q["raw_log_files_copied"]==38
assert q["rust_test_outcomes"]=={"passed":37,"failed":0,"ignored":4}
assert q["operation_created"] is False and q["deadline_selected"] is False
assert q["current_qualification_job_id"]=="1a1ba7cdd03-12894-1b0d"
for record in [import_pin,binding_pin]+[entry["copy"] for entry in q["original_files_copied"]]:
    source=Path(record["path"]);relative=source.relative_to(import_root)
    assert not relative.is_absolute() and ".." not in relative.parts
    verify(record)
    items.append({"source":str(source),"relative":"owner-import/"+str(relative),"sha256":record["sha256"]})
assert len(q["original_files_copied"])==47
names=[r["relative"] for r in items];assert len(names)==len(set(names))
for name in names:
    rel=Path(name);assert not rel.is_absolute() and ".." not in rel.parts
with (TOOLS/"build-preparation-publication-preflight.stdout").open("xb") as so,(TOOLS/"build-preparation-publication-preflight.stderr").open("xb") as se:
    result=subprocess.run(["bash","scripts/project-preflight.sh","--dev"],cwd=DOCS,stdout=so,stderr=se,check=False)
preflight={"argv":["bash","scripts/project-preflight.sh","--dev"],"cwd":str(DOCS),"exit":result.returncode,
    "stdout":pin(TOOLS/"build-preparation-publication-preflight.stdout"),"stderr":pin(TOOLS/"build-preparation-publication-preflight.stderr"),
    "scope":"Packaging preflight only; zero source qualification methods or commands are added."}
write(TOOLS/"build-preparation-publication-preflight.json",preflight);assert result.returncode==0
DEST.mkdir(parents=True);RAW=DEST/"raw";RAW.mkdir()
entries=[]
for item in items:
    r=copied(Path(item["source"]),RAW/item["relative"],item["sha256"])
    entries.append({"relative":"raw/"+item["relative"],**r})
for source,relative in [(SPEC,"packaging/allowlist.json"),(Path(__file__).resolve(),"packaging/publish-build-preparation-c8-v1.py"),
    (TOOLS/"build-preparation-publication-preflight.json","packaging/preflight.json"),
    (TOOLS/"build-preparation-publication-preflight.stdout","packaging/preflight.stdout"),
    (TOOLS/"build-preparation-publication-preflight.stderr","packaging/preflight.stderr")]:
    r=copied(source,RAW/relative);entries.append({"relative":"raw/"+relative,**r})
primary=[]
for item in spec["primary"]:
    r=copied(RAW/item["raw"],DEST/item["name"]);primary.append({"relative":item["name"],**r})
write(DEST/"summary.json",spec["summary"])
with (DEST/"README.md").open("x") as f:f.write(spec["readme"]);f.flush();os.fsync(f.fileno())
archive=DEST/"raw.tar.gz"
with archive.open("xb") as output:
    with gzip.GzipFile(filename="",mode="wb",fileobj=output,mtime=0) as gz:
        with tarfile.open(fileobj=gz,mode="w",format=tarfile.PAX_FORMAT) as tar:
            for entry in sorted(entries,key=lambda e:e["relative"]):
                path=DEST/entry["relative"];data=path.read_bytes()
                assert len(data)==entry["copied"]["bytes"] and hashlib.sha256(data).hexdigest()==entry["copied"]["sha256"]
                info=tarfile.TarInfo(entry["relative"]);info.size=len(data);info.mode=0o644;info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=""
                tar.addfile(info,io.BytesIO(data))
expected={e["relative"]:e["copied"] for e in entries}
assert len(expected)==len(entries)
with tarfile.open(archive,"r:gz") as tar:
    members=tar.getmembers();assert len(members)==len(expected) and {m.name for m in members}==set(expected)
    for member in members:
        assert member.isfile();data=tar.extractfile(member).read();wanted=expected[member.name]
        assert len(data)==wanted["bytes"] and hashlib.sha256(data).hexdigest()==wanted["sha256"]
manifest={"schema":"TRNM-W1-C8-ALLOWLISTED-BUILD-PREPARATION1","bundle":"build-preparation","source":SOURCE,
    "allowlist":spec_pin,"packager":pin(Path(__file__).resolve()),"packaging_preflight":preflight,"jobs":jobs,
    "raw_file_count":len(entries),"raw_total_bytes":sum(e["copied"]["bytes"] for e in entries),"raw_files":entries,
    "primary_files":primary,"summary":pin(DEST/"summary.json"),"README":pin(DEST/"README.md"),"raw_archive":pin(archive),
    "archive_member_bytes_independently_verified":True,"no_symlinks_or_hardlinks":True,
    "source_targets_old_evidence_operations_deadlines_written":False,"private_SQLite_or_ELF_or_inherited_environment_included":False,
    "C8_research_operation_created_by_packaging":False,"C8_runtime_lifecycle_result_claimed":False,
    "C7_unknown_request_replayed":False,"new_complete_proofs":0}
assert pin(SPEC)==spec_pin and verify(spec["owner_import"])==import_pin
write(DEST/"manifest.json",manifest)
result={"schema":"TRNM-W1-C8-BUILD-PREPARATION-PUBLICATION-RESULT1","source":SOURCE,"directory":str(DEST),
    "manifest":pin(DEST/"manifest.json"),"archive":pin(archive),"README":pin(DEST/"README.md"),"summary":pin(DEST/"summary.json"),
    "raw_file_count":len(entries),"raw_total_bytes":manifest["raw_total_bytes"],
    "primary":[pin(DEST/x["name"]) for x in spec["primary"]],"commit_or_push_performed":False,"C8_operation_created":False,"C7_request_replayed":False}
write(TOOLS/"build-preparation-publication-result-01.json",result)
print(json.dumps(result),flush=True)
