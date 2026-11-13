#!/usr/bin/env python3
"""Allowlisted C7 preparation and launch-Unknown publication; no operation actions."""
import gzip,hashlib,io,json,os,shutil,stat,subprocess,tarfile
from pathlib import Path
TOOLS=Path("/home/qian-qi/work/chain-w1-base96-m12-tools-20261108-ec265b")
SPEC=TOOLS/"publication-allowlist-01.json"
spec=json.loads(SPEC.read_text())
assert spec["schema"]=="TRNM-W1-C7-PUBLICATION-ALLOWLIST1"
REPO=Path(spec["docs_repo"]);EVIDENCE=Path(spec["evidence_root"])
assert REPO==Path("/home/qian-qi/work/chain-w1-c7-attestation-20261108-ec265b")
assert EVIDENCE==REPO/"evidence/pon-w1-base96-integration-20261108"
assert {b["name"] for b in spec["bundles"]}=={"build-preparation","lifecycle-c7"}
assert all(not (EVIDENCE/b["name"]).exists() for b in spec["bundles"])
def pin(p):
    assert p.is_file() and not p.is_symlink() and p.resolve()==p
    h=hashlib.sha256()
    with p.open("rb") as f:
        before=os.fstat(f.fileno());assert before.st_nlink==1
        for block in iter(lambda:f.read(1048576),b""):h.update(block)
        after=os.fstat(f.fileno())
    assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(p),"bytes":after.st_size,"sha256":h.hexdigest()}
def write(p,value):
    with p.open("x") as f:json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def copy(src,dst,expected=None):
    before=pin(src)
    assert src.name!="request.json"
    assert src.suffix not in (".db",".sqlite",".sqlite3",".bin",".elf",".env")
    with src.open("rb") as f:assert f.read(4)!=b"\x7fELF"
    if expected is not None:assert before["sha256"]==expected
    dst.parent.mkdir(parents=True,exist_ok=True)
    assert not dst.exists()
    shutil.copyfile(src,dst);dst.chmod(0o644)
    after=pin(src);copied=pin(dst)
    assert before==after and copied["bytes"]==before["bytes"] and copied["sha256"]==before["sha256"]
    assert (src.stat().st_dev,src.stat().st_ino)!=(dst.stat().st_dev,dst.stat().st_ino)
    return {"original":before,"copied":copied}
with (TOOLS/"publication-preflight.stdout").open("xb") as so,(TOOLS/"publication-preflight.stderr").open("xb") as se:
    result=subprocess.run(["bash","scripts/project-preflight.sh","--dev"],cwd=REPO,stdout=so,stderr=se,check=False)
preflight={"argv":["bash","scripts/project-preflight.sh","--dev"],"cwd":str(REPO),"exit":result.returncode,
    "stdout":pin(TOOLS/"publication-preflight.stdout"),"stderr":pin(TOOLS/"publication-preflight.stderr"),
    "scope":"Packaging preflight only, not included in source qualification method or command counts."}
write(TOOLS/"publication-preflight.json",preflight)
assert result.returncode==0
results=[]
for bundle in spec["bundles"]:
    root=EVIDENCE/bundle["name"];root.mkdir(parents=True)
    raw=root/"raw";raw.mkdir()
    entries=[]
    names=set()
    for item in bundle["items"]:
        rel=Path(item["relative"])
        assert not rel.is_absolute() and ".." not in rel.parts and str(rel) not in names
        names.add(str(rel));r=copy(Path(item["source"]),raw/rel,item.get("sha256"))
        entries.append({"relative":str(Path("raw")/rel),**r})
    extras=[(TOOLS/"publication-preflight.json","packaging/preflight.json"),
        (TOOLS/"publication-preflight.stdout","packaging/preflight.stdout"),
        (TOOLS/"publication-preflight.stderr","packaging/preflight.stderr"),
        (Path(__file__).resolve(),"packaging/publish-c7-v1.py")]
    for src,rel in extras:
        r=copy(src,raw/rel);entries.append({"relative":"raw/"+rel,**r})
    primary=[]
    for item in bundle["primary"]:
        r=copy(raw/item["raw"],root/item["name"])
        primary.append({"relative":item["name"],**r})
    write(root/"summary.json",bundle["summary"])
    with (root/"README.md").open("x") as f:f.write(bundle["readme"])
    archive=root/"raw.tar.gz"
    with archive.open("xb") as output:
        with gzip.GzipFile(filename="",mode="wb",fileobj=output,mtime=0) as gz:
            with tarfile.open(fileobj=gz,mode="w",format=tarfile.PAX_FORMAT) as tar:
                for entry in sorted(entries,key=lambda x:x["relative"]):
                    path=root/entry["relative"];data=path.read_bytes()
                    assert hashlib.sha256(data).hexdigest()==entry["copied"]["sha256"]
                    info=tarfile.TarInfo(entry["relative"]);info.size=len(data);info.mode=0o644;info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=""
                    tar.addfile(info,io.BytesIO(data))
    expected={e["relative"]:e["copied"] for e in entries}
    with tarfile.open(archive,"r:gz") as tar:
        members=tar.getmembers()
        assert len(members)==len(expected) and {m.name for m in members}==set(expected)
        for member in members:
            assert member.isfile()
            data=tar.extractfile(member).read();wanted=expected[member.name]
            assert len(data)==wanted["bytes"] and hashlib.sha256(data).hexdigest()==wanted["sha256"]
    manifest={"schema":"TRNM-W1-C7-ALLOWLISTED-PUBLICATION1","bundle":bundle["name"],"source":spec["source"],
        "allowlist_spec":pin(SPEC),"packager":pin(Path(__file__).resolve()),"packaging_preflight":preflight,
        "raw_file_count":len(entries),"raw_total_bytes":sum(e["copied"]["bytes"] for e in entries),
        "raw_files":entries,"primary_files":primary,"summary":pin(root/"summary.json"),"README":pin(root/"README.md"),"raw_archive":pin(archive),
        "archive_member_bytes_independently_verified":True,"no_symlinks_or_hardlinks":True,
        "old_source_targets_operations_deadlines_written":False,"private_SQLite_or_ELF_or_inherited_environment_included":False,
        "C7_heavy_execution_terminal_established":False,"C7_lifecycle_completed":False,
        "qualification_and_prepared_intent_are_not_actual_funding_or_runtime_evidence":True,
        "further_C7_operation_actions_stopped":True}
    write(root/"manifest.json",manifest)
    results.append({"bundle":bundle["name"],"directory":str(root),"manifest":pin(root/"manifest.json"),
        "archive":pin(archive),"README":pin(root/"README.md"),"summary":pin(root/"summary.json"),
        "raw_file_count":len(entries),"raw_total_bytes":manifest["raw_total_bytes"],"primary":[pin(root/p["name"]) for p in bundle["primary"]]})
write(TOOLS/"publication-result-01.json",{"schema":"TRNM-W1-C7-PUBLICATION-RESULT1","source":spec["source"],"bundles":results,
    "commit_or_push_performed":False,"no_C7_operation_replay":True,"no_C8_copy_build_or_operation":True})
print(json.dumps({"publication_result":pin(TOOLS/"publication-result-01.json"),"bundles":results}),flush=True)
