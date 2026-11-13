#!/usr/bin/env python3
"""Qualified source/build binding for retained guest W1 runner. Starts no proof."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument("--repo",type=Path,required=True)
p.add_argument("--out",type=Path,required=True)
p.add_argument("--target",type=Path,required=True)
p.add_argument("--expected-head",required=True)
p.add_argument("--cache-copy-record",type=Path,required=True)
p.add_argument("--cache-copy-sha256",required=True)
p.add_argument("--qualification-budget-seconds",type=int,choices=(2400,),required=True)
p.add_argument("--expected-tree",required=True)
a=p.parse_args()
repo=a.repo
out=a.out
target=a.target
head=a.expected_head
tree=a.expected_tree
assert all(x.is_absolute() and x.resolve()==x for x in (repo,out,target))
assert repo.is_dir() and target.is_dir() and not out.exists()
out.mkdir()
tc=Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
for leaf in ("rustc","rustdoc","rustfmt","cargo"):
    assert (tc/leaf).resolve()==tc/leaf and (tc/leaf).is_file()
env=os.environ.copy()
assert "RISC0_SKIP_BUILD" not in env
env.update(CARGO_TARGET_DIR=str(target),CARGO_BUILD_JOBS="2",CARGO_NET_OFFLINE="true",
    RUSTUP_TOOLCHAIN="1.95.0",RUSTUP_AUTO_INSTALL="0",RAYON_NUM_THREADS="2",PYTHONDONTWRITEBYTECODE="1",
    RISC0_HOME="/home/qian-qi/work/chain-w1-postwin-runtime-20261107-recovery/task-risc0",
    RUSTC=str(tc/"rustc"),RUSTDOC=str(tc/"rustdoc"),RUSTFMT=str(tc/"rustfmt"))
def pin(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        before=os.fstat(f.fileno())
        for b in iter(lambda:f.read(1048576),b""):h.update(b)
        after=os.fstat(f.fileno())
    assert (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(p),"bytes":after.st_size,"sha256":h.hexdigest()}
def write(p,v):
    with p.open("x") as f:json.dump(v,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def git(*args):
    return subprocess.check_output(["git","--no-optional-locks","-C",str(repo),*args]).decode().strip()
cache=a.cache_copy_record
assert cache.is_absolute() and cache.is_file() and not cache.is_symlink()
cache_pin=pin(cache)
assert cache_pin["sha256"]==a.cache_copy_sha256
cache_record=json.loads(cache.read_text())
assert cache_record["schema"]=="TRNM-W1-ISOLATED-QUALIFIED-CACHE-COPY2"
assert cache_record["role"]=="backend" and cache_record["destination"]==str(target)
assert cache_record["copy_complete"] is True and cache_record["copy_exit_code"]==0
assert cache_record["copy_return"]["exit_code"]==0 and cache_record["copy_return"]["direct_child_waited"] is True
assert cache_record["shared_source_inode_count"]==0 and cache_record["destination_hardlink_count"]==0
assert cache_record["destination_duplicate_inode_count"]==0 and cache_record["symlink_count"]==0
assert cache_record["source_regular_metadata_unchanged"] is True and cache_record["source_target_written"] is False
assert cache_record["source_stat_inventory_before_sha256"]==cache_record["source_stat_inventory_after_sha256"]
assert cache_record["source_binaries_before"]==cache_record["source_binaries_after"]
assert cache_record["cargo_started"] is False and cache_record["operation_created"] is False
assert cache_record["fresh_cargo_target"] is False and cache_record["independent_cleanroom_build"] is False
assert cache_record["destination_binaries_qualified_for_c8"] is False
assert cache_record["registry_cache_reused"] is True and cache_record["toolchain_reused"] is True
assert cache_record["outer_hepta_timeout_seconds"]==1800
assert Path(cache_record["source_target"])!=target
def check_recorded_file(record):
    path=Path(record["path"])
    assert path.is_absolute() and path.resolve()==path and not path.is_symlink()
    actual=pin(path)
    assert all(actual[k]==record[k] for k in ("path","bytes","sha256"))
    return actual
assert cache_record["source_qualifications"]==[cache_record["source_qualification"]]
qualification_pin=check_recorded_file(cache_record["source_qualification"])
check_recorded_file(cache_record["source_inventory"])
check_recorded_file(cache_record["declaration"])
for key in ("child_intent","stdout","stderr"):
    check_recorded_file(cache_record["copy_return"][key])
qualified=json.loads(Path(qualification_pin["path"]).read_text())
assert qualified["qualification_complete"] is True
assert qualified["source"]==cache_record["source"] and qualified["target"]==cache_record["source_target"]
assert qualified["source_clean_before"] is True and qualified["source_clean_after"] is True
assert all(row["passed"] is True and row["exit"]==row["expected_exit"] for row in qualified["commands"])
assert qualified["schema"]=="TRNM-W1-EXACT-BACKEND-QUALIFICATION2"
assert len(qualified["commands"])==7
assert qualified["runner_actual_source_identity"]["tested_commit"]==qualified["source"]["commit"]
assert qualified["runner_actual_source_identity"]["tested_tree"]==qualified["source"]["tree"]
qualified_binaries={"release/w1-staged-prover-v2":qualified["runner"]}
assert set(cache_record["source_binaries_before"])==set(cache_record["destination_binaries"])==set(qualified_binaries)
initial_binaries={}
for relative,qualified_file in qualified_binaries.items():
    old=cache_record["source_binaries_before"][relative]
    copied=cache_record["destination_binaries"][relative]
    assert old["path"]==str(Path(cache_record["source_target"])/relative)
    assert all(old[k]==qualified_file[k] for k in ("path","bytes","sha256"))
    assert copied["path"]==str(target/relative) and copied["nlink"]==1
    assert all(copied[k]==old[k] for k in ("bytes","sha256"))
    actual=check_recorded_file(copied);st=(target/relative).stat()
    assert (st.st_dev,st.st_ino,st.st_nlink)==(copied["device"],copied["inode"],1)
    assert (st.st_dev,st.st_ino)!=(old["device"],old["inode"])
    initial_binaries[relative]={**actual,"device":st.st_dev,"inode":st.st_ino,"nlink":st.st_nlink}
cache_origin={"kind":"copied-from-qualified-target","source":cache_record["source"],
    "source_target":cache_record["source_target"],"source_qualification":qualification_pin,
    "copy_record":cache_pin,"source_qualifications":cache_record["source_qualifications"],"initial_binaries":initial_binaries,"fresh_cargo_target":False,
    "registry_cache_reused":True,"toolchain_reused":True,"independent_cleanroom_build":False,
    "reflink_auto_may_share_copy_on_write_extents":cache_record["reflink_auto_may_share_copy_on_write_extents"],
    "prior_attempt_history":"Preserved by the pinned source qualification and its immutable provenance; not replaced by this copy.",
    "qualification_budget_seconds":a.qualification_budget_seconds}
assert git("rev-parse","HEAD")==head and git("rev-parse","HEAD^{tree}")==tree
assert not git("status","--porcelain=v1","--untracked-files=all")
rows=[]
def run(label,argv,expected=0,runenv=env):
    so=out/(label+".stdout");se=out/(label+".stderr")
    with so.open("xb") as a,se.open("xb") as b:
        result=subprocess.run(argv,cwd=repo,env=runenv,stdout=a,stderr=b,check=False)
    row={"label":label,"argv":argv,"cwd":str(repo),"exit":result.returncode,
         "expected_exit":expected,"passed":result.returncode==expected,"stdout":pin(so),"stderr":pin(se)}
    rows.append(row);write(out/(label+".command.json"),row)
    assert row["passed"],(label,result.returncode)
build_environment={k:env[k] for k in ("CARGO_TARGET_DIR","CARGO_BUILD_JOBS","CARGO_NET_OFFLINE",
    "RUSTUP_TOOLCHAIN","RUSTUP_AUTO_INSTALL","RAYON_NUM_THREADS","PYTHONDONTWRITEBYTECODE",
    "RISC0_HOME","RUSTC","RUSTDOC","RUSTFMT")}
write(out/"declaration.json",{"schema":"TRNM-W1-BACKEND-QUALIFICATION-DECLARATION1",
    "source":{"commit":head,"tree":tree},"repo":str(repo),"target":str(target),
    "environment":build_environment,"driver":pin(Path(__file__).resolve()),"cache_copy":cache_pin,"cache_origin":cache_origin,"qualification_budget_seconds":a.qualification_budget_seconds,
    "fresh_cargo_target":False,"target_origin":"copied-from-qualified-target","registry_cache_reused":True,"toolchain_reused":True,"independent_cleanroom_build":False,
    "guest_compilation_performed":False,"expensive_proof_started":False})
run("preflight",["bash","scripts/project-preflight.sh"])
run("source-before",["/usr/bin/python3.12","-B","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",head,"--output",str(out/"source-before.json")])
run("metadata",[str(tc/"cargo"),"metadata","--manifest-path","formal/pon-nakamoto-v1/w1_zkvm/Cargo.toml","--locked","--offline","--format-version","1"])
run("compiler-version",[str(tc/"rustc"),"--version","--verbose"])
run("build",[str(tc/"cargo"),"build","--release","--manifest-path","formal/pon-nakamoto-v1/w1_zkvm/Cargo.toml","-p","trnm-w1-zk-host-v2","--bin","w1-staged-prover-v2","--features","retained-v2-guest","--locked","--offline","--message-format=json-render-diagnostics"])
runner=target/"release/w1-staged-prover-v2"
artifacts=[json.loads(x) for x in (out/"build.stdout").read_text().splitlines() if x.startswith("{")]
selected=[r for r in artifacts if r.get("reason")=="compiler-artifact" and r.get("executable")==str(runner)]
assert len(selected)==1 and not selected[0]["profile"]["test"]
assert Path(selected[0]["manifest_path"]).resolve().is_relative_to(repo)
assert Path(selected[0]["target"]["src_path"]).resolve().is_relative_to(repo)
runner_before=pin(runner)
probe=out/"source-probe-must-remain-absent"
run("source-probe",[str(runner),"--r0vm","/home/qian-qi/work/chain-w1-postwin-runtime-20261107-recovery/fixed-backend-01/r0vm","source-binding-probe",str(probe)],1,
    {"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1"})
identity=[json.loads(x)["identity"] for x in (out/"source-probe.stdout").read_text().splitlines()
    if x.startswith("{") and json.loads(x).get("stage")=="RAW_COMMITTED_SOURCE_VERIFIED"]
assert len(identity)==1 and identity[0]["tested_commit"]==head and identity[0]["tested_tree"]==tree
assert (out/"source-probe.stderr").read_text().strip()=="Error: unknown stage" and not probe.exists()
assert pin(runner)==runner_before
run("source-after",["/usr/bin/python3.12","-B","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",head,"--output",str(out/"source-after.json")])
assert git("rev-parse","HEAD")==head and git("rev-parse","HEAD^{tree}")==tree and not git("status","--porcelain=v1","--untracked-files=all")
assert pin(cache)==cache_pin and check_recorded_file(cache_record["source_qualification"])==qualification_pin
manifest={"schema":"TRNM-W1-EXACT-BACKEND-QUALIFICATION2","source":{"commit":head,"tree":tree},
    "repo":str(repo),"target":str(target),"commands":rows,"runner":runner_before,"cargo_artifact":selected[0],
    "runner_actual_source_identity":identity[0],"build_environment":build_environment,
    "qualification_complete":True,"fresh_cargo_target":False,"cache_copy":cache_pin,"cache_origin":cache_origin,"qualification_budget_seconds":a.qualification_budget_seconds,
    "independent_cleanroom_build":False,"guest_compilation_performed":False,
    "expensive_proof_started":False,"source_probe_exit1_is_expected_unknown_stage":True,
    "source_clean_before":True,"source_clean_after":True}
write(out/"manifest.json",manifest)
print(json.dumps({"manifest":pin(out/"manifest.json"),"runner":manifest["runner"],"runner_build_log":str(out/"build.stdout"),"source":manifest["source"]}),flush=True)
