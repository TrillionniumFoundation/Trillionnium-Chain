#!/usr/bin/env python3
"""Verify the initial independent C8 owner cache, bind the exact plan, then exec the unchanged qualification driver."""
import hashlib,json,os,stat,subprocess
from pathlib import Path
HEAD="4e007a87ceecbec8d265f6a70cfd71d512a514b5"
TREE="19a4f1a6e1cec5c27e595fa555b97cddc4717a3c"
REPO=Path("/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b")
TOOLS=Path("/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b")
DRIVER=TOOLS/"qualify_source.py"
PLAN=TOOLS/"owner-plan.json"
TARGET=Path("/home/qian-qi/work/chain-w1-base9417-owner-target-20261108-ec265b")
VALIDATION=Path("/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b")
OUT=VALIDATION/"exact-owner-01"
BINDING=VALIDATION/"owner-launch-binding.json"
COPY=Path("/home/qian-qi/work/chain-w1-base9417-m12-tools-20261108-ec265b/owner-cache-copy-01.json")
PROVENANCE=COPY.parent/"owner-cache-launch-provenance-01.json"
C7={"commit":"40a3a45d6b8afc5c4706c5235fec47634f4aabbe","tree":"4b25e3194a0682adff40bb476f2e7c0a395639fe"}
LABELS=json.loads("[\"cargo-version\",\"rustc-version\",\"owned-fmt\",\"locked-graph-default\",\"locked-graph-all-features\",\"m12-strict-clippy\",\"node-strict-clippy\",\"m12-tests\",\"node-short-tests\",\"legacy-admission-root-tests\",\"legacy-reorg-root-tests\",\"owner-no-run-json\",\"backend-metadata-default\",\"backend-metadata-all\",\"verifier-metadata-default\",\"verifier-metadata-all\"]")
NON_FMT=json.loads("{\"cargo-version\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"--version\",\"--verbose\"],\"cwd\":\"trillionnium\"},\"rustc-version\":{\"argv\":[\"/home/qian-qi/.cargo/bin/rustc\",\"-vV\"],\"cwd\":\"trillionnium\"},\"locked-graph-default\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"metadata\",\"--locked\",\"--offline\",\"--format-version\",\"1\"],\"cwd\":\"trillionnium\"},\"locked-graph-all-features\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"metadata\",\"--locked\",\"--offline\",\"--format-version\",\"1\",\"--all-features\"],\"cwd\":\"trillionnium\"},\"m12-strict-clippy\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"clippy\",\"--locked\",\"--offline\",\"-p\",\"trnm-service-settlement\",\"--lib\",\"--tests\",\"--\",\"-D\",\"warnings\"],\"cwd\":\"trillionnium\"},\"node-strict-clippy\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"clippy\",\"--locked\",\"--offline\",\"-p\",\"trnm-pon-node\",\"--lib\",\"--tests\",\"--\",\"-D\",\"warnings\"],\"cwd\":\"trillionnium\"},\"m12-tests\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"test\",\"--locked\",\"--offline\",\"-p\",\"trnm-service-settlement\",\"native_generation_budget_v2\",\"--lib\",\"--\",\"--test-threads=1\"],\"cwd\":\"trillionnium\"},\"node-short-tests\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"test\",\"--locked\",\"--offline\",\"-p\",\"trnm-pon-node\",\"async_w1_generation_v2\",\"--lib\",\"--\",\"--test-threads=1\"],\"cwd\":\"trillionnium\"},\"legacy-admission-root-tests\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"test\",\"--locked\",\"--offline\",\"-p\",\"trnm-pon-node\",\"store::legacy_admission_root_tests::\",\"--lib\",\"--\",\"--test-threads=1\"],\"cwd\":\"trillionnium\"},\"legacy-reorg-root-tests\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"test\",\"--locked\",\"--offline\",\"-p\",\"trnm-pon-node\",\"store::legacy_reorg_root_tests::\",\"--lib\",\"--\",\"--test-threads=1\"],\"cwd\":\"trillionnium\"},\"owner-no-run-json\":{\"argv\":[\"/home/qian-qi/.cargo/bin/cargo\",\"test\",\"--locked\",\"--offline\",\"-p\",\"trnm-pon-node\",\"--lib\",\"--no-run\",\"--message-format=json\"],\"cwd\":\"trillionnium\"},\"backend-metadata-default\":{\"argv\":[\"cargo\",\"metadata\",\"--manifest-path\",\"formal/pon-nakamoto-v1/w1_zkvm/Cargo.toml\",\"--locked\",\"--offline\",\"--format-version\",\"1\"],\"cwd\":\"\"},\"backend-metadata-all\":{\"argv\":[\"cargo\",\"metadata\",\"--manifest-path\",\"formal/pon-nakamoto-v1/w1_zkvm/Cargo.toml\",\"--locked\",\"--offline\",\"--format-version\",\"1\",\"--all-features\"],\"cwd\":\"\"},\"verifier-metadata-default\":{\"argv\":[\"cargo\",\"metadata\",\"--manifest-path\",\"formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml\",\"--locked\",\"--offline\",\"--format-version\",\"1\"],\"cwd\":\"\"},\"verifier-metadata-all\":{\"argv\":[\"cargo\",\"metadata\",\"--manifest-path\",\"formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml\",\"--locked\",\"--offline\",\"--format-version\",\"1\",\"--all-features\"],\"cwd\":\"\"}}")
REQUIRED_FMT_FILES=json.loads("[\"trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs\",\"trillionnium/crates/trnm-pon-node/src/lib.rs\",\"trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2.rs\",\"trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/terminal.rs\",\"trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests.rs\",\"trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy.rs\",\"trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation.rs\",\"trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation/tests.rs\",\"trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation/timeout.rs\",\"trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/terminal.rs\",\"trillionnium/crates/trnm-service-settlement/src/native_generation_budget_v2.rs\",\"trillionnium/crates/trnm-service-settlement/src/native_generation_budget_v2/tests.rs\",\"trillionnium/crates/trnm-pon-node/src/store.rs\",\"trillionnium/crates/trnm-pon-node/src/store/legacy_reorg_root_tests.rs\",\"trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs\"]")
def pin(p):
    assert p.is_file() and not p.is_symlink() and p.resolve()==p
    h=hashlib.sha256()
    with p.open("rb") as f:
        before=os.fstat(f.fileno())
        for block in iter(lambda:f.read(1048576),b""):h.update(block)
        after=os.fstat(f.fileno())
    assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(p),"bytes":after.st_size,"sha256":h.hexdigest()}
def verify(record):
    actual=pin(Path(record["path"]))
    assert all(actual[k]==record[k] for k in ("path","bytes","sha256"))
    return actual
def identity_pin(p):
    actual=pin(p);st=p.stat()
    return {**actual,"device":st.st_dev,"inode":st.st_ino,"nlink":st.st_nlink}
def inventory(root):
    files={};links={};directories=[]
    for base,ds,fs in os.walk(root,followlinks=False):
        for leaf in ds+fs:
            path=Path(base)/leaf;st=path.lstat();rel=str(path.relative_to(root))
            if stat.S_ISREG(st.st_mode):files[rel]=[st.st_dev,st.st_ino,st.st_nlink,st.st_size,st.st_mode,st.st_mtime_ns,st.st_ctime_ns]
            elif stat.S_ISLNK(st.st_mode):links[rel]=os.readlink(path)
            elif stat.S_ISDIR(st.st_mode):directories.append(rel)
            else:raise ValueError("special cache entry: "+str(path))
    return {"files":files,"symlinks":links,"directories":sorted(directories)}
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def git(*args):
    return subprocess.check_output(["/usr/bin/git","--no-optional-locks","-C",str(REPO),*args],
        env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","GIT_OPTIONAL_LOCKS":"0"}).decode().strip()
assert all(p.is_absolute() and p.resolve()==p for p in (REPO,TOOLS,TARGET,VALIDATION))
assert REPO.is_dir() and TARGET.is_dir() and not OUT.exists() and not BINDING.exists()
assert git("rev-parse","HEAD")==HEAD and git("rev-parse","HEAD^{tree}")==TREE
assert not git("status","--porcelain=v1","--untracked-files=all")
copy_pin=pin(COPY);assert copy_pin["sha256"]=="ce1120304c1679afe96f147a21bdb82ae343f5ce57028bec1b38b75bb53b85e2"
provenance_pin=pin(PROVENANCE);assert provenance_pin["sha256"]=="da7e333fd83be87a306b1d99fd4d49dab931a53d48e2bee78d40c6dbe76f51c1"
copy=json.loads(COPY.read_text());provenance=json.loads(PROVENANCE.read_text())
assert copy["schema"]=="TRNM-W1-ISOLATED-QUALIFIED-CACHE-COPY2" and copy["role"]=="owner"
assert copy["source"]==C7 and copy["destination"]==str(TARGET)
assert copy["copy_complete"] is True and copy["copy_exit_code"]==0
assert copy["copy_return"]["exit_code"]==0 and copy["copy_return"]["direct_child_waited"] is True
assert copy["shared_source_inode_count"]==copy["destination_hardlink_count"]==copy["destination_duplicate_inode_count"]==0
assert copy["source_regular_metadata_unchanged"] is True and copy["source_target_written"] is False
assert copy["source_binaries_before"]==copy["source_binaries_after"]
assert copy["fresh_cargo_target"] is False and copy["destination_binaries_qualified_for_c8"] is False
assert copy["source_empty_origin_is_historical_only"] is True
assert copy["source_currently_contains_owner_debug_and_History_release"] is True
assert copy["cargo_started"] is False and copy["operation_created"] is False
assert provenance["schema"]=="TRNM-W1-C8-OWNER-COPIED-CACHE-LAUNCH-PROVENANCE1"
assert provenance["copy_record"]==copy_pin and provenance["source"]==C7
assert provenance["destination_target"]==str(TARGET) and provenance["destination_fresh_cargo_target"] is False
assert provenance["initial_destination_binaries"]==copy["destination_binaries"]
assert provenance["initial_source_binaries"]==copy["source_binaries_before"]
assert provenance["source_qualifications"]==copy["source_qualifications"]
for record in [copy["source_inventory"],copy["declaration"],*copy["source_qualifications"]]:
    verify(record)
for key in ("child_intent","stdout","stderr"):verify(copy["copy_return"][key])
assert len(copy["source_qualifications"])==2
assert [r["sha256"] for r in copy["source_qualifications"]]==[
    "6aeb6311539926f0e4f96c9fc2469953fbb879ba5897e7e3e0d16f1399d26261",
    "5025eadebdb08f85b1e8bb8c68076f29adc59d1048b277630deb2618b1189c3c"]
source=Path(copy["source_target"])
assert source==Path("/home/qian-qi/work/chain-w1-c7-owner-empty-target-20261108-ec265b")
source_files=inventory(source);target_files=inventory(TARGET)
assert digest(source_files)==copy["source_stat_inventory_before_sha256"]==copy["source_stat_inventory_after_sha256"]
assert set(source_files["files"])==set(target_files["files"])
assert len(target_files["files"])==copy["regular_files_checked"]==3065
assert source_files["directories"]==target_files["directories"]
assert source_files["symlinks"]==target_files["symlinks"]=={}
assert all(target_files["files"][rel][3:6]==source_files["files"][rel][3:6] for rel in source_files["files"])
source_inodes={(m[0],m[1]) for m in source_files["files"].values()}
target_inodes={(m[0],m[1]) for m in target_files["files"].values()}
assert not source_inodes & target_inodes
assert len(target_inodes)==len(target_files["files"]) and all(m[2]==1 for m in target_files["files"].values())
observed_source={rel:identity_pin(source/rel) for rel in copy["source_binaries_before"]}
observed_target={rel:identity_pin(TARGET/rel) for rel in copy["destination_binaries"]}
assert observed_source==copy["source_binaries_before"]
assert observed_target==copy["destination_binaries"]
driver_pin=pin(DRIVER)
assert driver_pin["sha256"]=="d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f"
plan_pin=pin(PLAN);plan=json.loads(PLAN.read_text())
assert plan["source_commit"]==HEAD and plan["source_tree"]==TREE
assert plan["fresh_cargo_target"] is False and isinstance(plan["cache_basis"],str) and "copied" in plan["cache_basis"].lower()
assert plan["declared_command_count"]==len(plan["commands"])+3==19
assert plan["declared_rust_passes"]==37 and plan["declared_rust_ignored"]==4
assert plan.get("extract_w1_block",False) is False
assert [r["label"] for r in plan["commands"]]==LABELS
for item in plan["commands"]:
    if item["label"]=="owned-fmt":
        argv=item["argv"]
        assert argv[:7]==["/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustfmt","--check","--edition","2021","--config","skip_children=true",REQUIRED_FMT_FILES[0]]
        files=argv[6:]
        assert set(REQUIRED_FMT_FILES)<=set(files)
        assert all(not Path(s).is_absolute() and ".." not in Path(s).parts and s.endswith(".rs") and (REPO/s).is_file() for s in files)
        assert item.get("cwd","")==""
    else:
        expected=NON_FMT[item["label"]]
        assert item["argv"]==expected["argv"] and item.get("cwd","")==expected["cwd"]
    assert set(item)<={"label","argv","cwd","timeout"}
    assert item.get("timeout",900)>0 and item.get("timeout",900)<=2400
assert pin(COPY)==copy_pin and pin(PROVENANCE)==provenance_pin and pin(PLAN)==plan_pin and pin(DRIVER)==driver_pin
assert git("rev-parse","HEAD")==HEAD and git("rev-parse","HEAD^{tree}")==TREE and not git("status","--porcelain=v1","--untracked-files=all")
argv=["/usr/bin/python3.12","-B",str(DRIVER),"--repo",str(REPO),"--head",HEAD,"--out",str(OUT),"--plan",str(PLAN),"--target",str(TARGET)]
env=os.environ.copy();env["PYTHONDONTWRITEBYTECODE"]="1"
binding={"schema":"TRNM-W1-C8-OWNER-LAUNCH-BINDING1","source_commit":HEAD,"source_tree":TREE,
    "repo":str(REPO),"target":str(TARGET),"out":str(OUT),"copy_record":copy_pin,"copy_provenance":provenance_pin,
    "original_C7_source":C7,"source_qualifications":copy["source_qualifications"],
    "fresh_cargo_target":False,"target_origin":"copied currently built C7 target; its earlier empty origin does not apply to C8",
    "initial_source_binaries":observed_source,"initial_target_binaries":observed_target,
    "initial_regular_files_checked":len(target_files["files"]),"initial_source_stat_digest":digest(source_files),
    "initial_destination_stat_digest":digest(target_files),"source_inode_sharing":0,"destination_hardlinks":0,"destination_duplicate_inodes":0,
    "registry_cache_reused":True,"toolchain_reused":True,"independent_cleanroom_build":False,
    "driver":driver_pin,"plan":plan_pin,"launcher":pin(Path(__file__).resolve()),"argv":argv,
    "declared_owner_command_count":19,"declared_owner_raw_logs":38,"declared_owner_passes":37,"declared_owner_ignored":4,
    "new_history_module10_tests_separate_from_owner19":True,
    "C8_qualification_complete_at_launch":False,"C7_targets_written":False,"C7_unknown_operation_replayed":False,
    "new_operation_created":False,"deadline_selected":False}
VALIDATION.mkdir(parents=True,exist_ok=True)
with BINDING.open("x") as f:json.dump(binding,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
print(json.dumps({"owner_launch_binding":pin(BINDING),"source":{"commit":HEAD,"tree":TREE},"fresh_cargo_target":False,
    "initial_regular_files_checked":3065,"C8_qualification_complete":False,"operation_created":False}),flush=True)
os.execve(argv[0],argv,env)
