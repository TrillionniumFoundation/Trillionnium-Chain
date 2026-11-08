#!/usr/bin/env python3
"""Strict C7 owner extraction and field-schema import; no Cargo, Node, operation or deadline."""
import argparse,hashlib,json,mmap,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument("--out",type=Path,required=True)
a=p.parse_args()
HEAD="40a3a45d6b8afc5c4706c5235fec47634f4aabbe"
TREE="4b25e3194a0682adff40bb476f2e7c0a395639fe"
REPO=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
QUAL=Path("/home/qian-qi/work/chain-w1-c7-root-validation-20261108-ec265b/exact-owner-01/manifest.json")
QUAL_SHA="6aeb6311539926f0e4f96c9fc2469953fbb879ba5897e7e3e0d16f1399d26261"
EXPECTED_OWNER={"path":"/home/qian-qi/work/chain-w1-c7-owner-empty-target-20261108-ec265b/debug/deps/trnm_pon_node-2c98293081e75af8","bytes":467950280,"sha256":"ae9ebf85ec7b76ea38c0ca1649d5a5e16f0015c915653eeea486c5090c3ce3c7"}
LABELS=["00-preflight","01-source-before","02-cargo-version","03-rustc-version","04-owned-fmt","05-locked-graph-default","06-locked-graph-all-features","07-m12-strict-clippy","08-node-strict-clippy","09-m12-tests","10-node-short-tests","11-legacy-admission-root-tests","12-legacy-reorg-root-tests","13-owner-no-run-json","14-backend-metadata-default","15-backend-metadata-all","16-verifier-metadata-default","17-verifier-metadata-all","99-source-after"]
assert a.out.is_absolute() and a.out.resolve()==a.out and not a.out.exists()
assert a.out.parent.is_dir()
def pin(path):
    assert path.is_file() and not path.is_symlink() and path.resolve()==path
    h=hashlib.sha256()
    with path.open("rb") as f:
        before=os.fstat(f.fileno());assert before.st_nlink==1
        for block in iter(lambda:f.read(1048576),b""):h.update(block)
        after=os.fstat(f.fileno())
    assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(path),"bytes":after.st_size,"sha256":h.hexdigest()}
def verify_record(record):
    observed=pin(Path(record["path"]))
    assert all(observed[k]==record[k] for k in ("path","bytes","sha256"))
    return observed
def write(path,value):
    with path.open("x") as f:
        json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def git(*args):
    return subprocess.check_output(["/usr/bin/git","--no-optional-locks","-C",str(REPO),*args],
        env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","GIT_OPTIONAL_LOCKS":"0"})
def source_clean():
    assert git("rev-parse","HEAD").decode().strip()==HEAD
    assert git("rev-parse","HEAD^{tree}").decode().strip()==TREE
    assert git("status","--porcelain=v1","--untracked-files=all")==b""
source_clean()
unchanged=["formal/pon-nakamoto-v1/w1_zkvm","formal/pon-nakamoto-v1/w1_v2_verifier",
    "trillionnium/crates/trnm-crypto-primitives","trillionnium/crates/trnm-protocol",
    "trillionnium/Cargo.lock","trillionnium/Cargo.toml"]
assert git("diff","--name-only","abab79dac0cb89eb2753d3f579119ac135650eb5","HEAD","--",*unchanged)==b""
qual_pin=pin(QUAL);assert qual_pin["sha256"]==QUAL_SHA
q=json.loads(QUAL.read_text())
assert q["schema"]=="TRNM-W1-EXACT-SOURCE-QUALIFICATION5"
assert q["source_commit"]==HEAD and q["source_tree"]==TREE and q["repo"]==str(REPO)
assert q["qualification_complete"] is True and q["actual_command_count"]==len(q["commands"])==19
assert [row["label"] for row in q["commands"]]==LABELS
assert all(row["exit"]==0 for row in q["commands"])
assert q["rust_test_outcomes"]=={"passed":37,"failed":0,"ignored":4}
assert q["python_test_methods_reported"]==0
verified_logs=[]
for row in q["commands"]:
    assert row["cwd"] in (str(REPO),str(REPO/"trillionnium"))
    for stream in ("stdout","stderr"):
        assert Path(row[stream]["path"])==QUAL.parent/(row["label"]+"."+stream)
        verified_logs.append(verify_record(row[stream]))
    raw=(Path(row["stdout"]["path"]).read_text()+"\n"+Path(row["stderr"]["path"]).read_text())
    parsed=[dict(zip(("passed","failed","ignored"),map(int,m))) for m in re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",raw)]
    assert parsed==row["rust_test_outcomes"],row["label"]
    assert row["python_test_counts"]==[]
assert len(verified_logs)==len({r["path"] for r in verified_logs})==38
counts={key:sum(result[key] for row in q["commands"] for result in row["rust_test_outcomes"]) for key in ("passed","failed","ignored")}
assert counts==q["rust_test_outcomes"]
identities={}
for label,leaf in (("01-source-before","source-before.json"),("99-source-after","source-after.json")):
    row=[r for r in q["commands"] if r["label"]==label];assert len(row)==1
    observed=pin(QUAL.parent/leaf);assert observed["sha256"]==row[0]["stdout"]["sha256"]
    identity=json.loads((QUAL.parent/leaf).read_text())
    assert identity["schema"]=="trnm-ci-source-v1" and identity["kind"]=="head"
    assert identity["tested_commit"]==HEAD and identity["tested_tree"]==TREE and identity["candidate"]==HEAD
    assert identity["tracked_worktree_verified"] is True and identity["tests_executed_by_identity_check"] is False
    identities[leaf]=observed
artifact_row=[r for r in q["commands"] if r["label"]=="13-owner-no-run-json"]
assert len(artifact_row)==1 and "--no-run" in artifact_row[0]["argv"] and "--message-format=json" in artifact_row[0]["argv"]
assert "--locked" in artifact_row[0]["argv"] and "--offline" in artifact_row[0]["argv"]
artifact_log=artifact_row[0]["stdout"]
records=[json.loads(line) for line in Path(artifact_log["path"]).read_text().splitlines() if line.startswith("{")]
selected=[r for r in records if r.get("reason")=="compiler-artifact" and r.get("profile",{}).get("test") is True and r.get("target",{}).get("name")=="trnm_pon_node" and r.get("executable")]
assert len(selected)==1
artifact=selected[0]
assert artifact["manifest_path"]==str(REPO/"trillionnium/crates/trnm-pon-node/Cargo.toml")
assert artifact["target"]["src_path"]==str(REPO/"trillionnium/crates/trnm-pon-node/src/lib.rs")
assert artifact["target"]["kind"]==["lib"] and artifact["target"]["crate_types"]==["lib"]
assert artifact["package_id"].startswith("path+file://"+str(REPO/"trillionnium/crates/trnm-pon-node")+"#")
owner_path=Path(artifact["executable"])
assert owner_path.is_absolute() and owner_path.resolve()==owner_path
assert owner_path.parent==Path(q["cargo_target"])/"debug/deps"
assert artifact["filenames"]==[str(owner_path)]
owner=pin(owner_path);assert owner==EXPECTED_OWNER
with owner_path.open("rb") as f:
    st_before=os.fstat(f.fileno())
    assert f.read(4)==b"\x7fELF"
    with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
        compiled_checkout=str(REPO/"trillionnium/crates/trnm-pon-node").encode()
        checkout_offset=mm.find(compiled_checkout)
        assert checkout_offset>=0,"actual owner ELF lacks expected compiled checkout path"
    st_after=os.fstat(f.fileno())
assert (st_before.st_dev,st_before.st_ino,st_before.st_size,st_before.st_mtime_ns,st_before.st_ctime_ns)==(st_after.st_dev,st_after.st_ino,st_after.st_size,st_after.st_mtime_ns,st_after.st_ctime_ns)
assert q["cargo_target"]==str(owner_path.parents[2]) and q["fresh_cargo_target"] is True
tc="/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin"
assert q["build_env"]["RUSTC"]==tc+"/rustc" and q["build_env"]["RUSTDOC"]==tc+"/rustdoc"
assert q["build_env"]["CARGO_INCREMENTAL"]=="0"
assert all(q[k] is False for k in ("production_qualified","security_qualified","original_business_budget_qualified","resource_billing_complete","payment_qualified"))
assert q["fresh_proof_generations"]==0
a.out.mkdir();(a.out/"raw").mkdir()
copies=[]
for path,leaf in [(QUAL,"original-qualification-manifest.json"),
    (QUAL.parent/"source-before.json","original-source-before.json"),
    (QUAL.parent/"source-after.json","original-source-after.json")]+[(Path(r["path"]),"raw/"+Path(r["path"]).name) for r in verified_logs]:
    before=pin(path);dest=a.out/leaf;shutil.copyfile(path,dest);copied=pin(dest)
    assert before==pin(path) and copied["sha256"]==before["sha256"] and copied["bytes"]==before["bytes"]
    copies.append({"original":before,"copy":copied})
binding={"schema":"TRNM-W1-C7-OWNER-ARTIFACT-EXTRACTION1","derived_extraction":True,
    "source_commit":HEAD,"source_tree":TREE,"qualification_manifest":qual_pin,
    "owner_executable":owner,"compiler_artifact_stdout":artifact_log,"cargo_artifact":artifact,
    "compiled_checkout_observation":{"path":compiled_checkout.decode(),"elf_byte_offset":checkout_offset,
        "scope":"Corroborating byte presence; source binding also requires original exact Cargo artifact, clean source identities and empty-target build provenance."},
    "fresh_cargo_target":True,"cache_basis":q["cache_basis"],"qualification_complete":True,
    "extractor":pin(Path(__file__).resolve()),"original_root_owner_artifact_file_claimed":False,
    "cargo_or_node_executed_by_extraction":False}
write(a.out/"extracted-owner-artifact.json",binding)
binding_pin=pin(a.out/"extracted-owner-artifact.json")
derived={"schema":"TRNM-W1-TIMEOUT-OWNER-QUALIFICATION1","source":{"commit":HEAD,"tree":TREE},
    "owner_binary":owner,"qualification_complete":True,"source_clean_before":True,"source_clean_after":True,
    "commands":q["commands"],"cargo_artifact":artifact,"cargo_artifact_log":artifact_log,
    "cargo_target":q["cargo_target"],"fresh_cargo_target":True,"registry_cache_reused":True,"toolchain_reused":True,
    "independent_reproducible_build_established":False,"independent_cleanroom_build":False,"fixed_guest_compilation_performed":False,
    "build_environment":q["build_env"],"actual_command_count":19,"rust_test_outcomes":counts,
    "sqlite_io_budget_established_by_this_trial":False,"requires_separate_owned_io_domain_controls":True,
    "derived_field_schema_mapping":True,"extracted_binding":binding_pin,"original_qualification_manifest":qual_pin,
    "source_only_checks_count_as_tests":False,"new_tests_or_cargo_executed_by_import":False,
    "node_executed_by_import":False,"operation_created":False,"deadline_selected":False,
    "adapter":pin(Path(__file__).resolve()),"original_files_copied":copies,
    "raw_log_files_verified":38,"raw_log_files_copied":38,"raw_rust_outcome_summaries_independently_reparsed":True,
    "source_prefix_compatibility":{"base":"abab79dac0cb89eb2753d3f579119ac135650eb5","head":HEAD,"prefixes":unchanged,"changed_paths":[]},
    "field_mapping":{"source.commit":"original qualification.source_commit and original source-before/after",
        "source.tree":"original qualification.source_tree and original source-before/after",
        "owner_binary":"unique original no-run Cargo test artifact executable, current-checkout manifest/src/package path and exact ELF readback",
        "qualification_complete":"original qualification.qualification_complete plus all exact 19 commands and 38 raw logs",
        "source_clean_before":"original 01-source-before row and raw identity",
        "source_clean_after":"original 99-source-after row and raw identity"}}
source_clean()
assert pin(QUAL)==qual_pin
write(a.out/"manifest.json",derived)
print(json.dumps({"manifest":pin(a.out/"manifest.json"),"extracted_binding":binding_pin,"owner_binary":owner,
    "tests":counts,"commands":19,"raw_logs_verified":38,"raw_logs_copied":38,"source_prefix_compatibility_passed":True,
    "compiled_checkout_observation":binding["compiled_checkout_observation"],"operation_created":False,"deadline_selected":False}),flush=True)
