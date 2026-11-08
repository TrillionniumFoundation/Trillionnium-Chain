#!/usr/bin/env python3
"""Strict C6 owner field-schema import; no Cargo, Node, transaction or operation."""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument("--out",type=Path,required=True)
a=p.parse_args()
HEAD="2bdd252aa6c300b7431b9ee897b254b7953cf562"
TREE="ac3cb7171c429fa5e12e29ee16839fa6f49f1b81"
REPO=Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
BASE=Path("/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b")
BINDING=BASE/"owner-artifact.json"
QUAL=BASE/"exact-owner-01/manifest.json"
OWNER=Path("/home/qian-qi/work/chain-w1-base62-owner-empty-target-20261108-ec265b/debug/deps/trnm_pon_node-2c98293081e75af8")
assert a.out.is_absolute() and a.out.resolve()==a.out and not a.out.exists()
assert a.out.parent.is_dir()
def pin(path):
    assert path.is_file() and not path.is_symlink()
    h=hashlib.sha256()
    with path.open("rb") as f:
        before=os.fstat(f.fileno());assert before.st_nlink==1
        for b in iter(lambda:f.read(1048576),b""):h.update(b)
        after=os.fstat(f.fileno())
    assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(path),"bytes":after.st_size,"sha256":h.hexdigest()}
def verify_record(record):
    obs=pin(Path(record["path"]))
    assert all(obs[k]==record[k] for k in ("path","bytes","sha256"))
    return obs
def write(path,value):
    with path.open("x") as f:
        json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def git(*args):
    return subprocess.check_output(["/usr/bin/git","--no-optional-locks","-C",str(REPO),*args],env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","GIT_OPTIONAL_LOCKS":"0"})
assert git("rev-parse","HEAD").decode().strip()==HEAD
assert git("rev-parse","HEAD^{tree}").decode().strip()==TREE
assert git("status","--porcelain=v1","--untracked-files=all")==b""
unchanged=["formal/pon-nakamoto-v1/w1_zkvm","formal/pon-nakamoto-v1/w1_v2_verifier","trillionnium/crates/trnm-crypto-primitives","trillionnium/crates/trnm-protocol","trillionnium/Cargo.lock","trillionnium/Cargo.toml"]
assert git("diff","--name-only","abab79dac0cb89eb2753d3f579119ac135650eb5","HEAD","--",*unchanged)==b""
binding_pin=pin(BINDING);assert binding_pin["sha256"]=="3ab195ababccc9aa2abfffde5527227f81cc52e6a1d6abe09068d4fb7b79aeed"
qual_pin=pin(QUAL);assert qual_pin["sha256"]=="5a5b7d7ef41a5cf4f5429ef420326777706aae54e4bd88eabf83658530b85b3f"
binding=json.loads(BINDING.read_text());q=json.loads(QUAL.read_text())
assert binding["schema"]=="TRNM-W1-C6-OWNER-ARTIFACT1"
assert binding["source_commit"]==q["source_commit"]==HEAD
assert binding["source_tree"]==q["source_tree"]==TREE
assert binding["qualification_manifest"]=={"path":str(QUAL),"sha256":qual_pin["sha256"]}
assert q["schema"]=="TRNM-W1-EXACT-SOURCE-QUALIFICATION5" and q["repo"]==str(REPO)
assert q["qualification_complete"] is True and q["actual_command_count"]==len(q["commands"])==19
assert all(row["exit"]==0 for row in q["commands"])
assert q["rust_test_outcomes"]=={"passed":37,"failed":0,"ignored":4}
counts={key:sum(result[key] for row in q["commands"] for result in row["rust_test_outcomes"]) for key in ("passed","failed","ignored")}
assert counts==q["rust_test_outcomes"]
verified_logs=[verify_record(row[stream]) for row in q["commands"] for stream in ("stdout","stderr")]
for label,leaf in (("01-source-before","source-before.json"),("99-source-after","source-after.json")):
    row=[r for r in q["commands"] if r["label"]==label];assert len(row)==1
    obs=pin(QUAL.parent/leaf);assert obs["sha256"]==row[0]["stdout"]["sha256"]
    identity=json.loads((QUAL.parent/leaf).read_text())
    assert identity["schema"]=="trnm-ci-source-v1" and identity["tested_commit"]==HEAD and identity["tested_tree"]==TREE
    assert identity["tracked_worktree_verified"] is True and identity["tests_executed_by_identity_check"] is False
artifact_row=[r for r in q["commands"] if r["label"]=="13-owner-no-run-json"]
assert len(artifact_row)==1 and "--no-run" in artifact_row[0]["argv"]
artifact_log=verify_record(binding["compiler_artifact_stdout"])
assert artifact_log==artifact_row[0]["stdout"]
records=[json.loads(x) for x in Path(artifact_log["path"]).read_text().splitlines() if x.startswith("{")]
selected=[x for x in records if x.get("reason")=="compiler-artifact" and x.get("executable")==str(OWNER) and x.get("profile",{}).get("test") is True]
assert len(selected)==1
artifact=selected[0]
assert artifact["manifest_path"]==str(REPO/"trillionnium/crates/trnm-pon-node/Cargo.toml")
assert artifact["target"]["src_path"]==str(REPO/"trillionnium/crates/trnm-pon-node/src/lib.rs")
assert artifact["target"]["name"]=="trnm_pon_node"
owner=verify_record(binding["owner_executable"])
assert owner=={"path":str(OWNER),"bytes":467878704,"sha256":"66190e5b704edc538b42d18ef12750d134f85ae6da4eb42122681f814cd4efa6"}
assert q["cargo_target"]==str(OWNER.parents[2]) and binding["fresh_cargo_target"] is True and q["fresh_cargo_target"] is True
tc="/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin"
assert q["build_env"]["RUSTC"]==tc+"/rustc" and q["build_env"]["RUSTDOC"]==tc+"/rustdoc"
a.out.mkdir()
copies=[]
for path,leaf in [(BINDING,"original-owner-artifact.json"),(QUAL,"original-qualification-manifest.json"),(Path(artifact_log["path"]),"original-owner-cargo-artifact.stdout"),(QUAL.parent/"source-before.json","original-source-before.json"),(QUAL.parent/"source-after.json","original-source-after.json")]:
    before=pin(path);dest=a.out/leaf;shutil.copyfile(path,dest)
    copied=pin(dest);assert before==pin(path) and copied["sha256"]==before["sha256"] and copied["bytes"]==before["bytes"]
    copies.append({"original":before,"copy":copied})
derived={"schema":"TRNM-W1-TIMEOUT-OWNER-QUALIFICATION1","source":{"commit":HEAD,"tree":TREE},
"owner_binary":owner,"qualification_complete":True,"source_clean_before":True,"source_clean_after":True,
"commands":q["commands"],"cargo_artifact":artifact,"cargo_artifact_log":artifact_log,
"cargo_target":q["cargo_target"],"fresh_cargo_target":True,"registry_cache_reused":True,"toolchain_reused":True,
"independent_reproducible_build_established":False,"independent_cleanroom_build":False,"fixed_guest_compilation_performed":False,
"build_environment":q["build_env"],"actual_command_count":19,"rust_test_outcomes":counts,
"sqlite_io_budget_established_by_this_trial":False,"requires_separate_owned_io_domain_controls":True,
"derived_field_schema_mapping":True,"original_binding":binding_pin,"original_qualification_manifest":qual_pin,
"source_only_checks_count_as_tests":False,"new_tests_or_cargo_executed_by_import":False,
"adapter":pin(Path(__file__).resolve()),"original_files_copied":copies,
"source_prefix_compatibility":{"base":"abab79dac0cb89eb2753d3f579119ac135650eb5","head":HEAD,"prefixes":unchanged,"changed_paths":[]},
"field_mapping":{"source.commit":"original binding.source_commit and qualification.source_commit","source.tree":"original binding.source_tree and qualification.source_tree","owner_binary":"original binding.owner_executable verified against actual Cargo JSON and ELF","qualification_complete":"original qualification.qualification_complete plus all 19 command exit codes","source_clean_before":"original 01-source-before row and raw identity","source_clean_after":"original 99-source-after row and raw identity"}}
write(a.out/"manifest.json",derived)
print(json.dumps({"manifest":pin(a.out/"manifest.json"),"owner_binary":owner,"tests":counts,"commands":19,"operation_created":False}),flush=True)
