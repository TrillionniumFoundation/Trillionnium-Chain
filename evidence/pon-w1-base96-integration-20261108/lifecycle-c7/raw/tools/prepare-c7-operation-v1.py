#!/usr/bin/env python3
"""Freeze all completed C7 gates and prepare one new operation; selects no deadline."""
import hashlib,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path("/home/qian-qi/work/chain-w1-c7-timeout-reorg-20261108-ec265b-01")
IMPORT=Path("/home/qian-qi/work/chain-w1-base96-m12-tools-20261108-ec265b/owner-import-c7-01")
DRIVER=Path("/home/qian-qi/work/chain-w1-base96-m12-tools-20261108-ec265b/driver-v4.py")
SOURCE={"commit":"40a3a45d6b8afc5c4706c5235fec47634f4aabbe","tree":"4b25e3194a0682adff40bb476f2e7c0a395639fe"}
GATES=[["backend",{"path":"/home/qian-qi/work/chain-w1-c7-backend-qualification-20261108-ec265b-01/manifest.json","bytes":11958,"sha256":"7f9368578b4cb5d12f5e4f50e8a1fbfa320545ebd901a489ca4984ca6e657d9b"},7,0],["native",{"path":"/home/qian-qi/work/chain-w1-c7-native-qualification-20261108-ec265b-01/manifest.json","bytes":16997,"sha256":"3870f4ff23cc1d9591b92fe5751536b104a6fb5a0db8576f0e5ad09b8cc87681"},10,4],["owner",{"path":"/home/qian-qi/work/chain-w1-c7-root-validation-20261108-ec265b/exact-owner-01/manifest.json","bytes":23342,"sha256":"6aeb6311539926f0e4f96c9fc2469953fbb879ba5897e7e3e0d16f1399d26261"},19,37],["core",{"path":"/home/qian-qi/work/chain-w1-c7-root-validation-20261108-ec265b/exact-ci-core-01/manifest.json","bytes":21320,"sha256":"d74f30544e9a41d00b209e4016085d33a0ef678cd33a4e64532ab25b20bf3e1d"},20,571],["receiver",{"path":"/home/qian-qi/work/chain-w1-c7-root-validation-20261108-ec265b/exact-receiver-01/manifest.json","bytes":6591,"sha256":"9f7eb12ae0f01eb79946fbff4cf9e69330f642cf5dec08ff50cf71c1ec904a1c"},4,11],["history-compile-list",{"path":"/home/qian-qi/work/chain-w1-c7-root-validation-20261108-ec265b/exact-history-local-01/manifest.json","bytes":7425,"sha256":"5025eadebdb08f85b1e8bb8c68076f29adc59d1048b277630deb2618b1189c3c"},5,0],["staged-isolated",{"path":"/home/qian-qi/work/chain-w1-c7-root-validation-20261108-ec265b/exact-staged-01/manifest.json","bytes":5686,"sha256":"4311dac940b8c5e46100f4c555999684de483665fdad90d2cee546ca99dccc5c"},4,32]]
ARGS=["--repo","/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b","--root","/home/qian-qi/work/chain-w1-c7-timeout-reorg-20261108-ec265b-01","--expected-commit","40a3a45d6b8afc5c4706c5235fec47634f4aabbe","--owner-binary","/home/qian-qi/work/chain-w1-c7-owner-empty-target-20261108-ec265b/debug/deps/trnm_pon_node-2c98293081e75af8","--target-dir","/home/qian-qi/work/chain-w1-c7-owner-empty-target-20261108-ec265b","--runner-binary","/home/qian-qi/work/chain-w1-base96-backend-target-20261108-ec265b/release/w1-staged-prover-v2","--runner-build-log","/home/qian-qi/work/chain-w1-c7-backend-qualification-20261108-ec265b-01/build.stdout","--native-qualification","/home/qian-qi/work/chain-w1-c7-native-qualification-20261108-ec265b-01/manifest.json"]
def pin(path):
    assert path.is_file() and not path.is_symlink()
    h=hashlib.sha256()
    with path.open("rb") as f:
        before=os.fstat(f.fileno())
        for block in iter(lambda:f.read(1048576),b""):h.update(block)
        after=os.fstat(f.fileno())
    assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(path),"bytes":after.st_size,"sha256":h.hexdigest()}
def write(path,value):
    with path.open("x") as f:
        json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def verify(record):
    observed=pin(Path(record["path"]))
    assert all(observed[k]==record[k] for k in ("path","bytes","sha256"))
    return observed
assert not ROOT.exists()
assert pin(DRIVER)["sha256"]=="b66019d2f47c225174de4f69c508e2b163d69f915b1e9eada59eef9368317464"
import_pin=pin(IMPORT/"manifest.json")
assert import_pin["sha256"]=="f4e880fa93b7e87412aa76d1e2534acbb8c04e7115e41650db766469f747ae55"
owner=json.loads((IMPORT/"manifest.json").read_text())
assert owner["source"]==SOURCE and owner["qualification_complete"] is True
assert owner["actual_command_count"]==19 and owner["raw_log_files_verified"]==38 and owner["raw_log_files_copied"]==38
assert owner["rust_test_outcomes"]=={"passed":37,"failed":0,"ignored":4}
assert owner["operation_created"] is False and owner["deadline_selected"] is False
gate_pins=[]
for role,record,count,passed in GATES:
    actual=verify(record);q=json.loads(Path(record["path"]).read_text())
    source=q.get("source") or {"commit":q["source_commit"],"tree":q["source_tree"]}
    assert source==SOURCE and q["qualification_complete"] is True
    assert len(q["commands"])==count
    for row in q["commands"]:
        expected=1 if role=="backend" and row["label"]=="source-probe" else 0
        assert row["exit"]==row.get("expected_exit",expected)==expected
        if "passed" in row:assert row["passed"] is True
        for stream in ("stdout","stderr"):verify(row[stream])
    if role=="native":
        assert q["test_counts"]["native_example"]==2 and q["test_counts"]["verifier"]==2
        actual_passed=4
    elif role=="backend":
        assert q["runner_actual_source_identity"]["tested_commit"]==SOURCE["commit"]
        assert q["runner_actual_source_identity"]["tested_tree"]==SOURCE["tree"]
        actual_passed=0
    else:
        actual_passed=sum(sum(row["python_test_counts"]) for row in q["commands"])
        actual_passed+=sum(result["passed"] for row in q["commands"] for result in row["rust_test_outcomes"])
        assert q["actual_command_count"]==count
    assert actual_passed==passed
    for label in (("source-before","source-after") if role in ("backend","native") else ("01-source-before","99-source-after")):
        row=[r for r in q["commands"] if r["label"]==label];assert len(row)==1
        identity=json.loads(Path(row[0]["stdout"]["path"]).read_text())
        assert identity["tested_commit"]==SOURCE["commit"] and identity["tested_tree"]==SOURCE["tree"]
        assert identity["tracked_worktree_verified"] is True and identity["tests_executed_by_identity_check"] is False
    gate_pins.append({"role":role,"manifest":actual,"actual_command_count":count,"actual_passed_tests":actual_passed,
        "raw_log_files_reverified":len(q["commands"])*2,"source_before_after_reverified":True})
assert sum(g["actual_command_count"] for g in gate_pins)==69
assert sum(g["actual_passed_tests"] for g in gate_pins)==655
ROOT.mkdir()
shutil.copytree(IMPORT,ROOT/"qualification")
assert pin(ROOT/"qualification/manifest.json")["sha256"]==import_pin["sha256"]
for entry in owner["original_files_copied"]:
    original=Path(entry["copy"]["path"]);relative=original.relative_to(IMPORT)
    copied=pin(ROOT/"qualification"/relative)
    assert copied["sha256"]==entry["copy"]["sha256"] and copied["bytes"]==entry["copy"]["bytes"]
write(ROOT/"preparation-provenance.json",{
    "schema":"TRNM-W1-C7-TIMEOUT-PREPARATION-PROVENANCE1","source":SOURCE,
    "owner_schema_import_original":import_pin,"owner_schema_import_copy":pin(ROOT/"qualification/manifest.json"),
    "gate_manifests":gate_pins,"actual_qualification_commands":69,"actual_passed_tests":655,"ignored_tests":4,
    "history_compile_list_executed_test_methods":0,"source_probe_exit1_expected_and_not_a_test":True,
    "target_cache_origins":{"owner":"empty C7 target at original owner qualification start; registry/toolchain reused",
        "native":"independent copy of qualified C6 native target03; registry/toolchain reused; fresh=false",
        "backend":"independent copy of qualified C6 backend attempt02 cache; transitive failed C6 attempt01 preserved; fresh=false"},
    "driver":pin(DRIVER),"preparer":pin(Path(__file__).resolve()),
    "operation_created_before_prepare":False,"deadline_selected_before_launch":False,
    "all_old_source_targets_operations_deadlines_preserved":True,
    "resource_accounting_remains_unknown":True,"full_resource_cap_retained":True,"provider_payment_authorized":False,
    "fixture_boundary":"Fresh provider operation and isolated research Node; deterministic NativeCancel bytes can repeat across C5/C6/C7. Gross principal1000 is not additive across these fixtures or a claim of new global funds."
})
argv=["/usr/bin/python3.12","-B",str(DRIVER),"prepare",*ARGS]
result=subprocess.run(argv,cwd=ARGS[1],
    env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1"},check=False)
raise SystemExit(result.returncode)
