#!/usr/bin/env python3
"""Verify all completed C8 gates and prepare one new C8 operation only when explicitly invoked; selects no deadline."""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path("/home/qian-qi/work/chain-w1-c8-timeout-reorg-20261108-ec265b-01")
IMPORT=Path("/home/qian-qi/work/chain-w1-base9417-m12-tools-20261108-ec265b/owner-import-c8-01")
DRIVER=Path("/home/qian-qi/work/chain-w1-base9417-m12-tools-20261108-ec265b/driver-v4.py")
SOURCE={"commit":"4e007a87ceecbec8d265f6a70cfd71d512a514b5","tree":"19a4f1a6e1cec5c27e595fa555b97cddc4717a3c"}
GATE_FILE=IMPORT.parent/"lifecycle-complete-gates-01.json"
EXPECTED_GATES=[("backend",7,0),("native",10,4),("owner",19,37),("core",20,571),("receiver",4,11),("historical-regressions",4,10),("history-compile-list",5,0),("staged-isolated",4,32)]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--gates-sha256",required=True)
args=parser.parse_args()
assert len(args.gates_sha256)==64 and all(x in "0123456789abcdef" for x in args.gates_sha256)
ARGS=["--repo","/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b","--root","/home/qian-qi/work/chain-w1-c8-timeout-reorg-20261108-ec265b-01","--expected-commit","4e007a87ceecbec8d265f6a70cfd71d512a514b5","--owner-binary","/home/qian-qi/work/chain-w1-base9417-owner-target-20261108-ec265b/debug/deps/trnm_pon_node-2c98293081e75af8","--target-dir","/home/qian-qi/work/chain-w1-base9417-owner-target-20261108-ec265b","--runner-binary","/home/qian-qi/work/chain-w1-base9417-backend-target-20261108-ec265b/release/w1-staged-prover-v2","--runner-build-log","/home/qian-qi/work/chain-w1-c8-backend-qualification-20261108-ec265b-01/build.stdout","--native-qualification","/home/qian-qi/work/chain-w1-c8-native-qualification-20261108-ec265b-01/manifest.json"]
def pin(path):
    assert path.is_absolute() and path.is_file() and not path.is_symlink() and path.resolve()==path
    h=hashlib.sha256()
    with path.open("rb") as f:
        before=os.fstat(f.fileno());assert before.st_nlink==1
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
gate_file_pin=pin(GATE_FILE);assert gate_file_pin["sha256"]==args.gates_sha256
gate_file=json.loads(GATE_FILE.read_text())
assert gate_file["schema"]=="TRNM-W1-C8-LIFECYCLE-COMPLETE-GATES1"
assert gate_file["source"]==SOURCE and gate_file["all_component_jobs_terminal_success"] is True
assert [(g["role"],g["actual_command_count"],g["actual_passed_tests"]) for g in gate_file["gates"]]==EXPECTED_GATES
GATES=[(g["role"],g["manifest"],g["actual_command_count"],g["actual_passed_tests"]) for g in gate_file["gates"]]
for g in gate_file["gates"]:
    job=g["job"];verify(job["exit_record"])
    terminal=json.loads(Path(job["exit_record"]["path"]).read_text())
    assert terminal["job_id"]==job["job_id"] and terminal["exit_code"]==0
    assert terminal["cancelled"] is False and terminal["timed_out"] is False
    assert terminal["output_complete"] is True and terminal["output_durable"] is True
    assert terminal["log_errors"]=={"stdout":None,"stderr":None}
    assert terminal["log_synced"]=={"stdout":True,"stderr":True}
    assert terminal["log_truncated"]=={"stdout":False,"stderr":False}
assert not ROOT.exists()
assert pin(DRIVER)["sha256"]=="b66019d2f47c225174de4f69c508e2b163d69f915b1e9eada59eef9368317464"
import_pin=pin(IMPORT/"manifest.json")
assert import_pin["sha256"]=="d7ce0440c68a30cd6a00c5c1e964a1a360f27767848bdca63667991e3f7d2619"
owner=json.loads((IMPORT/"manifest.json").read_text())
assert owner["source"]==SOURCE and owner["qualification_complete"] is True
assert owner["actual_command_count"]==19 and owner["raw_log_files_verified"]==38 and owner["raw_log_files_copied"]==38
assert owner["rust_test_outcomes"]=={"passed":37,"failed":0,"ignored":4}
assert owner["operation_created"] is False and owner["deadline_selected"] is False
assert owner["fresh_cargo_target"] is False and owner["independent_cleanroom_build"] is False
assert owner["owner_binary"]=={"path":"/home/qian-qi/work/chain-w1-base9417-owner-target-20261108-ec265b/debug/deps/trnm_pon_node-2c98293081e75af8","bytes":467190280,"sha256":"1cc1db569c0d21f27aabc3ddbef4730ce11a6481c026b35ed69460c09028d456"}
verify(owner["owner_binary"])
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
assert sum(g["actual_command_count"] for g in gate_pins)==73
assert sum(g["actual_passed_tests"] for g in gate_pins)==665
assert pin(GATE_FILE)==gate_file_pin
ROOT.mkdir()
shutil.copytree(IMPORT,ROOT/"qualification")
assert pin(ROOT/"qualification/manifest.json")["sha256"]==import_pin["sha256"]
for entry in owner["original_files_copied"]:
    original=Path(entry["copy"]["path"]);relative=original.relative_to(IMPORT)
    copied=pin(ROOT/"qualification"/relative)
    assert copied["sha256"]==entry["copy"]["sha256"] and copied["bytes"]==entry["copy"]["bytes"]
write(ROOT/"preparation-provenance.json",{
    "schema":"TRNM-W1-C8-TIMEOUT-PREPARATION-PROVENANCE1","source":SOURCE,
    "owner_schema_import_original":import_pin,"owner_schema_import_copy":pin(ROOT/"qualification/manifest.json"),
    "gate_manifests":gate_pins,"complete_gate_binding":gate_file_pin,"actual_qualification_commands":73,"actual_passed_tests":665,"ignored_tests":4,
    "history_compile_list_executed_test_methods":0,"source_probe_exit1_expected_and_not_a_test":True,
    "target_cache_origins":{"owner":"independent copy of currently built C7 owner plus History release cache; earlier C7 empty origin is historical only; registry/toolchain reused; fresh=false",
        "native":"independent copy of qualified C7 native cache; registry/toolchain reused; fresh=false",
        "backend":"independent copy of qualified C7 backend cache; transitive older failed attempts preserved; registry/toolchain reused; fresh=false"},
    "driver":pin(DRIVER),"preparer":pin(Path(__file__).resolve()),
    "operation_created_before_prepare":False,"deadline_selected_before_launch":False,
    "all_old_source_targets_operations_deadlines_preserved":True,"C7_unknown_request_replayed":False,
    "resource_accounting_remains_unknown":True,"full_resource_cap_retained":True,"provider_payment_authorized":False,
    "fixture_boundary":"Fresh provider operation and isolated research Node; deterministic NativeCancel bytes can repeat across C5/C6 and a completed C8 independent Node fixture; C7 Unknown establishes no refund. Gross principal1000 is not additive across these fixtures or a claim of new global funds."
})
argv=["/usr/bin/python3.12","-B",str(DRIVER),"prepare",*ARGS]
result=subprocess.run(argv,cwd=ARGS[1],
    env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1"},check=False)
raise SystemExit(result.returncode)
