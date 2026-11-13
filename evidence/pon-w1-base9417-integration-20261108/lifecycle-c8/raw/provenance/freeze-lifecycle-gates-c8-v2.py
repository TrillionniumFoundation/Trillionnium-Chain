#!/usr/bin/env python3
"""Freeze verified C8 gate inputs only. Never executes the preparer, Cargo, Node, or a research operation."""
import hashlib,json,os,re,subprocess
from pathlib import Path
TOOLS=Path("/home/qian-qi/work/chain-w1-base9417-m12-tools-20261108-ec265b")
INPUT=TOOLS/"lifecycle-gate-freeze-inputs-02.json"
INPUT_SHA="e8f7370d1cf39708f16908a8f0415b29c4d33f52022c6a83812c0dc3a19ed72e"
OUT=TOOLS/"lifecycle-complete-gates-02.json"
CHECK=TOOLS/"lifecycle-gate-verification-02.json"
SOURCE={"commit":"4e007a87ceecbec8d265f6a70cfd71d512a514b5","tree":"19a4f1a6e1cec5c27e595fa555b97cddc4717a3c"}
REPO=Path("/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b")
def pin(p):
    assert p.is_absolute() and p.is_file() and not p.is_symlink() and p.resolve()==p
    h=hashlib.sha256()
    with p.open("rb") as f:
        before=os.fstat(f.fileno());assert before.st_nlink==1
        for b in iter(lambda:f.read(1048576),b""):h.update(b)
        after=os.fstat(f.fileno())
    assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(p),"bytes":after.st_size,"sha256":h.hexdigest()}
def verify(record):
    p=pin(Path(record["path"]))
    assert p["sha256"]==record["sha256"]
    if "bytes" in record:assert p["bytes"]==record["bytes"]
    return p
def write(p,obj):
    with p.open("x") as f:json.dump(obj,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def source():
    env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","GIT_OPTIONAL_LOCKS":"0"}
    def git(*argv):return subprocess.check_output(["/usr/bin/git","--no-optional-locks","-C",str(REPO),*argv],env=env)
    assert git("rev-parse","HEAD").decode().strip()==SOURCE["commit"]
    assert git("rev-parse","HEAD^{tree}").decode().strip()==SOURCE["tree"]
    assert git("status","--porcelain=v1","--untracked-files=all")==b""
source()
input_pin=pin(INPUT);assert input_pin["sha256"]==INPUT_SHA
spec=json.loads(INPUT.read_text())
assert spec["schema"]=="TRNM-W1-C8-LIFECYCLE-GATE-FREEZE-INPUTS2" and spec["source"]==SOURCE
assert spec["repo"]==str(REPO) and spec["output"]==str(OUT)
assert spec["new_research_operation_created"] is False and spec["new_research_operation_authorized"] is False
assert not OUT.exists() and not CHECK.exists() and not Path(spec["runtime_root_not_to_create"]).exists()
expected=[("backend",7,0),("native",10,4),("owner",19,37),("core",20,571),("receiver",4,11),("historical-regressions",4,10),("history-compile-list",5,0),("staged-isolated",4,32)]
assert [(g["role"],g["actual_command_count"],g["actual_passed_tests"]) for g in spec["gates"]]==expected
streams=[];job_records=[];observed_rows=[]
def job_metadata(job,expected_exit):
    exit_pin=verify(job["exit_record"]);root=Path(exit_pin["path"]).parent
    assert root==Path("/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs")/job["job_id"]
    terminal=json.loads(Path(exit_pin["path"]).read_text())
    assert terminal["job_id"]==job["job_id"] and terminal["exit_code"]==expected_exit
    assert terminal["cancelled"] is False and terminal["timed_out"] is False
    assert terminal["output_complete"] is True and terminal["output_durable"] is True
    assert terminal["log_errors"]=={"stdout":None,"stderr":None}
    assert terminal["log_synced"]=={"stdout":True,"stderr":True} and terminal["log_truncated"]=={"stdout":False,"stderr":False}
    records={n:pin(root/n) for n in ("exit.json","exit.witness.json","started.json","child.json","stdout.log","stderr.log")}
    witness=json.loads((root/"exit.witness.json").read_text());started=json.loads((root/"started.json").read_text())
    assert witness["job_id"]==started["job_id"]==job["job_id"]
    assert witness["exit_sha256"]==exit_pin["sha256"]
    assert witness["launch_nonce"]==started["launch_nonce"]==terminal["launch_nonce"]
    for stream in ("stdout","stderr"):
        assert records[stream+".log"]["bytes"]==terminal["log_bytes"][stream]["seen"]==terminal["log_bytes"][stream]["stored"]
    result={"job_id":job["job_id"],"expected_exit":expected_exit,"raw_records":records,"terminal":terminal}
    job_records.append(result);return result
def manifest(gate,failed=False):
    mp=verify(gate["manifest"]);q=json.loads(Path(mp["path"]).read_text());role=gate["role"]
    src=q.get("source") or {"commit":q["source_commit"],"tree":q["source_tree"]}
    assert src==SOURCE and q["qualification_complete"] is (not failed)
    assert len(q["commands"])==gate["actual_command_count"]
    parsed_passed=0;parsed_failed=0;parsed_ignored=0;python_attempted=0
    for row in q["commands"]:
        want=1 if (failed and row["label"]=="02-w1-retained-staged-tests") or (role=="backend" and row["label"]=="source-probe") else 0
        assert row["exit"]==row.get("expected_exit",want)==want
        if "passed" in row:assert row["passed"] is True
        raw=[]
        for stream in ("stdout","stderr"):
            p=verify(row[stream]);streams.append({"role":role,"label":row["label"],"stream":stream,**p});raw.append(Path(p["path"]).read_text())
        combined="\n".join(raw)
        py=[int(n) for n in re.findall(r"^Ran ([0-9]+) tests? in ",combined,re.M)]
        rust=[dict(zip(("passed","failed","ignored"),map(int,m))) for m in re.findall(r"test result: [^.]+\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;",combined)]
        if "python_test_counts" in row:assert py==row["python_test_counts"]
        if "rust_test_outcomes" in row:assert rust==row["rust_test_outcomes"]
        python_attempted+=sum(py);parsed_passed+=sum(py)+sum(r["passed"] for r in rust)
        parsed_failed+=sum(r["failed"] for r in rust);parsed_ignored+=sum(r["ignored"] for r in rust)
        observed_rows.append({"role":role,"label":row["label"],"exit":row["exit"],"python_attempts":sum(py),"rust":rust})
    labels=("source-before","source-after") if role in ("backend","native") else ("01-source-before","99-source-after")
    for label in labels:
        row=[r for r in q["commands"] if r["label"]==label];assert len(row)==1
        ident=json.loads(Path(row[0]["stdout"]["path"]).read_text())
        assert ident["tested_commit"]==SOURCE["commit"] and ident["tested_tree"]==SOURCE["tree"]
        assert ident["tracked_worktree_verified"] is True and ident["tests_executed_by_identity_check"] is False
    if failed:
        assert [r["exit"] for r in q["commands"]]==[0,0,1,0] and python_attempted==32
        failed_text=Path(q["commands"][2]["stderr"]["path"]).read_text()
        assert sum(x.endswith(" ... ok") for x in failed_text.splitlines())==31
        assert "FAILED (failures=1)" in failed_text and "['DEADLINE_EXHAUSTED_BEFORE_SPAWN']" in failed_text
        parsed_passed-=1;parsed_failed+=1
    else:assert parsed_failed==0 and parsed_passed==gate["actual_passed_tests"]
    if role=="native":assert q["test_counts"]["native_example"]==q["test_counts"]["verifier"]==2
    if role=="backend":
        assert q["runner_actual_source_identity"]["tested_commit"]==SOURCE["commit"]
        assert q["runner_actual_source_identity"]["tested_tree"]==SOURCE["tree"]
    return q,{"passed":parsed_passed,"failed":parsed_failed,"ignored":parsed_ignored}
all_counts={"passed":0,"failed":0,"ignored":0};manifests={};job_by_id={}
for gate in spec["gates"]:
    q,counts=manifest(gate);manifests[gate["role"]]=q
    for key in all_counts:all_counts[key]+=counts[key]
    job_by_id[gate["job"]["job_id"]]=job_metadata(gate["job"],0)
assert all_counts=={"passed":665,"failed":0,"ignored":4}
failed=spec["original_failed_staged_attempt"]
assert failed["job"]["job_id"]=="1a1ba8f182e-12894-1b97"
assert failed["manifest"]["sha256"]=="a6e8363bfa6a157fc1b414b64e4af59bb11211166fe06f1b0962460253e89e25"
failed_gate={"role":"original-staged-failed","manifest":failed["manifest"],"actual_command_count":4,"actual_passed_tests":31}
original,fc=manifest(failed_gate,True);assert fc=={"passed":31,"failed":1,"ignored":0}
old_job=job_metadata(failed["job"],1)
assert len(streams)==154 and len(observed_rows)==77 and len(job_records)==9
repeat_gate=spec["gates"][-1];assert repeat_gate["job"]["job_id"]=="1a1ba97e353-12894-1bcf"
repeat=manifests["staged-isolated"];old_row=original["commands"][2];new_row=repeat["commands"][2]
assert new_row["argv"]==old_row["argv"] and new_row["cwd"]==old_row["cwd"]
assert new_row["label"]==old_row["label"]=="02-w1-retained-staged-tests" and new_row["exit"]==0
rt=Path(new_row["stderr"]["path"]).read_text()
assert sum(x.endswith(" ... ok") for x in rt.splitlines())==32 and rt.splitlines()[-1]=="OK"
provenance={k:verify(v) for k,v in spec["repeat_provenance"].items()}
declaration=json.loads(Path(provenance["declaration"]["path"]).read_text())
binding=json.loads(Path(provenance["launch_binding"]["path"]).read_text())
assert declaration["schema"]=="TRNM-W1-C8-STAGED-ONE-REPEAT-DECLARATION1"
assert declaration["source_commit"]==binding["source_commit"]==SOURCE["commit"] and declaration["source_tree"]==binding["source_tree"]==SOURCE["tree"]
assert declaration["maximum_additional_attempts"]==1 and declaration["stop_after_second_failure"] is True
assert declaration["test_argv_changed"] is False and declaration["test_parameters_changed"] is False
assert declaration["source_changed"] is False and declaration["environment_overrides"]=={}
assert declaration["added_cpu_or_memory_limits"] is False and declaration["priority_changed"] is False
assert declaration["required_quiet_window"] is True and declaration["old_failure_retained"] is True
assert declaration["aggregate_must_include_both_attempts"] is True and declaration["short_timeout_seconds"]==0.2
assert declaration["planned_job_key"]=="root-c8-exact-staged-declared-repeat-20261108-ec265b-01"
assert declaration["outer_timeout_seconds"]==600
assert declaration["repeat_out"]==str(Path(repeat_gate["manifest"]["path"]).parent)
assert declaration["new_operation_created"] is False and declaration["deadline_selected"] is False
assert declaration["test_plan_sha256"]==provenance["test_plan"]["sha256"]
assert declaration["driver_sha256"]==provenance["qualification_driver"]["sha256"]
assert declaration["base_wrapper_sha256"]==provenance["original_base_wrapper"]["sha256"]
assert declaration["original"]==binding["original_failed_attempt"]
assert declaration["original"]["job_id"]==failed["job"]["job_id"]
assert declaration["original"]["manifest_sha256"]==failed["manifest"]["sha256"]
assert declaration["original"]["stderr_sha256"]==old_row["stderr"]["sha256"]
for key,value in old_job["terminal"].items():assert declaration["original"]["terminal"][key]==value
assert binding["schema"]=="TRNM-W1-C8-STAGED-DECLARED-REPEAT-LAUNCH1"
assert binding["repeat_declaration_sha256"]==provenance["declaration"]["sha256"]
assert binding["input_sha256"]==declaration["input_sha256"]
assert binding["all_first_attempts_passed"] is False and binding["repeat_is_causal_explanation"] is False
assert binding["unchanged_original_test_parameters"] is True and binding["declared_test_methods"]==32
assert binding["new_operation_not_created"] is True and binding["new_operation_deadline_not_selected"] is True
assert len(binding["known_current_components"])==7
for c in binding["known_current_components"]:
    role="history-compile-list" if c["component"]=="history-local" else c["component"]
    g=[x for x in spec["gates"] if x["role"]==role];assert len(g)==1;g=g[0]
    assert c["job_id"]==g["job"]["job_id"] and c["manifest"]==g["manifest"]["path"] and c["manifest_sha256"]==g["manifest"]["sha256"]
    for key,value in job_by_id[c["job_id"]]["terminal"].items():assert c["authoritative_terminal"][key]==value
    assert c["current_unit"]["MainPID"]=="0" and c["current_unit"]["ActiveState"] in ("inactive","failed")
assert binding["original_failed_unit"]["fields"]["MainPID"]=="0"
repeat_job=job_by_id[repeat_gate["job"]["job_id"]]
first_output=json.loads(Path(repeat_job["raw_records"]["stdout.log"]["path"]).read_text().splitlines()[0])
assert first_output["schema"]==binding["schema"] and first_output["known_components_terminal_and_currently_inactive"]==7
assert first_output["pre_staged_methods"]==633 and first_output["new_operation_not_created"] is True
artifact_path=Path(spec["gates"][-2]["manifest"]["path"]).parent/"history-artifact-and-list.json"
history=json.loads(artifact_path.read_text())
assert history["full_history_executed"] is False and history["listed_test_count"]==1 and history["test_passes_claimed"]==0
history_artifact=pin(artifact_path)
owner_pin=verify(spec["owner_import"]);owner=json.loads(Path(owner_pin["path"]).read_text())
assert owner["source"]==SOURCE and owner["qualification_complete"] is True and owner["fresh_cargo_target"] is False
assert owner["actual_command_count"]==19 and owner["raw_log_files_verified"]==owner["raw_log_files_copied"]==38
assert owner["rust_test_outcomes"]=={"passed":37,"failed":0,"ignored":4}
preparer=verify(spec["preparer"]);driver=verify(spec["driver"])
frozen_buildprep=verify(spec["buildprep_frozen_manifest"]);handoff=verify(spec["post_owner_handoff"])
attempt_accounting={
 "qualifying_coverage":{"commands":73,"passed_methods":665,"failed_methods":0,"ignored_methods":4},
 "original_failed_staged_attempt":{"commands":4,"executed_methods":32,"passed_methods":31,"failed_methods":1,"ignored_methods":0,
    "manifest":failed["manifest"],"job":failed["job"],"raw_log_files_reverified":8,"termination_reason":"DEADLINE_EXHAUSTED_BEFORE_SPAWN"},
 "all_declared_qualification_attempts":{"commands":77,"executed_methods":697,"passed_methods":696,"failed_methods":1,"ignored_methods":4},
 "staged_repeat_count":1,"original_attempt_reclassified":False,"original_test_argv_and_cwd_unchanged":True,
 "staged_control_deadline_seconds":0.2,"default_settlement_grace_seconds":5,"same_source_qualified_again_not_a_deadline_extension":True}
assert declaration["first_campaign"]=={"commands":73,"method_executions":665,"passed":664,"failed":1,"ignored":4,"unexpected_nonzero_commands":1,"expected_negative_commands":1}
assert declaration["if_repeat_passes"]=={"commands_including_repeat":77,"method_executions":697,"passed":696,"failed":1,"ignored":4,"all_first_attempts_passed":False}
gate={"schema":"TRNM-W1-C8-LIFECYCLE-COMPLETE-GATES2","source":SOURCE,
 "selected_coverage_jobs_terminal_success":True,"prior_qualification_failures_preserved":True,"staged_repeat_limit":1,
 "gates":spec["gates"],"original_failed_staged_attempt":failed,"declared_staged_attempts":2,"attempt_accounting":attempt_accounting,
 "repeat_declaration_and_actual_launch":provenance,"actual_component_job_metadata":job_records,
 "history_compile_list_artifact":history_artifact,"strict_owner_import":owner_pin,"post_owner_handoff":handoff,
 "build_preparation_frozen_manifest":frozen_buildprep,"preparer":preparer,"driver":driver,
 "generator":pin(Path(__file__).resolve()),"input_specification":input_pin,
 "all_first_attempts_passed":False,"source_and_raw_checks_are_not_new_test_methods":True,
 "global_historical_reap_or_full_resource_accounting_established":False,"provider_payment_authorized":False,
 "operation_created":False,"deadline_selected":False,"runtime_launch_requires_separate_instruction":True}
source();assert pin(INPUT)==input_pin and verify(spec["preparer"])==preparer
assert not Path(spec["runtime_root_not_to_create"]).exists()
write(OUT,gate)
check={"schema":"TRNM-W1-C8-LIFECYCLE-GATE-VERIFICATION2","source":SOURCE,"gate_binding":pin(OUT),
 "input_specification":input_pin,"generator":pin(Path(__file__).resolve()),"commands_verified":77,"component_attempts_verified":9,
 "raw_streams_verified":154,"raw_streams":streams,"actual_command_observations":observed_rows,
 "attempt_accounting":attempt_accounting,"repeat_declaration_and_actual_launch":provenance,
 "job_metadata_verified":job_records,"C8_research_root_absent":True,"operation_created":False,"deadline_selected":False,
 "Cargo_Node_preparer_or_tests_executed":False}
write(CHECK,check)
print(json.dumps({"gate_binding":pin(OUT),"verification":pin(CHECK),"source":SOURCE,"preparer":preparer,"driver":driver,
 "raw_streams_verified":154,"component_attempts":9,"attempt_accounting":attempt_accounting,
 "repeat_declaration":provenance["declaration"],"repeat_wrapper":provenance["wrapper"],"repeat_launch_binding":provenance["launch_binding"],
 "operation_created":False,"deadline_selected":False}),flush=True)
