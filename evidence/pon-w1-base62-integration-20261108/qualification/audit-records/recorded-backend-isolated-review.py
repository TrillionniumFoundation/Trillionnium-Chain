FAILED_TERMINAL="{\n  \"at_unix_ms\": 1794119668189,\n  \"audit_recorded\": true,\n  \"automatic_retry\": false,\n  \"cancelled\": false,\n  \"exit_code\": 124,\n  \"job_id\": \"1a1b9cfa141-12894-1706\",\n  \"launch_nonce\": \"d24bcb4d80400c6e1206b401c1a51d1e\",\n  \"log_bytes\": {\n    \"stderr\": {\n      \"seen\": 0,\n      \"stored\": 0\n    },\n    \"stdout\": {\n      \"seen\": 0,\n      \"stored\": 0\n    }\n  },\n  \"log_errors\": {\n    \"stderr\": null,\n    \"stdout\": null\n  },\n  \"log_synced\": {\n    \"stderr\": true,\n    \"stdout\": true\n  },\n  \"log_truncated\": {\n    \"stderr\": false,\n    \"stdout\": false\n  },\n  \"output_complete\": true,\n  \"output_durable\": true,\n  \"state\": \"timed_out\",\n  \"terminal_publication_confirmed\": true,\n  \"terminal_publication_protocol\": 1,\n  \"timed_out\": true\n}"
SUCCESS_TERMINAL="{\n  \"at_unix_ms\": 1794120833993,\n  \"audit_recorded\": true,\n  \"automatic_retry\": false,\n  \"cancelled\": false,\n  \"exit_code\": 0,\n  \"job_id\": \"1a1b9ed804c-12894-17aa\",\n  \"launch_nonce\": \"ce344fb97e1000db8a78e6498c290bff\",\n  \"log_bytes\": {\n    \"stderr\": {\n      \"seen\": 0,\n      \"stored\": 0\n    },\n    \"stdout\": {\n      \"seen\": 646,\n      \"stored\": 646\n    }\n  },\n  \"log_errors\": {\n    \"stderr\": null,\n    \"stdout\": null\n  },\n  \"log_synced\": {\n    \"stderr\": true,\n    \"stdout\": true\n  },\n  \"log_truncated\": {\n    \"stderr\": false,\n    \"stdout\": false\n  },\n  \"output_complete\": true,\n  \"output_durable\": true,\n  \"state\": \"succeeded\",\n  \"terminal_publication_confirmed\": true,\n  \"terminal_publication_protocol\": 1,\n  \"timed_out\": false\n}"
ISOLATED_TERMINAL="{\n  \"at_unix_ms\": 1794121029311,\n  \"audit_recorded\": true,\n  \"automatic_retry\": false,\n  \"cancelled\": false,\n  \"exit_code\": 0,\n  \"job_id\": \"1a1b9f1bf0b-12894-17b8\",\n  \"launch_nonce\": \"3f2c7bb70a2bcdb058fb8f269311f96a\",\n  \"log_bytes\": {\n    \"stderr\": {\n      \"seen\": 0,\n      \"stored\": 0\n    },\n    \"stdout\": {\n      \"seen\": 841,\n      \"stored\": 841\n    }\n  },\n  \"log_errors\": {\n    \"stderr\": null,\n    \"stdout\": null\n  },\n  \"log_synced\": {\n    \"stderr\": true,\n    \"stdout\": true\n  },\n  \"log_truncated\": {\n    \"stderr\": false,\n    \"stdout\": false\n  },\n  \"output_complete\": true,\n  \"output_durable\": true,\n  \"state\": \"succeeded\",\n  \"terminal_publication_confirmed\": true,\n  \"terminal_publication_protocol\": 1,\n  \"timed_out\": false\n}"
#!/usr/bin/env python3
"""Review frozen backend attempts only; writes external archive, runs no tests."""
import collections, gzip, hashlib, io, json, os, stat, tarfile
from pathlib import Path
ROOT=Path("/home/qian-qi/work/chain-w1-base62-adversarial-review-20261108-ec265b")
MTOOLS=Path("/home/qian-qi/work/chain-w1-base62-m12-tools-20261108-ec265b")
OUT=Path("/home/qian-qi/work/chain-w1-c6-backend-qualification-20261108-ec265b-02")
SNAP=MTOOLS/"backend-attempt-01-failure-snapshot"
C6="2bdd252aa6c300b7431b9ee897b254b7953cf562"
TREE="ac3cb7171c429fa5e12e29ee16839fa6f49f1b81"
SOURCE_SHA="2edd14596053103164150807856703c7fac8d4fd5ade634f8acc7203a35025e4"
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p,limit=24*1024*1024):
    fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK)
    try:
        a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_size<=limit
        parts=[];left=limit+1
        while left:
            b=os.read(fd,min(left,1048576))
            if not b:break
            parts.append(b);left-=len(b)
        b=b"".join(parts);z=os.fstat(fd)
        key=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        assert key(a)==key(z) and len(b)==z.st_size and len(b)<=limit
        return b
    finally:os.close(fd)
def load(b):return json.loads(b.decode())
def dump(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,indent=2)+"\n").encode()
def write(p,b):
    with p.open("xb") as f:f.write(b)
def finish(name,raw,index,summary):
    d=ROOT/name;d.mkdir()
    write(d/"summary.json",dump(summary));write(d/"raw-output-index.json",dump(index))
    buf=io.BytesIO()
    with gzip.GzipFile(fileobj=buf,mode="wb",mtime=0) as gz:
        with tarfile.open(fileobj=gz,mode="w") as t:
            for k,b in sorted(raw.items()):
                assert not k.startswith("/") and ".." not in Path(k).parts
                x=tarfile.TarInfo(k);x.size=len(b);x.mode=0o644;x.mtime=0;t.addfile(x,io.BytesIO(b))
    assert len(buf.getvalue())<25*1024*1024
    write(d/"raw-logs.tar.gz",buf.getvalue())
    files=[]
    for p in sorted(d.iterdir()):
        b=p.read_bytes();files.append({"path":p.name,"bytes":len(b),"sha256":sha(b)})
    write(d/"manifest.json",dump({"schema":"TRNM-W1-INDEPENDENT-ATTEMPT-REVIEW-ARCHIVE1","files":files,
        "scope":"explicit logs/JSON/source drivers only; no ELF, SQLite, state tree, environment dump or credentials"}))
    print(json.dumps({"component":name,"manifest_sha256":sha((d/"manifest.json").read_bytes()),
          "archive_sha256":sha(buf.getvalue()),"archive_bytes":len(buf.getvalue()),"raw_members":len(raw)}),flush=True)
def collector():
    raw={};index=[]
    def add(p,rel,pin=None):
        b=read(p)
        if pin:
            assert sha(b)==pin["sha256"],str(p)
            if "bytes" in pin:assert len(b)==pin["bytes"],str(p)
        assert rel not in raw
        raw[rel]=b;index.append({"archive_member":rel,"original_path":str(p),"bytes":len(b),"sha256":sha(b)})
        return b
    return raw,index,add

raw,index,add=collector()
m=load(add(SNAP/"manifest.json","original-failure-snapshot.json",{"sha256":"cc32c4c7384e847b8135502f738df25285187ae0ee5a7b39b58eb37a7e81b7cf"}))
assert m["source"]=={"commit":C6,"tree":TREE} and m["qualification_complete"] is False
assert m["exit_code"]==124 and m["terminal_state"]=="timed_out" and m["original_timeout_seconds"]==900
assert not m["build_command_row_exists"] and not m["complete_qualification_manifest_exists"]
assert not Path(m["failed_attempt_output"],"manifest.json").exists()
assert not m["cargo_build_finished_messages"] and not m["cargo_runner_artifact_messages"]
for row in m["snapshotted_files"]:
    s=row["snapshot"];p=Path(s["path"]);rel=p.relative_to(SNAP)
    assert rel.parts[0] in {"qualification-output","original-job","preparation"}
    assert p.suffix in {".json",".py",".stdout",".stderr"}
    data=add(p,rel.as_posix(),s)
    assert data==read(Path(row["source"]["path"])), ("original no longer matches snapshot",row["source"]["path"])
scope=load(add(Path(m["current_scope"]["path"]),"current-scope.json",m["current_scope"]))
assert scope["original_cgroup_exists"] is False and scope["current_scope_matches"]==[]
partial=[load(x) for x in raw["qualification-output/build.stdout"].splitlines() if x]
assert not any(x.get("reason")=="build-finished" for x in partial)
assert not any(x.get("reason")=="compiler-artifact" and x.get("executable")==m["existing_runner"]["source"]["path"] for x in partial)
rows=[load(b) for k,b in raw.items() if k.endswith(".command.json")]
assert len(rows)==4 and all(x["exit"]==0 for x in rows)
assert {x["label"] for x in rows}=={"preflight","source-before","metadata","compiler-version"}
terminal=load(FAILED_TERMINAL.encode())
assert terminal["exit_code"]==124 and terminal["timed_out"] is True and terminal["output_complete"] is True and terminal["output_durable"] is True
raw["durable-job-terminal.json"]=FAILED_TERMINAL.encode()
index.append({"archive_member":"durable-job-terminal.json","original_path":"authoritative process_status","bytes":len(raw["durable-job-terminal.json"]),"sha256":sha(raw["durable-job-terminal.json"])})
summary={"schema":"TRNM-W1-C6-BACKEND-FAILED-ATTEMPT-REVIEW1","source":m["source"],"job_id":m["failed_attempt_job_id"],
    "actual_terminal":"timed_out","actual_exit":124,"original_outer_budget_seconds":900,
    "completed_command_rows":4,"completed_command_labels":[x["label"] for x in rows],
    "cargo_build_started_but_terminal_record_missing":True,"qualified_runner_artifact_missing":True,
    "source_after_missing":True,"complete_qualification_manifest_missing":True,
    "all_allowlisted_snapshot_files_match_original_bytes":True,
    "existing_c5_runner_not_c6_qualified":True,"existing_elf_not_copied_or_rehashed_in_this_audit":True,
    "current_known_scope_gone_is_not_historical_wait_reap":True,"all_historical_wait_reaped":None,
    "original_attempt_remains_failed":True,"new_complete_proofs":0,"tests_run_by_audit":0}
finish("backend-attempt-01",raw,index,summary)

raw,index,add=collector()
m=load(add(OUT/"manifest.json","manifest.json",{"sha256":"f7c538e360541f15ebea2f8aea7e2fc50bde53ee1cdcd1354b3624b042c2979c"}))
decl=load(add(OUT/"declaration.json","declaration.json",{"sha256":"71b2c50bafc7de44b41cb964b6281b21e15796fda3104bcd5c0941d1d1a1ba2f"}))
plan=load(add(MTOOLS/"backend-attempt-02-plan.json","provenance/backend-attempt-02-plan.json",{"sha256":"b3f4f4e85afd5ac5e0c25277df5b10aad424eebab4b3b2bfa592616c0d46cdcc"}))
add(Path(decl["driver"]["path"]),"provenance/backend-qualify-failed-cache-v5.py",decl["driver"])
add(Path(m["cache_copy"]["path"]),"provenance/backend-cache-copy.json",m["cache_copy"])
add(Path(m["cache_provenance"]["prior_failed_attempt_snapshot"]["path"]),"provenance/original-failure-snapshot.json",m["cache_provenance"]["prior_failed_attempt_snapshot"])
assert m["source"]==decl["source"]==plan["source"]=={"commit":C6,"tree":TREE}
assert m["qualification_budget_seconds"]==decl["qualification_budget_seconds"]==plan["qualification_budget_seconds"]==1800
assert plan["original_failed_attempt"]["timeout_seconds"]==900 and plan["prior_job_extended"] is False
assert m["fresh_cargo_target"] is False and m["cache_provenance"]["target_origin"]=="failed-c6-build-cache-reuse"
assert m["cache_provenance"]["prior_failed_attempt_remains_failed"] is True and m["cache_provenance"]["prior_failed_attempt_exit_code"]==124
commands=m["commands"];assert len(commands)==7
for c in commands:
    assert c["exit"]==c["expected_exit"]==(1 if c["label"]=="source-probe" else 0)
    assert c["passed"] is True and c["cwd"]==m["repo"]
    for stream in ("stdout","stderr"):
        p=Path(c[stream]["path"]);assert p.parent==OUT and p.name==c["label"]+"."+stream
        add(p,p.name,c[stream])
    cb=add(OUT/(c["label"]+".command.json"),c["label"]+".command.json")
    assert load(cb)==c
before=add(OUT/"source-before.json","source-before.json",{"sha256":SOURCE_SHA})
after=add(OUT/"source-after.json","source-after.json",{"sha256":SOURCE_SHA})
assert before==after and load(before)["tracked_worktree_verified"] is True
compiler=[load(x) for x in raw["build.stdout"].splitlines() if x]
chosen=[x for x in compiler if x.get("reason")=="compiler-artifact" and x.get("executable")==m["runner"]["path"]]
assert len(chosen)==1 and chosen[0]==m["cargo_artifact"] and chosen[0]["profile"]["test"] is False
assert chosen[0]["fresh"] is False
assert Path(chosen[0]["manifest_path"]).resolve().is_relative_to(Path(m["repo"]))
assert Path(chosen[0]["target"]["src_path"]).resolve().is_relative_to(Path(m["repo"]))
runner=read(Path(m["runner"]["path"]),64*1024*1024)
assert len(runner)==m["runner"]["bytes"] and sha(runner)==m["runner"]["sha256"]
probe=[load(x) for x in raw["source-probe.stdout"].splitlines() if x]
assert [x["stage"] for x in probe]==["EMBEDDED_GUEST_IDENTITY_VERIFIED","RAW_COMMITTED_SOURCE_VERIFIED"]
assert probe[1]["identity"]==m["runner_actual_source_identity"]==load(before)
assert probe[0]["identity"]["mode"]=="retained-v2-guest" and probe[0]["identity"]["uses_retained_original_guest"] is True
assert probe[0]["identity"]["fresh_guest_compilation_claimed"] is False
assert probe[0]["identity"]["cryptographic_proof_complete"] is False
assert raw["source-probe.stderr"]==b"Error: unknown stage\n"
assert not (OUT/"source-probe-must-remain-absent").exists()
terminal=load(SUCCESS_TERMINAL.encode())
assert terminal["exit_code"]==0 and terminal["timed_out"] is False and terminal["output_complete"] is True and terminal["output_durable"] is True
raw["durable-job-terminal.json"]=SUCCESS_TERMINAL.encode()
index.append({"archive_member":"durable-job-terminal.json","original_path":"authoritative process_status","bytes":len(raw["durable-job-terminal.json"]),"sha256":sha(raw["durable-job-terminal.json"])})
summary={"schema":"TRNM-W1-C6-BACKEND-SECOND-ATTEMPT-REVIEW1","source":m["source"],"job_id":terminal["job_id"],
    "actual_terminal":"succeeded","actual_exit":0,"new_outer_qualification_budget_seconds":1800,
    "actual_commands":7,"actual_exit0_commands":6,"expected_exit1_source_probe_commands":1,
    "all_bound_outputs_and_per_command_records_match":True,"source_before_after_and_actual_probe_equal":True,
    "runner":{"path":m["runner"]["path"],"bytes":len(runner),"sha256":sha(runner),"independently_rehashed":True,"copied":False},
    "cargo_artifact_fresh":False,"fresh_cargo_target":False,"cache_origin":"failed-c6-build-cache-reuse",
    "original_failed_attempt_remains_failed":True,"original_failed_attempt_outer_budget_seconds":900,
    "operation_research_deadline_changed":False,"operation_budget_seconds_distinct_from_build":120,
    "retained_guest_sdk_checked_not_recompiled":True,"source_probe_is_not_a_proof":True,
    "new_complete_proofs":0,"tests_run_by_audit":0}
finish("backend-attempt-02",raw,index,summary)

# The sole predeclared unchanged full-suite isolated followup is a separate cohort.
import re
root=Path("/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b")
tools=Path("/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b")
out=root/"exact-staged-isolated-01"
raw,index,add=collector()
m=load(add(out/"manifest.json","manifest.json",{"sha256":"930ca954936e198dfa3fdab2df0b2d4ca8438111f4e20042ae178c790b095103"}))
plan=load(add(tools/"staged-isolated-plan.json","provenance/staged-isolated-plan.json",{"sha256":m["plan_sha256"]}))
add(tools/"qualify_c6.py","provenance/qualify_c6.py",{"sha256":m["driver_sha256"]})
binding=load(add(root/"staged-isolated-launch-binding.json","provenance/staged-isolated-launch-binding.json",{"sha256":"d97e62b5cf6c9ff0f2584bbe13b300489fa38320735346befe280346f5b88e80"}))
old=load(add(root/"exact-ci-core-01/manifest.json","provenance/original-core-manifest.json",{"sha256":binding["original_core_manifest_sha256"]}))
assert (m["source_commit"],m["source_tree"])==(C6,TREE)
assert m["driver_sha256"]==old["driver_sha256"]==binding["driver_sha256"]
assert m["plan_sha256"]==binding["plan_sha256"]=="df94954295e5b394f2e5f817c8624f949b0e512e5f0d91249969f1e3dccabbf6"
assert m["build_env"]==old["build_env"]
assert plan["maximum_isolated_attempts"]==binding["attempt_limit"]==binding["attempt_index"]==1
assert plan["fixed_fixture_parameters"]=={"timeout_wall_seconds":0.15,"ignored_sigterm_wall_seconds":0.2,"ignored_sigterm_actual_default_termination_grace_seconds":5,"no_child_ready_handshake":True}
assert binding["prior_failure_erased"] is False and binding["other_qualification_cargo_or_full_source_job_active"] is False
assert all(not x["observed_recursive_pids"] for x in binding["known_jobs"])
assert all(x["full_historical_reap_proven"] is False for x in binding["known_jobs"])
commands=m["commands"];assert len(commands)==m["actual_command_count"]==4
for c in commands:
    assert c["exit"]==0 and c["cwd"]==m["repo"]
    for stream in ("stdout","stderr"):
        p=Path(c[stream]["path"]);assert p.parent==out
        add(p,p.name,c[stream])
before=add(out/"source-before.json","source-before.json",{"sha256":SOURCE_SHA})
after=add(out/"source-after.json","source-after.json",{"sha256":SOURCE_SHA})
assert before==after and load(before)["tracked_worktree_verified"] is True
oldrow=next(c for c in old["commands"] if c["label"]=="14-w1-retained-staged-tests")
newrow=next(c for c in commands if c["label"]=="02-w1-retained-staged-tests")
assert oldrow==binding["original_failure_record"] and oldrow["exit"]==1
assert oldrow["argv"]==newrow["argv"]==plan["commands"][0]["argv"]
assert oldrow["cwd"]==newrow["cwd"]
assert m["commands"][0]["started_monotonic_ns"]>binding["prelaunch_monotonic_ns"]
oldtext=add(Path(oldrow["stderr"]["path"]),"provenance/original-staged-failure.stderr",oldrow["stderr"]).decode()
newtext=raw["02-w1-retained-staged-tests.stderr"].decode()
rx=re.compile(r"^(test_\S+ \([^\n]+\)) \.\.\. (ok|FAIL|ERROR|skipped[^\n]*)$",re.M)
old_names=dict(rx.findall(oldtext));new_names=dict(rx.findall(newtext))
assert len(old_names)==len(new_names)==32 and set(old_names)==set(new_names)
assert collections.Counter(old_names.values())=={"ok":30,"FAIL":2}
assert collections.Counter(new_names.values())=={"ok":32}
assert re.findall(r"^Ran (\d+) tests in ",newtext,re.M)==["32"] and re.search(r"^OK$",newtext,re.M)
assert "skipped=" not in newtext and "FAILED (" not in newtext
terminal=load(ISOLATED_TERMINAL.encode())
assert terminal["exit_code"]==0 and terminal["output_complete"] is True and terminal["output_durable"] is True and terminal["timed_out"] is False
raw["durable-job-terminal.json"]=ISOLATED_TERMINAL.encode()
index.append({"archive_member":"durable-job-terminal.json","original_path":"authoritative process_status","bytes":len(raw["durable-job-terminal.json"]),"sha256":sha(raw["durable-job-terminal.json"])})
summary={"schema":"TRNM-W1-C6-SOLE-ISOLATED-STAGED-REVIEW1","source":{"commit":C6,"tree":TREE},
    "job_id":terminal["job_id"],"actual_exit":0,"commands":4,
    "methods":32,"passed":32,"failed":0,"errors":0,"skipped":0,
    "same_original_method_names":True,"method_names":list(new_names),
    "previously_failed_methods_now_pass":[n for n,v in old_names.items() if v=="FAIL"],
    "repeat_passed_methods":30,"newly_satisfied_original_failed_methods":2,
    "original_core_remains_failed":True,"original_staged_failure_kept":{"passed":30,"failed":2,"omitted_output_limit_subcase":True},
    "argv_cwd_driver_and_declared_build_environment_identical":True,"entire_inherited_environment_independently_snapshotted":False,
    "source_before_after_exact_equal":True,"fixed_fixture_parameters":plan["fixed_fixture_parameters"],
    "known_prior_qualification_jobs_observed_inactive_at_launch":len(binding["known_jobs"]),
    "full_historical_process_tree_reaped_established":False,
    "load_independent_behavior_or_causal_host_io_failure_explanation_established":False,
    "audit_reran_tests":False,"new_complete_proofs":0}
finish("staged-isolated-01",raw,index,summary)

