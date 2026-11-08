#!/usr/bin/env python3
"""Publish one allowlisted completed C8 lifecycle bundle; no experiment, signal or DB access."""
import argparse,gzip,hashlib,io,json,os,re,stat,subprocess,tarfile
from pathlib import Path
TOOLS=Path("/home/qian-qi/work/chain-w1-base9417-m12-tools-20261108-ec265b")
DOCS=Path("/home/qian-qi/work/chain-w1-c8-attestation-20261108-ec265b")
DEST=DOCS/"evidence/pon-w1-base9417-integration-20261108/lifecycle-c8"
SPEC=TOOLS/"lifecycle-allowlist-01.json"
JOBROOT=Path("/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs")
parser=argparse.ArgumentParser()
parser.add_argument("--allowlist-sha256",required=True)
args=parser.parse_args()
def pin(path):
    assert path.is_absolute() and path.is_file() and not path.is_symlink() and path.resolve()==path
    with path.open("rb") as f:
        a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
        data=f.read();b=os.fstat(f.fileno())
    assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
    return {"path":str(path),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
def checked(path,sha=None,size=None):
    p=pin(path)
    if sha is not None:assert p["sha256"]==sha,(path,p["sha256"],sha)
    if size is not None:assert p["bytes"]==size,(path,p["bytes"],size)
    return p
def load(path):return json.loads(path.read_text())
def write(path,value):
    with path.open("x") as f:
        json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def copy(src,dst,wanted=None):
    before=pin(src);data=src.read_bytes()
    assert before==pin(src) and len(data)==before["bytes"] and hashlib.sha256(data).hexdigest()==before["sha256"]
    assert src.name!="request.json" and src.suffix not in {".db",".sqlite",".sqlite3",".elf",".env"}
    assert data[:4]!=b"\x7fELF" and not data.startswith(b"SQLite format 3")
    if src.suffix not in {".bin",".gz"}:data.decode("utf-8")
    if wanted is not None:assert before["sha256"]==wanted
    dst.parent.mkdir(parents=True,exist_ok=True)
    with dst.open("xb") as f:f.write(data);f.flush();os.fsync(f.fileno())
    dst.chmod(0o644);actual=pin(dst)
    assert before==pin(src) and (before["bytes"],before["sha256"])==(actual["bytes"],actual["sha256"])
    assert (src.stat().st_dev,src.stat().st_ino)!=(dst.stat().st_dev,dst.stat().st_ino)
    return {"original":before,"copied":actual}
specpin=checked(SPEC,args.allowlist_sha256);s=load(SPEC);assert s["schema"]=="TRNM-W1-C8-LIFECYCLE-ALLOWLIST1"
source=s["source"];root=Path(s["root"]);op=s["operation"];deadline=s["original_deadline_ns"]
assert source=={"commit":"4e007a87ceecbec8d265f6a70cfd71d512a514b5","tree":"19a4f1a6e1cec5c27e595fa555b97cddc4717a3c"}
assert not DEST.exists()
items=list(s["items"])
for x in items:checked(Path(x["source"]),x.get("sha256"),x.get("bytes"))
plan=load(root/"plan.json");config=load(root/"config.json");launch=load(root/"launch-declaration.json")
main=load(root/"run/funded-owner-cancellation-result.json");typed=load(root/"run/m12-terminal-failure-observed.json")
reorg=load(root/"run/owner-timeout-reorg-result.json");cold=load(root/"cold-reconcile-01/result.json")
start=load(root/"run/owner-cancel-start/result.json");deadline_seen=load(root/"run/owner-timeout-deadline-observed.json")
cancel_requested=load(root/"run/owner-cancel-requested.json");readonly=load(TOOLS/"terminal-readonly-observation-01.json")
assert plan["source"]==launch["source"]==source and plan["operation"]==op
assert plan["deadline_selected"] is False and plan["winner_or_proof_started"] is False
assert launch["original_deadline_ns"]==deadline==main["original_deadline_ns"]==cold["original_deadline_ns"]
assert launch["original_deadline_ns"]-launch["selected_monotonic_ns"]==120_000_000_000
assert launch["config"]==pin(root/"config.json") and launch["plan"]==pin(root/"plan.json")
assert main["real_expensive_generation_started"] and main["fresh_generation_attempts"]==1 and main["original_deadline_timeout_observed"]
assert main["original_provider_operation"]==op==typed["operation"]==cold["original_operation"]==reorg["provider_operation"]
assert not main["deadline_renewed"] and main["new_complete_proofs"]==0 and not main["full_proof_verified"]
assert not main["provider_payment_observed"] and not main["public_chain_transactions_sent"]
assert typed["failure_kind"]=="Unknown" and typed["consumed"] is None and typed["m12_resource_cap_retained"]
assert typed["recorded_before_owner_veto"] and typed["cancellation_at_failure"] is None
assert typed["recorded_monotonic_ns"]<cancel_requested["requested_monotonic_ns"]
assert main["m12_cold_begin"]==reorg["m12_dispatch_begin"]==cold["m12_begin"]=="Done"
assert main["m12_original_resource_cap_retained"] and cold["original_resource_cap_retained"]
assert cold["native_transactions_submitted"]==cold["new_generation_dispatches"]==cold["target_cancel_requests_sent"]==0
hot_target=main["target_terminal_observation"]["observation"]["target"]
assert hot_target==cold["target_observation"]["retained_target_readback"]
target=hot_target["result"]
assert target["cause"]=="original-deadline" and target["original_deadline_monotonic_ns"]==deadline
assert target["resources"]["gpu_ns"] is None and target["all_descendants_reaped"] is None
assert target["finished_monotonic_ns"]>=deadline and target["direct_child_reaped"] is True
assert not hot_target["may_dispatch_again"] and not target["can_authorize_payment"]
assert reorg["before_reorg"]==reorg["original_cancel_restored"]==main["native_task"]==cold["native_task"]
assert reorg["cancel_removed"]==reorg["actual_cold_reopen"]
assert reorg["cancel_removed"]["funding_row"]["status"]=="reserved" and reorg["cancel_removed"]["funding_row"]["remaining"]==1000
assert not reorg["cancel_removed"]["canonical_cancel_observed"] and not reorg["cancel_removed"]["refund_claim"]
assert reorg["original_cancel_restored"]["funding_row"]["status"]=="cancelled"
assert reorg["original_cancel_restored"]["gross_owner_refund_units"]==1000 and reorg["provider_balance_unchanged"]
assert reorg["new_cancel_wire_signed"] is False and reorg["new_generation_dispatches"]==reorg["new_native_cancel_transactions"]==0
assert readonly["signals_sent"]==readonly["new_dispatches"]==0 and readonly["all_history_reaped"] is None
assert all(x["status"]=="ABSENT" for x in readonly["known_processes"])
assert all(x["status"]=="ABSENT" for x in readonly["owned_cgroups"])
jobs=[]
for j in s["jobs"]:
    p=JOBROOT/j["id"];e=load(p/"exit.json");w=load(p/"exit.witness.json")
    assert e["job_id"]==w["job_id"]==j["id"] and e["exit_code"]==j["expected_exit"]
    assert e["output_complete"] and e["output_durable"] and not e["cancelled"] and not e["timed_out"]
    assert e["log_errors"]=={"stdout":None,"stderr":None} and e["log_synced"]=={"stdout":True,"stderr":True}
    assert e["log_truncated"]=={"stdout":False,"stderr":False}
    assert w["launch_nonce"]==e["launch_nonce"] and w["exit_sha256"]==pin(p/"exit.json")["sha256"]
    pins={}
    for name in ("started.json","child.json","exit.json","exit.witness.json","stdout.log","stderr.log"):
        q=pin(p/name);pins[name]=q
        if name in ("stdout.log","stderr.log"):
            k=name.split(".")[0];assert q["bytes"]==e["log_bytes"][k]["seen"]==e["log_bytes"][k]["stored"]
        items.append({"source":q["path"],"relative":"jobs/"+j["role"]+"/"+name,"sha256":q["sha256"],"bytes":q["bytes"]})
    tests=None
    if j["role"] in ("heavy","cold"):
        text=(p/"stdout.log").read_text()
        match=re.search(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;.*finished in ([0-9.]+)s",text)
        assert match and match.groups()[:3]==("1","0","0")
        tests={"passed":1,"failed":0,"ignored":0,"wall_seconds_reported":match.group(4)}
    jobs.append({**j,"actual_terminal":e,"raw_files":pins,"research_test_outcome":tests})
for stage in s["staged_manifests"]:
    p=Path(stage["path"]);checked(p,stage["sha256"],stage["bytes"]);m=load(p)
    assert m["source_commit"]==source["commit"] and m["source_tree"]==source["tree"]
    items.append({"source":str(p),"relative":"qualification-attempts/"+stage["role"]+"/manifest.json","sha256":stage["sha256"]})
    for row in m["commands"]:
        for stream in ("stdout","stderr"):
            rec=row[stream];checked(Path(rec["path"]),rec["sha256"],rec["bytes"])
            items.append({"source":rec["path"],"relative":"qualification-attempts/"+stage["role"]+"/"+Path(rec["path"]).name,"sha256":rec["sha256"]})
# Actual byte comparisons across deterministic independent research Nodes. No DB or old operation is opened.
comparisons=[]
newtask=load(root/"run/native-funded-intent.json")["task"]
for tag,oldroot in s["old_fixture_roots"].items():
    old=Path(oldroot)
    row={"older_fixture":tag,"older_root":str(old),"older_source":load(old/"plan.json")["source"],"older_plan":pin(old/"plan.json"),"independent_node_fixture":True,"same_global_funds_claimed":False,"files":[]}
    for name in ("native-cancel-wire.bin","native-cancel-packet.bin"):
        a=old/"run"/name;b=root/"run"/name
        pa=pin(a);pb=pin(b);same=a.read_bytes()==b.read_bytes()
        assert same and pa["sha256"]==pb["sha256"]
        row["files"].append({"old":pa,"C8":pb,"exact_bytes_equal":same})
    oldintent=old/"run/native-funded-intent.json";oldtask=load(oldintent)["task"]
    assert oldtask==newtask
    row["native_task"]={"C8":newtask,"older":oldtask,"equal":True,"older_intent":pin(oldintent)}
    comparisons.append(row)
comparison={"schema":"TRNM-W1-C8-DETERMINISTIC-INDEPENDENT-FIXTURE-COMPARISON1","comparisons":comparisons,
    "interpretation":"Identical deterministic NativeTask/Cancel wire and packet across separate research Nodes; provider operation/deadline/output domain is new. Gross refunds must not be summed as global-chain funds.","public_chain_transactions_sent":False}
comparepath=TOOLS/"deterministic-cancel-comparison-c8-01.json";write(comparepath,comparison)
items.append({"source":str(comparepath),"relative":"derived/deterministic-cancel-comparison.json","sha256":pin(comparepath)["sha256"]})
names=[x["relative"] for x in items];assert len(names)==len(set(names))
for n in names:assert not Path(n).is_absolute() and ".." not in Path(n).parts
# The repository preflight is required before writing the new evidence subdirectory.
with (TOOLS/"lifecycle-publication-preflight.stdout").open("xb") as so,(TOOLS/"lifecycle-publication-preflight.stderr").open("xb") as se:
    p=subprocess.run(["bash","scripts/project-preflight.sh","--dev"],cwd=DOCS,stdout=so,stderr=se,timeout=90)
preflight={"argv":["bash","scripts/project-preflight.sh","--dev"],"cwd":str(DOCS),"exit":p.returncode,
    "stdout":pin(TOOLS/"lifecycle-publication-preflight.stdout"),"stderr":pin(TOOLS/"lifecycle-publication-preflight.stderr"),
    "scope":"Packaging only; no new source qualification or research methods are counted."}
write(TOOLS/"lifecycle-publication-preflight.json",preflight);assert p.returncode==0
DEST.mkdir(parents=True);raw=DEST/"raw";raw.mkdir()
entries=[]
for x in items:
    r=copy(Path(x["source"]),raw/x["relative"],x.get("sha256"))
    entries.append({"relative":"raw/"+x["relative"],**r})
for a,b in [(SPEC,"packaging/allowlist.json"),(Path(__file__).resolve(),"packaging/publish-lifecycle-c8-v1.py"),(TOOLS/"lifecycle-publication-preflight.json","packaging/preflight.json"),(TOOLS/"lifecycle-publication-preflight.stdout","packaging/preflight.stdout"),(TOOLS/"lifecycle-publication-preflight.stderr","packaging/preflight.stderr")]:
    entries.append({"relative":"raw/"+b,**copy(a,raw/b)})
primary=[]
for a,b in s["primary"]:primary.append({"relative":b,**copy(raw/a,DEST/b)})
live=start["trigger"]
assert live["stage"]=="prove-batch-0000" and "prover_identity" in live
assert live["observed_monotonic_ns"]<deadline
jmap={x["role"]:x for x in jobs}
timeline={"clock":"CLOCK_MONOTONIC, original boot "+launch["original_identity"]["boot_id"],
    "selected_monotonic_ns":launch["selected_monotonic_ns"],"original_budget_ns":120000000000,
    "live_prover_observed_monotonic_ns":live["observed_monotonic_ns"],"original_deadline_ns":deadline,
    "deadline_wait_observed_monotonic_ns":deadline_seen["observed_monotonic_ns"],
    "target_finished_monotonic_ns":target["finished_monotonic_ns"],
    "target_finished_minus_deadline_ns":target["finished_monotonic_ns"]-deadline,
    "target_finished_scope":"Target termination record; never completion of a full proof",
    "typed_unknown_recorded_monotonic_ns":typed["recorded_monotonic_ns"],
    "explicit_owner_veto_requested_monotonic_ns":cancel_requested["requested_monotonic_ns"],
    "cold_helper_start_monotonic_ns":cold["target_observation"]["actual_command"]["started_monotonic_ns"],
    "cold_helper_exit_observed_monotonic_ns":cold["target_observation"]["actual_command"]["completed_monotonic_ns"],
    "deadline_renewed":False}
summary={"schema":"TRNM-W1-C8-LIFECYCLE-PUBLIC-SUMMARY1","source":source,"operation":op,"statement":main["native_reorg_roundtrip"]["statement"],
    "research_root":str(root),"research_tests":{"heavy":jmap["heavy"]["research_test_outcome"],"cold":jmap["cold"]["research_test_outcome"],"total_passed":2,"added_to_ordinary_697_test_count":False},
    "jobs":{k:{"job_id":jmap[k]["id"],"exit_code":jmap[k]["actual_terminal"]["exit_code"],"output_complete":jmap[k]["actual_terminal"]["output_complete"],"output_durable":jmap[k]["actual_terminal"]["output_durable"]} for k in jmap},
    "original_qualification_attempt_accounting":s["qualification_attempts"],"timeline":timeline,
    "plan":pin(root/"plan.json"),"config":pin(root/"config.json"),"launch_declaration":pin(root/"launch-declaration.json"),
    "preparation":pin(root/"preparation-provenance.json"),"owner_binary":plan["owner_binary"],
    "runner":load(root/"runner-source-probe.json")["runner"],"native_winner":config["native_winner"],"verifier":config["verifier"],"retained_guest":config["guest"],"retained_r0vm":config["r0vm"],
    "fresh_guest_compilation_claimed":False,"independent_cleanroom_build_claimed":False,
    "actual_expensive_generation":{"fresh_dispatch_attempts":1,"live_observation":live,"original_deadline_termination":True,"target_cause":target["cause"],"target_exit_code":target["exit_code"],"new_complete_proofs":0,"full_proof_verified":False},
    "M12":{"begin":"Done","meaning":"dispatch lifecycle terminal only","failure_kind":"Unknown","consumed":None,"original_resource_cap_retained":True,"resource_cap":config["resource_cap"],"failure_recorded_before_owner_request":True,"accepted_outcome_independent_timestamp":None,"new_cancellation_journal_event_proven":False,"resource_settlement_complete":False,"provider_payment_authorized":False},
    "native_task":{"task":newtask,"native_cancel_operation":reorg["before_reorg"]["original_operation"],"gross_principal_refund_units":1000,"owner_balance_after_cancel":reorg["owner_balance_after_cancel"],"owner_balance_with_cancel_removed":reorg["owner_balance_while_cancel_removed"],"net_refund_not_claimed_as_1000":True,"provider_balance_unchanged":True,"wire":pin(root/"run/native-cancel-wire.bin"),"packet":pin(root/"run/native-cancel-packet.bin"),"same_deterministic_bytes_as_C5_C6":True,"fixture_comparison":pin(comparepath),"separate_research_nodes_not_additive_global_funds":True,"public_chain_transactions_sent":False},
    "reorg":{"before":reorg["before_reorg"],"removed":reorg["cancel_removed"],"cold_reopen_removed":reorg["actual_cold_reopen"],"restored":reorg["original_cancel_restored"],"same_cancel_wire_restored":True,"new_cancel_wire_signed":False,"new_native_cancel_transactions":0,"new_generation_dispatches":0},
    "independent_cold":{"m12_begin":"Done","original_config_unchanged":True,"original_deadline_unchanged":True,"same_retained_target_object_as_hot":True,"same_canonical_cancel_object_as_restored":True,"new_generation_dispatches":0,"native_transactions_submitted":0,"target_cancel_requests_sent":0,"fullcap_retained":True},
    "resource_observation":{"target_cpu_stat":target["resources"]["cpu_stat"],"cpu_stat_scope":"retained owned child cgroup only; not a complete all-history cost invoice","gpu_ns":None,"memory_peak_bytes":target["resources"]["memory_peak_bytes"],"all_descendants_reaped":None,"direct_child_reaped":True,"target_child_cgroup_empty_at_cleanup":target["child_cgroup_observation"]["recursive_empty"],"current_known_pid_births":readonly["known_processes"],"current_owned_cgroups":readonly["owned_cgroups"],"current_exact_units":readonly["exact_units"],"readonly_signals_sent":0},
    "boundaries":{"new_complete_proofs":0,"positive_provider_payments":0,"resource_cap_releases":0,"production_qualified":False,"winner_Node_admission_qualified":False,"old_two_Pending_operations_reclassified":False,"C7_unknown_replayed":False,"full_history_process_reap_qualified":False,"GPU_accounting_complete":False},
    "primary_files":[{"relative":x["relative"],"bytes":x["copied"]["bytes"],"sha256":x["copied"]["sha256"]} for x in primary],
    "independent_review":s.get("independent_review"),"packaging_scope":"Original allowlisted bytes and derived index only; no private SQLite, ELF, inherited environment, source edits, deadline changes, signals, or new experiment."}
write(DEST/"summary.json",summary)
readme=f"""# C8 actual costly timeout, owner cancellation, reorg, and cold recovery

This bundle records the new provider operation `{op}` on exact source `{source["commit"]}` / tree `{source["tree"]}`. The main research test passed once in **{jmap["heavy"]["research_test_outcome"]["wall_seconds_reported"]} s**, then the independently launched cold test passed once in **{jmap["cold"]["research_test_outcome"]["wall_seconds_reported"]} s**. Both durable jobs exited 0 with complete, durable stdout/stderr. This is **0 new complete proofs**, **0 positive provider payments**, and **0 resource-cap releases**.

## What actually closed

One new costly generation dispatch entered actual `r0vm` segment proving under the original 8-CPU affinity, CPUQuota 800%, 8 GiB, two segment workers, two compression workers, and Rayon 4 declaration. At its original single 120-second deadline the target terminated with cause `original-deadline`. Before any owner veto, the typed M12 API recorded `Failure(Unknown)`, `consumed = null`, and retained the original resource cap. The later explicit owner veto and ordinary owner-signed NativeTask Cancel authorized the research fixture's gross 1000-unit principal refund.

A valid alternative branch removed that Cancel from canonical ancestry, restoring the Reserved row with 1000 remaining; a real Node cold reopen observed that removed state without dispatch or a new transaction. Restoring the original Cancel ancestry used the **same wire and packet**, followed by an independent process reopening the original config/operation/deadline. It observed M12 `Done`, the same canonical Cancel, and zero new generation, Cancel request, or NativeTask transaction submissions.

## Clock and ordering

All these monotonic times share original boot `{launch["original_identity"]["boot_id"]}`.

| Observation | Monotonic ns |
| --- | ---: |
| Single deadline selection | {timeline["selected_monotonic_ns"]} |
| Actual live r0vm observation | {timeline["live_prover_observed_monotonic_ns"]} |
| Original deadline | {deadline} |
| Deadline reached, before target terminal inference | {timeline["deadline_wait_observed_monotonic_ns"]} |
| Target termination record | {timeline["target_finished_monotonic_ns"]} |
| Typed Unknown recorded | {timeline["typed_unknown_recorded_monotonic_ns"]} |
| Explicit owner veto requested | {timeline["explicit_owner_veto_requested_monotonic_ns"]} |

The target termination record is **{timeline["target_finished_minus_deadline_ns"]} ns ({timeline["target_finished_minus_deadline_ns"]/1e9:.9f} s) after the original deadline**. This is a termination observation, not proof completion or a renewed deadline. The research test wall time includes reconciliation/refund/reorg work and is not proof latency.

## Distinct accounting boundaries

M12 `Done` describes the dispatch lifecycle. The typed failure remains Unknown, consumed resources remain null, and the full original cap remains reserved. The retained child-cgroup CPU counters are partial scope evidence; GPU time, all historical descendant wait/reap ownership, and complete resource settlement remain unqualified. The provider balance is unchanged.

The 1000-unit amount is **gross principal** in one deterministic independent research Node fixture. The Cancel wire, packet, and NativeTask identity were compared byte-for-byte with the C5 and C6 fixtures and are identical; the comparison inputs and hashes are retained in `raw/derived/deterministic-cancel-comparison.json`. These fixtures do not establish separate additive global-chain refunds, and no public-chain transaction was submitted. The observed balances are {reorg["owner_balance_after_cancel"]} after Cancel and {reorg["owner_balance_while_cancel_removed"]} while it is removed; 1000 is not asserted to be the net account change.

The terminal target observed its child cgroup recursively empty. A later bounded read-only check found the five recorded PID/birth identities absent, both exact former cgroups absent, and the two exact jobs inactive with MainPID 0. It sent **0 signals**. Current absence does not prove that every historical descendant was reaped or fully charged.

## Qualification history remains intact

The selected coverage consists of 73 commands and 665 passing methods, with 4 ignored. The preserved first staged attempt had 31 passing methods and 1 failure because its deadline was exhausted before spawning. Its sole predeclared repeat used the same source, argv, cwd and deadline parameters and passed all 32. Across all declared ordinary qualification attempts the count remains **77 commands, 697 executed methods, 696 passed, 1 failed, and 4 ignored**. The original failure is not reclassified. Actual default settlement grace was 5 s; patching a module constant to 0.15 did not change the function's captured default. Backend's deliberate source probe exit 1 is an expected negative check, separately identified.

The two research passes here are separate from that 697-method count. GATES2, its original verification, the first-failure and unique-repeat manifests/raw streams/jobs, the declaration and wrapper, the strict owner import, and the unchanged original driver are retained. C8 caches were copied, not empty or independently clean-room rebuilt. The fixed upstream r0vm and retained guest were reused; no fresh guest compilation is claimed.

## Independent review and reading this bundle

A separate read-only review crosschecked 18 original JSON files and the two jobs\' four complete output streams, totaling 22 members / 291595 bytes. It found no contradictory record within that bounded scope, re-opened no Node database, rehashed no ELF, ran no new method or operation, and sent no signal. Its immutable 8-file bundle is retained under `raw/independent-review/`; `independent-review.json` is its exact summary. Numeric timestamps establish target termination then typed Unknown then the explicit owner request. The accepted cancellation outcome has no independent timestamp, and a new cancellation journal event is not separately proven.


Start with `summary.json`; `result.json`, `typed-failure.json`, `reorg.json`, and `cold.json` are the main exact raw JSON copies. `plan.json` had no selected deadline; `launch-declaration.json` selected it once and pins `config.json`. `started.json` binds the actual live prover; `terminal-observation.json` and `current-owned-readback.json` give their precise limited observation scopes. `gates.json` retains the complete gate binding.

`manifest.json` gives every original and copied path, size, and SHA256. `raw.tar.gz` contains the same allowlisted raw files; every member's bytes were independently checked against the copied files. Private SQLite databases, executables, inherited environment and checkpoint segment/receipt bodies are excluded.

C5/C6 actual records, the two older Pending operations, and C7 launch-Unknown are unchanged. C7 is never replayed or reclassified by this C8 experiment. This bundle establishes neither complete cryptographic/protocol qualification, winning W1 Node admission, production readiness, full proof performance, nor provider payment.
"""
with (DEST/"README.md").open("x") as f:f.write(readme);f.flush();os.fsync(f.fileno())
archive=DEST/"raw.tar.gz"
with archive.open("xb") as out:
    with gzip.GzipFile(filename="",mode="wb",fileobj=out,mtime=0) as gz:
        with tarfile.open(fileobj=gz,mode="w",format=tarfile.PAX_FORMAT) as tar:
            for e in sorted(entries,key=lambda x:x["relative"]):
                data=(DEST/e["relative"]).read_bytes();assert hashlib.sha256(data).hexdigest()==e["copied"]["sha256"]
                info=tarfile.TarInfo(e["relative"]);info.size=len(data);info.mode=0o644;info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=""
                tar.addfile(info,io.BytesIO(data))
expected={e["relative"]:e["copied"] for e in entries}
with tarfile.open(archive,"r:gz") as tar:
    members=tar.getmembers();assert len(members)==len(expected) and {m.name for m in members}==set(expected)
    for m in members:
        assert m.isfile();data=tar.extractfile(m).read();p=expected[m.name]
        assert len(data)==p["bytes"] and hashlib.sha256(data).hexdigest()==p["sha256"]
manifest={"schema":"TRNM-W1-C8-ALLOWLISTED-LIFECYCLE1","source":source,"operation":op,"allowlist":specpin,"packager":pin(Path(__file__).resolve()),"preflight":preflight,
    "raw_file_count":len(entries),"raw_total_bytes":sum(x["copied"]["bytes"] for x in entries),"raw_files":entries,"primary_files":primary,
    "summary":pin(DEST/"summary.json"),"README":pin(DEST/"README.md"),"raw_archive":pin(archive),"jobs":jobs,
    "archive_member_bytes_independently_verified":True,"all_raw_originals_rehashed_after_copy":True,"no_symlinks_or_hardlinks":True,
    "private_SQLite_ELF_inherited_environment_included":False,"source_targets_old_evidence_modified":False,"new_dispatches_by_packaging":0,"C7_unknown_replayed":False}
write(DEST/"manifest.json",manifest)
result={"schema":"TRNM-W1-C8-LIFECYCLE-PUBLICATION-RESULT1","source":source,"operation":op,"directory":str(DEST),"manifest":pin(DEST/"manifest.json"),"archive":pin(archive),"summary":pin(DEST/"summary.json"),"README":pin(DEST/"README.md"),"raw_file_count":len(entries),"raw_total_bytes":manifest["raw_total_bytes"],"primary":[pin(DEST/b) for a,b in s["primary"]],"deterministic_fixture_comparison":pin(comparepath),"research_passed":2,"new_complete_proofs":0,"positive_provider_payments":0,"M12_consumed":None,"M12_cap_retained":True,"source_or_old_evidence_modified":False,"commit_or_push_performed":False}
assert pin(SPEC)==specpin
write(TOOLS/"lifecycle-publication-result-01.json",result)
print(json.dumps(result),flush=True)
