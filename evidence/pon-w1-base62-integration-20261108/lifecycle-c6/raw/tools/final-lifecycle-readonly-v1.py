#!/usr/bin/env python3
"""Final readonly C6 lifecycle/source audit. Never opens or changes research databases."""
import hashlib,json,os,subprocess,time
from pathlib import Path
ROOT=Path("/home/qian-qi/work/chain-w1-c6-timeout-reorg-20261108-ec265b-01")
REPO=Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
HEAD="2bdd252aa6c300b7431b9ee897b254b7953cf562"
TREE="ac3cb7171c429fa5e12e29ee16839fa6f49f1b81"
def pin(p):
    assert p.is_file() and not p.is_symlink()
    with p.open("rb") as f:
        before=os.fstat(f.fileno());data=f.read();after=os.fstat(f.fileno())
    assert (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    return {"path":str(p),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
def write(p,v):
    with p.open("x") as f:json.dump(v,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def read(rel):return json.loads((ROOT/rel).read_text())
argv=["/usr/bin/python3.12","-B","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",HEAD,"--output",str(ROOT/"runtime-source-after.json")]
started=time.monotonic_ns()
with (ROOT/"runtime-source-after.stdout").open("xb") as so,(ROOT/"runtime-source-after.stderr").open("xb") as se:
    result=subprocess.run(argv,cwd=REPO,stdout=so,stderr=se,env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1"},check=False)
row={"argv":argv,"cwd":str(REPO),"started_monotonic_ns":started,"finished_monotonic_ns":time.monotonic_ns(),"exit":result.returncode,"stdout":pin(ROOT/"runtime-source-after.stdout"),"stderr":pin(ROOT/"runtime-source-after.stderr"),"tests_executed":False}
write(ROOT/"runtime-source-after.command.json",row);assert result.returncode==0
guard=read("runtime-source-after.json")
assert guard["tested_commit"]==HEAD and guard["tested_tree"]==TREE and guard["tracked_worktree_verified"] is True
assert guard["tests_executed_by_identity_check"] is False
main=read("run/funded-owner-cancellation-result.json")
cold=read("independent-cold-reconcile/result.json")
reorg=read("run/owner-timeout-reorg-result.json")
failure=read("run/m12-terminal-failure-observed.json")
veto=read("run/owner-cancel-requested.json")
plan=read("plan.json");config=read("config.json");live=read("run/owner-cancel-start/result.json")
target=main["target_terminal_observation"]["observation"]["target"]
assert target==cold["target_observation"]["retained_target_readback"]
assert main["native_task"]==cold["native_task"]==reorg["before_reorg"]==reorg["original_cancel_restored"]
assert reorg["cancel_removed"]==reorg["actual_cold_reopen"]
assert reorg["cancel_removed"]["funding_row"]["status"]=="reserved" and reorg["cancel_removed"]["funding_row"]["remaining"]==1000 and reorg["cancel_removed"]["refund_claim"] is False
assert main["native_task"]["funding_row"]["status"]=="cancelled" and main["native_task"]["gross_owner_refund_units"]==1000
assert pin(ROOT/"run/native-cancel-wire.bin")["sha256"]==reorg["original_cancel_wire_sha256"]
assert pin(ROOT/"run/native-cancel-packet.bin")["sha256"]==reorg["original_cancel_packet_sha256"]
assert main["original_provider_operation"]==cold["original_operation"]==failure["operation"]==plan["operation"]==config["provider_operation"]
assert main["original_deadline_ns"]==cold["original_deadline_ns"]==failure.get("original_deadline_ns",config["original_deadline_ns"])==target["original_deadline_monotonic_ns"]==config["original_deadline_ns"]
assert failure["failure_kind"]=="Unknown" and failure["consumed"] is None and failure["cancellation_at_failure"] is None
assert failure["recorded_monotonic_ns"]<veto["requested_monotonic_ns"]
assert failure["m12_resource_cap_retained"] is True and main["m12_original_resource_cap_retained"] is True and cold["original_resource_cap_retained"] is True
assert not main["provider_payment_observed"] and not failure["provider_payment_authorized"] and not cold["can_authorize_payment"]
assert main["fresh_generation_attempts"]==1 and main["new_complete_proofs"]==0
assert main["all_descendants_reaped"] is None and target["result"]["all_descendants_reaped"] is None
assert target["result"]["cause"]=="original-deadline" and target["result"]["sticky_cancel"] is False and target["result"]["exit_code"]==-9
assert target["result"]["resources"]["gpu_ns"] is None
assert main["deadline_renewed"] is False and cold["deadline_renewed"] is False
assert cold["m12_begin"]=="Done" and cold["new_generation_dispatches"]==cold["target_cancel_requests_sent"]==cold["native_transactions_submitted"]==0
boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip();assert boot==config["original_boot_id"]
known=[]
for pid,birth in [(3666406,119922032),(3666427,119922076),(3666955,119923218),(3666984,119923351),(3668215,119925002),(3668546,119925536)]:
    try:
        fields=(Path("/proc")/str(pid)/"stat").read_text().rsplit(") ",1)[1].split()
        now={"pid":pid,"present":True,"start_ticks":int(fields[19]),"state":fields[0],"expected_start_ticks":birth,"original_identity_present":int(fields[19])==birth}
    except FileNotFoundError:
        now={"pid":pid,"present":False,"expected_start_ticks":birth,"original_identity_present":False}
    known.append(now)
assert all(not p["original_identity_present"] for p in known)
child_group=Path(live["trigger"]["child_cgroup"]["path"])
parent_group=Path(live["parent_cgroup"]["path"])
assert not child_group.exists() and not parent_group.exists()
receipt={"schema":"TRNM-W1-C6-LIFECYCLE-FINAL-READONLY1","source":{"commit":HEAD,"tree":TREE},"source_after":pin(ROOT/"runtime-source-after.json"),"source_check_command":pin(ROOT/"runtime-source-after.command.json"),
"operation":plan["operation"],"statement":failure["statement"],"original_deadline_ns":config["original_deadline_ns"],"target_finished_monotonic_ns":target["result"]["finished_monotonic_ns"],"deadline_to_target_terminal_ns":target["result"]["finished_monotonic_ns"]-config["original_deadline_ns"],
"main_result":pin(ROOT/"run/funded-owner-cancellation-result.json"),"failure_record":pin(ROOT/"run/m12-terminal-failure-observed.json"),"reorg_result":pin(ROOT/"run/owner-timeout-reorg-result.json"),"cold_result":pin(ROOT/"independent-cold-reconcile/result.json"),
"hot_target_equals_cold_target":True,"cancel_before_equals_restore_equals_final_equals_cold":True,"removed_cancel_equals_actual_cold_reopen":True,
"typed_failure_precedes_owner_veto":True,"failure_recorded_monotonic_ns":failure["recorded_monotonic_ns"],"owner_veto_requested_monotonic_ns":veto["requested_monotonic_ns"],
"principal_refund_units":1000,"provider_payment":False,"resources":"UNKNOWN","consumed":None,"m12_resource_cap_retained":True,"m12_dispatch_lifecycle":"Done",
"original_boot_id":boot,"current_original_process_identity_observations":known,"current_parent_cgroup_present":parent_group.exists(),"current_child_cgroup_present":child_group.exists(),"signals_sent":0,
"all_historical_child_births_captured":False,"all_historical_descendants_wait_reaped":None,
"fresh_generation_attempts":1,"new_complete_proofs":0,"new_generation_dispatches_by_this_readback":0,"native_transactions_submitted_by_this_readback":0,"databases_opened_by_this_readback":False,
"fixture_scope":"new independent research Node directory and fresh provider/M12 operation; deterministic NativeTask cancel ID/wire/packet equal prior C5 fixture; not new global-chain funds and refunds must not be added across fixtures",
"readback_script":pin(Path(__file__).resolve())}
write(ROOT/"final-readonly-verification.json",receipt)
print(json.dumps({"final_readonly_verification":pin(ROOT/"final-readonly-verification.json"),"source_after":pin(ROOT/"runtime-source-after.json"),"deadline_to_target_terminal_ns":receipt["deadline_to_target_terminal_ns"],"no_historical_reap_claim":True}),flush=True)
