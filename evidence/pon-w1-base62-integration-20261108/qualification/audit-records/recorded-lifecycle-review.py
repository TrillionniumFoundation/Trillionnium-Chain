#!/usr/bin/env python3
"""Independent, local-only consistency audit of already completed C6 lifecycle bytes."""
import hashlib,json,re,struct
from decimal import Decimal
from pathlib import Path
R=Path("/workspace/scratch/ec265b67753e/adversarial-c6-lifecycle-inputs")
O=Path("/workspace/scratch/ec265b67753e/adversarial-c6-lifecycle-review")
O.mkdir(exist_ok=False)
def raw(p):return (R/p).read_bytes()
def j(p):return json.loads(raw(p))
def sha(b):return hashlib.sha256(b).hexdigest()
def compact(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def save(n,v):(O/n).write_text(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
config=j("config.json");plan=j("plan.json");launch=j("launch-declaration.json")
start=j("run/owner-cancel-start/result.json")
terminal=j("run/owner-cancel-reconcile/result.json")
parent=j("run/owner-cancel-reconcile-command/result.json")
request=j("run/target-request.json")
failure=j("run/m12-terminal-failure-observed.json")
veto=j("run/owner-cancel-requested.json")
veto_out=j("run/owner-cancel-m12-outcome.json")
reorg=j("run/owner-timeout-reorg-result.json")
final=j("run/funded-owner-cancellation-result.json")
cold=j("independent-cold-reconcile/result.json")
coldcmd=j("independent-cold-reconcile/target-reconcile/result.json")
funded=j("run/native-funded-intent.json")
owner=j("run/owner-declaration.json")
proof=j("run/proof/intent.json")
decl=j("run/proof/controller/prove-batch-0000/declaration.json")
prepare=j("run/proof/controller/prepare-full-execution/result.json")
cancel=j("run/native-cancel-dispatch-intent.json")
submit=j("run/native-cancel-submission-observed.json")
extra=j("final-inputs.json")
C6="2bdd252aa6c300b7431b9ee897b254b7953cf562";TREE="ac3cb7171c429fa5e12e29ee16839fa6f49f1b81"
OP="8058cfa81675504da3f0593b8df7c51cb0b1f3fd6db1daa4d3f83172a6d4eacc"
assert (config["expected_commit"],config["expected_tree"])==(C6,TREE)
assert launch["source"]==plan["source"]=={"commit":C6,"tree":TREE}
assert launch["config"]["sha256"]==sha(raw("config.json"))
assert launch["plan"]["sha256"]==sha(raw("plan.json"))
assert launch["driver"]==plan["driver"] and launch["driver"]["sha256"]==sha(raw("external-driver-v4.py"))
clockkeys={"original_boot_id","original_deadline_ns","launch_observation","original_deadline_declaration"}
assert {k:v for k,v in config.items() if k not in clockkeys}==plan["config_without_clock"]
assert plan["deadline_selected"] is False and plan["winner_or_proof_started"] is False
assert plan["maximum_original_budget_ns"]==120_000_000_000
deadline=config["original_deadline_ns"];selected=launch["selected_monotonic_ns"]
assert deadline-selected==120_000_000_000 and deadline==launch["original_deadline_ns"]
assert config["original_deadline_declaration"]["plan_sha256"]==sha(raw("plan.json"))
assert config["original_deadline_declaration"]["deadline_can_be_renewed"] is False
assert config["provider_operation"]==plan["operation"]==OP
assert config["research_node_path"]==str(Path("/home/qian-qi/work/chain-w1-c6-timeout-reorg-20261108-ec265b-01")/"research-node")
assert owner["research_genesis_only"] is True and funded["research_genesis_only"] is True
assert owner["research_node_path"]==funded["research_node_path"]==config["research_node_path"]
assert owner["native_obligation_units"]==funded["native_obligation_units"]==1000
assert sha(raw("run/owner-cancel-start/result.json"))==veto["start_observation_sha256"]
assert sha(raw("run/target-request.json"))==start["target_request_raw_sha256"]
assert request["execution_source_commitment"]==start["config_sha256"]==terminal["config_sha256"]==sha(raw("config.json"))
normalized=dict(request);statement=normalized.pop("statement")
request_sha=sha(compact(request));normalized_sha=sha(compact(normalized))
assert request_sha==start["target_request_sha256"]==funded["target_request_sha256"]
assert normalized_sha==funded["normalized_request_digest"]
target=terminal["observation"]["target"];result=target["result"];job=target["worker"]
assert job==start["original_job"]==veto["original_job"]==result["provider_job"]==terminal["observation"]["original_job"]
assert job["request_sha256"]==request_sha and job["operation"]==OP and request["operation"]==OP
assert statement==failure["statement"]==veto["statement"]==funded["statement"]==reorg["statement"]==cold["original_statement"]
assert target["state"]=="terminal" and target["sticky_cancel"] is False and result["sticky_cancel"] is False
assert result["cause"]=="original-deadline" and result["exit_code"]==-9 and result["error"] is None
assert result["command_success"] is False and result["may_dispatch_again"] is False and target["may_dispatch_again"] is False
assert result["clock_domain"]==request["clock_domain"]
for value in (start["original_deadline_ns"],terminal["original_deadline_ns"],request["deadline_monotonic_ns"],target["original_deadline_monotonic_ns"],result["original_deadline_monotonic_ns"],parent["original_proof_deadline_ns"],veto["original_deadline_ns"],reorg["original_deadline_ns"],cold["original_deadline_ns"],final["original_deadline_ns"],proof["original_deadline_monotonic_ns"]):
    assert value==deadline
assert start["original_boot_id"]==terminal["original_boot_id"]==config["original_boot_id"]==job["identity"]["boot_id"]
assert prepare["observer_boot_id"]==decl["observer_boot_id"]==config["original_boot_id"]
for x in (prepare,decl):assert Decimal(str(x["effective_deadline_monotonic"]))*Decimal(1_000_000_000)==deadline
assert start["fresh_generation_started"] is True and start["owner_cancel_performed"] is False
assert start["trigger"]["stage"]=="prove-batch-0000"
assert start["trigger"]["stage_declaration_sha256"]==sha(raw("run/proof/controller/prove-batch-0000/declaration.json"))
assert parent["returncode"]==0 and parent["direct_child_waited"] is True and parent["timed_out"] is False
assert terminal["original_deadline_timeout_observed"] is True and terminal["cancellation_observed"] is False
assert terminal["owner_cancel_performed"] is False and terminal["resource_reservation_must_remain"] is True
assert failure["failure_kind"]=="Unknown" and failure["consumed"] is None and failure["cancellation_at_failure"] is None
assert failure["native_refund_authorized"] is False and failure["provider_payment_authorized"] is False
assert failure["m12_resource_cap_retained"] is True and failure["recorded_before_owner_veto"] is True
timeline=[
("deadline selected",selected),
("native winner",proof["winner"]["native_winner_monotonic_ns"]),
("live r0vm observed",start["trigger"]["observed_monotonic_ns"]),
("original deadline",deadline),
("original deadline observed",j("run/owner-timeout-deadline-observed.json")["observed_monotonic_ns"]),
("target terminal",result["finished_monotonic_ns"]),
("reconcile helper completed",terminal["completed_monotonic_ns"]),
("parent observed helper exit",parent["completed_monotonic_ns"]),
("M12 Unknown Failure",failure["recorded_monotonic_ns"]),
("explicit owner request",veto["requested_monotonic_ns"]),
("independent cold parent exit",coldcmd["completed_monotonic_ns"])]
assert all(a[1]<b[1] for a,b in zip(timeline,timeline[1:]))
runtime_digest=hashlib.sha256(b"TRNM-W1-OWNED-TERMINAL-RUNTIME3"+b"".join(hashlib.sha256(raw(p)).digest() for p in ("run/owner-cancel-reconcile/result.json","run/owner-cancel-reconcile-command/result.json","run/owner-cancel-start/result.json","run/target-request.json"))).digest()
jid=job["job_id"].encode()
binding=(b"TRNM-W1-OWNED-TERMINAL-3"+bytes.fromhex(statement)+bytes.fromhex(job["provider_namespace"])+bytes.fromhex(OP)+bytes.fromhex(normalized_sha)+struct.pack("<Q",len(jid))+jid+bytes.fromhex(sha(raw("config.json")))+runtime_digest+b"\x01"+bytes.fromhex(request["clock_domain"])+struct.pack("<Q",parent["completed_monotonic_ns"])+b"\x00")
typed_digest=sha(binding)
assert typed_digest==failure["evidence_digest"]
assert final["target_terminal_observation"]==terminal and final["native_reorg_roundtrip"]==reorg
assert cold["target_observation"]["retained_target_readback"]==target
assert cold["target_observation"]["actual_command"]==coldcmd
assert sha(raw("independent-cold-reconcile/target-reconcile/stdout.log"))==coldcmd["stdout_sha256"]
assert sha(raw("independent-cold-reconcile/target-reconcile/stderr.log"))==coldcmd["stderr_sha256"]
assert j("independent-cold-reconcile/target-reconcile/stdout.log")==target
same_cancel=reorg["before_reorg"]
assert same_cancel==reorg["original_cancel_restored"]==final["native_task"]==cold["native_task"]
assert reorg["cancel_removed"]==reorg["actual_cold_reopen"]
assert reorg["cancel_removed"]["funding_row"]["status"]=="reserved" and reorg["cancel_removed"]["funding_row"]["remaining"]==1000
assert same_cancel["funding_row"]["status"]=="cancelled" and same_cancel["funding_row"]["remaining"]==0
assert same_cancel["gross_owner_refund_units"]==1000 and same_cancel["net_account_delta_not_claimed"] is True
assert same_cancel["original_operation"]==cancel["operation"]==submit["operation"]
assert same_cancel["canonical_inclusion"]==submit["accepted_block"]==reorg["original_cancel_tip"]
assert cancel["generation_statement"]==statement
binary_infos=[json.loads(x) for x in extra["binary_info_raw"]]
assert binary_infos[0]["sha256"]==cancel["wire_sha256"]==reorg["original_cancel_wire_sha256"]
assert binary_infos[1]["sha256"]==cancel["packet_sha256"]==reorg["original_cancel_packet_sha256"]
assert reorg["m12_dispatch_begin"]==final["m12_cold_begin"]==cold["m12_begin"]=="Done"
assert reorg["m12_readback_unchanged"] is True and reorg["m12_original_resource_cap_retained"] is True
assert final["m12_original_resource_cap_retained"] is True and cold["original_resource_cap_retained"] is True
assert reorg["new_generation_dispatches"]==reorg["new_target_cancel_requests"]==reorg["new_native_cancel_transactions"]==0
assert cold["new_generation_dispatches"]==cold["target_cancel_requests_sent"]==cold["native_transactions_submitted"]==0
assert reorg["new_cancel_wire_signed"] is False and cold["can_authorize_payment"] is False
assert final["provider_payment_observed"] is False and final["node_positive"] is False
assert reorg["provider_balance_unchanged"] is True
assert final["new_complete_proofs"]==terminal["new_complete_proofs"]==start["new_complete_proofs"]==0
assert final["fresh_generation_attempts"]==1 and final["real_expensive_generation_started"] is True
assert final["target_cancel_command"]["target_cancel_request_sent"] is False
assert all(x["deadline_renewed"] is False for x in (final,cold,reorg))
assert result["resources"]["gpu_ns"] is None and result["resources"]["memory_peak_bytes"] is None
assert result["all_descendants_reaped"] is None and final["all_descendants_reaped"] is None
assert cold["target_process_scope_reconciled_by_this_reader"] is False
events=[json.loads(line) for line in raw("run/proof/controller/prove-batch-0000/stdout.log").splitlines()]
ident=[x["identity"] for x in events if x.get("stage")=="RAW_COMMITTED_SOURCE_VERIFIED"]
assert len(ident)==1 and (ident[0]["tested_commit"],ident[0]["tested_tree"])==(C6,TREE)
segments=[x["event"]["index"] for x in events if x.get("event",{}).get("stage")=="REAL_SEGMENT_PROVING_STARTED"]
assert set(segments)=={0,1} and len(segments)==2
assert proof["winner"]["node_admission"] is False and proof["winner"]["parent_eligibility_checked"] is False
jobs=[]
for row in extra["original_jobs"]:
    status=json.loads(row["status_raw"]);out=json.loads(row["output_raw"])
    assert status["state"]=="succeeded" and status["exit_code"]==0 and status["output_complete"] is True and status["output_durable"] is True and status["timed_out"] is False
    assert not out["stderr"]["text"] and re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",out["stdout"]["text"])==[("1","0","0")]
    jobs.append({"status":status,"stdout":out["stdout"]["text"],"stdout_sha256":sha(out["stdout"]["text"].encode()),"stderr_sha256":sha(out["stderr"]["text"].encode())})
old=json.loads(Path("/workspace/scratch/ec265b67753e/adversarial-c5-timeout-review.json").read_text())
old_cancel=next(x for x in old["findings"] if x["subject"]=="Same original native Cancel survives reorg and cold recovery")
assert OP!=old["operation"] and statement!=old["statement"]
assert binary_infos[0]["sha256"]==old_cancel["wire_sha256"] and binary_infos[1]["sha256"]==old_cancel["packet_sha256"]
assert same_cancel["original_operation"]==old_cancel["cancel_operation"]
source_checks=[]
prior=Path("/workspace/scratch/ec265b67753e/adversarial-m12-final-readback")
for rel in ["trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/terminal.rs","trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation/timeout.rs"]:
    b=(prior/rel).read_bytes()
    assert sha(b)==config["source_files"][rel]==start["source"]["source_files"][rel]==terminal["source"]["source_files"][rel]
    source_checks.append({"path":rel,"sha256":sha(b),"matches_prior_audited_source_and_actual_c6_config":True})
pins=[]
for f in j("snapshot.json")["files"]+extra["files"]:
    pins.append({"original_path":f["path"],"bytes":f["size"],"sha256":f["sha256"]})
pins.extend({"original_path":x["path"],"bytes":x["size"],"sha256":x["sha256"],"read_via":"independent file_info full SHA256"} for x in binary_infos)
review={"schema":"TRNM-W1-C6-LIFECYCLE-INDEPENDENT-READONLY-REVIEW1",
 "original_root":"/home/qian-qi/work/chain-w1-c6-timeout-reorg-20261108-ec265b-01",
 "source":{"commit":C6,"tree":TREE},"operation":OP,"statement":statement,"provider_job":job,
 "review_complete":True,"critical_counterevidence_found":False,
 "one_fresh_generation_attempt":True,"new_complete_proofs":0,
 "original_deadline_ns":deadline,"original_budget_ns":deadline-selected,
 "timeline":[{"event":name,"monotonic_ns":n,"seconds_after_selection":(n-selected)/1e9} for name,n in timeline],
 "terminal_snapshot_seconds_after_original_deadline":(result["finished_monotonic_ns"]-deadline)/1e9,
 "independent_digest_recomputation":{"runtime_evidence_digest":runtime_digest.hex(),"typed_terminal_evidence_digest":typed_digest,"normalized_request_sha256":normalized_sha,"full_canonical_request_sha256":request_sha},
 "findings":{"natural_deadline_precedes_unknown_failure_and_explicit_owner_veto":True,"target_cancel_request_sent":False,
  "unknown_resources_consumed":None,"full_original_resource_cap_retained":config["resource_cap"],
  "m12_dispatch_done_is_not_cap_release_or_settlement":True,"provider_payment_observed":False,"node_positive":False,
  "same_original_cancel_observation_restored_and_cold_exact":True,"cold_target_readback_exact":True,
  "cancel_removed_reserved_units":1000,"restored_cancel_remaining":0,"gross_research_principal_refund_units":1000,
  "net_account_delta_claimed":False,"owner_balance_after_cancel":reorg["owner_balance_after_cancel"],
  "owner_balance_while_cancel_removed":reorg["owner_balance_while_cancel_removed"],
  "provider_balance_unchanged_asserted_by_pinned_successful_owner":True,
  "new_dispatches_or_target_cancel_or_native_transactions_in_reorg_and_cold":0,
  "native_cancel_operation":same_cancel["original_operation"],"native_cancel_inclusion":same_cancel["canonical_inclusion"],
  "native_cancel_wire_sha256":binary_infos[0]["sha256"],"native_cancel_packet_sha256":binary_infos[1]["sha256"],
  "m12_cancel_accepted_observed":veto_out["accepted_observed"],"m12_cancel_journal_event_new":veto_out["journal_event_new"],"m12_cancel_new_event_proven":veto_out["new_event_proven"],
  "real_segment_proving_started_indices":segments},
 "distinct_scope":{"new_generation_operation_and_statement":True,"new_research_node_path":config["research_node_path"],
  "executed_driver_requires_new_absent_out_target_and_node":True,"same_deterministic_native_cancel_bytes_as_c5":True,
  "same_native_cancel_id_as_c5":True,"same_new_node_or_operation_as_c5":False,"globally_new_chain_funds_claimed":False,"cumulative_2000_units_claimed":False},
 "source_adapter_readback":source_checks,"original_jobs":jobs,"input_artifact_pins":pins,
 "limits":["Read-only consistency review; no new experiments, Node opens, submissions, source edits or reexecution of balances.",
  "One bounded C6 research operation. It does not settle the original two full-proof operations.",
  "Unknown GPU time, memory peak and all historical descendants wait/reap; empty cgroup is not complete historical accounting.",
  "Original proof deadline remains fixed. Target/cleanup/refund/reorg/cold terminal observations occur after it and are not an in-budget successful proof.",
  "Balance equality and restoration rely on successful assertions in exact pinned source; reviewer did not independently reopen/replay Node.",
  "Separate deterministic research nodes can produce the same NativeTask Cancel ID/wire/packet and balances. They are not globally new funds and refunds are not cumulative across C5/C6.",
  "Actual expensive generation and NativeTask maintenance/Cancel admission do not constitute winning W1 admission; native winner records parent_eligibility_checked=false and node_admission=false.",
  "External driver SHA is bound in plan/launch; the external driver is not itself a member of the C6 Git tree.",
  "M12 cancellation is accepted-observed, with journal_event_new=null and new_event_proven=false; no stronger event-newness claim is made."],
 "qualification":{"bounded_lifecycle_observed":True,"resource_settlement_complete":False,"positive_provider_payment_qualified":False,"winning_node_admission_qualified":False,"crypto_protocol_security_qualified":False,"production_qualified":False}}
save("summary.json",review)
save("original-job-readbacks.json",jobs)
save("input-artifact-index.json",pins)
print(json.dumps({"out":str(O),"summary_sha256":sha((O/"summary.json").read_bytes()),"typed_digest":typed_digest,"runtime_digest":runtime_digest.hex(),"original_deadline_ns":deadline,"input_pins":len(pins),"main_and_cold_passed":True,"reviewer_reran_tests":False},ensure_ascii=False))

