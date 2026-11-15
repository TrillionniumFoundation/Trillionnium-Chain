from pathlib import Path,PurePosixPath
from datetime import datetime,timezone
import hashlib,importlib,json,sys,traceback
sys.dont_write_bytecode=True
R=Path("/home/qian-qi/throughput-final-ci-observation-20261107");P=R/"pinned-readers-819309fd-v1"
for x in (P/"scripts",P/"scripts/ci",P/"formal/pon-nakamoto-v1"):sys.path.insert(0,str(x))
from check_cross_arch_cost import ARCHITECTURES,COST_CAMPAIGN_TIMEOUT_SECONDS
D=Path(sys.argv[1]);stage=json.loads((D/"readback-stage1.json").read_bytes())
def req(v,m):
 if not v:raise ValueError(m)
def canon(v):return json.dumps(v,sort_keys=True,separators=(",",":"))
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
 return h.hexdigest()
out={"schema":"trnm-final819-w1-pure-and-native-record-readback-v2","artifact_id":stage["artifact_id"],"family":stage.get("family"),"arch":stage.get("arch"),"source_kind":stage.get("source_kind"),"tested_commit":stage.get("tested_commit"),"errors":[],"manifests":[],"complete_component_readback":False,"native_invocations":0,"source_or_host_recreated":False,"business_qualification":False}
try:
 req(stage["archive_authenticated"] and stage["source_bound"] and stage["manifest_hashes_complete"] and not stage["errors"],"authenticated stage1 required")
 inventory={x["name"]:x for x in stage["archive_inventory"]};spec=ARCHITECTURES[stage["arch"]]
 for item in stage["manifests"]:
  path=Path(item["path"]);req(sha(path)==item["manifest_sha256"],"retained manifest changed")
  m=json.loads(path.read_bytes());schema=m["schema"];rank=schema=="pon-w1-rank-batch-execution-v5"
  if rank:module="pon_w1_rank_batch_reader_v5";binary="pon_w1_rank_batch_v5"
  elif schema in ("trnm-w1-false-trace-reuse-execution-v1","trnm-w1-full-limb-reuse-execution-v1"):module="pon_w1_false_trace_reuse_reader_v1";binary="pon_w1_false_trace_reuse_v1"
  elif schema in ("trnm-w1-legal-strategy-execution-v1","trnm-w1-legal-strategy-execution-v2","trnm-w1-legal-strategy-execution-v3"):
   version=schema.rsplit("-",1)[-1];module="pon_w1_legal_strategy_reader_"+version;binary="pon_w1_legal_strategy_v3" if version=="v3" else "pon_w1_legal_strategy_v1"
  else:raise ValueError("unknown original W1 manifest schema")
  reader=importlib.import_module(module);family=stage["family"]
  req(m.get("expected_commit",m.get("expected_source_commit"))==stage["tested_commit"],"native expected source")
  before=m["source_before"];req(before==m["source_after"] and before["commit"]==stage["tested_commit"] and before["tree"]==stage["source_before"]["tested_tree"] and before["tracked_worktree_verified"] is True and before["source_state"]=="committed-clean","native complete committed source")
  req(before["tracked_entries"]==stage["source_before"]["tracked_entries"] and before["tracked_bytes"]==stage["source_before"]["tracked_bytes"],"native/source receipt bytes")
  req(m["architecture"]==stage["arch"] and m["target"]==spec["target"],"native architecture")
  req(m["build_environment_overrides"]=={} and m["cargo_configuration_before"]==m["cargo_configuration_after"] and m["cargo_configuration_before"]["violations"]==[],"original build configuration")
  if not rank:
   req(m["execution_context"]=="github-hosted" and m["result"]=="PASS" and m["default_release_configuration_checked"] is True and m["source_changed"] is False,"original hosted complete result")
   ctx=m["runner_context"];req(ctx["GITHUB_RUN_ID"]=="42402618462" and ctx["GITHUB_RUN_ATTEMPT"]=="1" and ctx["GITHUB_EVENT_NAME"]=="push" and ctx["GITHUB_REPOSITORY"]=="TrillionniumFoundation/Trillionnium-Chain" and ctx["RUNNER_ARCH"]==spec["runner_arch"] and ctx["TRNM_COST_RUNNER_LABEL"]==spec["runner"],"actual hosted campaign context")
  else:req(m["execution_context"]=="local-component-research" and m["original_public_service_resource_contract_used"] is False and m["result"]=="COMPLETE_COMPONENT_OBSERVATION","rank component scope")
  req(all(m.get(k) is v for k,v in reader.FALSE_FLAGS.items()),"original false scope flags")
  bname=str(PurePosixPath(item["member"]).parent/binary);b=inventory[bname]
  req(b["elf_machine"]==spec["elf_machine"] and b["sha256"]==m["binary_sha256_before"]==m["binary_sha256_after"]==m["retained_binary_sha256_before"]==m["retained_binary_sha256_after"],"retained actual binary identity")
  observations=m["observations"];req(all(x["exit_code"]==0 and x["timed_out"] is False for x in observations),"all original process terminals")
  if family=="false-trace":
   planned=["campaign.stdout"];expected_selector="--false-trace-full-limb-v1" if "full-limb" in schema else reader.SELECTOR
  elif rank:
   grid=reader.grid();req(canon(m["planned_shards"])==canon(grid) and len(grid)==66 and len(m["shards"])==66,"original rank66 grid");planned=[f"campaign-{i:02d}.stdout" for i in range(66)];expected_selector=reader.SELECTOR
  else:
   grid=[{"class":name,"target_index":ti,"reuse_winners":h} for name in reader.CLASSES for ti in range(len(reader.TARGETS)) for h in reader.HORIZONS]
   req(len(grid)==30 and m["planned_shards"]==grid and len(m["shards"])==30,"original legal30 grid");planned=[f"campaign-{i:02d}.stdout" for i in range(30)];expected_selector=reader.SELECTOR
  native=[x for x in observations if x["stdout"] in planned]
  req(len(native)==len(planned) and {x["stdout"] for x in native}==set(planned) and len(observations)==len(planned)+(3 if rank else 4),"full original process denominator")
  paths=[];native_rows=[]
  for i,name in enumerate(planned):
   obs=next(x for x in native if x["stdout"]==name);cmd=obs["command"]
   req(Path(cmd[0]).name==binary and cmd[1]==expected_selector and obs["timeout_seconds"]==COST_CAMPAIGN_TIMEOUT_SECONDS,"original native command/budget")
   if family!="false-trace":
    shard=m["shards"][i];req(shard["observation"]==obs,"shard captured process binding")
    config=shard["configuration"]
    if rank:
     n,t,h=grid[i];req(config=={"class":n,"target_index":t,"horizon":h} and shard["result"]=="COMPLETE_COMPONENT_OBSERVATION","rank shard configuration")
    else:
     req(config==grid[i] and shard["result"]=="PASS","legal shard configuration");n,t,h=config["class"],config["target_index"],config["reuse_winners"]
    req(cmd[2:]==["--class",n,"--target-index",str(t),"--reuse-winners",str(h)],"complete shard command")
   pp=path.parent/name;member=str(PurePosixPath(item["member"]).parent/name)
   req(pp.is_file() and not pp.is_symlink() and sha(pp)==inventory[member]["sha256"],"original native stdout digest")
   paths.append(pp);native_rows.append({k:obs.get(k) for k in ("command","exit_code","process_exit_code","timed_out","elapsed_ns","timeout_seconds","stdout","stderr","wait4_cpu_ns","wait4_maxrss_kib")})
  if rank:
   req(all(o.get("executed") is True and o.get("process_exit_code")==0 and o.get("source_before")==before and o.get("source_after")==before for o in observations),"rank every original native process source/exit")
  if family=="false-trace":analyzed=reader.analyze(paths[0],full_limb="full-limb" in schema)
  elif rank:analyzed=reader.campaign([reader.analyze(p) for p in paths])
  else:analyzed=reader.analyze(paths)
  req(canon(analyzed)==canon(m["reader"]),"independent pure reader differs from original retained result")
  req(not analyzed.get("semantic_alerts"),"original reader semantic alert")
  result_path=D/("independent-v2-"+path.parent.name+".json")
  with result_path.open("x") as f:json.dump(analyzed,f,indent=2);f.write("\n")
  out["manifests"].append({"schema":schema,"path":str(path),"reader_module":module,"original_result":m["result"],"native_commands":native_rows,"complete_native_command_denominator":len(planned),"original_total_processes":len(observations),"retained_binary_sha256":b["sha256"],"retained_binary_elf_machine":b["elf_machine"],"independent_reader_equal":True,"reader_result_path":str(result_path),"reader_result_sha256":sha(result_path),"reader_scope_flags":{k:analyzed.get(k) for k in reader.FALSE_FLAGS},"qualification_status":analyzed.get("qualification_status"),"policy_sample_count_satisfied":analyzed.get("policy_sample_count_satisfied")})
 out["native_invocations"]=sum(x["complete_native_command_denominator"] for x in out["manifests"])
 out["complete_component_readback"]=len(out["manifests"])==len(stage["manifests"])
except Exception as e:
 out["errors"].append(type(e).__name__+": "+str(e));traceback.print_exc()
out["finished_utc"]=datetime.now(timezone.utc).isoformat()
with (D/"readback-pure-v2.json").open("x") as f:json.dump(out,f,indent=2);f.write("\n")
print(json.dumps({"artifact_id":out["artifact_id"],"complete_component_readback":out["complete_component_readback"],"errors":out["errors"],"manifest_count":len(out["manifests"]),"original_native_commands":sum(x["complete_native_command_denominator"] for x in out["manifests"]),"business_qualification":False}))
raise SystemExit(0 if out["complete_component_readback"] else 1)
