import datetime,gzip,hashlib,json,pathlib,re,zipfile
P=pathlib.Path(__file__).resolve().parent
HEAD="b28098c092dca72165c0d26054fce95a8636d777"
MERGE="49b40ecff37acac0b00a23b28a69d65df98308d1"
TREE="7c39ccecd82f05a3d68857efdef9e8c67bdf8069"
def sha(b):return hashlib.sha256(b).hexdigest()
known=json.loads((P/"gate-map.json").read_text())["public_host_fixtures"]
expected={(x["target"],x["selector"]) for x in known}
arch=("architecture_delivery_compare","signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract")
evaluation=("evaluation_sync_observation","actual_public_full_sync_query_partial_refusals_reorg_and_retirement")
lanes=[];records=[]
for lane,job,aid,name,source in [
 ("head",126173966811,13271043247,"b280-runtime-head-13271043247.zip",HEAD),
 ("actual-merge",126173967101,13272091585,"b280-runtime-merge-13272091585.zip",MERGE)]:
 data=(P/name).read_bytes();receipt=json.loads((P/(str(aid)+"-download-receipt.json")).read_text());meta=receipt["metadata"]
 assert sha(data)==meta["digest"].split(":",1)[1]==receipt["actual_sha256"] and len(data)==meta["size_in_bytes"]==receipt["actual_bytes"]
 with zipfile.ZipFile(P/name) as z:
  shard=json.loads(z.read("rust-shard.json"))
  assert shard["before"]==shard["after"]
  assert shard["before"]["tested_commit"]==source and shard["before"]["candidate"]==HEAD and shard["before"]["tested_tree"]==TREE
  assert shard["status"]=="failed" and shard["exit_code"]==101
  command=z.read("rust-shard.sh")
  assert sha(command)==shard["command_sha256"]
  assert b"cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features" in command
  wanted=["rust-shard.json","rust-shard.sh","workspace-tests.log"]
  observed=[]
  for target,selector in [arch,evaluation]:
   base="public-fixtures/"+target+"/"+selector
   m=json.loads(z.read(base+"/manifest.json"));pr=json.loads(z.read(base+"/preparation.json"))
   c=json.loads(z.read(base+"-host/controller-result.json"));launch=json.loads(z.read(base+"/launch.json"))
   inside=json.loads(z.read(base+"-host/inside-before.json"));outside=json.loads(z.read(base+"-host/outside-after.json"))
   native=z.read(base+"/native.log");txt=native.decode();process=m["process"]
   assert sha(native)==m["log"]["sha256"] and len(native)==m["log"]["size_bytes"]
   assert m["source_before"]==m["source_after"]==pr["source_before"]==pr["source_after"]
   assert m["source_before"]["commit"]==source and m["source_before"]["tree"]==TREE
   assert pr["source_before"]["tracked_source_identity"]==shard["before"]
   assert m["binary_before"]==m["binary_after"]==pr["binary"]
   assert m["cli_binary_before"]==m["cli_binary_after"]==pr["cli_binary"]
   assert m["preparation_sha256"]==sha(z.read(base+"/preparation.json"))
   assert process["command"]==[m["binary_before"]["path"],selector,"--exact","--show-output","--test-threads=1"]
   assert process["reaped"] and process["started"] and process["supervisors_bound"] and not process["timed_out"] and process["cleanup_errors"]==[] and process["failure"] is None
   assert c["failure"] is None and c["final_host_errors"]==[] and c["cleanup"]=="already-collected"
   assert inside["limits"]==outside["limits"]=={"cpu.max":"25000 100000","cpu.max.burst":"0","memory.max":"2147483648","memory.swap.max":"0","pids.max":"256"}
   assert outside["counters"]["cgroup.events"].splitlines()[0]=="populated 0" and outside["counters"]["pids.current"]=="0"
   errors=re.findall(r'^called .*$|^thread .*panicked at.*$',txt,re.M)
   result=re.findall(r"^test result:.*$",txt,re.M)
   if (target,selector)==arch:
    assert process["exit_code"]==0 and m["passed"] and launch["passed"] and c["passed"]
    assert m["named_execution"]["test"]==selector and m["named_execution"]["result"]=="PASS" and m["named_execution"]["executed_tests"]==1
    binding=c["preparation_execution_binding"]
    assert binding["source_commit"]==source and binding["binary_sha256"]==m["binary_before"]["sha256"] and binding["manifest_sha256"]==sha(z.read(base+"/manifest.json"))
    report=z.read(base+"/native/report.json")
    assert len(report)==m["report_file"]["size_bytes"] and sha(report)==m["report_file"]["sha256"]==binding["report_sha256"]
    assert binding["samples"]==18 and binding["business_reader_passed"] and binding["business_reader_failure"] is None and binding["performance_acceptance"] is False
   else:
    assert process["exit_code"]==101 and not m["passed"] and not launch["passed"] and not c["passed"]
    assert any("evaluation_sync_observation.rs:551:46" in x for x in errors)
    assert any('code: Some(OwnerReorgTerminationCpuRequired), kind: DependencyUnavailable, message: "OWNER_REORG_TERMINATION_CPU_REQUIRED"' in x for x in errors)
    binding=None
   wanted += [base+"/"+n for n in ["execution-start.json","launch.json","manifest.json","native.log","preparation.json"]]
   wanted += [base+"-host/"+n for n in ["child-result.json","controller-result.json","inside-before.json","inside-after.json","outside-after.json","systemd-run.log"]]
   observed.append({"target":target,"selector":selector,"passed":m["passed"],"manifest_sha256":sha(z.read(base+"/manifest.json")),"process":process,"native_result_lines":result,"native_panic_lines":errors,"source_before_after":m["source_before"],"binary":m["binary_before"],"cli_binary":m["cli_binary_before"],"log_bytes":len(native),"log_sha256":sha(native),"preparation_sha256":m["preparation_sha256"],"host_failure":c["failure"],"final_host_errors":c["final_host_errors"],"host_cleanup":c["cleanup"],"parent_reused":c["parent_reused"],"outside_after_counters":outside["counters"],"original_limits":outside["limits"],"launch_passed":launch["passed"],"controller_passed":c["passed"],"preparation_execution_binding":binding,"native_execution_authenticated":m["native_execution_authenticated"],"runtime_limits_or_deadlines_changed":m["runtime_limits_or_deadlines_changed"]})
  observed_pairs={(d["target"],d["selector"]) for d in observed}
  actual_pairs=set()
  for n in z.namelist():
   if n.startswith("public-fixtures/") and n.endswith("/manifest.json"):
    d=json.loads(z.read(n));actual_pairs.add((d["target"],d["selector"]))
  assert actual_pairs==observed_pairs and observed_pairs<=expected
  for n in wanted:
   b=z.read(n);records.append({"artifact_id":aid,"lane":lane,"member":n,"bytes":len(b),"sha256":sha(b),"text":b.decode()})
  lanes.append({"lane":lane,"job_id":job,"run_id":41708487030,"attempt":1,"artifact_id":aid,"artifact_file":name,"artifact_bytes":len(data),"artifact_sha256":sha(data),"artifact_metadata":meta,"rust_shard":shard,"shard_command_sha256_verified":sha(command),"whole_workspace_passed":False,"public_fixture_observations":observed,"public_fixture_denominator":9,"public_fixture_passed":1,"public_fixture_failed":1,"public_fixture_unobserved":[{"target":t,"selector":s} for t,s in sorted(expected-observed_pairs)]})
out={"schema":"b280-original-runtime-host-two-lane-terminal-readback-v1","observed_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"candidate":HEAD,"actual_merge":MERGE,"expected_tree":TREE,"lanes":lanes,"scope":"Two original workspace commands stopped at the same actual evaluation fixture CPU-owner refusal. The architecture fixture is one unique successful named test executed in two source lanes, with 18 samples per lane. Later seven Host selectors were unobserved in each lane.","claims":{"all_nine_host_selectors_pass":False,"whole_workspace_pass":False,"service_performance_acceptance_pass":False,"later_source_qualified":False,"release_or_activation_authorized":False},"reader":{"file":pathlib.Path(__file__).name,"sha256":sha(pathlib.Path(__file__).read_bytes()),"executes_native_code":False}}
dest=P/"runtime-two-lane-terminal-readback.json";dest.write_text(json.dumps(out,indent=2)+"\n")
bundle={"schema":"b280-runtime-two-lane-selected-original-records-v1","candidate":HEAD,"actual_merge":MERGE,"record_count":len(records),"scope":"Complete original workspace logs and selected exact original command/native/Host/source receipts from both failed runtime lanes. Excludes generated database/key state and full architecture-report bytes; their hashes and exact reader receipts are retained.","records":records}
packed=gzip.compress((json.dumps(bundle,indent=2)+"\n").encode(),mtime=0);bf=P/"runtime-two-lane-selected-original-records.json.gz";bf.write_bytes(packed)
print(json.dumps({"readback":{"file":str(dest),"bytes":dest.stat().st_size,"sha256":sha(dest.read_bytes())},"original_records":{"file":str(bf),"bytes":len(packed),"sha256":sha(packed),"record_count":len(records)},"lanes":[{"lane":d["lane"],"observed":[{k:f[k] for k in ["target","selector","passed","native_result_lines","native_panic_lines"]} for f in d["public_fixture_observations"]],"unobserved":len(d["public_fixture_unobserved"])} for d in lanes]},indent=2))

