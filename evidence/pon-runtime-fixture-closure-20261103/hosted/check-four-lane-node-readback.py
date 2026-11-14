import datetime,hashlib,json,pathlib,re,zipfile
P=pathlib.Path(__file__).resolve().parent
ROOT=P.parents[1]
HEAD="b28098c092dca72165c0d26054fce95a8636d777"
MERGE="49b40ecff37acac0b00a23b28a69d65df98308d1"
BASE="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
TREE="7c39ccecd82f05a3d68857efdef9e8c67bdf8069"
def digest(b):return hashlib.sha256(b).hexdigest()
metadata=json.loads((P/"20261103T2117-artifact-metadata.json").read_text())
metas={a["id"]:a for a in metadata["pq"]["artifacts"]}
plan_path=ROOT/"next-validation/full-node-b280-j1/plan.json"
plan=json.loads(plan_path.read_text())
registered=plan["registered"]; ignored_original=plan["original_ignored"]
assert len(registered)==len(set(registered))==971
assert len(ignored_original)==len(set(ignored_original))==23
lanes=[
("arm64-head",126170051709,13269328356,"b280-pq-arm-head-full-13269328356.zip",HEAD,"head","ARM64"),
("x64-head",126170052598,13269873705,"b280-pq-x64-head-full-13269873705.zip",HEAD,"head","X64"),
("x64-actual-merge",126170052239,13269449017,"b280-pq-x64-merge-full-13269449017.zip",MERGE,"prospective-merge","X64"),
("arm64-actual-merge",126170052621,13270947933,"b280-pq-arm-merge-full-13270947933.zip",MERGE,"prospective-merge","ARM64")]
results=[];common_successes=None;common_ignored=None
for label,job,aid,name,commit,kind,arch in lanes:
 raw=(P/name).read_bytes(); meta=metas[aid]
 assert digest(raw)==meta["digest"].split(":",1)[1] and len(raw)==meta["size_in_bytes"]
 assert meta["workflow_run"]["head_sha"]==HEAD and meta["workflow_run"]["id"]==41708487004
 with zipfile.ZipFile(P/name) as z:
  names=z.namelist();assert len(names)==len(set(names))
  source=json.loads(z.read("source.json"))
  assert source["tested_commit"]==commit and source["candidate"]==HEAD and source["kind"]==kind and source["tested_tree"]==TREE
  assert source["tracked_worktree_verified"] and source["tracked_entries"]==7563 and source["tracked_bytes"]==872904508
  if kind=="prospective-merge":assert source["base"]==BASE and source["prospective_merge"]==MERGE
  cmds=[]
  for n in names:
   if not n.endswith(".json"):continue
   d=json.loads(z.read(n))
   if not isinstance(d,dict) or d.get("schema")!="trnm-pq-native-command-v1":continue
   b=z.read(d["log_file"])
   assert len(b)==d["log_bytes"] and digest(b)==d["log_sha256"],n
   assert d["before"]==d["after"]==source and d["exit_code"]==0 and d["status"]=="command_succeeded",n
   assert d["environment"]["GITHUB_RUN_ID"]=="41708487004" and d["environment"]["GITHUB_RUN_ATTEMPT"]=="1",n
   cmds.append({"record":n,"argv":d["argv"],"exit_code":d["exit_code"],"log_file":d["log_file"],"log_bytes":d["log_bytes"],"log_sha256":d["log_sha256"],"elapsed_ns":d["elapsed_ns"],"source_before_after_equal":True})
  node=json.loads(z.read("node-lib.json"));log=z.read("node-lib.log").decode()
  assert node["environment"]["RUNNER_ARCH"]==arch
  assert node["argv"]==["cargo","+1.95.0","test","--locked","--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node","--lib","--all-features","--","--show-output","--test-threads=1"]
  starts=re.findall(r"^running (\d+) tests?$",log,re.M);assert starts and starts[0]=="971"
  summaries=re.findall(r"^test result: (?:ok|FAILED)\..*$",log,re.M)
  terminal=summaries[-1]
  m=re.fullmatch(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s",terminal);assert m
  counts=tuple(map(int,m.groups()[:5]));assert counts==(948,0,23,0,0)
  final_success_section=log.rsplit("\nsuccesses:\n",1)[1].split("\ntest result:",1)[0]
  success=[line.strip() for line in final_success_section.splitlines() if line.strip()]
  assert len(success)==len(set(success))==948
  ignored=re.findall(r"^test (.+?) \.\.\. ignored(?:, (.*))?$",log,re.M);ignored_names=[n for n,reason in ignored]
  assert len(ignored_names)==len(set(ignored_names))==23
  assert set(success).isdisjoint(ignored_names)
  assert set(ignored_names)==set(ignored_original)
  assert set(success)|set(ignored_names)==set(registered)
  if common_successes is None:common_successes=sorted(success);common_ignored=sorted(ignored)
  else:assert sorted(success)==common_successes and sorted(ignored)==common_ignored
  original43=[]
  for line in z.read("required-tests.tsv").decode().splitlines():
   key,test=line.split("\t");e=json.loads(z.read(key+"-execution.json"))
   assert e["result"]=="PASS" and e["executed_tests"]==1 and e["test"]==test and test in success
   original43.append({"id":key,"test":test,"executed_tests":1,"result":"PASS"})
  assert len(original43)==43 and len(set(r["test"] for r in original43))==43
  clippy=json.loads(z.read("clippy.json"))
  assert clippy["argv"]==["cargo","+1.95.0","clippy","--locked","--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node","--lib","--tests","--all-features","--","-D","warnings"]
  history=[n for n in success if n.startswith("ingress::history_import::tests::")]
  hist_ignored=[n for n in ignored_names if n.startswith("ingress::history_import::tests::")]
  assert len(history)==25 and len(hist_ignored)==1
  results.append({"lane":label,"job_id":job,"run_id":41708487004,"attempt":1,"artifact_id":aid,"artifact_file":name,"artifact_bytes":len(raw),"artifact_sha256":digest(raw),"artifact_metadata":meta,"source":source,"source_before_after_identical":True,"node_command":node,"outer_summary":terminal,"outer_passed":948,"outer_failed":0,"outer_ignored":23,"outer_measured":0,"outer_filtered":0,"complete_971_registry_matches_frozen_original":True,"unique_success_names":948,"success_names_sha256":digest(("\n".join(sorted(success))+"\n").encode()),"ignored_names_sha256":digest(("\n".join(sorted(ignored_names))+"\n").encode()),"child_summaries_retained_not_added":summaries[:-1],"history_passed":25,"history_ignored":1,"original43_named_controls":original43,"strict_clippy":clippy,"verified_command_records":cmds})
out={"schema":"b280-pq-original-node-four-lane-readback-v1","observed_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"run_id":41708487004,"attempt":1,"event_head":HEAD,"actual_merge":MERGE,"ordered_actual_merge_parents":[BASE,HEAD],"expected_tree":TREE,"actual_merge_metadata_url":"https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/git/commits/"+MERGE,"actual_merge_metadata_rechecked_in_current_agent":True,"scope":"Four complete original Node library commands at b280 head/actual merge under original test source profile, plus original 43 named controls per lane; not full workspace integration, performance acceptance, later source or whole-chain PQ qualification.","frozen_original_registry":{"plan_file":str(plan_path),"plan_sha256":digest(plan_path.read_bytes()),"registered":registered,"original_ignored":ignored_original},"common_948_passed_names":common_successes,"common_23_ignored_names_and_reasons":[{"name":n,"reason":r} for n,r in common_ignored],"same_948_unique_pass_names_all_four_lanes":True,"same_original_23_ignored_all_four_lanes":True,"lanes":results,"counts_policy":"948 unique pass names repeated on four lanes; 43 original selectors overlap the full Node set and are not 172 unique controls. Nested child harnesses are retained but not added.","profile_interpretation":json.loads((P/"pq-original-node-three-lane-readback-20261103T2104.json").read_text())["profile_interpretation"],"claims":{"full_original_node_four_lane_pass":True,"whole_workspace_pass":False,"nine_positive_host_selectors_pass":False,"four_second_f0_three_campaign_acceptance_pass":False,"whole_chain_pq_qualified":False,"later_head_qualified":False,"activation_authorized":False},"reader":{"file":pathlib.Path(__file__).name,"sha256":digest(pathlib.Path(__file__).read_bytes()),"executes_native_code":False}}
f=P/"pq-original-node-four-lane-readback.json";f.write_text(json.dumps(out,indent=2)+"\n")
print(json.dumps({"file":str(f),"bytes":f.stat().st_size,"sha256":digest(f.read_bytes()),"lanes":[{k:d[k] for k in ["lane","job_id","artifact_id","outer_summary","source_before_after_identical","complete_971_registry_matches_frozen_original"]} for d in results]},indent=2))

