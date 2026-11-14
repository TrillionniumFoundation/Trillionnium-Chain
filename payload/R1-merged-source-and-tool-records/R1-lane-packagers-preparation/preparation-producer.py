import pathlib,os,stat,sys,json,hashlib,ast,difflib,datetime
D=json.loads(sys.argv[1]);SELF=sys.argv[2];O=pathlib.Path(D["output"])
assert not O.exists() and [x["kind"]for x in D["bases"]]==["full","external"]
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sg(x):return [x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def rd(p):
 p=pathlib.Path(p);assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=1024*1024
  with os.fdopen(fd,"rb",closefd=False)as f:b=f.read(a.st_size+1)
  assert sg(a)==sg(os.fstat(fd)) and len(b)==a.st_size
  return b,sg(a)
 finally:os.close(fd)
def sha(x):return hashlib.sha256(x).hexdigest()
def js(x):return(json.dumps(x,indent=2)+"\n").encode()
def save(name,b):
 p=O/name
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 rb,v=rd(p);assert rb==b
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
prepared=[]
for spec in D["bases"]:
 old,version=rd(spec["path"]);assert len(old)==spec["bytes"] and sha(old)==spec["sha256"]
 oldtext=old.decode();newtext=oldtext
 for r in spec["replacements"]:
  assert r["count"]>0 and newtext.count(r["old"])==r["count"],r["old"]
  newtext=newtext.replace(r["old"],r["new"])
 back=newtext
 for r in reversed(spec["replacements"]):
  assert back.count(r["new"])==r["count"],r["new"]
  back=back.replace(r["new"],r["old"])
 assert back==oldtext
 oldast=ast.parse(oldtext);newast=ast.parse(newtext);compile(newtext,spec["output_name"],"exec")
 changes=[]
 def compare(a,b,path="module"):
  assert type(a)is type(b),(path,type(a).__name__,type(b).__name__)
  if isinstance(a,ast.Constant):
   assert a.kind==b.kind and type(a.value)is type(b.value),path
   if a.value!=b.value:changes.append({"ast_path":path,"old":a.value,"new":b.value,"old_line":a.lineno,"new_line":b.lineno})
  elif isinstance(a,ast.AST):
   assert a._fields==b._fields
   for n in a._fields:compare(getattr(a,n),getattr(b,n),path+"."+n)
  elif isinstance(a,list):
   assert len(a)==len(b),path
   for i,(x,y)in enumerate(zip(a,b)):compare(x,y,path+"["+str(i)+"]")
  else:assert a==b,(path,a,b)
 compare(oldast,newast);assert len(changes)==spec["expected_constant_changes"]
 functions_old={n.name:ast.get_source_segment(oldtext,n)for n in oldast.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
 functions_new={n.name:ast.get_source_segment(newtext,n)for n in newast.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
 assert set(functions_old)==set(functions_new)
 unaffected=set(functions_old)-({"main"}if spec["kind"]=="full"else set())
 assert all(functions_old[k]==functions_new[k]for k in unaffected)
 if spec["kind"]=="full":
  assert '\nSTART_HEAD = "'+D["expected_start_head"]+'"' in oldtext and '\nSTART_HEAD = "'+D["expected_start_head"]+'"' in newtext
  assert "2700 if label == \"repository-truth\" else 300" in newtext and "require(len(names) == 39" in newtext
  assert 'original["schema"] == "trnm-final-linux-repository-truth-offline-source-v4"' in newtext
  assert 'set(initial_inventory["files"]) == names' in newtext
 else:
  assert newtext.count("Ran 78 tests")==1 and '"tests":78 if matches else None' in newtext
  assert '"local_lane_timeout_seconds"]==2700' in newtext and "assert len(names)==27" in newtext and "assert actual==names" in newtext
  assert 'd["schema"]=="trnm-final-linux-external-evidence-existing-source-v2"' in newtext
 assert not any(x["new"]=="passed"for x in changes)
 diff="".join(difflib.unified_diff(oldtext.splitlines(True),newtext.splitlines(True),fromfile=spec["copy_name"],tofile=spec["output_name"]))
 prepared.append({"spec":spec,"old":old,"version":version,"new":newtext.encode(),"diff":diff.encode(),"constant_changes":changes,"unchanged_functions":sorted(unaffected)})
O.mkdir(mode=0o700)
saved=[save("preparation-producer.py",SELF.encode()),save("preparation-inputs.json",js(D))]
scripts=[];patches=[];proof_rows=[]
for item in prepared:
 spec=item["spec"];base=save(spec["copy_name"],item["old"]);new=save(spec["output_name"],item["new"]);patch=save(spec["patch_name"],item["diff"])
 saved += [base,new,patch];scripts.append({"kind":spec["kind"],**new});patches.append({"kind":spec["kind"],**patch})
 proof_rows.append({"kind":spec["kind"],"base":base,"new":new,"patch":patch,"exact_ordered_replacement_count":len(spec["replacements"]),"replacements":spec["replacements"],"exact_reverse_reconstruction_of_old_bytes":True,"compile_only_passed":True,"ast_structure_identical_except_listed_constant_values":True,"constant_changes":item["constant_changes"],"unchanged_function_source_segments":item["unchanged_functions"],"full_start_head_unchanged":True if spec["kind"]=="full"else None,"original_stage_counts_raw_rosters_budgets_and_driver_schema_unchanged":True})
both=save("both-packagers-precise.patch",b"".join(x["diff"]for x in prepared));saved.append(both)
base="/home/qian-qi/chain-final-consolidation-20261114-root"
contract={"schema":"trnm-R1-closed-log-manifest-input-contract-not-executable-v1","status":"PREPARED_ONLY_WAIT_FOR_REAL_TERMINAL","head":D["head"],"tree":D["tree"],"source_bytes":D["source_bytes"],"source_sha256":D["source_sha256"],"source_entries":D["source_entries"],"source_tracked_bytes":D["source_tracked_bytes"],"full_expected_start_head":D["expected_start_head"],"bundle":{"bytes":D["bundle_bytes"],"sha256":D["bundle_sha256"],"filename":D["bundle_filename"],"single_prerequisite_assumption":False,"actual_root_reported_prerequisites":D["bundle_prerequisites"]},"future_full_receipts":base+"/final-repository-truth-offline-2a8646-v1","future_full_package":base+"/package-original-repository-truth-2a8646-v1-prci","future_external_receipts":base+"/final-external-evidence-2a8646-v1","future_external_package":base+"/package-original-external-evidence-2a8646-v1-prci","original_full_driver":D["original_full_driver"],"original_external_driver":D["original_external_driver"],"full_step_count":18,"external_step_count":12,"full_lane_argv":["bash","scripts/ci/ci_job.sh","repository-truth"],"external_lane_argv":["bash","scripts/ci/ci_job.sh","external-evidence-contract"],"lane_timeout_seconds":2700,"full_counts":{"n":"actual closed nested original file count","required_flat":39,"original_files":"39+n","payload_files":"42+n","zip_members":"43+n"},"external_counts":{"n":"actual closed nested original file count","required_flat":27,"original_files":"27+n","payload_files":"30+n","zip_members":"31+n"},"successful_full_lane_requires_original_12_nested_logs":True,"external_required_readiness_tests":78,"closed_manifest_schema":"trnm-closed-original-sublogs-manifest-v1","closed_manifest_exact_fields":["schema","head","tree","receipt_directory","terminal_summary_sha256","files"],"closed_manifest_file_fields":["path","bytes","sha256"],"closed_manifest_must_be_created_only_after_terminal":True,"actual_complete_directory_must_equal":"required flat originals plus exactly the operator-pinned complete nested-file roster","unknown_members":"reject and report; never silently omit or normalize","actual_R1_terminal_summary_sha256":None,"actual_R1_terminal_read":False,"actual_P1_live_receipts_read":False,"elapsed_and_total_bytes":"derive only from pinned actual terminal and original bytes","failure_boundary":"original lane status/exit/errors must agree; retain failures; earlier irregular non-lane failure is preserved separately, never normalized","packagers_executed":False,"stage_source_git_network_test_actions":False}
saved.append(save("closed-log-manifest-contract.json",js(contract)))
proof={"schema":"trnm-R1-packagers-static-identity-proof-v1","created_at":now(),"packagers":proof_rows,"both_precise_patch":both,"original_false_qualification_flags_unchanged":True,"original_failure_preservation_unchanged":True,"no_control_flow_or_operator_or_call_structure_changes":True,"no_packager_import_or_execution":True,"no_actual_terminal_invented":True,"P1_original_versions_unchanged":True,"no_ROG_live_receipts_read":True,"stage_source_git_network_test_actions":False}
pr=save("static-identity-proof.json",js(proof));saved.append(pr)
readme="""# R1 original-results packagers — preparation only

These two scripts narrowly adapt the root-reviewed P1 full-v2 and external packagers to the explicit R1 source pins. Changes are limited to the final head/tree, source hash/tracked-byte identity, full bundle identity, exact receipt/package/ZIP paths, and descriptive package namespaces. Full START_HEAD remains the actual P1 commit.

The original full 18 stages, external 12 stages, 39/27 required flat originals, full 12 mandatory successful-lane sublogs, 2700-second budgets, external 78-test readiness observation, exact source before/after, stable regular/single-link reads, raw-stream hashes, complete directory union, original drivers/schemas, and all failure/qualification boundaries remain unchanged.

Each runtime invocation still requires a real terminal-summary SHA, actual 0/1 terminal exit, and actual complete closed-log manifest SHA. No success, failure, elapsed time, byte count or nested log roster is invented. Unknown files cause rejection instead of silent exclusion. Irregular earlier failures remain separate original receipts, never normalized into a complete gate.

The P1 versions remain byte-identical. This preparation does not reread the already closed P1 execution directory. This preparation only parses and compiles the new script text; it does not import or execute either packager, contact ROG/network services, change source/Git/PR state, run tests, or write stage.
"""
saved.append(save("README.md",readme.encode()))
for item in prepared:
 raw,v=rd(item["spec"]["path"]);assert raw==item["old"] and v==item["version"]
idx=save("EVIDENCE_INDEX.json",js({"schema":"trnm-R1-packagers-preparation-index-v1","files":saved,"self_and_summary_excluded":True,"all_preparation_only":True}))
summary={"schema":"trnm-R1-packagers-preparation-summary-v1","status":"PREPARED_ONLY_WAIT_FOR_REAL_TERMINAL","head":D["head"],"tree":D["tree"],"expected_start_head":D["expected_start_head"],"scripts":scripts,"patches":patches,"both_patch":both,"proof":pr,"index":idx,"P1_base_files_unchanged":True,"packagers_executed":False,"live_ROG_receipts_read":False,"actual_R1_terminal_not_observed":True,"stage_source_git_network_test_actions":False}
sr=save("summary.json",js(summary))
print(json.dumps({"summary":sr,"scripts":scripts,"patches":patches,"both_patch":both,"proof":pr,"index":idx,"status":summary["status"]}),flush=True)
