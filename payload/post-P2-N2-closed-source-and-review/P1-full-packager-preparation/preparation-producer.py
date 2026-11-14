import pathlib,os,stat,sys,json,hashlib,ast,difflib,datetime
D=json.loads(sys.argv[1]);SELF=sys.argv[2];O=pathlib.Path(D["output"])
assert not O.exists() and len(D["bases"])==1 and D["bases"][0]["kind"]=="full"
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
spec=D["bases"][0];old,version=rd(spec["path"]);assert len(old)==spec["bytes"] and sha(old)==spec["sha256"]
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
constant_changes=[]
def compare(a,b,path="module"):
 assert type(a)is type(b),(path,type(a).__name__,type(b).__name__)
 if isinstance(a,ast.Constant):
  assert a.kind==b.kind and type(a.value)is type(b.value),path
  if a.value!=b.value:constant_changes.append({"ast_path":path,"old":a.value,"new":b.value,"old_line":a.lineno,"new_line":b.lineno})
 elif isinstance(a,ast.AST):
  assert a._fields==b._fields
  for n in a._fields:compare(getattr(a,n),getattr(b,n),path+"."+n)
 elif isinstance(a,list):
  assert len(a)==len(b),path
  for i,(x,y)in enumerate(zip(a,b)):compare(x,y,path+"["+str(i)+"]")
 else:assert a==b,(path,a,b)
compare(oldast,newast)
assert len(constant_changes)==15
funcold={n.name:ast.get_source_segment(oldtext,n)for n in oldast.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
funcnew={n.name:ast.get_source_segment(newtext,n)for n in newast.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
assert set(funcold)==set(funcnew) and {k:v for k,v in funcold.items()if k!="main"}=={k:v for k,v in funcnew.items()if k!="main"}
assert "2700 if label == \"repository-truth\" else 300" in newtext
assert 'require(len(names) == 39' in newtext and 'set(initial_inventory["files"]) == names' in newtext
assert 'original["schema"] == "trnm-final-linux-repository-truth-offline-source-v4"' in newtext
assert 'args.terminal_exit_code == (0 if derived == "passed" else 1)' in newtext
assert '\nSTART_HEAD = "'+D["head"]+'"' in newtext
assert not any(x["new"]=="passed"for x in constant_changes)
diff="".join(difflib.unified_diff(oldtext.splitlines(True),newtext.splitlines(True),fromfile=spec["copy_name"],tofile=spec["output_name"]))
O.mkdir(mode=0o700)
saved=[]
saved.append(save("preparation-producer.py",SELF.encode()))
saved.append(save("preparation-inputs.json",js(D)))
basecopy=save(spec["copy_name"],old);saved.append(basecopy)
newfile=save(spec["output_name"],newtext.encode());saved.append(newfile)
patch=save(spec["patch_name"],diff.encode());saved.append(patch)
contract={"schema":"trnm-P1-full-v2-closed-log-manifest-input-contract-v1","status":"PREPARED_ONLY_WAIT_FOR_REAL_TERMINAL","head":D["head"],"tree":D["tree"],"expected_start_head":D["head"],"source_bytes":D["source_bytes"],"source_sha256":D["source_sha256"],"source_entries":D["source_entries"],"source_tracked_bytes":D["source_tracked_bytes"],"bundle":{"bytes":D["bundle_bytes"],"sha256":D["bundle_sha256"],"filename":D["bundle_filename"],"single_prerequisite_assumption":False},"future_full_receipts":D["full_receipts"],"future_full_package":D["future_package"],"original_driver":D["original_full_driver"],"original_driver_schema":"trnm-final-linux-repository-truth-offline-source-v4","exact_original_step_count":18,"original_lane_argv":["bash","scripts/ci/ci_job.sh","repository-truth"],"original_lane_timeout_seconds":2700,"closed_manifest_schema":"trnm-closed-original-sublogs-manifest-v1","closed_manifest_exact_fields":["schema","head","tree","receipt_directory","terminal_summary_sha256","files"],"closed_manifest_file_fields":["path","bytes","sha256"],"closed_manifest_must_be_created_only_after_terminal":True,"actual_complete_directory_must_equal":"39 required flat original files plus exactly the operator-pinned closed ci-observations manifest roster","counts":{"n":"actual closed nested original file count","original_files":"39+n","payload_files":"42+n","zip_members":"43+n"},"successful_lane_requires_original_12_nested_logs":True,"terminal_and_manifest_hashes_are_runtime_required_actual_inputs":True,"actual_full_terminal_summary_sha256":None,"actual_full_terminal_read":False,"unknown_members":"reject and report, never silently omit","elapsed_and_total_bytes":"derive only from pinned actual terminal and original bytes","failure_boundary":"original lane status/exit/errors must agree; a failure is retained; earlier irregular non-lane failure is preserved separately, never normalized","prior_17_stage_source_index_failure_is_not_accepted_as_full_result":True,"packager_executed":False,"live_ROG_receipts_read":False,"stage_source_git_network_test_actions":False}
saved.append(save("closed-log-manifest-contract.json",js(contract)))
proof={"schema":"trnm-P1-full-v2-packager-static-identity-proof-v1","created_at":now(),"base":basecopy,"new":newfile,"patch":patch,"exact_ordered_replacement_count":len(spec["replacements"]),"replacements":spec["replacements"],"exact_reverse_reconstruction_of_old_bytes":True,"python_compile_only_passed":True,"ast_structure_identical_except_listed_constant_values":True,"constant_changes":constant_changes,"all_non_main_function_source_segments_byte_identical":True,"function_names":sorted(funcold),"main_structure_identical_except_listed_identity_constants":True,"original_18_step_gate_and_39_required_flat_contract_unchanged":True,"original_2700_second_timeout_unchanged":True,"original_12_success_sublogs_unchanged":True,"false_qualification_flags_unchanged":True,"original_driver_and_runtime_schema_unchanged":True,"actual_terminal_not_supplied_or_invented":True,"packager_import_or_execution_performed":False,"network_stage_source_git_native_actions":False}
saved.append(save("static-identity-proof.json",js(proof)))
readme="""# P1 full-lane v2 original-results packager — preparation only

This is a narrow fixed-identity adapter of the root-reviewed M8 full packager. It binds P1 head/tree and source raw identity, the exact reviewed 8,575-byte bundle, the v2 receipt and new package/ZIP paths, and the package's descriptive namespace.

The corrected v2 attempt starts at P1 itself, because the earlier M8-to-P1 fast-forward completed before source-index verification failed. HEAD and START_HEAD are both the explicit P1 commit. The original invocation, initial-head, ancestry, bundle advertisement and fast-forward records remain strictly checked. No Git operation is performed by this packager.

The original 18 steps, 39 required flat originals, all 12 required successful-lane ci-observations logs, 2700-second lane, failure/status checks, exact eleven-field source identity, stable regular/single-link reads, raw streams, directory union, CRC/SHA verification and false qualification flags remain unchanged. Actual additional nested logs require a complete operator-pinned closed manifest; unknown or missing files are rejected.

The first P1 v1 attempt's 17-stage failure before the lane started remains separate original evidence. It cannot be accepted or normalized by this complete 18-stage packager.

No P1 v2 terminal, summary digest, nested-log roster, elapsed time, success or failure is invented. All three CLI values must be supplied from the actual closed execution. The prepared packager was parsed and compiled only, not imported or executed. No ROG receipt was read. Preparation does not write stage, source, Git refs, PR metadata, network state or tests.
"""
saved.append(save("README.md",readme.encode()))
after,v=rd(spec["path"]);assert after==old and v==version
index=save("EVIDENCE_INDEX.json",js({"schema":"trnm-P1-full-v2-packager-preparation-index-v1","files":saved,"self_and_summary_excluded":True,"all_preparation_only":True}))
summary={"schema":"trnm-P1-full-v2-packager-preparation-summary-v1","status":"PREPARED_ONLY_WAIT_FOR_REAL_TERMINAL","head":D["head"],"tree":D["tree"],"expected_start_head":D["head"],"prepared_script":newfile,"precise_patch":patch,"static_identity_proof":next(r for r in saved if r["path"].endswith("static-identity-proof.json")),"index":index,"base_bytes_unchanged":True,"packager_executed":False,"actual_full_terminal_not_observed":True,"prior_v1_17_stage_failure_not_normalized":True,"stage_source_git_network_test_actions":False}
sr=save("summary.json",js(summary))
print(json.dumps({"summary":sr,"script":newfile,"patch":patch,"proof":summary["static_identity_proof"],"index":index,"status":summary["status"]}),flush=True)
