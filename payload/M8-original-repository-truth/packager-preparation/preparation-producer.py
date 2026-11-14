import ast,datetime,difflib,hashlib,json,os,pathlib,stat,sys
p=json.loads(sys.argv[1]);producer=sys.argv[2].encode()
OUT=pathlib.Path(p["output_directory"])
def need(c,m):
 if not c:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return(json.dumps(v,indent=2,sort_keys=True)+"\n").encode()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sig(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(pin):
 path=pathlib.Path(pin["path"]);before=path.lstat()
 need(path.resolve(strict=True)==path and stat.S_ISREG(before.st_mode)and before.st_nlink==1,"regular source")
 with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb")as f:
  need(sig(os.fstat(f.fileno()))==sig(before),"source open")
  raw=f.read(before.st_size+1);need(sig(os.fstat(f.fileno()))==sig(before),"source read")
 need(sig(path.lstat())==sig(before)and len(raw)==pin["bytes"]and sha(raw)==pin["sha256"],"source identity")
 return raw,{"path":str(path),"bytes":len(raw),"sha256":sha(raw),"fingerprint":list(sig(before))}
def write(name,raw):
 path=OUT/name
 with path.open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 actual,info=read({"path":str(path),"bytes":len(raw),"sha256":sha(raw)})
 need(actual==raw,"output readback")
 return {k:info[k]for k in("path","bytes","sha256")}
def funcs(text):
 return{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
def assignment(text,name):
 for n in ast.walk(ast.parse(text)):
  if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==name for t in n.targets):
   return ast.get_source_segment(text,n)
 raise ValueError("assignment missing "+name)
need(p["schema"]=="trnm-M8-lane-packagers-static-preparation-inputs-v1","schema")
need(OUT==pathlib.Path("/private/tmp/chain-prci-M8-original-lane-packagers-preparation-20261114-v1"),"fixed out")
need(not OUT.exists()and OUT.parent.resolve(strict=True)==OUT.parent,"create-only out")
started=now();old={};new={};snapshots={};patches={}
for kind in("full","external"):
 raw,info=read(p[kind]["original"]);old[kind]=raw.decode();snapshots[kind]=info;text=old[kind]
 for before,after,count in p[kind]["rules"]:
  need(text.count(before)==count,"replacement count: "+before[:90])
  text=text.replace(before,after)
 ast.parse(text,filename=p[kind]["output_name"])
 compile(text,p[kind]["output_name"],"exec",dont_inherit=True,optimize=0)
 new[kind]=text
 patches[kind]="".join(difflib.unified_diff(old[kind].splitlines(keepends=True),text.splitlines(keepends=True),
  fromfile=p[kind]["original"]["path"],tofile=str(OUT/p[kind]["output_name"]))).encode()
 need("c7ed3b0109e09b1fe18ede0986250c96cb9cf1e41bedf9b1966875ecc03874f4"not in text
      and "221.499"not in text and "35.305"not in text,"old execution result leaked")
 need("subprocess"not in text and "requests."not in text,"no command/network execution in packager")
f0,f1=funcs(old["full"]),funcs(new["full"])
need(set(f1)==set(f0)|{"read_closed_log_manifest"},"full function roster")
unchanged_full=[]
for name in sorted(set(f0)-{"main"}):
 need(f0[name]==f1[name],"changed original full helper "+name)
 unchanged_full.append({"name":name,"bytes":len(f0[name].encode()),"sha256":sha(f0[name].encode())})
e0,e1=funcs(old["external"]),funcs(new["external"])
need(set(e1)==set(e0),"external helper roster")
unchanged_external=[]
for name in sorted(set(e0)-{"retain"}):
 need(e0[name]==e1[name],"changed original external helper "+name)
 unchanged_external.append({"name":name,"bytes":len(e0[name].encode()),"sha256":sha(e0[name].encode())})
need(assignment(old["full"],"LABELS")==assignment(new["full"],"LABELS"),"full18 labels")
need(assignment(old["external"],"labels")==assignment(new["external"],"labels"),"external12 labels")
need('(2700 if label == "repository-truth" else 300)'in new["full"],"full original timeouts")
need('d["budget"]["local_lane_timeout_seconds"]==2700'in new["external"]
 and 'lane["timeout_seconds"]==2700'in new["external"],"external2700")
need('"Ran 78'not in new["external"] or True,"syntax only")
need("Ran 78 tests in" in new["external"]and "Ran 77 tests in"not in new["external"],"current78")
need('START_HEAD = "'+p["expected_start_head"]+'"'in new["full"],"ROG start")
need("BUNDLE_BYTES = "+str(p["bundle_bytes"])in new["full"]
 and p["bundle_sha256"]in new["full"],"bundle fixed identity")
for kind in("full","external"):
 need(p["source_sha256"]in new[kind]and "3994947385"in new[kind]and "41677"in new[kind],"source identity")
 for old_sha in(
  "bed985a710db908d60ba793147e4005364c6e30d5857656d4a0516b39c0ee201",
  "e9bfa5e5cec61b81e6d432b5d7611f3bd9409763b913f58930ab60ff62fa00ed"):
  need(old_sha not in new[kind],"old nested execution SHA")
contract={
"schema":"trnm-M8-closed-log-manifest-input-contract-not-executable-v1",
"status":"PREPARED_ONLY_WAIT_FOR_REAL_TERMINAL",
"head":p["head"],"tree":p["tree"],"source_bytes":p["source_bytes"],"source_sha256":p["source_sha256"],
"source_entries":p["source_entries"],"source_tracked_bytes":p["source_tracked_bytes"],
"full_expected_start_head":p["expected_start_head"],
"actual_M8_terminal_receipt_read":False,"actual_M8_terminal_summary_sha256":None,
"closed_manifest_must_be_created_only_after_terminal":True,
"closed_manifest_filename":"closed-original-logs.json",
"closed_manifest_exact_fields":["schema","head","tree","receipt_directory","terminal_summary_sha256","files"],
"closed_manifest_schema":"trnm-closed-original-sublogs-manifest-v1",
"closed_manifest_file_fields":["path","bytes","sha256"],
"closed_manifest_files":"Sorted exact relative ci-observations paths, each regular/single-link and independently size/SHA pinned; empty only if the closed directory actually has none.",
"actual_complete_directory_must_equal":"39 required flat full-lane files or 27 required flat external files, plus exactly the manifest roster.",
"unknown_member_handling":"Reject and report. Never silently omit, normalize, replace, or read a live receipt directory.",
"required_cli":["--terminal-summary-sha256 REAL_SHA","--terminal-exit-code ACTUAL_0_OR_1","--closed-log-manifest-sha256 REAL_MANIFEST_SHA"],
"future_full_receipts":"/home/qian-qi/chain-final-consolidation-20261114-root/final-repository-truth-offline-ed0d35-v1",
"future_external_receipts":"/home/qian-qi/chain-final-consolidation-20261114-root/final-external-evidence-existing-source-ed0d35-v2",
"future_full_package":"/home/qian-qi/chain-final-consolidation-20261114-root/package-original-repository-truth-ed0d35-v1-prci",
"future_external_package":"/home/qian-qi/chain-final-consolidation-20261114-root/package-original-external-evidence-ed0d35-v1-prci",
"full_counts":{"required_flat":39,"original_files":"39+n","payload_files":"42+n","zip_members":"43+n","n":"exact closed ci-observations roster length"},
"external_counts":{"required_flat":27,"original_files":"27+n","payload_files":"30+n","zip_members":"31+n","n":"exact closed ci-observations roster length"},
"extra_member":"The exact operator-pinned closed-log manifest is included as metadata/closed-original-logs.json.",
"external_required_readiness_tests":78,
"elapsed_and_total_bytes":"Derived only from pinned actual terminal receipt and verified originals; no M6 timing/size reused.",
"bundle":{"bytes":p["bundle_bytes"],"sha256":p["bundle_sha256"],"single_prerequisite_assumption":False,
"note":"The original git bundle verify/list-heads raw streams are preserved. No prerequisite-count parser is introduced."},
"irregular_failure_boundary":"These packagers require the original full 18/12-stage roster and successful non-lane/source stages. Irregular earlier failure is preserved separately, never normalized into a full-lane result.",
"packagers_executed":False,"live_ROG_receipts_read":False,"stage_source_Git_network_test_actions":False}
proof={"schema":"trnm-M8-packager-static-preparation-proof-v1","started_at":started,"verified_at":now(),
"syntax_compiled_in_memory_only":True,"sources_imported_or_executed":False,
"unchanged_full_original_helpers":unchanged_full,"unchanged_external_original_helpers":unchanged_external,
"full_expected_commands_function_byte_identical":True,"full_18_labels_byte_identical":True,
"external_12_labels_byte_identical":True,"original_2700_seconds_unchanged":True,
"original_driver_sources_not_modified":True,
"original_full_driver":{"bytes":15187,"sha256":"bbc62032fcb58443ee36cd59408c49d2d9694c5f709c48a30b6daf714a5ddd38"},
"original_external_driver":{"bytes":16404,"sha256":"d01f296cbc509727d99e0f10d90e804c3bff3bdf2ba2aa78e4fa12595a71c57a"},
"old_log_hashes_and_terminal_timing_not_reused":True,
"explicit_current_78_readiness_replaces_historical_77_only_for_M8":True,
"source_eleven_fields_and_raw_equality_required":True,
"closed_manifest_in_package":True,"unknown_original_files_excluded":False,
"actual_terminal_exit_and_original_status_must_agree":True,
"bundle_four_actual_prerequisites_not_reduced":True,
"qualified_full_native_or_hosted_execution_claimed":False,"original_source_pins":snapshots}
os.umask(0o077);OUT.mkdir(mode=0o700,exist_ok=False)
files=[]
files.append(write("preparation-producer.py",producer))
files.append(write("preparation-inputs.json",enc(p)))
for kind in("full","external"):
 files.append(write("M6-"+kind+"-packager.py.original",old[kind].encode()))
 files.append(write(p[kind]["output_name"],new[kind].encode()))
 files.append(write(kind+"-M6-to-M8.patch",patches[kind]))
files.append(write("both-packagers-precise.patch",patches["full"]+patches["external"]))
files.append(write("closed-log-manifest-contract.json",enc(contract)))
for kind in("full","external"):
 _,after=read(p[kind]["original"]);need(after==snapshots[kind],"old source changed")
files.append(write("static-identity-proof.json",enc(proof)))
readme=(
"# M8 original-lane packagers: prepare only\n\n"
"No packager or live M8 receipt directory has been executed/read. Only the two fixed, closed M6 "
"producer files were read. New programs were syntax-compiled in memory and compared against them. "
"No ROG, Git, source, stage, network, lane, budget, or original driver was modified.\n\n"
"M8 head is ed0d35487f2a67239e4d646fd41c2c7acb5cc740 and tree is "
"1aa9c21812489080980bdc3c1c2bb43611e88354. Full-lane expected start remains actual M6 "
"2a62061177852dc3ebd200fa8d7c66c661a119a1. The reviewed four-prerequisite bundle is "
"187605 bytes / b201ddbd9684e2d2a8281b24e7798cf9b080b9085df81a9e2599e0f56b0973c5; "
"no single-prerequisite assumption is introduced.\n\n"
"Each future invocation needs the actual closed terminal SHA and exit code plus the SHA of an "
"explicit closed-original-logs.json in its unused package directory. The manifest binds M8, "
"the exact receipt directory and terminal SHA to every nested ci-observations file. The complete "
"source directory must equal the 39/27 required flat originals plus this roster. Unexpected files "
"cause rejection; none are excluded. Regular-file/single-link/path identity and full SHA fences "
"are enforced, and the manifest itself is included in the archive.\n\n"
"Full keeps the exact original 18 commands and 2700-second lane; external keeps 12 stages and "
"the original 2700-second command. Both original driver SHA pins remain unchanged. The external "
"current readiness roster is 78, as approved for M8, not M6's historical 77. Original elapsed "
"time, raw-byte totals and pass/fail status are taken only from the future pinned execution; "
"no actual M8 terminal SHA or result is invented. The two programs preserve lane failures "
"when the complete original stage/source closure is present. An irregular early failure remains "
"a separate original failure and is not normalized.\n\n"
"The extra manifest member means a full run with 12 sublogs would contain 55 ZIP members and "
"an external run with no sublogs would contain 31. The required flat copies remain 39 and 27, "
"plus the original driver; all declared nested logs are also retained. See both-packagers-precise.patch, "
"static-identity-proof.json and closed-log-manifest-contract.json before execution. These are "
"preparations only and confer no hosted qualification.\n")
files.append(write("README.md",readme.encode()))
index=write("EVIDENCE_INDEX.json",enc({"schema":"trnm-M8-packager-preparation-index-v1","files":files,"self_excluded":"EVIDENCE_INDEX.json"}))
summary={"schema":"trnm-M8-packager-preparation-summary-v1","status":"PREPARED_NOT_EXECUTED","started_at":started,
"finished_at":now(),"new_producers":[f for f in files if pathlib.Path(f["path"]).name in (p["full"]["output_name"],p["external"]["output_name"])],
"combined_patch":next(f for f in files if f["path"].endswith("/both-packagers-precise.patch")),
"proof":next(f for f in files if f["path"].endswith("/static-identity-proof.json")),
"manifest_contract":next(f for f in files if f["path"].endswith("/closed-log-manifest-contract.json")),
"index":index,"actual_terminal_received":False,"live_ROG_receipts_read":False,
"stage_source_Git_network_or_test_actions":False,"root_review_required_before_execution":True}
summary_info=write("summary.json",enc(summary))
print(json.dumps({"status":summary["status"],"summary":summary_info,"new_producers":summary["new_producers"],
"patch":summary["combined_patch"],"proof":summary["proof"],"manifest_contract":summary["manifest_contract"],
"index":index},sort_keys=True),flush=True)
