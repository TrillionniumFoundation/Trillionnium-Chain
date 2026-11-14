import pathlib,os,stat,sys,json,hashlib,datetime,re
D=json.loads(sys.argv[1]);SELF=sys.argv[2];B=pathlib.Path("/private/tmp/chain-prci-N-cross-cost-job-log-review-20261114-v1");O=B/"outer-analysis-v1";O.mkdir(mode=0o700)
def js(v):return(json.dumps(v,indent=2)+"\n").encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):
 assert p.resolve(strict=True)==p
 f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(f);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
  with os.fdopen(f,"rb",closefd=False)as st:b=st.read(s.st_size+1)
  z=os.fstat(f);assert len(b)==s.st_size and(s.st_ino,s.st_mtime_ns,s.st_ctime_ns,s.st_size)==(z.st_ino,z.st_mtime_ns,z.st_ctime_ns,z.st_size);return b
 finally:os.close(f)
def save(name,b):
 p=O/name
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert read(p)==b
 return{"path":str(p),"bytes":len(b),"sha256":sha(b)}
raw=read(B/"x64-job132415017426.log");assert len(raw)==184799 and sha(raw)=="154555d87f24fbaed2609d14b18837c228256c65af29633eb42f611b9e291c81"
log=raw.decode();lines=log.splitlines();kept=raw.splitlines(keepends=True);assert len(lines)==1436
ctrl=json.loads(re.sub(r"^20[0-9-]+T[0-9:.]+Z ","",lines[1354]))
assert ctrl["schema"]=="trnm-ci-original-public-host-controller-v2"and ctrl["failure"]is None and ctrl["final_host_errors"]==[]and ctrl["systemd_run_exit"]==1
assert ctrl["command_argv"]==["python3","scripts/ci/run_from_zero_native.py","--out","/home/runner/work/_temp/ci-observations/from-zero-native"]
p=ctrl["preparation"];assert p["failure_type"]is None and p["source_error"]is None and p["process"]["exit_code"]==0 and p["process"]["timed_out"]is False and p["format_preparation"]["process"]["exit_code"]==0 and p["format_preparation"]["process"]["timed_out"]is False
metadata=json.loads(read(B/"existing-two-cost-job-metadata.json"))
findings={"schema":"trnm-N-x64-cost-outer-log-causal-boundary-v1","reviewed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source_run":43582713392,"source_job":132415017426,"source_head_from_run_metadata":"5a4b7fe8de1adce803184f262fd9f704ead1930c","source_tree_from_run_metadata":"4bc5ade0813ba3172eeb0ad7425358469a1b1edd","observed_window":[metadata["observation_started_at"],metadata["observation_finished_at"]],"original_log":{"path":str(B/"x64-job132415017426.log"),"bytes":len(raw),"sha256":sha(raw),"lines":1436},"facts":{"host_command_lines":[1339,1340],"controller_line":1355,"github_exit1_line":1356,"controller_schema":ctrl["schema"],"controller_failure":None,"final_host_errors":[],"format_preparation_exit":0,"compile_preparation_exit":0,"format_preparation_timed_out":False,"compile_preparation_timed_out":False,"systemd_run_exit":1,"command_argv":ctrl["command_argv"]},"failure_boundary":"The controlled systemd invocation returned 1 after successful format/compile preparation; the outer log does not expose the native inner failure assertion.","CONFIRMATION_TARGET_text_present":"CONFIRMATION_TARGET"in log,"original_4s_and_16_workers_actual_execution_verified":False,"native_source_before_after_bytes_read":False,"host_or_cpu_performance_cause_proven":False,"only_recommended_next_artifact":{"id":14109658844,"name":"cost-x64-5a4b7fe8de1adce803184f262fd9f704ead1930c-1","bytes_from_upload_log":9884207,"zip_sha256_from_upload_log":"10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4","line_references":[1418,1420,1421,1422],"url":"https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43582713392/artifacts/14109658844","reason":"Need the original from-zero manifest/native stdout-stderr/source-before-after to identify the actual inner error and whether the unchanged acceptance window/workers ran.","artifact_API_metadata_not_yet_requested":True,"artifact_not_downloaded":True},"other_arch_scope":"arm64 only original job/failed-step metadata observed; no arm log or artifact fetched","four_seconds_failure_not_inferred_from_failed_job":True,"stage_source_CI_or_remote_mutations":False,"hosted_qualification":False}
rows=[]
rows.append(save("findings.json",js(findings)))
offset=sum(len(x)for x in kept[:1354]);r=kept[1354]
rows.append(save("controller-original-line1355.log",r))
rows.append(save("controller-extraction-identity.json",js({"original_log_sha256":sha(raw),"line":1355,"byte_start":offset,"byte_end":offset+len(r),"bytes":len(r),"sha256":sha(r),"timestamp_preserved":True})))
rows.append(save("controller-parsed.json",js(ctrl)))
parts=[];nextoff=0
for page in D["download_pages"]:
 b=bytes.fromhex(page["bytes_hex"]);assert page["offset"]==nextoff and sha(b)==page["chunk_sha256"]and len(b)==page["next_offset"]-page["offset"];nextoff=page["next_offset"];parts.append(b)
assert D["download_pages"][-1]["status"]["exit_code"]==0 and D["download_pages"][-1]["output_complete"]is True and nextoff==6110
rows.append(save("actual-download-terminal-pages.json",js(D["download_pages"])))
rows.append(save("actual-download-terminal.log",b"".join(parts)))
rows.append(save("readonly-inspection-producer.py",D["inspection_script"].encode()))
t=D["inspection_terminal"];b=bytes.fromhex(t["bytes_hex"]);assert t["status"]["exit_code"]==0 and t["output_complete"]is True and sha(b)==t["chunk_sha256"]
rows.append(save("readonly-inspection-terminal.json",js(t)));rows.append(save("readonly-inspection-terminal.log",b))
rows.append(save("seal-producer.py",SELF.encode()))
readme="""# N x64 cross-cost: original outer-log boundary

This is a new N sample, run 43582713392 / job 132415017426 / head 5a4b7fe8de1adce803184f262fd9f704ead1930c. The original complete job log was obtained through one bounded official gh GET and retained unchanged (184,799 bytes, SHA256 154555d87f24fbaed2609d14b18837c228256c65af29633eb42f611b9e291c81). HTTP headers were not requested; completeness is based on the actual gh exit 0 plus both stream EOFs, not an invented provider log digest.

Both newly observed cost jobs failed step 12, Execute exact native from-zero service controls. The x64 step ran 10:15:55–10:21:40Z; arm64 10:15:43–10:21:14Z. The x64 original log shows the protected host controller invoking run_from_zero_native.py. Its controller record at line 1355 reports no host/controller failure, no final host errors, successful format/compile preparation without timeout, and systemd_run_exit=1. Line 1356 reports the step's exit 1.

The native inner error is absent from this outer stream. This evidence does not prove CONFIRMATION_TARGET, actual four-second/sixteen-worker execution, or a particular CPU/performance defect. Native source-before/after bytes also remain unread. The one relevant artifact explicitly named by the original upload log is 14109658844, 9,884,207 bytes, upload digest 10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4. Its metadata must be checked before any separate authorized retrieval; no artifact has been requested here.

No source, stage, refs, CI execution or remote state was changed. No C0 archive or older log was downloaded.
"""
rows.append(save("review.md",readme.encode()))
idx=save("EVIDENCE_INDEX.json",js({"schema":"trnm-N-cost-outer-analysis-index-v1","files":rows,"original_download_index":{"path":str(B/"EVIDENCE_INDEX.json"),"sha256":"26f0503151e4b23768f2dc502effbb7e75b91080b5ea53d527a12f8648d7d84b"}}))
print(json.dumps({"findings":rows[0],"review":rows[-1],"index":idx,"inner_cause_still_unobserved":True,"stage_changed":False}),flush=True)
