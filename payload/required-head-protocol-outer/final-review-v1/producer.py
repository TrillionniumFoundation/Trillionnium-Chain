import os,stat,json,re,hashlib,sys,datetime
from pathlib import Path
D=Path("/private/tmp/chain-prci-H5DF-required-head-protocol-original-log-20261114-v1");E=D/"final-review-v1"
def sha(b):return hashlib.sha256(b).hexdigest()
def fp(s):return s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns
def stable(pin):
 p=Path(pin["path"]);a=p.lstat();assert stat.S_ISREG(a.st_mode)and a.st_nlink==1
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW),"rb")as f:
  assert fp(a)==fp(os.fstat(f.fileno()));raw=f.read();assert fp(a)==fp(os.fstat(f.fileno()))
 assert fp(a)==fp(p.lstat())and len(raw)==pin["bytes"]and sha(raw)==pin["sha256"]
 return raw
def pin(p):
 raw=p.read_bytes();return{"path":str(p),"bytes":len(raw),"sha256":sha(raw)}
def put(name,raw):
 p=E/name
 with p.open("xb")as f:f.write(raw)
 info=pin(p);assert stable(info)==raw
 return info
def dump(x):return(json.dumps(x,indent=2,sort_keys=True,ensure_ascii=False)+"\n").encode()
assert sys.flags.optimize==0
projection=json.loads(sys.argv[1]);term=json.loads(sys.argv[2])
sp={"path":str(D/"acquisition-summary.json"),"bytes":14551,"sha256":"d2849e851192fab8acdc5ffb1aedc457d604dd6aeba5d8706214d490daf1a327"}
ip={"path":str(D/"EVIDENCE_INDEX.json"),"bytes":2931,"sha256":"7f43177c3399d2dfb958bba1e0a8305e67af8ee10a79661ef885e127562c8f59"}
acq=json.loads(stable(sp));index=json.loads(stable(ip));originals={x["path"]:stable(x)for x in index["files"]}
assert acq["actual_GETs"]==2 and acq["status"]=="ACQUIRED"
job=acq["jobs"][0];assert job["job_id"]==132528769008 and job["identity_valid"]and job["log_complete"]
assert projection["log"]==job["steps"][1]["stdout"]and projection["metadata"]==job["observed_job"]
log=originals[projection["log"]["path"]];lines=log.decode().splitlines()
assert len(lines)==projection["total_lines"]
sources=projection["source_records"];assert len(sources)==2 and sources[0]["source"]==sources[1]["source"]
for source in sources:
 actual="\n".join(re.sub(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z\s?","",s)for s in lines[source["start_line"]-1:source["end_line"]])
 assert json.loads(actual)==source["source"]
src=sources[0]["source"]
assert src["tested_commit"]==src["candidate"]=="5df7ae6f482157c5f7fdcbcd52222117a965053f"and src["tested_tree"]=="6be4940d38cc88782657f2684cbefe48866f8b9f"
ctrlrow=projection["controllers"][0];cline=ctrlrow["line"];ctext=re.sub(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z\s?","",lines[cline-1]);ctrl=json.loads(ctext)
assert ctrl["systemd_run_exit"]==1 and ctrl["passed"]is False and ctrl["failure"]is None and ctrl["final_host_errors"]==[]
assert ctrl["preparation"]["completed"]and ctrl["preparation"]["process"]["exit_code"]==ctrl["preparation"]["format_preparation"]["process"]["exit_code"]==0
t=term["terminal"];assert t["status"]["exit_code"]==0 and t["status"]["state"]=="exited"and t["output_complete"]is True
offset=0;terminalraw=b""
for page in term["pages"]:
 b=bytes.fromhex(page["bytes_hex"]);assert page["offset"]==offset and page["next_offset"]==offset+len(b)and sha(b)==page["chunk_sha256"]
 offset=page["next_offset"];terminalraw+=b
assert offset==t["available_end"]==t["status"]["bytes_seen"]==t["status"]["bytes_stored"]==876
E.mkdir(mode=0o700)
put("producer.py",Path(__file__).read_bytes())
termpin=put("acquisition-actual-terminal.json",dump(term))
rawpin=put("acquisition-actual-terminal.log",terminalraw)
ctrlpin=put("original-controller-result.json",ctext.encode()+b"\n")
failed=[s for s in job["observed_job"]["steps"]if s["conclusion"]=="failure"]
assert len(failed)==1 and failed[0]["number"]==8 and failed[0]["name"]=="Run actual protocol-contract checks"
artifact={"id":14126950344,"name":"head-protocol-contract-5df7ae6f482157c5f7fdcbcd52222117a965053f-1","bytes":7258904,"sha256":"2ccebd8388401d327834f437675c782a69393ec8444ffa9bdcfae1469bd7d1a0","origin":"original upload-action log lines 1482,1484-1486","url":"https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43621754143/artifacts/14126950344","metadata_API_freshly_verified":False,"downloaded":False,"whole_zip_verified":False}
assert artifact["sha256"]in lines[1481]and"Final size is 7258904 bytes. Artifact ID is 14126950344"in lines[1484]
facts={"schema":"trnm-H5DF-required-head-protocol-outer-cause-review-v1","status":"OUTER_FAILURE_CONFIRMED_INNER_UNKNOWN","sealed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"job_id":132528769008,"run_id":43621754143,"attempt":1,"name":"protocol-contract","required14_member":True,"acquisition":sp,"acquisition_index":ip,"original_log":projection["log"],"metadata_raw":job["steps"][0]["stdout"],"actual_terminal":termpin,"actual_terminal_raw":rawpin,"observation_interval":{k:acq[k]for k in("started_at","finished_at","elapsed_seconds")},"GETs":2,"GET_exit_codes":[s["exit"]for s in job["steps"]],"HTTP_status_unparsed":True,"job_url":job["observed_job"]["html_url"],"failed_step":failed[0],"source_before_after":sources,"source_before_after_equal":True,"preparation_source_before":ctrl["preparation"]["source_before"]["tracked_source_identity"],"preparation_source_after":ctrl["preparation"]["source_after"]["tracked_source_identity"],"host_controller_line":cline,"original_host_controller":ctrlpin,"outer":{"native_command_argv":ctrl["command_argv"],"systemd_run_exit":ctrl["systemd_run_exit"],"passed":ctrl["passed"],"failure":ctrl["failure"],"final_host_errors":ctrl["final_host_errors"],"preparation_completed":ctrl["preparation"]["completed"],"format_exit":ctrl["preparation"]["format_preparation"]["process"]["exit_code"],"build_exit":ctrl["preparation"]["process"]["exit_code"],"preparation_binary_sha256":ctrl["preparation"]["binary_sha256"],"binary_downloaded":False},"error_lines":projection["failure_context"],"inner_failure":"UNKNOWN","native_manifest_acquired":False,"searched_specific_native_failure_tokens_present":projection["native_error_token_matches"],"artifact_from_original_upload":artifact,"limits":"Outer original log establishes this job's failure and source, not the inner failure code, original control outcomes or per-request time line. No reason is inherited from R1/cross-cost/service-model jobs.","no_additional_GET_artifact_native_or_source_ref_stage_change":True,"qualification":False}
factpin=put("exact-outer-facts.json",dump(facts))
selected=set([cline-1,1408,1481,1483,1484,1485])
for sr in sources:selected.update(range(sr["start_line"]-1,sr["end_line"]))
for i,s in enumerate(lines):
 if"run_from_zero_host.py"in s or"bash scripts/ci/ci_job.sh protocol-contract"in s:selected.add(i)
excpin=put("original-line-excerpts.json",dump({"original_log":projection["log"],"total_lines":len(lines),"lines":[{"line":i+1,"text":lines[i]}for i in sorted(selected)]}))
put("README.txt",b"Closed original required HEAD protocol job132528769008/run43621754143/attempt1. Two authorized GETs both completed. Actual source-before/after identifies H5DF/tree6be. Step8 failed; Host preparation build/fmt succeeded, systemd_run_exit=1, failure=null and final_host_errors=[]. Inner reason remains UNKNOWN because native manifest was not obtained. No inference from earlier jobs, no artifact/native execution, no CI or source/ref/stage changes. Raw acquisition receipt remains unchanged. Artifact ID/size/digest are quoted from original upload lines, not fresh artifact API validation.\n")
rows=index["files"]+[ip]+[pin(p)for p in sorted(E.iterdir())if p.is_file()]
for p in rows:stable(p)
idx=put("EVIDENCE_INDEX.json",dump({"schema":"trnm-H5DF-required-head-protocol-closed-review-index-v1","files":rows,"self_excluded":True,"count":len(rows),"bytes":sum(p["bytes"]for p in rows)}))
seal=put("seal-summary.json",dump({"schema":"trnm-H5DF-required-head-protocol-outer-seal-v1","status":facts["status"],"facts":factpin,"excerpts":excpin,"index":idx,"originals_unchanged":True,"no_active_network_or_writer_after_exit":True}))
print(json.dumps({"facts":factpin,"excerpts":excpin,"index":idx,"seal":seal,"actual_terminal":termpin,"artifact":artifact},sort_keys=True))
