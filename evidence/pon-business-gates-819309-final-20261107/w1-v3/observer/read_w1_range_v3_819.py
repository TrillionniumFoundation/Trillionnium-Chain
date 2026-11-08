from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os,re,selectors,signal,subprocess,sys,time
sys.dont_write_bytecode=True
R=Path("/home/qian-qi/throughput-final-ci-observation-20261107")
V=R/"w1-components-transport-v2-package";O=R/"w1-range-v3";D=O/"13586509176"
PREFIX=R/"w1-components-transport-v2/13586509176/artifact.zip"
ID=13586509176;START=170967040;TOTAL=174175856;TAIL=TOTAL-START;MAX_BODY=4*1024**2;LIMIT=120
PREFIX_SHA="7915efca8e574436400a7d9bb5c8e59c8681ba0522f77dd5b119fddafac5dae2"
FULL_SHA="d5e6720c1070b1772107be2d316aea6d27dfdf8dd68535103650730138e9bf38"
EXPECTED_RANGE=f"bytes {START}-{TOTAL-1}/{TOTAL}"
def require(v,m):
 if not v:raise ValueError(m)
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def save(p,v):
 with p.open("x") as f:json.dump(v,f,indent=2);f.write("\n")
def clean(s):
 s=re.sub(r"https?://[^\s\"<>]+","[redacted-url]",s)
 return re.sub(r"(?im)^(authorization|proxy-authorization):[^\r\n]*",r"\1: [redacted]",s)
def parse_headers(raw):
 require(len(raw)<=65536,"HTTP_HEADER_LIMIT")
 lines=raw.replace(b"\r\n",b"\n").decode("latin1").split("\n")
 require(bool(lines) and re.fullmatch(r"HTTP/[0-9]+(?:\.[0-9]+)? [0-9]{3}(?: .*)?",lines[0]) is not None,"HTTP_STATUS_LINE_MALFORMED")
 headers={}
 for line in lines[1:]:
  if not line:continue
  require(not line[0].isspace() and ":" in line,"HTTP_HEADER_MALFORMED")
  key,value=line.split(":",1);key=key.strip().lower();value=value.strip()
  if key in ("content-range","content-length","content-type","content-encoding"):
   require(key not in headers,"HTTP_GUARD_HEADER_DUPLICATE")
   require(len(value)<=256,"HTTP_GUARD_HEADER_LENGTH");headers[key]=clean(value)
 return {"status_line":clean(lines[0]),"status":int(lines[0].split()[1]),"headers":headers,"raw_headers_sha256":hashlib.sha256(raw).hexdigest(),"raw_header_bytes":len(raw)}
def validate_headers(info):
 require(info["status"]==206,"HTTP_STATUS_MUST_BE_206")
 h=info["headers"];require(h.get("content-range")==EXPECTED_RANGE,"CONTENT_RANGE_MISMATCH")
 if "content-length" in h:
  require(re.fullmatch(r"[0-9]+",h["content-length"]) is not None and int(h["content-length"])==TAIL,"CONTENT_LENGTH_MISMATCH")
 require(h.get("content-encoding","identity").lower()=="identity","CONTENT_ENCODING_MUST_PRESERVE_ORIGINAL_BYTES")
def check_body_size(n):
 require(n<=MAX_BODY,"RANGE_BODY_4MIB_LIMIT")
 require(n<=TAIL,"RANGE_BODY_EXCEEDS_DECLARED_TAIL")
def identity(label,record):
 cmd=["/usr/bin/gh","api","--hostname","github.com","--method","GET","user"]
 item={"argv":cmd,"timeout_seconds":30};record[label]=item
 try:
  c=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
  item.update(exit_code=c.returncode,timed_out=False,stdout_bytes=len(c.stdout),stdout_sha256=hashlib.sha256(c.stdout).hexdigest(),stderr_bytes=len(c.stderr),stderr_sanitized=clean(c.stderr.decode("utf-8","replace"))[:4096])
  require(c.returncode==0 and len(c.stdout)<=16384,"IDENTITY_GET_FAILED_OR_OVERSIZE")
  u=json.loads(c.stdout);item.update(login=u.get("login"),id=u.get("id"))
  require(u.get("login")=="ProfHepta" and u.get("id")==102159240,"IDENTITY_MUST_BE_PROFHEPTA")
  with (O/(label+".json")).open("xb") as f:f.write(c.stdout)
 except subprocess.TimeoutExpired as e:
  item.update(exit_code=None,timed_out=True);raise ValueError("IDENTITY_TIMEOUT") from e
def range_get(record):
 cmd=["/usr/bin/gh","api","--hostname","github.com","--method","GET","--include","--header",f"Range: bytes={START}-{TOTAL-1}","repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/13586509176/zip"]
 rr={"argv":cmd,"timeout_seconds":LIMIT,"maximum_body_bytes":MAX_BODY,"attempted":True,"completed":False,"timed_out":False,"process_exit_code":None,"body_bytes_observed":0,"body_bytes_retained":0,"stderr_bytes_observed":0,"stderr_text_truncated":False,"raw_headers_retained":False}
 record["range_get"]=rr
 start=time.monotonic_ns();deadline=time.monotonic()+LIMIT
 proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 sel=selectors.DefaultSelector();header=bytearray();err=bytearray();writer=None;header_done=False;failure=None
 for name,stream in (("stdout",proc.stdout),("stderr",proc.stderr)):
  os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,name)
 try:
  while sel.get_map():
   left=deadline-time.monotonic()
   if left<=0:rr["timed_out"]=True;raise TimeoutError("RANGE_GET_TIMEOUT_120S")
   events=sel.select(min(left,0.25))
   for key,_ in events:
    chunk=os.read(key.fileobj.fileno(),65536)
    if not chunk:sel.unregister(key.fileobj);continue
    if key.data=="stderr":
     rr["stderr_bytes_observed"]+=len(chunk)
     room=65536-len(err);err.extend(chunk[:max(room,0)])
     if len(chunk)>room:rr["stderr_text_truncated"]=True
     continue
    if not header_done:
     header.extend(chunk);positions=[(header.find(mark),len(mark)) for mark in (b"\r\n\r\n",b"\n\n") if header.find(mark)>=0]
     if not positions:
      require(len(header)<=65536,"HTTP_HEADER_LIMIT");continue
     at,width=min(positions);info=parse_headers(bytes(header[:at]));rr["http"]=info
     validate_headers(info);chunk=bytes(header[at+width:]);header.clear();header_done=True
     writer=(D/"tail.bin").open("xb")
    rr["body_bytes_observed"]+=len(chunk);check_body_size(rr["body_bytes_observed"])
    writer.write(chunk);rr["body_bytes_retained"]+=len(chunk)
  require(header_done,"HTTP_HEADER_NOT_COMPLETE")
  left=max(0,deadline-time.monotonic())
  try:code=proc.wait(timeout=left)
  except subprocess.TimeoutExpired as e:rr["timed_out"]=True;raise TimeoutError("RANGE_GET_TIMEOUT_120S") from e
  rr["process_exit_code"]=code
  require(code==0 and rr["body_bytes_retained"]==TAIL,"RANGE_PROCESS_OR_BODY_INCOMPLETE")
  rr["completed"]=True
 except Exception as e:
  failure=e;rr["error"]=type(e).__name__+": "+str(e)
  if proc.poll() is None:
   os.killpg(proc.pid,signal.SIGKILL);rr["observer_terminated_own_gh_process_group"]=True
  try:rr["process_exit_code"]=proc.wait(timeout=5)
  except subprocess.TimeoutExpired:rr["process_exit_code"]=None
 finally:
  if writer is not None:writer.close()
  rr["elapsed_ns"]=time.monotonic_ns()-start
  rr["stderr_sanitized"]=clean(err.decode("utf-8","replace"))
  rr["stderr_observed_sha256"]=hashlib.sha256(err).hexdigest()
  rr["unread_pipe_or_kernel_body_bytes_unknown"]=failure is not None
  sel.close()
  for stream in (proc.stdout,proc.stderr):stream.close()
  tail=D/"tail.bin"
  if tail.exists():rr["tail_file"]={"path":str(tail),"bytes":tail.stat().st_size,"sha256":sha(tail)}
 if failure is not None:raise failure
def main():
 seal=json.loads((V/"SEAL.json").read_bytes())
 require(sha(V/"SHA256SUMS")==seal["sha256sums_sha256"] and sha(V/"W1_COVERAGE.json")==seal["coverage_sha256"],"V2_MUST_BE_FULLY_SEALED")
 rows=json.loads((V/"EXTERNAL_ARCHIVES.json").read_bytes());matches=[x for x in rows if x["artifact_id"]==ID]
 require(len(matches)==1,"SEALED_PARTIAL_IDENTITY");old=matches[0]
 require(old["download_timed_out"] is True and old["actual_bytes"]==START and old["actual_sha256"]==PREFIX_SHA and old["github_expected_bytes"]==TOTAL and old["github_expected_digest"]=="sha256:"+FULL_SHA and old["archive_path"]==str(PREFIX),"SEALED_PARTIAL_BINDING")
 require(PREFIX.is_file() and not PREFIX.is_symlink() and PREFIX.stat().st_size==START and sha(PREFIX)==PREFIX_SHA,"PRESERVED_PARTIAL_BYTES")
 O.mkdir();D.mkdir()
 rec={"schema":"trnm-final819-one-range-v3-receipt","artifact_id":ID,"candidate":"819309fd312298e099642e1253b1d4ba07113e98","original_workflow_run":42402618462,"v2_seal_sha256":sha(V/"SEAL.json"),"completed":False,"errors":[],"no_ci_or_native_execution":True,"business_qualification":False,"started_utc":datetime.now(timezone.utc).isoformat()}
 plan={"schema":"trnm-final819-one-range-v3-plan","artifact_id":ID,"prefix_path":str(PREFIX),"prefix_bytes":START,"prefix_sha256":PREFIX_SHA,"range_header":f"bytes={START}-{TOTAL-1}","required_content_range":EXPECTED_RANGE,"required_http_status":206,"body_limit_bytes":MAX_BODY,"body_expected_bytes":TAIL,"get_timeout_seconds":LIMIT,"range_get_attempts":1,"expected_complete_archive_bytes":TOTAL,"expected_complete_archive_sha256":FULL_SHA,"original_v1_v2_core14_unchanged":True,"identity_reads_only_other_network_calls":True,"v2_seal_sha256":rec["v2_seal_sha256"]}
 save(O/"plan.json",plan)
 ok_before=False
 try:
  identity("identity-before",rec);ok_before=True
  range_get(rec)
  full=D/"artifact.zip";h=hashlib.sha256();n=0;ph=hashlib.sha256()
  with full.open("xb") as out:
   for src in (PREFIX,D/"tail.bin"):
    with src.open("rb") as inp:
     for block in iter(lambda:inp.read(1048576),b""):
      out.write(block);h.update(block);n+=len(block)
      if src==PREFIX:ph.update(block)
  require(ph.hexdigest()==PREFIX_SHA and n==TOTAL and h.hexdigest()==FULL_SHA,"ASSEMBLED_ORIGINAL_ARCHIVE_DIGEST_MISMATCH")
  require(PREFIX.stat().st_size==START and sha(PREFIX)==PREFIX_SHA,"ORIGINAL_PARTIAL_CHANGED")
  rec["assembled_archive"]={"path":str(full),"bytes":n,"sha256":h.hexdigest(),"complete_github_size_digest_matched":True,"original_partial_unchanged":True,"body_was_only_original_tail":True}
  rec["completed"]=True
 except Exception as e:rec["errors"].append(type(e).__name__+": "+str(e));rec["completed"]=False
 finally:
  if ok_before:
   try:identity("identity-after",rec)
   except Exception as e:rec["errors"].append(type(e).__name__+": "+str(e));rec["completed"]=False
  rec["finished_utc"]=datetime.now(timezone.utc).isoformat();save(O/"receipt.json",rec)
 print(json.dumps({"directory":str(O),"completed":rec["completed"],"errors":rec["errors"],"http":rec.get("range_get",{}).get("http"),"body_bytes":rec.get("range_get",{}).get("body_bytes_retained"),"assembled_archive":rec.get("assembled_archive")}),flush=True)
 return 0 if rec["completed"] else 1
if __name__=="__main__":raise SystemExit(main())
