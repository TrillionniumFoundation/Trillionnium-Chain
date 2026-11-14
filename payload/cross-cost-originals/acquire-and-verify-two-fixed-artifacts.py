import concurrent.futures,datetime,hashlib,json,os,pathlib,re,signal,stat,subprocess,sys,threading,time,zipfile,zlib
E=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3")
L=pathlib.Path("/private/tmp/chain-R1-required-cross-arch-cost-log-review-20261114-v2")
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64";RUN=43604217412
ROWS=[
{"id":14119000610,"arch":"arm64","job":132481412245,"name":"cost-arm64-"+HEAD+"-1","bytes":9927038,"sha256":"8249d0279e12e95bb59da7644b3d62ca1243589f9488b26e3b2b95560c9735ff","log_bytes":184625,"log_sha256":"2563aac4968c906fa6664d84be5ba069093d0dc3bbdc7a055b9f0f796098b170"},
{"id":14119380013,"arch":"x64","job":132481412405,"name":"cost-x64-"+HEAD+"-1","bytes":9851618,"sha256":"d46ce31d5db37912f19115160d8b46e0bf32597fb3c4976a9c80b70bcc3df456","log_bytes":184966,"log_sha256":"e42c8af82a6600ef7dfe65c8e57d96728c3f38f5f0a8df54af0b62d921c4b8a4"}]
lock=threading.Lock()
def need(v,m):
 if not v:raise ValueError(m)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def emit(v):
 with lock:print(json.dumps(v,sort_keys=True),flush=True)
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def fi(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,"rb") as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,"regular output")
  h=hashlib.sha256();n=0
  while True:
   b=f.read(65536)
   if not b:break
   h.update(b);n+=len(b)
  z=os.fstat(f.fileno())
 need(identity(a)==identity(z)==identity(p.lstat()) and n==a.st_size,"stable file")
 return {"path":str(p),"bytes":n,"sha256":h.hexdigest()}
def put(p,b):
 with p.open("xb") as f:f.write(b)
 return fi(p)
need(not E.exists(),"create only");E.mkdir(mode=0o700)
put(E/"acquire-and-verify-two-fixed-artifacts.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
put(E/"requested-artifacts.json",jb({"run_id":RUN,"run_attempt":1,"head":HEAD,"artifacts":ROWS,"full_ZIP_GET_timeout_seconds":1200,"no_automatic_retry":True}))
ENV={k:v for k,v in os.environ.items() if k!="GH_DEBUG" and not k.startswith("GIT_TRACE") and k!="GIT_CURL_VERBOSE"}
ENV["GH_PAGER"]="cat";ENV["GH_PROMPT_DISABLED"]="1";ENV["PYTHONDONTWRITEBYTECODE"]="1"
def capture(label,endpoint,timeout,cap,stdout_name=None):
 argv=["/opt/homebrew/bin/gh","api","--hostname","github.com","--method","GET","-H","Accept: application/vnd.github+json","-H","X-GitHub-Api-Version: 2026-03-10",endpoint]
 op=E/(stdout_name or label+".stdout");ep=E/(label+".stderr");started=now();clock=time.monotonic()
 with op.open("xb") as fo,ep.open("xb") as fe:
  proc=subprocess.Popen(argv,cwd=E,env=ENV,stdin=subprocess.DEVNULL,stdout=fo,stderr=fe,start_new_session=True)
  start={"label":label,"argv":argv,"cwd":str(E),"pid":proc.pid,"started_at":started,"timeout_seconds":timeout,"stdout_cap_bytes":cap,"stderr_cap_bytes":1048576,"stdout_path":str(op),"stderr_path":str(ep),"automatic_retry":False}
  put(E/(label+".start.json"),jb(start));emit({"event":"started","label":label,"pid":proc.pid,"time":started,"timeout_seconds":timeout})
  timeout_reached=False;size_exceeded=False;next_progress=30
  while proc.poll() is None:
   elapsed=time.monotonic()-clock;n=op.stat().st_size
   if elapsed>=next_progress:
    emit({"event":"progress","label":label,"pid":proc.pid,"elapsed_seconds":elapsed,"stdout_bytes":n,"stderr_bytes":ep.stat().st_size,"time":now()});next_progress+=30
   if elapsed>=timeout:timeout_reached=True;break
   if n>cap or ep.stat().st_size>1048576:size_exceeded=True;break
   time.sleep(.2)
  if timeout_reached or size_exceeded:
   os.killpg(proc.pid,signal.SIGKILL);actual=proc.wait(timeout=10);code=124 if timeout_reached else 125
  else:actual=proc.returncode;code=actual
 row={**start,"completed_at":now(),"elapsed_seconds":time.monotonic()-clock,"timeout_reached":timeout_reached,"size_exceeded":size_exceeded,"exit_code":code,"process_returncode":actual,"stdout":fi(op),"stderr":fi(ep)}
 put(E/(label+".step.json"),jb(row));emit({"event":"completed","label":label,"pid":proc.pid,"exit_code":code,"stdout_bytes":row["stdout"]["bytes"],"stdout_sha256":row["stdout"]["sha256"],"stderr":row["stderr"],"time":row["completed_at"]})
 return row
def verify_zip(p,row):
 stable=fi(p);need(stable["bytes"]==row["bytes"] and stable["sha256"]==row["sha256"],"whole official ZIP size/SHA")
 seen=set();total=0;files=[]
 with zipfile.ZipFile(p) as z:
  infos=z.infolist();need(len(infos)<=10000,"member count")
  for i in infos:
   name=i.filename;pp=pathlib.PurePosixPath(name)
   need(name and not name.startswith("/") and "\\" not in name and "\x00" not in name and all(ord(c)>=32 for c in name),"safe member characters")
   need(all(x not in ("",".","..") for x in pp.parts) and str(pp)==name.rstrip("/"),"canonical member")
   need(name not in seen,"duplicate member");seen.add(name)
   mode=i.external_attr>>16;kind=stat.S_IFMT(mode)
   need(kind in (0,stat.S_IFREG,stat.S_IFDIR) and not i.flag_bits&1,"regular unencrypted member")
   need(i.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED),"known compression")
   need(i.file_size<=256*1024*1024,"member size bound")
   if i.is_dir():need(i.file_size==0,"empty directory entry");continue
   total+=i.file_size;need(total<=512*1024*1024,"whole uncompressed bound")
   h=hashlib.sha256();crc=0;n=0
   with z.open(i) as f:
    while True:
     b=f.read(65536)
     if not b:break
     h.update(b);crc=zlib.crc32(b,crc);n+=len(b)
   need(n==i.file_size and crc&0xffffffff==i.CRC,"full CRC/size")
   files.append({"path":name,"bytes":n,"sha256":h.hexdigest(),"crc32":format(i.CRC,"08x"),"compressed_bytes":i.compress_size,"mode":mode})
 need(fi(p)==stable,"ZIP changed during verification")
 index={"schema":"trnm-original-artifact-full-member-index-v1","artifact_id":row["id"],"zip":stable,"member_count":len(infos),"file_count":len(files),"total_uncompressed_bytes":total,"all_members_CRC_SHA256_verified":True,"files":files,"manifest_filemap_validated":False,"no_inner_code_executed":True,"no_members_extracted":True}
 pin=put(E/(str(row["id"])+".index.json"),jb(index))
 emit({"event":"ZIP_members_verified","artifact_id":row["id"],"files":len(files),"uncompressed_bytes":total,"index":pin,"time":now()})
 return pin
def one(row):
 result={"requested":row,"metadata":None,"binding":None,"download":None,"member_index":None,"errors":[]}
 try:
  log=L/("job-"+str(row["job"])+"-original-log.stdout");pin=fi(log)
  need(pin["bytes"]==row["log_bytes"] and pin["sha256"]==row["log_sha256"],"original upload log pin")
  text=log.read_text();need(row["name"] in text and str(row["id"]) in text and str(row["bytes"]) in text and row["sha256"] in text,"upload original declared tuple")
  result["upload_log"]=pin
  endpoint="repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/"+str(row["id"])
  result["metadata"]=capture("artifact-"+str(row["id"])+"-metadata",endpoint,90,2*1024*1024)
  need(result["metadata"]["exit_code"]==0,"metadata GET failed; no automatic retry")
  m=json.loads((E/("artifact-"+str(row["id"])+"-metadata.stdout")).read_bytes());w=m.get("workflow_run") or {}
  checks={"id":m.get("id")==row["id"],"name":m.get("name")==row["name"],"size":m.get("size_in_bytes")==row["bytes"],"digest":m.get("digest")=="sha256:"+row["sha256"],"run_id":w.get("id")==RUN,"head_sha":w.get("head_sha")==HEAD,"not_expired":m.get("expired") is False}
  result["binding"]={"checks":checks,"metadata_fields":{"id":m.get("id"),"name":m.get("name"),"size_in_bytes":m.get("size_in_bytes"),"digest":m.get("digest"),"expired":m.get("expired"),"workflow_run":w,"archive_download_url":m.get("archive_download_url")},"attempt_bound_by":"Original fixed job metadata/run_attempt1 and exact artifact name suffix -1; artifact metadata itself has no assumed attempt field."}
  need(all(checks.values()),"artifact metadata mismatch; no ZIP download")
  result["download"]=capture("artifact-"+str(row["id"])+"-zip",endpoint+"/zip",1200,row["bytes"]+65536,str(row["id"])+".zip")
  need(result["download"]["exit_code"]==0,"official ZIP GET failed; not retried")
  result["member_index"]=verify_zip(E/(str(row["id"])+".zip"),row)
 except Exception as exc:result["errors"].append({"type":type(exc).__name__,"message":str(exc)})
 put(E/(str(row["id"])+".completion.json"),jb(result))
 return result
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 futures=[pool.submit(one,x) for x in ROWS];results=[f.result() for f in futures]
summary={"schema":"trnm-R1-cross-arch-artifact-acquisition-v3","status":"ZIP_AND_ALL_MEMBERS_VERIFIED" if all(not x["errors"] for x in results) else "HOLD_PARTIAL_OR_FAILED","run_id":RUN,"head":HEAD,"run_attempt":1,"artifacts":results,"manifest_filemap_and_inner_diagnosis":"PENDING_SEPARATE_READONLY_REVIEW","tests_or_native_execution":False,"source_CI_Git_stage_changed":False,"automatic_retry":False,"completed_at":now()}
pin=put(E/"acquisition-summary.json",jb(summary))
emit({"event":"terminal","status":summary["status"],"summary":pin,"artifacts":[{"id":x["requested"]["id"],"index":x["member_index"],"errors":x["errors"]} for x in results]})
