import pathlib,os,sys,json,hashlib,datetime,time,urllib.request,urllib.parse,zipfile,stat,re
D=json.loads(sys.argv[1]);SELF=sys.argv[2];O=pathlib.Path("/private/tmp/chain-prci-N-x64-native-artifact-14109658844-20261114-v1")
assert not O.exists();O.mkdir(mode=0o700);os.umask(0o077)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def js(x):return(json.dumps(x,indent=2)+"\n").encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def save(n,b):
 p=O/n
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==b
 return{"path":str(p),"bytes":len(b),"sha256":sha(b)}
def fi(p):
 h=hashlib.sha256();n=0
 with p.open("rb")as f:
  for b in iter(lambda:f.read(65536),b""):h.update(b);n+=len(b)
 return{"path":str(p),"bytes":n,"sha256":h.hexdigest()}
a=D["artifact"];assert a["id"]==14109658844 and a["workflow_run"]["id"]==43582713392 and a["workflow_run"]["head_sha"]=="5a4b7fe8de1adce803184f262fd9f704ead1930c" and a["size_in_bytes"]==9884207 and a["digest"]=="sha256:10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4" and a["expired"]is False
save("producer.py",SELF.encode());save("fixed-inputs-and-official-tool-provenance.json",js(D))
url=os.environ["TRNM_N_COST_REUSABLE_FILE_URL"];u=urllib.parse.urlsplit(url);assert u.scheme=="https"and u.hostname=="sdmntprwestus3.oaiusercontent.com"and u.path.startswith("/files/")and not u.username and not u.password
class NoCrossHost(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  p=urllib.parse.urlsplit(newurl)
  if p.scheme!="https"or p.hostname!=u.hostname:raise ValueError("unexpected reusable-file redirect host")
  return super().redirect_request(req,fp,code,msg,headers,newurl)
started=now();tick=time.monotonic();deadline=tick+120;part=O/"N-cost-x64-14109658844.zip.partial";receipt={"schema":"trnm-N-single-artifact-reusable-file-transfer-v1","started_at":started,"artifact_id":a["id"],"run_id":a["workflow_run"]["id"],"head":a["workflow_run"]["head_sha"],"metadata_digest":a["digest"],"file_reference":D["file_reference"],"official_artifact_GET_calls":1,"reusable_file_GET_calls":1,"reusable_file_url_redacted":{"scheme":u.scheme,"hostname":u.hostname,"path":u.path},"signed_query_or_authorization_headers_saved":False,"compressed_cap_bytes":20*1024*1024,"timeout_seconds":120,"read_socket_timeout_seconds":30};error=None;n=0;h=hashlib.sha256();status=None;headers={}
try:
 req=urllib.request.Request(url,method="GET")
 with urllib.request.build_opener(NoCrossHost).open(req,timeout=30)as res,part.open("xb")as out:
  status=res.status;assert status==200
  headers={k:res.headers.get(k)for k in("Content-Length","Content-Type","ETag","Last-Modified","Date","Content-Range")if res.headers.get(k)is not None}
  if "Content-Length"in headers:assert int(headers["Content-Length"])==9884207
  while True:
   if time.monotonic()>deadline:raise TimeoutError("reusable-file transfer exceeded original bound")
   b=res.read(min(65536,20*1024*1024-n+1))
   if not b:break
   if n+len(b)>20*1024*1024:raise ValueError("compressed cap exceeded")
   out.write(b);h.update(b);n+=len(b)
  out.flush();os.fsync(out.fileno())
 assert n==9884207 and h.hexdigest()==a["digest"].split(":")[1],"complete artifact size/digest mismatch"
 zip_path=O/"N-cost-x64-14109658844.zip";os.rename(part,zip_path)
 receipt.update(status="complete",http_status=status,headers=headers,bytes=n,sha256=h.hexdigest(),elapsed_seconds=round(time.monotonic()-tick,3),finished_at=now(),whole_API_digest_verified=True)
except Exception as e:
 receipt.update(status="UNKNOWN_or_failed",http_status=status,headers=headers,bytes=n,sha256=h.hexdigest(),error=type(e).__name__+": "+str(e),elapsed_seconds=round(time.monotonic()-tick,3),finished_at=now(),whole_API_digest_verified=False)
 save("transport.json",js(receipt));print(json.dumps({"status":receipt["status"],"bytes":n,"error":receipt["error"]}),flush=True);sys.exit(1)
transport=save("transport.json",js(receipt));rows=[];actual_total=0
try:
 with zipfile.ZipFile(zip_path,"r")as z:
  infos=z.infolist();assert len(infos)<=512
  names=set();declared=0
  for x in infos:
   p=pathlib.PurePosixPath(x.filename);mode=x.external_attr>>16
   assert x.filename and not x.filename.startswith(("/","\\"))and "\\"not in x.filename and "\x00"not in x.filename and not re.match(r"^[A-Za-z]:",x.filename)
   assert ".."not in p.parts and str(p)==x.filename.rstrip("/") and x.filename not in names and not stat.S_ISLNK(mode) and not(x.flag_bits&1)
   assert stat.S_IFMT(mode)in(0,stat.S_IFREG,stat.S_IFDIR) and x.file_size<=32*1024*1024
   names.add(x.filename);declared+=x.file_size;assert declared<=128*1024*1024
  for x in infos:
   h=hashlib.sha256();size=0
   with z.open(x,"r")as f:
    for b in iter(lambda:f.read(65536),b""):
     size+=len(b);actual_total+=len(b);assert size<=32*1024*1024 and actual_total<=128*1024*1024;h.update(b)
   assert size==x.file_size
   rows.append({"path":x.filename,"bytes":size,"compressed_bytes":x.compress_size,"sha256":h.hexdigest(),"crc32":format(x.CRC,"08x"),"directory":x.is_dir(),"mode":mode})
 assert actual_total==declared
except Exception as e:
 failure=save("zip-validation-failure.json",js({"status":"failed","error":type(e).__name__+": "+str(e),"transport":transport,"whole_zip_digest_verified":True,"member_validation_completed":False,"members_completed":len(rows),"bytes_processed":actual_total}))
 print(json.dumps({"status":"zip_validation_failed","failure":failure}),flush=True);sys.exit(1)
index=save("ZIP_MEMBER_INDEX.json",js({"schema":"trnm-N-original-native-artifact-member-index-v1","artifact":a,"zip":fi(zip_path),"member_count":len(rows),"uncompressed_bytes":actual_total,"bounds":{"compressed_bytes":20*1024*1024,"members":512,"individual_file_bytes":32*1024*1024,"uncompressed_bytes":128*1024*1024},"all_member_crc_size_sha_verified":True,"all_paths_safe_and_unique":True,"extracted_members":[],"files":rows,"package_code_executed":False}))
summary=save("summary.json",js({"schema":"trnm-N-x64-original-native-artifact-custody-v1","status":"whole_zip_and_members_verified","artifact":a,"transport":transport,"zip":fi(zip_path),"index":index,"member_count":len(rows),"uncompressed_bytes":actual_total,"source_stage_git_CI_mutations":False,"package_code_executed":False,"inner_failure_not_yet_interpreted":True,"finished_at":now()}))
print(json.dumps({"status":"whole_zip_and_members_verified","summary":summary,"zip":fi(zip_path),"index":index,"transport":transport,"member_count":len(rows),"uncompressed_bytes":actual_total,"candidate_members":[r for r in rows if any(t in r["path"]for t in("from-zero","source-before","source-after","manifest.json"))]}),flush=True)
