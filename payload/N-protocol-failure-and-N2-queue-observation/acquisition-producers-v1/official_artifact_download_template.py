import concurrent.futures,hashlib,json,os,pathlib,stat,time,urllib.request,urllib.parse,zipfile
ROOT=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1")
D=ROOT/"official-complete-artifacts-v1";D.mkdir(mode=0o700)
# FETCHES is supplied solely from the official connector's returned file references.
FETCHES = OFFICIAL_EPHEMERAL_FILE_REFERENCES
class GuardedRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  u=urllib.parse.urlparse(newurl)
  if u.scheme!="https" or u.hostname!="sdmntprwestus3.oaiusercontent.com":raise ValueError("redirect outside official fixed host")
  return super().redirect_request(req,fp,code,msg,headers,newurl)
def utc():return time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
def one(item):
 aid=item["artifact_id"];p=D/(str(aid)+".zip");begin=utc();clock=time.monotonic()
 row={k:v for k,v in item.items() if k!="url"};row.update({"started_at":begin,"original_public_artifact_endpoint":"https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/"+str(aid)+"/zip","official_temporary_url_not_retained":True})
 try:
  u=urllib.parse.urlparse(item["url"]);assert u.scheme=="https" and u.hostname=="sdmntprwestus3.oaiusercontent.com"
  opener=urllib.request.build_opener(GuardedRedirect())
  count=0;h=hashlib.sha256()
  with opener.open(urllib.request.Request(item["url"],method="GET"),timeout=30) as response,p.open("xb") as f:
   assert response.status==200
   while True:
    if time.monotonic()-clock>120:raise TimeoutError("bounded download deadline")
    b=response.read(65536)
    if not b:break
    count+=len(b)
    if count>item["bytes"]:raise ValueError("artifact larger than metadata")
    f.write(b);h.update(b)
   f.flush();os.fsync(f.fileno())
  assert count==item["bytes"] and h.hexdigest()==item["sha256"]
  s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
  members=[];total=0
  with zipfile.ZipFile(p,"r") as z:
   infos=z.infolist();assert len(infos)<=1000 and len({x.filename for x in infos})==len(infos)
   for info in infos:
    q=pathlib.PurePosixPath(info.filename)
    assert not q.is_absolute() and str(q)==info.filename and all(t not in ("..",".git","") for t in q.parts)
    assert "\\" not in info.filename and all(ord(c)>=32 and ord(c)!=127 for c in info.filename)
    assert not info.is_dir() and not stat.S_ISLNK(info.external_attr>>16) and not(info.flag_bits&1)
    total+=info.file_size
    assert info.file_size<=32*1024*1024 and total<=128*1024*1024
    data=z.read(info.filename)
    assert len(data)==info.file_size
    members.append({"path":info.filename,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"crc32":format(info.CRC,"08x"),"compressed_bytes":info.compress_size})
  ss=p.lstat();assert (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(ss.st_dev,ss.st_ino,ss.st_size,ss.st_mtime_ns,ss.st_ctime_ns)
  index={"schema":"trnm-N-protocol-original-artifact-member-index-v1","artifact_id":aid,"original_zip_bytes":count,"original_zip_sha256":h.hexdigest(),"member_count":len(members),"member_bytes":total,"every_member_crc_bytes_sha256_verified":True,"files":members}
  raw=(json.dumps(index,indent=2,sort_keys=True)+"\n").encode()
  with (D/(str(aid)+".index.json")).open("xb") as f:f.write(raw)
  row.update({"status":"COMPLETE_API_AND_UPLOAD_SHA_AND_ALL_MEMBER_CRC_VERIFIED","zip_path":str(p),"downloaded_bytes":count,"actual_sha256":h.hexdigest(),"member_count":len(members),"member_bytes":total,"index_bytes":len(raw),"index_sha256":hashlib.sha256(raw).hexdigest(),"relevant_member_names":[x["path"] for x in members if any(t in x["path"] for t in ["manifest.json","confirmation/report","process.json","host/inside","host/stderr","host/stdout"]) ]})
 except BaseException as e:
  row.update({"status":"INCOMPLETE_OR_REJECTED","error_type":type(e).__name__,"partial_file_preserved":p.exists(),"partial_bytes":p.stat().st_size if p.exists() else 0})
 row.update({"finished_at":utc(),"elapsed_seconds":time.monotonic()-clock})
 with (D/(str(aid)+".receipt.json")).open("xb") as f:f.write((json.dumps(row,indent=2,sort_keys=True)+"\n").encode())
 return row
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:rows=list(pool.map(one,FETCHES))
summary={"schema":"trnm-N-protocol-two-official-complete-artifacts-v1","only_original_artifact_reads":True,"artifact_code_executed":False,"source_git_stage_tests_mutated":False,"artifacts":rows}
with (D/"summary.json").open("xb") as f:f.write((json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
print(json.dumps(summary,sort_keys=True))
