from pathlib import Path,PurePosixPath
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib,json,os,re,resource,shutil,stat,subprocess,time,zipfile
SPEC=json.loads("[{\"job_id\":128662229865,\"label\":\"new-jobs/128662229865\",\"source\":\"2bdd252aa6c300b7431b9ee897b254b7953cf562\"},{\"job_id\":128662229758,\"label\":\"new-jobs/128662229758\",\"source\":\"2bdd252aa6c300b7431b9ee897b254b7953cf562\"},{\"job_id\":128662229491,\"label\":\"new-jobs/128662229491\",\"source\":\"2bdd252aa6c300b7431b9ee897b254b7953cf562\"},{\"job_id\":128660701948,\"label\":\"new-jobs/128660701948\",\"source\":\"2bdd252aa6c300b7431b9ee897b254b7953cf562\"},{\"job_id\":128660701711,\"label\":\"new-jobs/128660701711\",\"source\":\"2bdd252aa6c300b7431b9ee897b254b7953cf562\"},{\"job_id\":128660701637,\"label\":\"new-jobs/128660701637\",\"source\":\"2bdd252aa6c300b7431b9ee897b254b7953cf562\"},{\"job_id\":128660701605,\"label\":\"new-jobs/128660701605\",\"source\":\"2bdd252aa6c300b7431b9ee897b254b7953cf562\"},{\"job_id\":128660701377,\"label\":\"new-jobs/128660701377\",\"source\":\"2bdd252aa6c300b7431b9ee897b254b7953cf562\"},{\"job_id\":128655993256,\"label\":\"history/replica-1\",\"source\":\"96a241bf43f6a46d35dfb3d4ced9594ed8ceca75\"},{\"job_id\":128655993533,\"label\":\"history/replica-2\",\"source\":\"96a241bf43f6a46d35dfb3d4ced9594ed8ceca75\"}]")
OUT=Path("/home/qian-qi/work/chain-w1-c6-later-failures-and-history-20261108-ec265b-01")
CACHE=Path(str(OUT)+"-download-cache");CACHE.mkdir(exist_ok=False)
gh=shutil.which("gh");assert gh
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  while b:=f.read(1024*1024):h.update(b)
 return h.hexdigest()
def jput(path,d):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("x") as f:json.dump(d,f,sort_keys=True,indent=2);f.write("\n")
def cap():resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024*1024,128*1024*1024))
def fetch(s):
 base=OUT/s["label"];rawlog=(base/"job.log").read_text()
 ids=sorted(set(re.findall(r"Artifact ID(?: is)? (\d+)",rawlog)))
 assert len(ids)==1,(s["job_id"],ids)
 aid=int(ids[0]);endpoint=f"repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/{aid}"
 result=dict(s,artifact_id=aid,started_unix_ns=time.time_ns(),read_only=True)
 meta=subprocess.run([gh,"api",endpoint],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
 (base/"artifact-metadata.raw.json").write_bytes(meta.stdout);(base/"artifact-metadata.stderr").write_bytes(meta.stderr)
 result["metadata_exit"]=meta.returncode;result["metadata_sha256"]=hashlib.sha256(meta.stdout).hexdigest()
 if meta.returncode:
  result["error"]="metadata-fetch-failed";jput(base/"artifact-fetch.json",result);return result
 m=json.loads(meta.stdout)
 result["metadata_source"]=m.get("workflow_run",{}).get("head_sha")
 result["metadata_size"]=m.get("size_in_bytes");result["metadata_digest"]=m.get("digest")
 assert result["metadata_source"]==s["source"],(s,m)
 assert m.get("expired") is False and m["size_in_bytes"]<=128*1024*1024
 path=CACHE/f"{aid}.zip";err=base/"artifact-download.stderr"
 argv=[gh,"api",endpoint+"/zip"];result["argv"]=argv;timeout=False;exception=None
 with path.open("xb") as of,err.open("xb") as ef:
  try:p=subprocess.run(argv,stdout=of,stderr=ef,timeout=120,preexec_fn=cap);rc=p.returncode
  except subprocess.TimeoutExpired:rc=None;timeout=True
  except Exception as e:rc=None;exception=repr(e)
 result.update({"exit_code":rc,"timed_out":timeout,"exception":exception,"cache_path":str(path),
  "archive_bytes":path.stat().st_size,"archive_sha256":sha(path),"finished_unix_ns":time.time_ns()})
 if rc==0:
  result["metadata_digest_matches"]=(m.get("digest") is None or m["digest"]=="sha256:"+result["archive_sha256"])
  result["metadata_size_matches"]=m["size_in_bytes"]==path.stat().st_size
  with zipfile.ZipFile(path) as z:
   members=[]
   for i in z.infolist():
    pp=PurePosixPath(i.filename)
    assert not pp.is_absolute() and ".." not in pp.parts
    mode=(i.external_attr>>16)&0xffff;assert not stat.S_ISLNK(mode)
    members.append({"name":i.filename,"bytes":i.file_size,"compressed_bytes":i.compress_size,"crc32":f"{i.CRC:08x}","is_dir":i.is_dir()})
   jput(base/"artifact-members.json",{"artifact_id":aid,"archive_sha256":result["archive_sha256"],"members":members})
   candidate=[i for i in members if not i["is_dir"] and re.search(r"(summary|manifest|report|receipt|result|resources|stderr|stdout|host-controller|public-host|diagnostic|campaign)",i["name"],re.I) and re.search(r"\.(json|jsonl|log|txt|stderr|stdout)$",i["name"]) and i["bytes"]<=24*1024*1024]
   result["member_count"]=len(members);result["candidate_count"]=len(candidate)
   jput(base/"artifact-candidates.json",candidate)
   print(json.dumps({"job_id":s["job_id"],"artifact_id":aid,"bytes":result["archive_bytes"],"sha256":result["archive_sha256"],
    "matches":result["metadata_digest_matches"] and result["metadata_size_matches"],"candidate_count":len(candidate),
    "candidates":candidate[:24]}),flush=True)
 jput(base/"artifact-fetch.json",result)
 return result
records=[]
with ThreadPoolExecutor(max_workers=2) as pool:
 for f in as_completed([pool.submit(fetch,s) for s in SPEC]):
  records.append(f.result())
jput(OUT/"artifact-fetch-manifest.json",{"schema":"TRNM-W1-C6-LATER-ARTIFACT-READ1","requests":records,
 "GET_count":len(records)*2,"read_only":True,"cache_not_public_evidence":True,"no_members_extracted_yet":True})
print(json.dumps({"finished":True,"requests":len(records),"raw_archive_total_bytes":sum(r.get("archive_bytes",0) for r in records),
 "failed":[r for r in records if r.get("exit_code")!=0]}),flush=True)
