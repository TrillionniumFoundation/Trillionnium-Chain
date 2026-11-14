#!/usr/bin/env python3
"""Three explicitly authorized small artifacts; six GETs maximum, no retries or native execution."""
import concurrent.futures,datetime,hashlib,io,json,os,re,selectors,stat,subprocess,sys,time,zipfile,zlib
from pathlib import Path,PurePosixPath
OUT=Path("/private/tmp/chain-prci-R1-budget-three-artifact-originals-20261114-v1")
LOGS=Path("/private/tmp/chain-consolidation-20261114-root/R1-other-failed-job-original-logs-v1")
GH="/opt/homebrew/bin/gh"
REPO="TrillionniumFoundation/Trillionnium-Chain"
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
RUN=43604217513
SPECS=[
  {
    "job": 132475258169,
    "component": "pool-scan-before",
    "subject": "ae657e262278ae4a058220f66a6a0495721eb9ad",
    "artifact": 14117367614,
    "name": "pon-budget-controls-pool-scan-before-ae657e262278ae4a058220f66a6a0495721eb9ad-1",
    "bytes": 6927,
    "sha256": "7c05f187fb5395fcddf250f6e772f366d7de7636824a9546cf4ca7b050ad22ed",
    "log_bytes": 323275,
    "log_sha": "24a5a568afc63d5135c485e9c61312fddbaf05696c5b678a87978b131d1f515b",
    "old_metadata": {
      "path": "/private/tmp/chain-consolidation-20261114-root/R1-other-failed-job-original-logs-v1/132475258169-metadata.stdout",
      "bytes": 3038,
      "sha256": "7c0c25705570c65aa2b4b51279e86d4e84eba6ed04ce3097264112df42730054"
    }
  },
  {
    "job": 132475258063,
    "component": "budget-before-v2",
    "subject": "89fb2269b0dd306fbd32c36f464842c3d7daee2b",
    "artifact": 14117727292,
    "name": "pon-budget-controls-budget-before-v2-89fb2269b0dd306fbd32c36f464842c3d7daee2b-1",
    "bytes": 7142,
    "sha256": "6001cd25a2166e59a314a89d2d04c426dadbc083182922c9f443cbb8359db77f",
    "log_bytes": 323222,
    "log_sha": "eed776ed4458c1410f4d264576cfa6aab417a8159db985226756252f202a8f80",
    "old_metadata": {
      "path": "/private/tmp/chain-consolidation-20261114-root/R1-other-failed-job-original-logs-v1/132475258063-metadata.stdout",
      "bytes": 3038,
      "sha256": "f32a5190e5e7bd17daae21f0c958d910dd304479a2b4b28f4d96ca6085f83b19"
    }
  },
  {
    "job": 132475257835,
    "component": "pool-before-v2",
    "subject": "84e68b4f7a9b2f48f9c47ed05c9a44229d186e30",
    "artifact": 14118225390,
    "name": "pon-budget-controls-pool-before-v2-84e68b4f7a9b2f48f9c47ed05c9a44229d186e30-1",
    "bytes": 7065,
    "sha256": "ff20fd1ec49332453151a25d9481eae8e1a34cb81f57947b15ce969b73ba3a9a",
    "log_bytes": 323305,
    "log_sha": "fc18f5f6f31c65825fd327a3d13f4b121089ad01a4f651fa32a3a52b2270c5f3",
    "old_metadata": {
      "path": "/private/tmp/chain-consolidation-20261114-root/R1-other-failed-job-original-logs-v1/132475257835-metadata.stdout",
      "bytes": 3036,
      "sha256": "3a8a8946caa39e707f7503e012bff9d18ebab51f234b7dbcec6d2176fb8c0497"
    }
  }
]
def need(v,c):
    if not v:raise ValueError(c)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def stable(path,size,sha):
    p=Path(path);s=p.lstat()
    need(p.is_absolute() and p.resolve()==p and stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==size,"SOURCE_IDENTITY")
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb") as f:
        need(fp(os.fstat(f.fileno()))==fp(s),"SOURCE_OPEN")
        raw=f.read(size+1)
        need(fp(os.fstat(f.fileno()))==fp(s),"SOURCE_FD_CHANGED")
    need(fp(p.lstat())==fp(s) and len(raw)==size and hashlib.sha256(raw).hexdigest()==sha,"SOURCE_PIN")
    return raw
def save(directory,name,raw):
    p=directory/name
    with p.open("xb")as f:f.write(raw)
    need(p.read_bytes()==raw,"OUTPUT_READBACK")
    return {"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def save_json(directory,name,data):return save(directory,name,(json.dumps(data,sort_keys=True,indent=2)+"\n").encode())
def pairs(items):
    out={}
    for k,v in items:
        need(k not in out,"DUPLICATE_KEY");out[k]=v
    return out
def strict(raw):return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError("NONFINITE")))
def capture(directory,label,endpoint,cap):
    argv=[GH,"api","--hostname","github.com","--method","GET",endpoint]
    env=os.environ.copy();env.pop("GH_DEBUG",None);env["GH_HOST"]="github.com"
    start=time.monotonic();deadline=start+120
    rec={"label":label,"argv":argv,"cwd":"/private/tmp","method":"GET","started_at":now(),"timeout_seconds":120,"automatic_retry":False,"GH_DEBUG_removed":True,"GH_HOST":"github.com","exit":None,"error":None,"stdout_eof":False,"stderr_eof":False}
    buffers={"stdout":bytearray(),"stderr":bytearray()};process=None;sel=selectors.DefaultSelector()
    try:
        process=subprocess.Popen(argv,cwd="/private/tmp",env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        rec["pid"]=process.pid
        for stream,label2 in ((process.stdout,"stdout"),(process.stderr,"stderr")):
            os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,label2)
        while sel.get_map():
            need(time.monotonic()<deadline,"REQUEST_120_SECOND_DEADLINE")
            for key,_ in sel.select(min(.1,max(0,deadline-time.monotonic()))):
                name=key.data;limit=cap if name=="stdout"else 65536
                chunk=os.read(key.fileobj.fileno(),min(65536,max(1,limit+1-len(buffers[name]))))
                if not chunk:
                    rec[name+"_eof"]=True;sel.unregister(key.fileobj);continue
                buffers[name].extend(chunk);need(len(buffers[name])<=limit,"REQUEST_OUTPUT_BOUND_"+name)
        rec["exit"]=process.wait(timeout=max(.01,deadline-time.monotonic()))
        need(rec["exit"]==0,"GH_GET_NONZERO")
    except Exception as e:rec["error"]=str(e)if isinstance(e,ValueError)else type(e).__name__
    finally:
        sel.close()
        if process:
            if process.poll()is None:
                rec["terminated_owned_request"]=True;process.terminate()
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait(timeout=2)
            rec["exit"]=process.returncode
            process.stdout.close();process.stderr.close()
        rec["finished_at"]=now();rec["elapsed_seconds"]=time.monotonic()-start
        rec["complete_transport"]=rec["error"]is None and rec["exit"]==0 and rec["stdout_eof"]and rec["stderr_eof"]
        rec["stdout"]=save(directory,label+".stdout",bytes(buffers["stdout"]))
        stderr=bytes(buffers["stderr"])
        # Never persist an error's redirected signed URL or any HTTP/authorization headers.
        safe=re.sub(rb"https?://[^\s\"'<>]+",b"[URL_REDACTED]",stderr)
        safe=re.sub(rb"(?im)^.*(?:authorization:|proxy-authorization:|set-cookie:|cookie:).*$",b"[HEADER_REDACTED]",safe)
        rec["stderr_consumed_bytes"]=len(stderr);rec["stderr_consumed_sha256"]=hashlib.sha256(stderr).hexdigest()
        rec["stderr_redacted"]=safe!=stderr
        rec["stderr"]=save(directory,label+(".stderr.redacted"if safe!=stderr else".stderr"),safe)
        rec["step_receipt"]=save_json(directory,label+".step.json",rec)
    return rec,bytes(buffers["stdout"])
def zip_index(directory,raw):
    with zipfile.ZipFile(io.BytesIO(raw))as z:
        infos=z.infolist();need(len(infos)==14,"EXACT_14_MEMBERS")
        seen=set();rows=[];total=0
        for i,info in enumerate(infos):
            name=info.filename;norm=name[:-1]if name.endswith("/")else name
            p=PurePosixPath(norm)
            need(norm and not p.is_absolute()and p.as_posix()==norm and "\\"not in name and ":"not in name
                 and all(x not in ("",".","..")for x in p.parts)and not any(ord(x)<32 or ord(x)==127 for x in name),"UNSAFE_ZIP_PATH")
            need(norm not in seen,"DUPLICATE_ZIP_PATH");seen.add(norm)
            mode=stat.S_IFMT(info.external_attr>>16)
            need(mode in (0,stat.S_IFREG,stat.S_IFDIR)and not(info.flag_bits&0x41)
                 and info.compress_type in (0,8),"SPECIAL_OR_ENCRYPTED_MEMBER")
            need(0<=info.file_size<=2*1024*1024,"MEMBER_SIZE_CAP")
            total+=info.file_size;need(total<=4*1024*1024,"ARCHIVE_EXPANDED_CAP")
            with z.open(info)as f:data=f.read(info.file_size+1)
            need(len(data)==info.file_size and zlib.crc32(data)&0xffffffff==info.CRC,"MEMBER_CRC_LENGTH")
            rows.append({"index":i,"path":name,"directory":info.is_dir(),"bytes":len(data),"compressed_bytes":info.compress_size,"crc32":f"{info.CRC:08x}","crc32_verified":True,"sha256":hashlib.sha256(data).hexdigest(),"executed":False})
    return {"schema":"trnm-r1-budget-original-zip-index-v1","members":rows,"member_count":len(rows),"expanded_bytes":total,"all_member_crc_verified":True,"members_executed":False}
def acquire(spec):
    d=OUT/str(spec["artifact"]);d.mkdir(mode=0o700)
    rec={"schema":"trnm-r1-budget-original-artifact-acquisition-v1","status":"HOLD","started_at":now(),"run":RUN,"run_attempt":1,"job":spec["job"],"workflow_current_head":HEAD,"historical_test_subject":spec["subject"],"artifact":spec["artifact"],"artifact_name":spec["name"],"steps":[],"errors":[],"whole_zip_sha256_verified":False,"all_member_crc_verified":False,"native_or_tests_executed_here":False,"source_refs_stage_modified":False,"qualification":False}
    try:
        old=spec["old_metadata"];job=strict(stable(old["path"],old["bytes"],old["sha256"]))
        need(job.get("id")==spec["job"]and job.get("run_id")==RUN and job.get("run_attempt")==1
             and job.get("head_sha")==HEAD and job.get("status")=="completed"and job.get("conclusion")=="failure","ORIGINAL_JOB_IDENTITY")
        rec["original_job_metadata"]=old
        lp=LOGS/(str(spec["job"])+"-original-log.stdout")
        log=stable(lp,spec["log_bytes"],spec["log_sha"])
        need(str(spec["artifact"]).encode()in log and spec["sha256"].encode()in log
             and spec["subject"].encode()in log and HEAD.encode()in log,"ORIGINAL_UPLOAD_SOURCE_ANCHOR")
        rec["original_job_log"]={"path":str(lp),"bytes":spec["log_bytes"],"sha256":spec["log_sha"]}
        ep="repos/"+REPO+"/actions/artifacts/"+str(spec["artifact"])
        step,metadata=capture(d,"fresh-artifact-metadata",ep,65536);rec["steps"].append(step)
        need(step["complete_transport"],"FRESH_METADATA_TRANSPORT")
        meta=strict(metadata)
        need(type(meta.get("id"))is int and meta["id"]==spec["artifact"]
             and meta.get("name")==spec["name"] and meta.get("size_in_bytes")==spec["bytes"]
             and meta.get("digest")=="sha256:"+spec["sha256"]and meta.get("expired")is False
             and meta.get("workflow_run",{}).get("id")==RUN
             and meta.get("workflow_run",{}).get("head_sha")==HEAD,"FRESH_ARTIFACT_IDENTITY")
        rec["fresh_artifact_metadata"]=step["stdout"]
        step,raw=capture(d,"original-zip",ep+"/zip",spec["bytes"]);rec["steps"].append(step)
        need(step["complete_transport"],"ZIP_TRANSPORT")
        need(len(raw)==spec["bytes"]and hashlib.sha256(raw).hexdigest()==spec["sha256"],"WHOLE_ZIP_DIGEST")
        rec["zip"]=save(d,str(spec["artifact"])+".zip",raw);rec["whole_zip_sha256_verified"]=True
        rec["index"]=save_json(d,"EVIDENCE_INDEX.json",zip_index(d,raw));rec["all_member_crc_verified"]=True
        rec["status"]="ORIGINAL_ZIP_VERIFIED"
    except Exception as e:rec["errors"].append(str(e)if isinstance(e,ValueError)else type(e).__name__)
    rec["finished_at"]=now()
    rec["summary"]=save_json(d,"summary.json",rec)
    print(json.dumps({"artifact":spec["artifact"],"status":rec["status"],"summary":rec["summary"]}),flush=True)
    return rec
def main():
    need(sys.flags.optimize==0,"OPTIMIZATION_FORBIDDEN")
    need(OUT.parent.resolve(strict=True)==OUT.parent,"OUTPUT_PARENT")
    OUT.mkdir(mode=0o700,exist_ok=False)
    producer=Path(__file__).read_bytes();producer_pin=save(OUT,"producer.py",producer)
    begun=now()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:
        futures=[pool.submit(acquire,s)for s in SPECS]
        rows=[f.result()for f in futures]
    success=all(r["status"]=="ORIGINAL_ZIP_VERIFIED"for r in rows)
    summary={"schema":"trnm-r1-budget-three-artifacts-v1","status":"ORIGINAL_ZIPS_VERIFIED"if success else"PARTIAL_OR_UNKNOWN","started_at":begun,"finished_at":now(),"producer":producer_pin,"artifacts":rows,"maximum_GETs":6,"maximum_parallel_requests":3,"per_request_timeout_seconds":120,"automatic_retry":False,"stage_source_refs_modified":False,"qualification":False}
    pin=save_json(OUT,"acquisition-summary.json",summary)
    print(json.dumps({"status":summary["status"],"summary":pin}),flush=True)
    return 0 if success else 1
if __name__=="__main__":raise SystemExit(main())
