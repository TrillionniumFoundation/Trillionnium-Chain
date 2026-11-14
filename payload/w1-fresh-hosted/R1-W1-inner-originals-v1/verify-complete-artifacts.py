import datetime,hashlib,io,json,os,pathlib,stat,sys,zipfile,zlib
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-complete-artifacts-v1")
O=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-inner-originals-v1")
O.mkdir(mode=0o700)
SHA=lambda b:hashlib.sha256(b).hexdigest()
def put(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("xb") as f:f.write(b)
def jb(x):return (json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def stable(p,cap):
    if p.resolve(strict=True)!=p:raise ValueError("noncanonical source")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,"rb") as f:
        a=os.fstat(f.fileno())
        if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>cap:raise ValueError("invalid source")
        raw=f.read(cap+1)
        b=os.fstat(f.fileno())
    if len(raw)!=a.st_size or identity(a)!=identity(b) or identity(a)!=identity(p.lstat()):raise ValueError("source changed")
    return raw,{"path":str(p),"bytes":len(raw),"sha256":SHA(raw),"version":list(identity(a))}
put(O/"verify-complete-artifacts.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
meta_raw,meta_pin=stable(E/"metadata-summary.json",2*1024*1024)
if meta_pin["bytes"]!=6117 or meta_pin["sha256"]!="2a538933fc2ffda93843423b2b3a75208343187596b2578fdd532b07b3324238":raise ValueError("metadata pin")
meta=json.loads(meta_raw)
dl_raw,dl_pin=stable(E/"download-summary.json",2*1024*1024);dl=json.loads(dl_raw)
if dl.get("all_complete") is not True:raise ValueError("complete download required")
results=[]
for r in meta["results"]:
    a=r["actual"];aid=a["id"]
    zip_raw,zip_pin=stable(E/(str(aid)+".zip"),16*1024*1024)
    if zip_pin["bytes"]!=a["size_in_bytes"] or "sha256:"+zip_pin["sha256"]!=a["digest"]:raise ValueError("archive digest/size")
    members=[];seen=set();selected=[];total=0
    with zipfile.ZipFile(io.BytesIO(zip_raw)) as z:
        infos=z.infolist()
        if len(infos)>1000:raise ValueError("member cap")
        for x in infos:
            name=x.filename;path=pathlib.PurePosixPath(name);mode=x.external_attr>>16
            if not name or name.startswith("/") or "\\" in name or "\x00" in name or any(p in ("",".","..") for p in path.parts) or name in seen:raise ValueError("unsafe/duplicate member")
            seen.add(name)
            if x.flag_bits&1:raise ValueError("encrypted member")
            if x.file_size>256*1024*1024:raise ValueError("member size cap")
            total+=x.file_size
            if total>512*1024*1024:raise ValueError("archive raw cap")
            if x.is_dir():
                if stat.S_IFMT(mode) not in (0,stat.S_IFDIR):raise ValueError("directory type")
                continue
            if stat.S_IFMT(mode) not in (0,stat.S_IFREG):raise ValueError("nonregular member")
        if sum(not x.is_dir() for x in infos)!=57:raise ValueError("original upload member count differs")
        for x in infos:
            if x.is_dir():continue
            n=x.filename
            select=(n.endswith(".json") and x.file_size<=1024*1024) or (n.endswith((".log",".stdout",".stderr")) and x.file_size<=8*1024*1024)
            dest=O/str(aid)/pathlib.PurePosixPath(n)
            f=None
            if select:
                dest.parent.mkdir(parents=True,exist_ok=True);f=dest.open("xb")
            h=hashlib.sha256();crc=0;count=0
            try:
                with z.open(x,"r") as stream:
                    while True:
                        b=stream.read(65536)
                        if not b:break
                        count+=len(b);h.update(b);crc=zlib.crc32(b,crc)
                        if f:f.write(b)
            finally:
                if f:f.close()
            if count!=x.file_size or crc!=x.CRC:raise ValueError("CRC/size mismatch")
            row={"path":n,"bytes":count,"sha256":h.hexdigest(),"compressed_bytes":x.compress_size,"crc32":f"{crc:08x}","compression":x.compress_type,"mode":x.external_attr>>16,"retained_as":"standalone original and complete ZIP" if select else "complete ZIP only"}
            if select:
                raw,pin=stable(dest,8*1024*1024)
                if pin["bytes"]!=count or pin["sha256"]!=row["sha256"]:raise ValueError("copy mismatch")
                row["extracted"]=pin;selected.append(pin)
            members.append(row)
    index={"schema":"trnm-complete-original-artifact-member-index-v1","artifact_metadata":a,"complete_archive":zip_pin,"file_count":len(members),"total_uncompressed_bytes":total,"crc_all_verified":True,"sha256_all_members_verified":True,"all_paths_regular":True,"files":members}
    ip=O/(str(aid)+"-index.json");put(ip,jb(index))
    manifest_path=O/str(aid)/"fresh-service/manifest.json"
    mr,mp=stable(manifest_path,1024*1024);manifest=json.loads(mr)
    results.append({"artifact_id":aid,"kind":r["expected_from_original_log"]["kind"],"job_id":r["expected_from_original_log"]["job_id"],"zip":zip_pin,"file_count":len(members),"total_uncompressed_bytes":total,"index":stable(ip,2*1024*1024)[1],"manifest":mp,"manifest_top_level_keys":list(manifest),"selected_files":len(selected)})
summary={"schema":"trnm-r1-fresh-service-complete-zip-verification-v1","created_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"metadata":meta_pin,"download_summary":dl_pin,"results":results,"complete":True,"native_or_tests_run":False,"qualification":False,"note":"All original bytes retained in full ZIP. Selected bounded text/JSON extracted without executing artifact content; report bodies above1MiB retained only in complete ZIP."}
put(O/"summary.json",jb(summary))
print(json.dumps({"summary":stable(O/"summary.json",2*1024*1024)[1],"results":results},sort_keys=True))
