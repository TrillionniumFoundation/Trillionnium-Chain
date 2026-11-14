import os,stat,hashlib,json,datetime,sys
from pathlib import Path
ROOT=Path("/private/tmp/chain-consolidation-20261114-root")
SRC=ROOT/"R1-required-protocol-failed-job-original-log-v1/132481412290-original-log.stdout"
OUT=Path("/private/tmp/chain-R1-required-head-protocol-artifact-review-20261114-v1")
def fp(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p):
    before=p.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and p.resolve(strict=True)==p
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        assert fp(os.fstat(fd))==fp(before)
        chunks=[]
        while True:
            b=os.read(fd,65536)
            if not b:break
            chunks.append(b)
        raw=b"".join(chunks)
        assert fp(os.fstat(fd))==fp(before)
    finally:os.close(fd)
    assert fp(p.lstat())==fp(before) and len(raw)==before.st_size
    return raw,fp(before)
raw,version=read(SRC)
assert len(raw)==219457 and hashlib.sha256(raw).hexdigest()=="a2abb8f09485c32739ca970ac1aa8ab12d3cfee01f53a954e9c9d2dded0ae935"
os.umask(0o077);OUT.mkdir()
def put(name,b):
    p=OUT/name
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,"wb") as f:f.write(b)
    return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def jput(name,o):return put(name,(json.dumps(o,indent=2,sort_keys=True)+"\n").encode())
text=raw.decode("utf-8")
lines=text.splitlines()
tokens=["trnm-ci-source-v1","Artifact name","artifact name","Artifact ID","Artifact size","SHA256","SHA-256","sha256:","Host","host manifest","failure","Failure","Error:","error:","exit code","from-zero","artifact download","Artifact download","Upload artifact","upload-artifact","132481412290","43604217412"]
selected=[{"line":i+1,"text":s} for i,s in enumerate(lines) if any(t in s for t in tokens)]
r={"schema":"trnm-r1-required-head-protocol-original-log-review-v1","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source":{"path":str(SRC),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"identity":version},"expected":{"run_id":43604217412,"run_attempt":1,"job_id":132481412290,"head":"2a86462a1ab20c68151719ba4635e3c294391e64","tree":"5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"},"line_count":len(lines),"selected_lines":selected,"tail":[{"line":i+1,"text":s} for i,s in enumerate(lines) if i>=len(lines)-90],"scope":"Original closed log only; no API, Git, tests, artifact execution or source mutation."}
original=put("original-job-log.stdout",raw)
index=jput("original-log-review.json",r)
put("review-original-log.py",sys.argv[1].encode())
assert fp(SRC.lstat())==version
print(json.dumps({"output":str(OUT),"original":original,"review":index,"selected":selected,"tail":r["tail"]},sort_keys=True))
