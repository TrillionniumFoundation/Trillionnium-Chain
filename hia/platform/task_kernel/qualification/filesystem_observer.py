"""Current source-bound Rust std differential and native filesystem contract fixture."""
from pathlib import Path
import ast,ctypes,hashlib,json,os,random,re,runpy,shutil,stat,struct,subprocess,sys,time,traceback
ROOT=Path(__file__).resolve().parents[4]
BUILD=Path(sys.argv[1]).resolve(strict=True)
WORK=Path(sys.argv[2]).absolute()
RUSTC=Path(sys.argv[3]).resolve(strict=True)
assert not ROOT in WORK.parents and WORK.resolve()==WORK and not WORK.exists()
assert __debug__, "Optimized observer refused"
WORK.mkdir(mode=0o700)
report={"schema":"trnm.task-kernel.filesystem-observations.v1","status":"FAIL","finalized":False,"scope":"actual Rust standard-library primitive differential plus native filesystem contract cases; not original TaskKernel full-owner qualification","stages":[],"pure_pairs":0,"filesystem_pairs":0,"native_contracts":0,"source_before":{}}
def sha(p): 
    b=Path(p).read_bytes();return {"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def save():(WORK/"observations.json").write_text(json.dumps(report,indent=2)+"\n")
def stage(name,argv,stdin=b"",cwd=None,timeout=120):
    row={"name":name,"argv":list(map(str,argv)),"cwd":str(cwd or ROOT),"timeout_seconds":timeout,"started":True,"completed":False}
    report["stages"].append(row);(WORK/(name+".stdin.raw")).write_bytes(stdin);save()
    try:
        p=subprocess.run(row["argv"],input=stdin,capture_output=True,cwd=cwd or ROOT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"),timeout=timeout)
        out,err=p.stdout,p.stderr;row.update(completed=True,exit=p.returncode)
    except subprocess.TimeoutExpired as e:
        out,err=e.stdout or b"",e.stderr or b"";row.update(error=repr(e),timeout=True)
        (WORK/(name+".stdout.raw")).write_bytes(out);(WORK/(name+".stderr.raw")).write_bytes(err);save();raise
    except OSError as e:
        row.update(error=repr(e),os_error=True);(WORK/(name+".stdout.raw")).write_bytes(b"");(WORK/(name+".stderr.raw")).write_bytes(b"");save();raise
    (WORK/(name+".stdout.raw")).write_bytes(out);(WORK/(name+".stderr.raw")).write_bytes(err);save()
    if p.returncode:raise RuntimeError(name+" exit "+str(p.returncode)+": "+err.decode(errors="replace")[-2000:])
    return out
save()
try:
    stage("preflight",["bash","scripts/project-preflight.sh","--audit"])
    build=json.loads((BUILD/"build.json").read_text())
    assert build["status"]=="PASS" and build["finalized"] and build["source_before"]==build["source_after"]
    for path,expected in build["source_before"].items():
        assert sha(path)==expected,path
    for name,expected in build["artifacts"].items():
        assert sha(BUILD/name)==expected,name
    original_source=Path(__file__).with_name("filesystem_original.rs")
    paths=[Path(__file__),original_source,BUILD/"path.so",BUILD/"filesystem-native.so",BUILD/"build.json",RUSTC]+[Path(p) for p in build["source_before"]]
    report["source_before"]={str(p):sha(p) for p in paths};save()
    report["rust_version"]=stage("rust-version",[RUSTC,"--version","--verbose"]).decode()
    assert report["rust_version"].splitlines()[0].startswith("rustc 1.95.0 ")
    stage("std-original-compile",[RUSTC,"--edition=2021",original_source,"-o",WORK/"std-original"])
    pure=ctypes.CDLL(str(BUILD/"path.so")).f0
    pure.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64];pure.restype=ctypes.c_uint32
    lib=ctypes.CDLL(str(BUILD/"filesystem-native.so"))
    new=lib.trnm_task_owner_new;new.argtypes=[];new.restype=ctypes.c_void_p
    invoke=lib.trnm_task_owner_invoke;invoke.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_uint64)];invoke.restype=ctypes.c_uint64
    free=lib.trnm_task_owner_free;free.argtypes=[ctypes.c_void_p];release=lib.trnm_task_owner_result_free;release.argtypes=[ctypes.c_void_p]
    def pf(op,x=b"",y=b""):return b"TKPF0001"+struct.pack("<QQQ",op,len(x),len(y))+x+y
    def ff(op,path=b"",a=0,b=0,target=b""):return b"TKFS0001"+struct.pack("<QQQQQ",op,len(path),a,b,len(target))+path+target
    rng=random.Random(918873)
    frames=[]
    paths=[b"",b".",b"..",b"/",b"//",b"///",b"./",b"./.",b"../",b"a/..",b"a//b/./c///",b"/./",b"/../",b"\0",b"\xff"]
    parts=[b"a",b"b",b".",b"..",b"",b"\xff",b"\0",b"./",b"\xc3\xa9"]
    for _ in range(4000):paths.append(b"/".join(rng.choice(parts) for _ in range(rng.randrange(0,20)))+rng.choice([b"",b"/",b"///",b"/."]))
    paths.extend([b"a"*255,b"a"*4096,b"a/"*10000+b"z"])
    frames.extend(pf(0,p) for p in paths)
    utf=[b"",bytes(range(256)),b"\xf0\x9f",b"\xed\xa0\x80",b"\xef\xbf\xbd",b"\xe2\x82A",b"\xf4\x90\x80\x80"]
    utf.extend(bytes(rng.randrange(256) for _ in range(rng.randrange(1,180))) for _ in range(1800))
    frames.extend(pf(1,p) for p in utf)
    schema=b"CREATE TABLE task_archive_metadata_v1 (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL)"
    whitespace=[9,10,11,12,13,32,133,160,5760,*range(8192,8203),8232,8233,8239,8287,12288]
    frames.extend(pf(2,chr(c).encode().join([bytes([x]) for x in schema]),schema) for c in whitespace)
    frames.extend([pf(2,b"CHECK",b"check"),pf(2,"CHEC\u212a".encode(),b"check"),pf(2,"\u0130".encode(),b"i"),pf(2,b"not equal",schema)])
    frames.extend(pf(3,struct.pack("<Q",c)) for c in sorted(set([*range(256),*range(8180,8240),*whitespace,12288,0x10ffff])))
    report["expected_pure_pairs"]=len(frames);save()
    original=stage("pure-original-run",[WORK/"std-original"],b"".join(x.hex().encode()+b"\n" for x in frames))
    lines=original.splitlines();assert len(lines)==len(frames)
    with (WORK/"pure-native-observations.jsonl").open("x") as stream:
        for i,(frame,line) in enumerate(zip(frames,lines)):
            code_s,hex_s=line.split(b"|",1);expected=(int(code_s),bytes.fromhex(hex_s.decode()))
            source=ctypes.create_string_buffer(frame);output=ctypes.create_string_buffer(len(frame)*4+128);scratch=ctypes.create_string_buffer(len(frame)*4+128)
            code=pure(source,len(frame),output,len(output),scratch,len(scratch))
            count=struct.unpack_from("<Q",output.raw)[0] if code==0 else 0
            actual=output.raw[:8+count] if code==0 and count<=len(output)-8 else b""
            row={"index":i,"input":frame.hex(),"code":code,"actual_output":actual.hex(),"original_code":expected[0],"original_output":expected[1].hex()}
            stream.write(json.dumps(row)+"\n");stream.flush()
            assert (code,actual)==expected,(i,row)
            assert source.raw[:len(frame)]==frame
            report["pure_pairs"]+=1
    save()
    original_tree=WORK/"original-fs";native_tree=WORK/"native-fs";original_tree.mkdir();native_tree.mkdir()
    calls=[]
    def setup(case):
        name=("case-"+str(case)).encode()
        for base in [original_tree,native_tree]:
            root=os.fsencode(base)+b"/"+name;os.mkdir(root)
            fd=os.open(root+b"/file",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640);os.write(fd,b"actual primitive fixture");os.close(fd)
            os.mkdir(root+b"/target")
            os.symlink(b"target",root+b"/link");os.symlink(b"missing",root+b"/broken")
        return name+b"/"
    mkdirs=[b"",b".",b"./",b"/",b"//",b"a",b"a/b",b"a//b///c/.",b"./x/y/..",b"missing/../z",b"file/child",b"link/child",b"broken/child",b"\0",b"a\0b",b"x"*256,b"deep/"*80+b"leaf"]
    for path in mkdirs:
        prefix=setup(len(calls));p=path if path in [b"",b"/",b"//"] else prefix+path;calls.append(ff(0,p))
    for op in [3,6,7]:
        for path in [b"file",b"target",b"missing",b"broken",b"link",b"\0",b"x"*256,b"file/nope"]:
            for ignore in ([0,1] if op==7 else [0]):
                prefix=setup(len(calls));calls.append(ff(op,prefix+path,26 if op==3 else 22,ignore))
    for a,b in [(b"file",b"new"),(b"missing",b"new"),(b"file",b"file"),(b"target",b"new"),(b"file\0",b"new"),(b"file",b"new\0"),(b"file",b""),(b"",b""),(b"",b"new"),(b"broken",b"new")]:
        prefix=setup(len(calls));calls.append(ff(8,prefix+a if a else b"",target=prefix+b if b else b""))
    for number in [0,1,2,4,13,17,20,21,22,28,36,40,122,9999]:
        calls.append(ff(9,a=number,b=22))
    report["expected_filesystem_pairs"]=len(calls);save()
    original=stage("filesystem-original-run",[WORK/"std-original"],b"".join(x.hex().encode()+b"\n" for x in calls),cwd=original_tree)
    lines=original.splitlines();assert len(lines)==len(calls)
    owner=new();assert owner
    def native_call(frame):
        s=ctypes.create_string_buffer(frame);ptr=ctypes.c_void_p();size=ctypes.c_uint64()
        code=invoke(owner,s,len(frame),ctypes.byref(ptr),ctypes.byref(size))
        data=ctypes.string_at(ptr,size.value) if ptr else b""
        published=bool(ptr)
        if ptr:release(ptr)
        assert s.raw[:len(frame)]==frame
        return code,data,published,size.value
    previous=os.getcwd();os.chdir(native_tree)
    try:
        with (WORK/"filesystem-native-observations.jsonl").open("x") as stream:
            for i,(frame,line) in enumerate(zip(calls,lines)):
                a,b=line.split(b"|",1);expected=(int(a),bytes.fromhex(b.decode()))
                code,data,published,size=native_call(frame)
                row={"index":i,"input":frame.hex(),"code":code,"actual_output":data.hex(),"published":published,"length":size,"original_code":expected[0],"original_output":expected[1].hex()}
                stream.write(json.dumps(row)+"\n");stream.flush()
                assert (code,data)==expected,(i,row)
                assert published
                report["filesystem_pairs"]+=1
        save()
        contract_root=b"contracts";os.mkdir(contract_root)
        os.mkdir(contract_root+b"/directory");os.symlink(b"directory",contract_root+b"/link");os.symlink(b"absent",contract_root+b"/broken")
        Path("contracts/file").write_bytes(b"fixed")
        contracts=[(ff(1,b"contracts/directory/db"),0,b""),(ff(1,b"contracts/link/db"),22,b"TaskV1 archive parent path is a symlink"),(ff(1,b"contracts/broken/db"),22,b"TaskV1 archive parent path is a symlink"),(ff(1,b"contracts/file/db"),22,b"TaskV1 archive parent path is not a directory"),(ff(2,b"contracts/db"),0,b"")]
        for suffix in [b"-wal",b"-shm",b"-journal"]:
            for shape in ["file","directory","symlink"]:
                path=contract_root+b"/db-"+suffix[1:]+b"-"+shape.encode()
                side=path+suffix
                if shape=="file":Path(os.fsdecode(side)).write_bytes(b"hold")
                elif shape=="directory":os.mkdir(side)
                else:os.symlink(b"absent",side)
                contracts.append((ff(2,path),25,b"TaskV1 archive sidecar is present"))
        with (WORK/"native-contract-observations.jsonl").open("x") as stream:
            for i,(frame,expected_code,expected_message) in enumerate(contracts):
                code,data,published,size=native_call(frame)
                row={"index":i,"input":frame.hex(),"native_code":code,"actual_output":data.hex(),"expected_business_code":expected_code,"expected_message":expected_message.hex()}
                stream.write(json.dumps(row)+"\n");stream.flush()
                assert code==0 and published and len(data)>=48,row
                business,ml,_,_,_,pl=struct.unpack_from("<QQQQQQ",data)
                assert business==expected_code and data[48:48+ml]==expected_message and len(data)==48+ml+pl,row
                report["native_contracts"]+=1
            nonces=[]
            for i in range(16):
                frame=ff(4,b"contracts/directory/final")
                code,data,published,size=native_call(frame)
                row={"reserve":i,"input":frame.hex(),"native_code":code,"actual_output":data.hex(),"published":published}
                stream.write(json.dumps(row)+"\n");stream.flush()
                assert code==0 and published and len(data)>=48,row
                business,ml,_,_,_,pl=struct.unpack_from("<QQQQQQ",data);p=data[48+ml:]
                assert business==0 and ml==0 and len(p)==pl
                match=re.fullmatch(rb"contracts/directory/\.trnm-task-archive-init-([0-9]+)-([0-9]+)-([0-9]+)",p)
                assert match,p
                assert int(match[1])==os.getpid() and int(match[2])>0
                nonces.append(int(match[3]));metadata=os.lstat(p)
                assert stat.S_ISREG(metadata.st_mode) and metadata.st_size==0
                report["native_contracts"]+=1
            assert nonces==list(range(16)),nonces
            report["reserve_nonces"]=nonces
    finally:
        free(owner);os.chdir(previous)
    def inventory(base):
        out={}
        for root,dirs,files in os.walk(os.fsencode(base),followlinks=False):
            for name in dirs+files:
                p=root+b"/"+name;rel=p[len(os.fsencode(base))+1:];st=os.lstat(p);row={"mode":st.st_mode}
                if stat.S_ISLNK(st.st_mode):row["target"]=os.readlink(p).hex()
                elif stat.S_ISREG(st.st_mode):row["sha256"]=hashlib.sha256(Path(os.fsdecode(p)).read_bytes()).hexdigest();row["bytes"]=st.st_size
                out[rel.hex()]=row
        return out
    original_inventory=inventory(original_tree);native_inventory={p:v for p,v in inventory(native_tree).items() if not bytes.fromhex(p).startswith(b"contracts")}
    (WORK/"original-filesystem.json").write_text(json.dumps(original_inventory,indent=2)+"\n")
    (WORK/"native-filesystem.json").write_text(json.dumps(native_inventory,indent=2)+"\n")
    assert original_inventory==native_inventory,"filesystem effects differ"
    report["source_after"]={p:sha(p) for p in report["source_before"]}
    assert report["source_before"]==report["source_after"]
    assert report["pure_pairs"]==report["expected_pure_pairs"] and report["filesystem_pairs"]==report["expected_filesystem_pairs"]
    report["artifact_identity"]={str(p.relative_to(WORK)):sha(p) for p in WORK.iterdir() if p.is_file() and (p.suffix in [".o",".so"] or p.name=="std-original")}
    report.update(status="PASS",finalized=True);save()
    print(json.dumps({"status":"PASS","pure_pairs":report["pure_pairs"],"filesystem_pairs":report["filesystem_pairs"],"native_contracts":report["native_contracts"]}))
except BaseException as e:
    report.update(status="FAIL",error=repr(e),traceback=traceback.format_exc());save();raise
