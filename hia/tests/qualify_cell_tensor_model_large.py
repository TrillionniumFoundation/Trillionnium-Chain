"""Opt-in stock TMA1 ABI-boundary diagnostic, not a general test runner."""
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import sys

SHARED_LIMIT = 1 << 20
TCD_LARGEST = 155421
TMR_LARGEST = 155974
TMA_LARGEST = 1204562
WIRE_LIMIT = 2097717
SCRATCH = 13944
RESULT = 96
IMAGE_LIMIT = 2 << 20
STDERR_LIMIT = 4096
CPU_SECONDS = 30
WALL_SECONDS = 45
ADDRESS_BYTES = 256 << 20
PAGE = 4096
GUARD = 16
OUTER = struct.Struct("<II96s32s32s")

# Each row is a fixed, deterministic generated case: (extent, SHA-256).
# The sealed child accepts no arbitrary byte source.
FIXED = {
    "prior-above-loan": (1048996, "02e25f1eb2337c35452d1b63aab96f94919e8ab3315512692891a88a36008006"),
    "maximum-constructible": (TMA_LARGEST, "e8d48123583bec679ebfc947caed4041c65c06a25bdc366cb649af763ddb6411"),
    "maximum-plus-suffix": (TMA_LARGEST + 1, "a03f5819c3bf31b969aaa8730b337e83fc959c5870027c2d9c704cba8b60b138"),
    "declared-wire-limit-plus-one": (WIRE_LIMIT + 1, "51c20767766fc8a1e44bc1ab5fdbeed70a41456a26a68b4c73995314bb419bb2"),
}


# Exact emitted Linux x86-64 fixture images, retained from the source-bound
# d7d43fe89bbf8d19bd99d40e5284202735e0c69a candidate qualification.
# This opt-in qualifier never launches a different built image.
IMAGES = {
    "direct": "9a832bd75b85aa7dc237a68748e9c3ca60b9404e2a70447b4c171681e46e60b0",
    "selfhost": "383da9520f816b66a53dfbea5a0a7cd3762344708e58bfff1f647ac9f0295938",
}
# The existing direct builder exports its scalar SHA rotate helper as well.
# Match the whole each-backend inventory separately and call only fixed f0.
EXPORTS = {"direct": frozenset({"f0", "tr_sha_rotr"}), "selfhost": frozenset({"f0"})}
COMPOSED_SOURCE = "13715aabd0c25d5f5e1ef7bf7fa376879c7adb390f51735936e736d634e36e4f"


BASELINE_HEAD = "d7d43fe89bbf8d19bd99d40e5284202735e0c69a"
BASELINE_TREE = "3756cd9d4241526e28cde85ab955b3337d9ba3cb"
ORIGINAL_SOURCE = {
    "cargo_lock_sha256": "86aa87b12d7299990b368a0c07b1236bce99b1f43c5f58482c2adf0266f9a25e",
    "original_manifest_source_sha256": "cf945af731b8172d6b093bded63d546ac3f3a15756524e739a50187dcdaebdc5",
    "original_closure_source_sha256": "72188669d94263583b5a716748e253f3a09eca09b93f0295bfb56f29a647307d",
}
TMA_ORIGINAL_SOURCE = {
    "original_model_root_source_sha256": "6311b100634a1358e2d1aad2d9b71300e75f599326f9f5c61d4eff8149ac3915",
    "original_tensor_model_source_sha256": "73499faf43769355947c598040ddedf9139341bb1a1745924425cd5f11f6c5e8",
    "original_tensor_model_pure_extract_sha256": "c48a16d41a8997fbcad7f7ef0b0f730cf027bfdbb6177a6ce62884c86460a458",
}
RUST_STDOUT = {
    "tma": "ca39f86e6ecb3535db299825f549c796eadf0c77aa5c3a6cd7842c18fe1e7b10",
    "tcd": "ea45751937ba3e8879b8bedc3f73af0d47f44305c1ee11b3a9066d2ade946b30",
}
TCD_IMAGES = {
    "direct": "26d75a1bbc40709ae4bf8019cfed4f0fecc49aa47ab8a3129e8f8f863d12c7d8",
    "selfhost": "36c88caefeca03befa7dedb61288a2ae39dc0d5804e3c08029a2477c88697a6b",
}


def sha(data):
    return hashlib.sha256(data).digest()


def fixtures():
    from hia.tests.test_cell_dependency_closure import closure, row
    from hia.tests.test_cell_model_release_root import roster, wire as tmr
    from hia.tests.test_cell_release_manifest import ident, release
    from hia.tests.test_cell_tensor_model_manifest import at_extent, root, value, wire

    paths = [b"A"*64+b"/"+b"B"*64+b"/"+b"C"*64+b"/"+b"D"*57+f"{i:03d}".encode()
             for i in range(256)]
    # Complete forward edges between 16 equally sized longest-path ranks.
    edges = [tuple(range((i//16+1)*16,256)) for i in range(256)]
    heights = [0]*len(paths)
    for i in range(len(paths)-1,-1,-1):
        heights[i] = 1 + max((heights[j] for j in edges[i]),default=0)
    facts = dict(paths=len(paths),path_bytes=255,dependency_depth=max(heights),edges=sum(map(len,edges)),
                 root_count=256,lineage_count=16,contract_file_count=1,declared_tensors=16384)
    # In a depth-16 DAG, equal longest-path ranks have no edges. Balancing
    # 256 vertices over 16 ranks maximizes all possible inter-rank edges.
    maximum_edges = (256*256 - 16*16*16)//2
    maximum_tcd = 48 + 8425 + 514 + 2 + 256*332 + 2*maximum_edges
    if (len(set(paths))!=256 or any(len(p)!=255 for p in paths) or paths!=sorted(paths)
            or facts["edges"]!=maximum_edges or facts["dependency_depth"]!=16
            or maximum_tcd!=TCD_LARGEST or maximum_tcd+553!=TMR_LARGEST
            or TMR_LARGEST+12+SHARED_LIMIT!=TMA_LARGEST):
        raise AssertionError("Maximum coverage geometry differed")
    rows = [row(path,i+1,role=1 if i==0 else 5,size=65546 if i==0 else 23,dependencies=deps)
            for i,(path,deps) in enumerate(zip(paths,edges,strict=True))]
    members = release(family=b"Z"*64,cells=[ident(i) for i in range(1,257)])
    inner = closure(*rows,roots=range(256),nested=members)
    r = tmr(inner,roster(rows),tuple(ident(i) for i in range(1,17)))
    c = at_extent(r,SHARED_LIMIT)
    t = wire(r,c)
    if (len(members),len(inner),len(r),len(c),len(t))!=(8425,TCD_LARGEST,TMR_LARGEST,
                                                       SHARED_LIMIT,TMA_LARGEST):
        raise AssertionError("Canonical constructive extent differed")
    initial_r = root([(1,65546)])
    initial_c = at_extent(initial_r,SHARED_LIMIT)
    initial = wire(initial_r,initial_c)
    cases = {
        "prior-above-loan": (initial,0,value(initial_r,initial_c,initial)),
        "maximum-constructible": (t,0,value(r,c,t)),
        "maximum-plus-suffix": (t+b".",93,b""),
        "declared-wire-limit-plus-one": (bytes(WIRE_LIMIT+1),90,b""),
    }
    return cases,inner,facts


def seal(raw, label):
    import fcntl
    fd = os.memfd_create(label,os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd,view)
            if n<=0:
                raise OSError("short fixture capture")
            view=view[n:]
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
        return fd
    except BaseException:
        os.close(fd)
        raise


def sealed_read(fd, n, maximum, digest):
    import fcntl
    import stat
    if not 0<n<=maximum:
        raise ValueError("sealed extent outside private fixture")
    st=os.fstat(fd)
    if (not stat.S_ISREG(st.st_mode) or st.st_nlink!=0 or st.st_size!=n
            or fcntl.fcntl(fd,fcntl.F_GET_SEALS)!=15 or os.lseek(fd,0,os.SEEK_CUR)!=n):
        raise ValueError("expected exact owned immutable memfd")
    raw=os.pread(fd,n+1,0)
    if len(raw)!=n or sha(raw).hex()!=digest or os.lseek(fd,0,os.SEEK_CUR)!=n:
        raise ValueError("sealed bytes or position changed")
    return raw


def bounded_child_capture(command, *, pass_fds=(), input_bytes=None, stdout_limit=OUTER.size):
    import selectors
    import subprocess
    import time
    import threading
    deadline=time.monotonic()+WALL_SECONDS
    proc=subprocess.Popen(command,stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          env={},close_fds=True,pass_fds=pass_fds)
    feed = None
    if input_bytes is not None:
        def send():
            try:
                with proc.stdin as stream:
                    stream.write(input_bytes)
            except BrokenPipeError:
                pass
        feed=threading.Thread(target=send)
        feed.start()
    buffers = {proc.stdout: (bytearray(),stdout_limit), proc.stderr: (bytearray(),STDERR_LIMIT)}
    try:
        with selectors.DefaultSelector() as selector:
            for stream in buffers:
                selector.register(stream,selectors.EVENT_READ)
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    raise TimeoutError("private observation deadline")
                ready=selector.select(remaining)
                if not ready:
                    raise TimeoutError("private observation deadline")
                for key,_ in ready:
                    buf,limit=buffers[key.fileobj]
                    got=os.read(key.fd,min(4096,limit-len(buf)+1))
                    if not got:
                        selector.unregister(key.fileobj)
                    else:
                        buf.extend(got)
                        if len(buf)>limit:
                            raise ValueError("private observation output exceeded fixed cap")
        proc.wait(timeout=max(0,deadline-time.monotonic()))
        return proc.returncode,bytes(buffers[proc.stdout][0]),bytes(buffers[proc.stderr][0])
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        if feed is not None:
            feed.join()
        proc.stdout.close()
        proc.stderr.close()


def child(case, input_fd, image_fd, image_n, backend):
    import ctypes as c
    import resource
    if case not in FIXED or backend not in IMAGES or input_fd==image_fd or min(input_fd,image_fd)<3:
        raise ValueError("unexpected private case or descriptors")
    if (platform.system(),platform.machine(),os.sysconf("SC_PAGESIZE"))!=("Linux","x86_64",PAGE):
        raise ValueError("unsupported exact fixture platform")
    resource.setrlimit(resource.RLIMIT_AS,(ADDRESS_BYTES,ADDRESS_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU,(CPU_SECONDS,CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    libc=c.CDLL(None,use_errno=True)
    if libc.prctl(4,0,0,0,0):
        raise OSError(c.get_errno(),"disabling core dumps")
    extent, digest=FIXED[case]
    image_hash=IMAGES[backend]
    data=sealed_read(input_fd,extent,WIRE_LIMIT+1,digest)
    sealed_read(image_fd,image_n,IMAGE_LIMIT,image_hash)
    libc.mmap.argtypes=[c.c_void_p,c.c_size_t,c.c_int,c.c_int,c.c_int,c.c_long]
    libc.mmap.restype=c.c_void_p
    libc.mprotect.argtypes=[c.c_void_p,c.c_size_t,c.c_int]
    libc.munmap.argtypes=[c.c_void_p,c.c_size_t]
    maps=[]
    canary=b"z"*GUARD

    def loan(data, write, suffix):
        usable=len(data)+GUARD+suffix
        pages=(usable+PAGE-1)//PAGE*PAGE
        amount=pages+2*PAGE
        begin=libc.mmap(None,amount,0,0x22,-1,0)
        if begin in (None,c.c_void_p(-1).value):
            raise OSError(c.get_errno(),"anonymous loan")
        maps.append((begin,amount))
        middle=begin+PAGE
        if libc.mprotect(middle,pages,3):
            raise OSError(c.get_errno(),"initializing private loan")
        p=middle+pages-len(data)-suffix
        c.memmove(p-GUARD,canary,GUARD)
        c.memmove(p,data,len(data))
        if suffix:
            c.memmove(p+len(data),canary,suffix)
        if not write and libc.mprotect(middle,pages,1):
            raise OSError(c.get_errno(),"read-only immutable loan")
        return p

    try:
        ptr=loan(data,False,0)
        out=loan(b"\xa5"*RESULT,True,GUARD)
        work=loan(b"\x49"*SCRATCH,True,GUARD)
        lib=c.CDLL("/proc/self/fd/"+str(image_fd))
        native=lib.f0
        native.argtypes=[c.c_void_p,c.c_uint64]*3
        native.restype=c.c_uint64
        raw=native(ptr,extent,out,RESULT,work,SCRATCH)
        after=sha(c.string_at(ptr,extent))
        if after.hex()!=digest or os.lseek(input_fd,0,os.SEEK_CUR)!=extent:
            raise ValueError("read-only input identity or held cursor differs")
        if raw>>32 and c.string_at(work,SCRATCH)!=b"\x49"*SCRATCH:
            raise ValueError("public ABI refusal reached private workspace")
        for at in (ptr-GUARD,out-GUARD,out+RESULT,work-GUARD,work+SCRATCH):
            if c.string_at(at,GUARD)!=canary:
                raise ValueError("private loan canary changed")
        if any(name.startswith("hepta") for name in sys.modules):
            raise ValueError("host HIA compiler loaded in the execution child")
        sys.stdout.buffer.write(OUTER.pack(raw>>32,raw&0xffffffff,c.string_at(out,RESULT),
                                          after,bytes.fromhex(image_hash)))
    finally:
        for p,size in maps:
            libc.munmap(p,size)


def framed(items):
    return b"".join(struct.pack("<I",len(d))+d for d in items)


def diagnose():
    """Require the known ABI refusal plus independent selfhost/Rust equality."""
    import tempfile
    from hia.tests.cell_manifest_original import build
    from hia.tests.native_support import MAX_EXTENT,NativeModule
    from hia.tests.test_cell_dependency_closure import SRC as TCD_SOURCE, result as tcd_value
    from hia.tests.test_cell_tensor_model_manifest import SRC
    if (platform.system(),platform.machine(),os.sysconf("SC_PAGESIZE"))!=("Linux","x86_64",PAGE):
        raise ValueError("unsupported exact fixture platform")
    if MAX_EXTENT!=SHARED_LIMIT:
        raise ValueError("generic runner guard differs; no broader fallback")
    cases,inner,geometry=fixtures()
    if {k:(len(d),sha(d).hex()) for k,(d,_,_) in cases.items()}!=FIXED:
        raise ValueError("fixed fixture identity changed")
    expected=b"".join(bytes([status])+output for _,status,output in cases.values())
    original_tcd=b"\0"+tcd_value(inner,256)
    original_receipts={}
    for label, opts, data, want in (
            ("tma",{"with_tensor_model_manifest":True},[x[0] for x in cases.values()],expected),
            ("tcd",{"with_closure":True},[inner],original_tcd)):
        with tempfile.TemporaryDirectory(prefix="trnm-large-original-") as d:
            binary,proof=build(Path(d),**opts)
            expected_sources = dict(ORIGINAL_SOURCE)
            if label=="tma":
                expected_sources.update(TMA_ORIGINAL_SOURCE)
            if any(proof.get(key)!=digest for key,digest in expected_sources.items()):
                raise ValueError(f"exact original {label} source or lock differs")
            rc,out,err=bounded_child_capture([str(binary)],input_bytes=framed(data),stdout_limit=len(want))
            if (rc,out,err)!=(0,want,b"") or sha(out).hex()!=RUST_STDOUT[label]:
                raise ValueError(f"exact unchanged locked Rust {label} differs")
            original_receipts[label]={**proof,"stdout_sha256":sha(out).hex(),"stdout_bytes":len(out)}
    original_receipts["tma"]["cases"]={
        key:{"input_bytes":len(raw),"input_sha256":sha(raw).hex(),"core_u32":status,
             "result_sha256":sha(output).hex(),"result_bytes":len(output)}
        for key,(raw,status,output) in cases.items()
    }
    reports={}
    for backend in ("direct","selfhost"):
        with NativeModule(TCD_SOURCE,backend=backend,byte_exports=("f0",)) as tcd:
            got=tcd.call("f0",[inner,b"\xa5"*72,b"\x49"*SCRATCH]).require_returned()
            if (got.value,got.arguments[0],got.arguments[1])!=(0,inner,original_tcd[1:]):
                raise ValueError(f"maximum original TCD dependency geometry differs: {backend}")
            tcd_hash=tcd.artifact_sha256
            if tcd_hash!=TCD_IMAGES[backend]:
                raise ValueError("previously qualified maximum-geometry TCD image differs")
        with NativeModule(SRC,backend=backend,byte_exports=("f0",)) as native:
            f=native.functions.get("f0",{})
            if native.exports!=EXPORTS[backend] or f.get("returns")!=["u32"] or [
                    param["type"] for param in f.get("params",[])]!=["readbuf","mutbuf","mutbuf"]:
                raise ValueError("reviewed fixed ABI differs")
            image=native.library.read_bytes()
            if (len(image)>IMAGE_LIMIT or sha(image).hex()!=native.artifact_sha256
                    or native.artifact_sha256!=IMAGES[backend]
                    or native.receipt["chain_migration"]["composed_source_sha256"]!=COMPOSED_SOURCE):
                raise ValueError("actual pinned emitted artifact changed")
            image_fd=seal(image,"tma-large-pinned-image")
            observed={}
            try:
                for key,(data,code,want) in cases.items():
                    input_fd=seal(data,"tma-large-owned-fixture")
                    try:
                        rc,out,err=bounded_child_capture([sys.executable,"-I","-S","-B",
                            str(Path(__file__).resolve()),"--child",key,str(input_fd),str(image_fd),
                            str(len(image)),backend],pass_fds=(input_fd,image_fd))
                    finally:
                        os.close(input_fd)
                    if rc!=0 or err or len(out)!=OUTER.size:
                        raise ValueError(f"no complete native observation: {backend}/{key} exit={rc}")
                    abi,status,raw,actual_input,actual_image=OUTER.unpack(out)
                    # Low Core zero under a nonzero ABI is NOT a TMA success.
                    expected_native = ((1,0,b"\xa5"*RESULT) if backend=="direct" else
                                       (0,code,want if not code else b"\xa5"*RESULT))
                    if (abi,status,raw)!=expected_native or actual_input!=sha(data) or actual_image!=sha(image):
                        raise ValueError(f"unexpected public TMA ABI observation: {backend}/{key}")
                    published = RESULT if abi==0 and status==0 else 0
                    observed[key]={"input_bytes":len(data),"input_sha256":actual_input.hex(),"abi_status":abi,
                                   "core_u32":status,"packed_result":f"0x{(abi<<32)|status:016x}",
                                   "published_bytes":published,"result_sha256":sha(raw).hex() if published else None,
                                   "terminal_sha256":sha(out).hex(),"unchanged_input":True,
                                   "output_untouched":raw==b"\xa5"*RESULT,"canary_controls":True,
                                   "abi_refused_before_workspace_write":True if abi else None}
            finally:
                os.close(image_fd)
            reports[backend]={"exact_tma_artifact":native.artifact_sha256,"exact_tcd_artifact":tcd_hash,
                              "exact_exports":sorted(native.exports),"source_binding":native.receipt["chain_migration"],"cases":observed}
    if len({b["exact_tma_artifact"] for b in reports.values()})!=2:
        raise ValueError("two distinct captured native emitters required")
    return {"schema":"trnm.tma1.large-stock-abi-diagnostic.v1",
            "baseline_head":BASELINE_HEAD,"baseline_tree":BASELINE_TREE,
            "original":original_receipts,"native":reports,"geometry":geometry,
            "format_wire_limit":WIRE_LIMIT,"maximum_constructible":TMA_LARGEST,
            "generic_runner_limit_unchanged":SHARED_LIMIT,"largest_attempted":WIRE_LIMIT+1,
            "fixture_allowlist":list(FIXED),"diagnostic_expected_behavior_observed":True,
            "dual_large_native_qualified":False,"generic_large_abi_claimed":False,
            "production_or_io_equivalence_claimed":False}


if __name__=="__main__":
    if len(sys.argv)==7 and sys.argv[1]=="--child":
        _,_,key,i,j,n,h=sys.argv
        child(key,int(i),int(j),int(n),h)
    elif len(sys.argv)==1:
        print(json.dumps(diagnose(),sort_keys=True,indent=2))
    else:
        raise SystemExit("only the predefined private TMA1 test is supported")
