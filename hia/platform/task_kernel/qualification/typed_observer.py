"""Differentially execute native typed methods and the actual original Rust adapter."""
from pathlib import Path
import ctypes
import hashlib
import json
import random
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
BUILD, ORIGINAL, WORK = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]).absolute()
assert __debug__ and not WORK.exists() and ROOT not in WORK.parents
WORK.mkdir(mode=0o700)
def identity(p):
    b=Path(p).read_bytes();return {"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
report={"schema":"trnm.hia.task-kernel.typed-qualification.v1","status":"FAIL","finalized":False,
        "scope":"canonical Borsh values, nine public IDs and four KernelCommand methods; full store not qualified",
        "native_calls":0,"original_calls":0,"controls":0}
def save():
    (WORK/"report.json").write_text(json.dumps(report,indent=2)+"\n")
def frame(op,kind,data):
    return b"TKTV0001"+struct.pack("<QQQ",op,kind,len(data))+data
try:
    build=json.loads((BUILD/"build.json").read_text())
    assert build["status"]=="PASS" and build["finalized"] and build["source_before"]==build["source_after"]
    inputs=dict(build["source_before"])
    for name,expected in build["artifacts"].items():
        p=BUILD/name;assert identity(p)==expected;inputs[str(p)]=expected
    for p in [Path(__file__),ORIGINAL,BUILD/"build.json"]:inputs[str(p)]=identity(p)
    assert {p:identity(p) for p in inputs}==inputs
    report["source_before"]=inputs;save()
    schema={int(k):v for k,v in json.loads(Path(__file__).with_name("type_layout.json").read_text()).items()}
    rng=random.Random(840_137)
    def value(kind,mode=0,depth=0,large=False):
        row=schema[kind];tag=row["kind"];count=row["count"]
        if tag==0:return b""
        if tag==1:
            if mode==0:return bytes(count)
            if mode==1:return b"\xff"*count
            return bytes(rng.randrange(256) for _ in range(count))
        if tag==2:return bytes([mode%2])
        if tag==3:
            raw=(b"x"*2_098_177 if large else [b"",b"\x00\x7f", "正文😀\u2002".encode()][mode%3])
            return struct.pack("<I",len(raw))+raw
        if tag==4:
            n=mode%3
            return struct.pack("<I",n)+b"".join(value(count,(mode+i)%3,depth+1,large) for i in range(n))
        if tag==5:
            return b"\x00" if mode%2==0 else b"\x01"+value(count,mode,depth+1,large)
        if tag==6:
            return b"".join(value(field,mode,depth+1,large) for field in row["fields"])
        if tag==7:
            variant=mode%count
            return bytes([variant])+value(row["fields"][variant],mode,depth+1,large)
        raise AssertionError(row)
    cases=[]
    def add(name,op,kind,data):cases.append((name,frame(op,kind,data)))
    for kind in schema:
        for mode in range(3):add(f"canonical-{kind}-{mode}",0,kind,value(kind,mode))
        raw=value(kind,1)
        for end in sorted({0,len(raw)//2,max(0,len(raw)-1),*range(min(12,len(raw)))}):
            add(f"truncated-{kind}-{end}",0,kind,raw[:end])
        add(f"trailing-{kind}",0,kind,raw+b"\x00")
    for bad in range(2,256):
        add(f"invalid-bool-{bad}",0,6,bytes([bad]))
        add(f"invalid-option-{bad}",0,76,bytes([bad]))
    for bad in range(6,256):add(f"invalid-enum-{bad}",0,67,bytes([bad]))
    for raw in [b"\xff",b"\xc0\xaf",b"\xe2\x82",b"\xf0\x9f",b"\xed\xa0\x80",b"a\xe2B",b"\xf4\x90\x80\x80",bytes(range(256))]:
        add("utf8-"+raw.hex(),0,8,struct.pack("<I",len(raw))+raw)
    ids=[33,37,39,43,45,48,51,54,56]
    for kind in ids:
        for mode in range(3):add(f"identifier-{kind}-{mode}",1,kind,value(kind,mode))
    for variant in range(6):
        for mode in range(3):
            raw=bytes([variant])+value(68+variant,mode)
            for op in range(2,6):add(f"command-{variant}-{mode}-{op}",op,67,raw)
    add("identifier-over-old-transport-cap",1,33,value(33,0,large=True))
    cases.extend([("empty-frame",b""),("unknown-op",frame(6,33,b"")),
                  ("unknown-type",frame(0,97,b"")),("invalid-method-type",frame(3,25,b"")),
                  ("invalid-id-type",frame(1,25,b""))])
    payload=b"".join(raw.hex().encode()+b"\n" for _,raw in cases)
    (WORK/"original.stdin.raw").write_bytes(payload)
    started=time.monotonic_ns()
    process=subprocess.run([str(ORIGINAL)],input=payload,capture_output=True,timeout=120)
    (WORK/"original.stdout.raw").write_bytes(process.stdout);(WORK/"original.stderr.raw").write_bytes(process.stderr)
    report["original_process"]={"argv":[str(ORIGINAL)],"exit_code":process.returncode,
                                "elapsed_ns":time.monotonic_ns()-started,"timeout_seconds":120};save()
    assert process.returncode==0 and not process.stderr
    lines=process.stdout.splitlines();assert len(lines)==len(cases)
    library=ctypes.CDLL(str(BUILD/"typed.so"));fn=library.f0
    fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;fn.restype=ctypes.c_uint32
    def native(raw,output_capacity=None,scratch_capacity=None):
        source=ctypes.create_string_buffer(raw)
        output=ctypes.create_string_buffer(output_capacity if output_capacity is not None else len(raw)+2048)
        scratch=ctypes.create_string_buffer(scratch_capacity if scratch_capacity is not None else len(raw)+131072)
        code=fn(source,len(raw),output,len(output),scratch,len(scratch))
        assert source.raw[:len(raw)]==raw
        if code:return code,b"",scratch.raw
        sizes=struct.unpack_from("<QQQQ",output.raw);extent=32+sum(sizes[1:])
        assert extent<=len(output)
        return code,output.raw[:extent],scratch.raw
    with (WORK/"native-observations.jsonl").open("x") as stream:
        for index,((name,raw),line) in enumerate(zip(cases,lines)):
            expected_code,expected_data=line.split(b"|",1)
            row={"index":index,"name":name,"input_hex":raw.hex(),"started":True}
            (WORK/"current-call.json").write_text(json.dumps(row)+"\n")
            code,data,scratch=native(raw)
            row.update(return_code=code,output_hex=data.hex(),expected_code=int(expected_code),
                       expected_output_hex=expected_data.decode(),equal=(code==int(expected_code) and data.hex()==expected_data.decode()))
            stream.write(json.dumps(row)+"\n");stream.flush()
            report["native_calls"]+=1;report["original_calls"]+=1;save()
            if not row["equal"]:
                (WORK/"failure-scratch.raw").write_bytes(scratch)
                raise AssertionError("Typed differential mismatch: "+name)
    controls=[]
    for name,raw,oc,sc,expected in [
        ("output-short",frame(0,1,b"\x00"),32,None,101),
        ("scratch-short",frame(0,1,b"\x00"),None,131104,102),
    ]:
        code,data,_=native(raw,oc,sc);controls.append({"name":name,"actual":code,"expected":expected})
        assert code==expected and not data
    report["controls"]=len(controls);report["control_observations"]=controls
    report["source_after"]={p:identity(p) for p in inputs};assert report["source_after"]==inputs
    report.update(status="PASS",finalized=True,public_identifier_methods=9,public_command_methods=4,
                  encoded_type_shapes=97,over_transport_cap_message_bytes=2_098_177,
                  full_task_kernel_owner_qualified=False)
    save()
except BaseException as error:
    report.update(status="FAIL",finalized=False,failure=repr(error));save();raise
print(json.dumps({k:v for k,v in report.items() if k not in ["source_before","source_after"]}))
