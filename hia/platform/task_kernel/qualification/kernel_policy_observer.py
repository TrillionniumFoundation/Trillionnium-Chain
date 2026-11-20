"""Run native store policy against actual private Rust methods and Dalek."""
from pathlib import Path
import ctypes
import hashlib
import json
import random
import struct
import subprocess
import sys
import time
from borsh_fixture import Fixtures

ROOT=Path(__file__).resolve().parents[4]
BUILD,ORIGINAL,WORK=Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]).absolute()
assert __debug__ and not WORK.exists() and ROOT not in WORK.parents
WORK.mkdir(mode=0o700);(WORK/"blobs").mkdir()
def identity(p):
    raw=Path(p).read_bytes();return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def blob(raw):
    digest=hashlib.sha256(raw).hexdigest();path=WORK/"blobs"/digest
    if not path.exists():path.write_bytes(raw)
    assert path.read_bytes()==raw
    return {"bytes":len(raw),"sha256":digest,"path":"blobs/"+digest}
report={"schema":"trnm.hia.task-kernel.kernel-policy-qualification.v1","status":"FAIL","finalized":False,
        "scope":"Store trust, static committed context, command envelope, authorization signature and config hash",
        "native_calls":0,"original_calls":0,"fixture_preparations":0,"controls":0,"stages":[]}
def save():(WORK/"report.json").write_text(json.dumps(report,indent=2)+"\n")
def frame(op,bundle=b"",extra=b"",height=0):return b"TKPL0001"+struct.pack("<QQQQ",op,height,len(bundle),len(extra))+bundle+extra
def uint(n,size):return n.to_bytes(size,"little")
def original(name,lines):
    data=b"\n".join(lines)+b"\n";(WORK/(name+".stdin.raw")).write_bytes(data)
    start=time.monotonic_ns()
    process=subprocess.run([str(ORIGINAL)],input=data,capture_output=True,timeout=360)
    (WORK/(name+".stdout.raw")).write_bytes(process.stdout);(WORK/(name+".stderr.raw")).write_bytes(process.stderr)
    report["stages"].append({"name":name,"argv":[str(ORIGINAL)],"exit_code":process.returncode,
                            "elapsed_ns":time.monotonic_ns()-start,"timeout_seconds":360});save()
    assert process.returncode==0 and not process.stderr
    output=process.stdout.splitlines();assert len(output)==len(lines)
    return output
def prepare(name,lines):
    result=original(name,lines);report["fixture_preparations"]+=len(lines)
    return [bytes.fromhex(line.decode()) for line in result]
def decoded(line):
    code,data=line.split(b"|",1);return int(code),bytes.fromhex(data.decode())

try:
    build=json.loads((BUILD/"build.json").read_text())
    assert build["status"]=="PASS" and build["finalized"] and build["source_before"]==build["source_after"]
    inputs=dict(build["source_before"])
    for name,expected in build["artifacts"].items():
        path=BUILD/name;assert identity(path)==expected;inputs[str(path)]=expected
    for path in [Path(__file__),Path(__file__).with_name("borsh_fixture.py"),ORIGINAL,BUILD/"build.json"]:inputs[str(path)]=identity(path)
    assert {p:identity(p) for p in inputs}==inputs
    report["source_before"]=inputs;save()
    fixtures=Fixtures(315_904);value=fixtures.value;fields=fixtures.fields;replace=fixtures.replace
    def field(kind,raw,index,p=0):
        a,b=fields(kind,raw,p)[index];return raw[a:b]
    def changed(kind,raw,index,new,p=0):return replace(raw,fields(kind,raw,p)[index],new)
    def bootstrap(raw,actor,index,new):
        p=fields(27,raw)[4+actor][0];return changed(26,raw,index,new,p)
    def trust_context(raw,index,new):
        p=fields(27,raw)[1][0];return changed(25,raw,index,new,p)
    def body_field(raw,kind,slot,index,new):
        p=fields(27,raw)[slot][0];return changed(kind,raw,index,new,p)
    def authorization(raw):return fields(68+raw[0],raw,1)[-1][0]
    def statement(raw,index,new):return changed(59,raw,index,new,authorization(raw))
    def signature(raw,new):return changed(60,raw,2,uint(len(new),4)+new,authorization(raw))
    def signer(raw,new):return changed(60,raw,1,new,authorization(raw))
    cases=[]
    def add(name,op,bundle=b"",extra=b"",height=0):cases.append((name,frame(op,bundle,extra,height)))
    bundles=prepare("prepare-trust",[b"trust:"+value(27,m).hex().encode() for m in range(3)])
    base=bundles[0]
    for mode,bundle in enumerate(bundles):
        add(f"trust-valid-mode-{mode}",0,bundle)
        add(f"config-hash-mode-{mode}",4,bundle,bytes([mode])*32)
    for n in [0,2,65535]:add(f"trust-schema-{n}",0,changed(27,base,0,uint(n,2)))
    for n in [0,2,4294967295]:add(f"trust-protocol-{n}",0,trust_context(base,2,uint(n,4)))
    add("trust-empty-chain",0,trust_context(base,1,bytes(4)))
    for index in [3,7,10]:add(f"trust-zero-id-{index}",0,changed(27,base,index,bytes(32)))
    for actor in range(2):
        for index in [0,1,3]:add(f"trust-zero-bootstrap-{actor}-{index}",0,bootstrap(base,actor,index,bytes(32)))
    add("trust-agents-equal",0,bootstrap(base,1,0,bytes([1])*32))
    key_positions=[(a,i) for a in range(2) for i in [1,3]]
    pub_positions=[(a,i) for a in range(2) for i in [2,4]]
    def pub(raw,position):
        actor,index=position;p=fields(27,raw)[4+actor][0];return field(26,raw,index,p)
    for j in range(4):
        for k in range(j):
            add(f"trust-key-id-duplicate-{j}-{k}",0,bootstrap(base,*key_positions[j],pub(base,key_positions[k])))
            add(f"trust-public-key-duplicate-{j}-{k}",0,bootstrap(base,*pub_positions[j],pub(base,pub_positions[k])))
    for slot in [8,11,12]:add(f"trust-zero-funding-{slot}",0,changed(27,base,slot,bytes(16)))
    for funding,hold in [(1,1),(1,2),((1<<128)-1,(1<<128)-1),((1<<127),(1<<127)+1),((1<<64)-1,1<<64)]:
        add(f"trust-funding-{funding}-{hold}",0,changed(27,changed(27,base,11,uint(funding,16)),12,uint(hold,16)))
    add("trust-requester-full-u128",0,changed(27,base,8,uint((1<<128)-1,16)))
    # ID preparation uses the original account_id/bond_id functions, retaining
    # malformed contexts and owners so later validation branches are reached.
    id_fixtures=[]
    for kind,slot in [(43,6),(45,9)]:
        context=field(25,field(kind,field(27,base,slot),1),0)
        original_context=field(kind,field(27,base,slot),1)
        other_context=changed(25,original_context,0,bytes([9])*32)
        id_fixtures.extend([(f"trust-body-context-{kind}",body_field(base,kind,slot,1,other_context)),
                            (f"trust-body-owner-{kind}",body_field(base,kind,slot,2,bytes([9])*32)),
                            (f"trust-body-schema-unchecked-{kind}",body_field(base,kind,slot,0,uint(65535,2)))])
    id_values=prepare("prepare-late-trust-ids",[b"ids:"+raw.hex().encode() for _,raw in id_fixtures])
    for (name,_),raw in zip(id_fixtures,id_values):add(name,0,raw)

    rng=random.Random(780_311)
    points=[]
    for y in list(range(20))+list(range((1<<255)-20,1<<255)):
        for sign in [0,1]:points.append(uint(y+(sign<<255),32))
    points.extend(bytes(rng.randrange(256) for _ in range(32)) for _ in range(128))
    for i,key in enumerate(points):add(f"dalek-public-key-{i}",5,b"",key)
    point_lines=original("prepare-public-key-classification",[frame(5,b"",key).hex().encode() for key in points])
    report["fixture_preparations"]+=len(points)
    classifications=[decoded(line)[1][32:] for line in point_lines]
    invalid=next(k for k,c in zip(points,classifications) if c==b"\x00\x00")
    weak=next(k for k,c in zip(points,classifications) if c==b"\x01\x01")
    noncanonical=uint((1<<255)-19+3,32)
    for slot,position in enumerate(pub_positions):
        for label,key in [("invalid",invalid),("weak",weak),("noncanonical",noncanonical)]:
            add(f"trust-public-{slot}-{label}",0,bootstrap(base,*position,key))
    invalids=base
    for slot,position in reversed(list(enumerate(pub_positions))):
        # Distinct invalid encodings retain the public-key uniqueness gate.
        key=next(k for k,c in zip(points[slot:],classifications[slot:]) if c==b"\x00\x00" and k not in [pub(invalids,p) for p in pub_positions])
        invalids=bootstrap(invalids,*position,key);add(f"trust-public-error-order-{slot}",0,invalids)
    add("trust-context-before-identities",0,changed(27,changed(27,base,3,bytes(32)),0,bytes(2)))
    add("trust-identities-before-public-key",0,changed(27,bootstrap(base,0,2,invalid),3,bytes(32)))
    add("config-hash-does-not-validate-trust",4,changed(27,base,0,bytes(2)),bytes(32))

    context=field(27,base,1)
    def execution(expected,height,old,new,schema=1,ctx=context):return uint(schema,2)+ctx+uint(expected,8)+old+uint(height,8)+new
    old=bytes([3])*32;new=bytes([4])*32
    for expected,height in [(0,0),(0,1),(0,(1<<64)-1),(1,0),(1,1),(1,2),((1<<64)-1,(1<<64)-1),((1<<64)-1,0)]:
        for same in [False,True]:add(f"execution-{expected}-{height}-same-{same}",1,base,execution(expected,height,old,old if same else new))
    add("execution-zero-parent",1,base,execution(0,1,bytes(32),new))
    add("execution-zero-target",1,base,execution(0,1,old,bytes(32)))
    add("execution-schema",1,base,execution(0,1,old,new,0))
    add("execution-context",1,base,execution(0,1,old,new,ctx=changed(25,context,0,bytes(32))))
    add("execution-does-not-revalidate-trust",1,changed(27,base,0,bytes(2)),execution(0,1,old,new))

    commands=prepare("prepare-signed-commands",[b"command:"+bundles[m].hex().encode()+b":"+(bytes([v])+value(68+v,m)).hex().encode()+b":"+str(a).encode() for v in range(6) for m in range(3) for a in range(2)])
    for i,command in enumerate(commands):
        mode=i//2%3;add(f"envelope-valid-{i}",2,bundles[mode],command,7);add(f"signature-valid-{i}",3,bundles[mode],command)
    command=commands[0]
    for height in [0,1,(1<<64)-1]:add(f"envelope-height-{height}",2,base,command,height)
    for n in [0,1,63,64,65,127,256]:
        raw=signature(command,b"x"*n);add(f"envelope-signature-width-{n}",2,base,raw);add(f"direct-signature-width-{n}",3,base,raw)
    for index,width in [(0,2),(2,2),(3,32)]:
        raw=statement(command,index,bytes(width));add(f"envelope-statement-field-{index}",2,base,raw)
    bad_context=changed(25,context,0,bytes(32));add("envelope-context-mismatch",2,base,statement(command,1,bad_context))
    for valid,expires,height in [(0,0,0),(0,0,1),(1,0,0),(1,0,1),(1,1,0),(1,1,1),(1,1,2),((1<<64)-1,(1<<64)-1,(1<<64)-1)]:
        raw=statement(statement(command,13,uint(valid,8)),14,uint(expires,8))
        add(f"envelope-interval-{valid}-{expires}-{height}",2,base,raw,height)
    for op in [2,3]:
        add(f"unknown-agent-{op}",op,base,statement(command,4,bytes([9])*32))
        add(f"wrong-key-role-{op}",op,base,signer(command,bytes([12])*32))
        add(f"invalid-committed-key-{op}",op,bootstrap(base,0,2,invalid),command)
        add(f"weak-committed-key-{op}",op,bootstrap(base,0,2,weak),command)
        add(f"noncanonical-committed-key-{op}",op,bootstrap(base,0,2,noncanonical),command)
        add(f"invalid-key-and-short-signature-{op}",op,bootstrap(base,0,2,invalid),signature(command,b""))
        add(f"unknown-agent-and-short-signature-{op}",op,base,signature(statement(command,4,bytes([9])*32),b""))
    add("envelope-context-before-height-signature",2,base,signature(statement(statement(command,0,bytes(2)),13,uint(1,8)),b""))
    add("envelope-height-before-signature",2,base,signature(statement(command,13,uint(1,8)),b""))
    add("direct-agent-before-key-role",3,base,signer(statement(command,4,bytes([9])*32),bytes(32)))
    malformed_signed=[statement(command,0,bytes(2)),statement(command,1,bad_context),statement(command,2,uint(65535,2)),statement(command,3,bytes(32)),statement(statement(command,13,uint(1,8)),14,bytes(8))]
    signed=prepare("prepare-direct-only-signatures",[b"sign:"+base.hex().encode()+b":"+raw.hex().encode()+b":0" for raw in malformed_signed])
    for i,raw in enumerate(signed):add(f"direct-signed-malformed-statement-{i}",3,base,raw);add(f"envelope-signed-malformed-statement-{i}",2,base,raw)
    sig=field(60,command,2,authorization(command))[4:]
    for i in range(64):add(f"strict-signature-bit-{i}",3,base,signature(command,sig[:i]+bytes([sig[i]^128])+sig[i+1:]))
    order=(1<<252)+27742317777372353535851937790883648493
    for scalar in [0,1,order-1,order,order+1,(1<<256)-1]:add(f"strict-scalar-{scalar}",3,base,signature(command,sig[:32]+uint(scalar,32)))
    for i,r in enumerate([bytes(32),uint(1,32),uint((1<<255)-19,32),uint((1<<255)-18,32),uint(1+(1<<255),32),bytes([255])*32]):add(f"strict-r-{i}",3,base,signature(command,r+sig[32:]))
    # More than the old transport cap is an ordinary trust context. Actual
    # bytes are hashed and compared by both native HIA and original Rust.
    for size in [129,2098177]:
        raw=trust_context(base,1,uint(size,4)+b"x"*size)
        large=prepare(f"prepare-long-trust-{size}",[b"trust:"+raw.hex().encode()])[0]
        add(f"trust-long-chain-{size}",0,large);add(f"config-long-chain-{size}",4,large,bytes([7])*32)
    for cut in [0,1,2,31,len(base)-1]:add(f"trust-borsh-truncated-{cut}",0,base[:cut])
    add("trust-borsh-trailing",0,base+b"x")
    for op in [1,2,3]:
        raw=execution(0,1,old,new) if op==1 else command
        for bad in [b"",raw[:-1],raw+b"x"]:add(f"extra-borsh-{op}-{len(bad)}",op,base,bad)
    cases.extend([("empty-frame",b""),("unknown-operation",frame(6)),("frame-length",b"TKPL0001"+struct.pack("<QQQQ",0,0,1,0)),("wrong-public-key-frame",frame(5,b"x",bytes(32)))])
    lines=original("original-differential",[raw.hex().encode() for _,raw in cases])
    library=ctypes.CDLL(str(BUILD/"kernel-policy.so"));fn=library.f0
    fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;fn.restype=ctypes.c_uint32
    def native(raw,output_capacity=4096,scratch_capacity=None):
        source=ctypes.create_string_buffer(raw);output=ctypes.create_string_buffer(output_capacity)
        scratch=ctypes.create_string_buffer(scratch_capacity if scratch_capacity is not None else 262144+len(raw))
        code=fn(source,len(raw),output,len(output),scratch,len(scratch))
        assert source.raw[:len(raw)]==raw
        if code:return code,b"",scratch.raw
        sizes=struct.unpack_from("<QQQQ",output.raw);extent=32+sum(sizes[1:]);assert extent<=len(output)
        return code,output.raw[:extent],scratch.raw
    with (WORK/"native-observations.jsonl").open("x") as stream:
        for index,((name,raw),line) in enumerate(zip(cases,lines)):
            expected_code,expected=decoded(line)
            row={"index":index,"name":name,"input":blob(raw),"expected_code":expected_code,"expected_output":blob(expected)}
            (WORK/"current-call.json").write_text(json.dumps(row)+"\n")
            start=time.monotonic_ns();code,data,scratch=native(raw)
            row.update(return_code=code,actual_output=blob(data),equal=(code==expected_code and data==expected),elapsed_ns=time.monotonic_ns()-start)
            stream.write(json.dumps(row)+"\n");stream.flush();report["native_calls"]+=1;report["original_calls"]+=1;save()
            if not row["equal"]:
                (WORK/"failure-scratch.raw").write_bytes(scratch)
                raise AssertionError("Kernel policy differential mismatch: "+name)
    raw=frame(0,base);expected=bytes(32);controls=[]
    for name,oc,sc,status in [("exact-output",32,None,0),("output-one-short",31,None,101),
                             ("exact-workspace",4096,262144+len(raw),0),("workspace-one-short",4096,262143+len(raw),102)]:
        code,data,_=native(raw,oc,sc);controls.append({"name":name,"code":code,"expected":status})
        assert code==status and (data==expected if status==0 else data==b"")
    report["controls"]=len(controls);report["control_observations"]=controls
    report["source_after"]={p:identity(p) for p in inputs};assert report["source_after"]==inputs
    report.update(status="PASS",finalized=True,private_original_methods=5,public_key_original_vectors=len(points),
                  actual_chain_bytes_over_transport_limit=2098177,full_task_kernel_owner_qualified=False,
                  wire_accepted=False,global_state_authority=False,production_activation=False)
    save()
except BaseException as error:
    report.update(status="FAIL",finalized=False,failure=repr(error));save();raise
print(json.dumps({k:v for k,v in report.items() if k not in ["source_before","source_after"]}))
