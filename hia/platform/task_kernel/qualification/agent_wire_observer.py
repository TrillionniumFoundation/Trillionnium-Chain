"""Execute native AgentTransaction methods against the unchanged Rust crate."""
from pathlib import Path
import ctypes
import hashlib
import json
import random
import struct
import subprocess
import sys
import time

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
report={"schema":"trnm.hia.task-kernel.agent-wire-qualification.v1","status":"FAIL","finalized":False,
        "scope":"Candidate AgentTransaction constructor, decoder, command/encoded/transaction_id getters",
        "native_calls":0,"original_calls":0,"fixture_preparations":0,"controls":0,"stages":[]}
def save():(WORK/"report.json").write_text(json.dumps(report,indent=2)+"\n")
def frame(op,data):return b"TKAW0001"+struct.pack("<QQ",op,len(data))+data
def u32(n):return struct.pack("<I",n)
def original(name,lines):
    data=b"\n".join(lines)+b"\n";(WORK/(name+".stdin.raw")).write_bytes(data)
    start=time.monotonic_ns()
    process=subprocess.run([str(ORIGINAL)],input=data,capture_output=True,timeout=120)
    (WORK/(name+".stdout.raw")).write_bytes(process.stdout);(WORK/(name+".stderr.raw")).write_bytes(process.stderr)
    report["stages"].append({"name":name,"argv":[str(ORIGINAL)],"exit_code":process.returncode,
                             "elapsed_ns":time.monotonic_ns()-start,"timeout_seconds":120});save()
    assert process.returncode==0 and not process.stderr
    output=process.stdout.splitlines();assert len(output)==len(lines)
    return output
def prepared(name,values):
    output=original(name,[b"prepare:"+v.hex().encode() for v in values])
    report["fixture_preparations"]+=len(values);return [bytes.fromhex(v.decode()) for v in output]
def decoded_result(line):
    code,encoded=line.split(b"|",1);return int(code),bytes.fromhex(encoded.decode())
def payload(output):
    code,ml,dl,pl=struct.unpack_from("<QQQQ",output)
    assert code==0 and ml==dl==0 and len(output)==32+pl
    return output[32:]
def wire_output(output):
    data=payload(output);cl,wl=struct.unpack_from("<QQ",data)
    assert len(data)==48+cl+wl
    return data[48+cl:]

try:
    build=json.loads((BUILD/"build.json").read_text())
    assert build["status"]=="PASS" and build["finalized"] and build["source_before"]==build["source_after"]
    inputs=dict(build["source_before"])
    for name,expected in build["artifacts"].items():
        path=BUILD/name;assert identity(path)==expected;inputs[str(path)]=expected
    for path in [Path(__file__),ORIGINAL,BUILD/"build.json"]:inputs[str(path)]=identity(path)
    assert {p:identity(p) for p in inputs}==inputs
    report["source_before"]=inputs;save()
    schema={int(k):v for k,v in json.loads(Path(__file__).with_name("type_layout.json").read_text()).items()}
    rng=random.Random(930_451)
    def value(kind,mode=0):
        row=schema[kind];tag=row["kind"];count=row["count"]
        if tag==0:return b""
        if tag==1:return bytes(count) if mode==0 else (b"\xff"*count if mode==1 else bytes(rng.randrange(256) for _ in range(count)))
        if tag==2:return bytes([mode%2])
        if tag==3:
            raw=[b"",b"\x00\x7f","正文😀".encode()][mode%3];return u32(len(raw))+raw
        if tag==4:return u32(mode%3)+b"".join(value(count,(mode+i)%3) for i in range(mode%3))
        if tag==5:return b"\x00" if mode%2==0 else b"\x01"+value(count,mode)
        if tag==6:return b"".join(value(k,mode) for k in row["fields"])
        if tag==7:return bytes([mode%count])+value(row["fields"][mode%count],mode)
        raise AssertionError(row)
    def end(kind,raw,p):
        row=schema[kind];tag=row["kind"];count=row["count"]
        if tag==0:return p
        if tag==1:return p+count
        if tag==2:return p+1
        if tag==3:return p+4+struct.unpack_from("<I",raw,p)[0]
        if tag==4:
            n=struct.unpack_from("<I",raw,p)[0];p+=4
            for _ in range(n):p=end(count,raw,p)
            return p
        if tag==5:return p+1 if raw[p]==0 else end(count,raw,p+1)
        if tag==6:
            for field in row["fields"]:p=end(field,raw,p)
            return p
        if tag==7:return end(row["fields"][raw[p]],raw,p+1)
        raise AssertionError(row)
    def fields(kind,raw,p):
        result=[]
        for k in schema[kind]["fields"]:
            q=end(k,raw,p);result.append((p,q));p=q
        return result
    def authorization(raw):return fields(68+raw[0],raw,1)[-1][0]
    def replace(raw,span,new):return raw[:span[0]]+new+raw[span[1]:]
    def statement(raw,index,new):return replace(raw,fields(59,raw,authorization(raw))[index],new)
    def context(raw,index,new):return replace(raw,fields(25,raw,authorization(raw)+2)[index],new)
    def signature(raw,n):return replace(raw,fields(60,raw,authorization(raw))[2],u32(n)+b"A"*n)

    cases=[]
    def add(name,op,raw):cases.append((name,frame(op,raw)))
    commands=prepared("prepare-commands",[bytes([v])+value(68+v,m) for v in range(6) for m in range(3)])
    base=commands[0]
    assert end(67,base,0)==len(base)
    for i,command in enumerate(commands):add(f"construct-variant-{i//3}-mode-{i%3}",0,command)
    # Constructor getters remain valid for Some(zero); decode rejects that wire.
    zero_commands=[statement(base,6,b"\x01"+bytes(32)),statement(base,8,b"\x01"+bytes(32))]
    for i,command in enumerate(zero_commands):add(f"construct-some-zero-{i}",0,command)
    constructor_inputs=commands+zero_commands
    constructor_lines=original("fixture-constructors",[frame(0,c).hex().encode() for c in constructor_inputs])
    report["fixture_preparations"]+=len(constructor_inputs)
    wires=[]
    for line in constructor_lines:
        code,data=decoded_result(line);assert code==0;wires.append(wire_output(data))
    for i,wire in enumerate(wires):add(f"decode-constructor-{i}",1,wire)
    base_wire=wires[0]
    for cut in sorted({0,1,2,7,8,9,10,11,12,140,172,173,205,206,257,258,293,294,325}):
        add(f"wire-truncated-{cut}",1,base_wire[:cut])
    for cut in sorted({0,1,2,17,len(base)//2,len(base)-1}):add(f"command-truncated-{cut}",0,base[:cut])
    add("command-trailing",0,base+b"\x00")
    for variant in [6,7,127,255]:add(f"command-bad-variant-{variant}",0,bytes([variant])+base[1:])
    for chain in [b"",b"x"*1,b"x"*127,b"x"*128,b"x"*129,"😀".encode()*32,"😀".encode()*32+b"x",b"\x00"]:
        add("context-chain-"+chain.hex()[:24]+"-"+str(len(chain)),0,context(base,1,u32(len(chain))+chain))
    for schema_version in [0,2,65535]:add(f"schema-{schema_version}",0,statement(base,0,struct.pack("<H",schema_version)))
    for protocol in [0,2,4294967295]:add(f"protocol-{protocol}",0,context(base,2,u32(protocol)))
    for kind in [0,1,3,7,8,65535]:add(f"statement-kind-{kind}",0,statement(base,2,struct.pack("<H",kind)))
    add("statement-digest-mismatch",0,statement(base,3,bytes(32)))
    for valid,expires in [(0,0),(1,0),(1,1),((1<<64)-1,(1<<64)-1),((1<<64)-1,(1<<64)-2)]:
        add(f"validity-{valid}-{expires}",0,statement(statement(base,13,struct.pack("<Q",valid)),14,struct.pack("<Q",expires)))
    for n in [0,1,31,32,63,64,65,127,256]:add(f"signature-width-{n}",0,signature(base,n))
    # Make exact 1 MiB and one-byte-over canonical commands without inventing a
    # smaller provider frame limit. The original computes their operation IDs.
    large=[]
    chain_at=35;old_size=struct.unpack_from("<I",base,chain_at)[0]
    for target in [1048576,1048577]:
        delta=target-len(base);raw=base[:chain_at]+u32(old_size+delta)+base[chain_at+4:chain_at+4+old_size]+b"x"*delta+base[chain_at+4+old_size:]
        assert len(raw)==target;large.append(raw)
    large=prepared("prepare-capacity-commands",large)
    assert [len(c) for c in large]==[1048576,1048577]
    for i,raw in enumerate(large):add(f"construct-command-capacity-{len(raw)}",0,raw)
    add("malformed-shape-before-command-capacity",0,statement(large[1],0,b"\x00\x00"))
    large_wire_line=original("fixture-capacity-wire",[frame(0,large[0]).hex().encode()])[0]
    report["fixture_preparations"]+=1
    large_wire=wire_output(decoded_result(large_wire_line)[1]);add("decode-exact-command-capacity",1,large_wire)

    def mutate(wire,p,new):return wire[:p]+new+wire[p+len(new):]
    for p in range(294):add(f"header-byte-{p}",1,mutate(base_wire,p,bytes([base_wire[p]^0x80])))
    for p in [140,173]:
        for tag in range(256):add(f"optional-tag-{p}-{tag}",1,mutate(base_wire,p,bytes([tag])))
        add(f"optional-absent-nonzero-{p}",1,mutate(base_wire,p+1,b"\x01"))
        add(f"optional-present-zero-{p}",1,mutate(base_wire,p,b"\x01"))
    for k in [0,1,2,7,8,65535]:add(f"wire-kind-{k}",1,mutate(base_wire,224,struct.pack("<H",k)))
    for n in [0,1,len(base)-1,len(base),len(base)+1,1048576,1048577,4294967295]:
        add(f"wire-length-{n}",1,mutate(base_wire,258,u32(n)))
    add("wire-trailing",1,base_wire+b"\x00")
    add("payload-and-wire-tamper",1,mutate(base_wire,294,b"\xff"))
    add("wire-only-tamper",1,mutate(base_wire,len(base_wire)-1,b"\xff"))
    # Mixed errors discriminate the original left-to-right rejection order.
    mixed=[("magic-before-schema",0,b"x",8,b"\x02\x00"),
           ("schema-before-flags",8,b"\x02\x00",10,b"\x01\x00"),
           ("flags-before-optional",10,b"\x01\x00",140,b"\x01"),
           ("capability-before-session",140,b"\x02",173,b"\x01"),
           ("optional-before-kind",140,b"\x01",224,b"\x00\x00"),
           ("kind-before-validity",224,b"\x00\x00",242,struct.pack("<Q",1)),
           ("length-before-commitment",258,u32(0),262,b"\xff")]
    for name,p,a,q,b in mixed:add(name,1,mutate(mutate(base_wire,p,a),q,b))
    inv=mutate(mutate(base_wire,242,struct.pack("<Q",1)),250,bytes(8))
    add("validity-before-length",1,mutate(inv,258,u32(0)))

    repaired=[]
    def repair_case(name,wire):repaired.append((name,wire))
    for p in [12,44,76,108,206,214,222,226,234,242]:
        repair_case(f"canonical-header-{p}",mutate(base_wire,p,bytes([base_wire[p]^1])))
    repair_case("canonical-operation-kind",mutate(base_wire,224,b"\x03\x00"))
    for p in [140,173]:repair_case(f"canonical-option-{p}",mutate(mutate(base_wire,p,b"\x01"),p+1,b"\x01"))
    for name,command in [("borsh-unknown-variant",b"\xff"+base[1:]),("borsh-truncated",base[:-1]),
                         ("borsh-trailing",base+b"\x00"),("shape-invalid",statement(base,0,bytes(2))),
                         ("signature-invalid",signature(base,63)),("over-command-capacity",large[1])]:
        repair_case(name,base_wire[:294]+command+bytes(32))
    repaired_lines=original("repair-wire-fixtures",[b"repair:"+raw.hex().encode() for _,raw in repaired])
    report["fixture_preparations"]+=len(repaired)
    for (name,_),line in zip(repaired,repaired_lines):add(name,1,bytes.fromhex(line.decode()))
    cases.extend([("empty-frame",b""),("unknown-op",frame(2,b"")),("frame-length",b"TKAW0001"+struct.pack("<QQ",0,1))])
    lines=original("original-differential",[raw.hex().encode() for _,raw in cases])
    library=ctypes.CDLL(str(BUILD/"agent-wire.so"));fn=library.f0
    fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3;fn.restype=ctypes.c_uint32
    def native(raw,output_capacity=None,scratch_capacity=None):
        source=ctypes.create_string_buffer(raw)
        output=ctypes.create_string_buffer(output_capacity if output_capacity is not None else len(raw)*2+4096)
        scratch=ctypes.create_string_buffer(scratch_capacity if scratch_capacity is not None else 262144+len(raw)*3)
        code=fn(source,len(raw),output,len(output),scratch,len(scratch))
        assert source.raw[:len(raw)]==raw
        if code:return code,b"",scratch.raw
        sizes=struct.unpack_from("<QQQQ",output.raw);extent=32+sum(sizes[1:]);assert extent<=len(output)
        return code,output.raw[:extent],scratch.raw
    with (WORK/"native-observations.jsonl").open("x") as stream:
        for index,((name,raw),line) in enumerate(zip(cases,lines)):
            expected_code,expected=decoded_result(line)
            row={"index":index,"name":name,"input":blob(raw),"expected_code":expected_code,"expected_output":blob(expected)}
            (WORK/"current-call.json").write_text(json.dumps(row)+"\n")
            code,data,scratch=native(raw);row.update(return_code=code,actual_output=blob(data),equal=(code==expected_code and data==expected))
            stream.write(json.dumps(row)+"\n");stream.flush();report["native_calls"]+=1;report["original_calls"]+=1;save()
            if not row["equal"]:
                (WORK/"failure-scratch.raw").write_bytes(scratch)
                raise AssertionError("Agent wire differential mismatch: "+name)
    raw=frame(0,base);expected=decoded_result(constructor_lines[0])[1];controls=[]
    for name,oc,sc,status in [("exact-output",len(expected),None,0),("output-one-short",len(expected)-1,None,101),
                              ("exact-workspace",None,262144+len(raw)*3,0),("workspace-one-short",None,262143+len(raw)*3,102)]:
        code,data,_=native(raw,oc,sc);controls.append({"name":name,"code":code,"expected":status})
        assert code==status and (data==expected if status==0 else data==b"")
    report["controls"]=len(controls);report["control_observations"]=controls
    report["source_after"]={p:identity(p) for p in inputs};assert report["source_after"]==inputs
    report.update(status="PASS",finalized=True,methods=5,command_variants=6,
                  actual_command_capacity_bytes=1048576,one_over_command_capacity_bytes=1048577,
                  some_zero_constructor_decode_asymmetry=True,full_task_kernel_owner_qualified=False,
                  wire_accepted=False,global_state_authority=False,production_activation=False)
    save()
except BaseException as error:
    report.update(status="FAIL",finalized=False,failure=repr(error));save();raise
print(json.dumps({k:v for k,v in report.items() if k not in ["source_before","source_after"]}))
