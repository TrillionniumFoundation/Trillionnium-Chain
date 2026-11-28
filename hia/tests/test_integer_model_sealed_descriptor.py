"""Native M06 held fd0 to anonymous stdout, against the stock Rust model loader."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hia.platform.integer_model_handoff.build import BODY, WORK, disassemble
from hia.platform.integer_model_sealed_descriptor.build import (
    ADAPTER, ELF, PREFIX, bounded, build,
)
from hia.platform.worker_audit.build import fresh_directory
from hia.platform.worker_audit_sealed_query.build import RAW_MAX
from hia.tests.test_integer_model_handoff import invoke, native_entry
from hia.tests.test_integer_model_project import (
    MARK, OPCODES, Session, create_state, digest, emit_existing_owner, original_with_projection,
    panel, request, snapshot_request,
)
from hia.tests.test_worker_audit_sealed_query import check_nonpipe_sink
from hia.tests.test_worker_journal_audit_stdin import (
    ALL_SEALS, SEAL_WRITE, checked_adapter_readback, physical_fixture,
)


def layout(directory):
    path=directory/ELF
    old=checked_adapter_readback(path,directory/"existing-adapter.txt")
    # Strict model-specific range only; no newly decoded system instruction.
    raw=directory/"isolated-thunk.raw"
    raw.write_bytes(path.read_bytes()[ADAPTER:PREFIX])
    rows=disassemble(raw)
    by_at={i:(op,args) for i,op,args in rows}
    allowed={"push","mov","call","test","jne","cmpl","cmpw","pop","ret","xor","nop"}
    if {op for _,op,_ in rows}-allowed:
        raise AssertionError("Unexpected syscall or thunk instruction")
    calls=[(i,int(arg,16)) for i,op,arg in rows if op=="call"]
    if calls!=[(15,PREFIX-ADAPTER)] or by_at.get(20)!=("test","%rax,%rax"):
        raise AssertionError("Changed handoff entry or complete status check")
    for i,op,arg in rows:
        if op=="jne" and (int(arg,16) not in by_at or int(arg,16)<=i):
            raise AssertionError("A model adapter branch escaped its decoded forward boundary")
    if [int(x.split(",")[0][1:],16) for _,op,x in rows if op=="mov" and x.endswith(",%eax")
        ] != [BODY-2,BODY]:
        raise AssertionError("Changed accepted model output lengths")
    (directory/"thunk-disassembly.json").write_text(json.dumps(rows)+"\n")
    return {"existing_fd_syscalls":old,"handoff_call":calls[0],
            "syscall_free_thunk":True,"status_checked_before_classifying":True}


def refuse(image,indexed):
    valid=indexed
    cases=(
        ("one-extra",b"x"*(RAW_MAX+1),0,ALL_SEALS,71,0),
        ("exact-invalid-max",b"x"*RAW_MAX,0,ALL_SEALS,74,RAW_MAX),
        ("empty",b"",0,ALL_SEALS,74,0),
        ("short",valid[:71],0,ALL_SEALS,74,71),
        ("bad-seals",valid,0,0,70,0),
        ("missing-write-seal",valid,0,ALL_SEALS & ~SEAL_WRITE,70,0),
        ("nonzero-cursor",valid,1,ALL_SEALS,72,1),
    )
    controls={}
    for name,data,initial,seals,code,cursor in cases:
        run,p=physical_fixture(image,data,initial=initial,seals=seals)
        if (run.returncode,run.stdout,run.stderr,p["offset_after"])!=(code,b"",b"",cursor):
            raise AssertionError("Wrong original descriptor refusal: "+name)
        controls[name]=p
    controls["parent-owned-nonpipe"]=check_nonpipe_sink(image,valid)
    return controls


def qualify(output):
    bounded(output)
    native=output/"sealed"
    image,proof=build(native)
    checked=layout(native)
    stock=output/"stock"
    stock.mkdir()
    old,owner_proof=emit_existing_owner(stock)
    rust_dir=output/"rust"
    rust_dir.mkdir()
    rust,original=original_with_projection(rust_dir)
    if original["mode"]!="verified-prebuilt-original-lock":
        raise AssertionError("No genuine exact Rust oracle; refuse")
    memory=native_entry(native/"original-named/libtrnm_integer_model_handoff_v1.so")
    evidence=[]
    probe=None
    for case,(artifact,family,rows,projection,downstream) in enumerate(panel()):
        bounded(output)
        work=output/f"case-{case}"
        s=Session(old,work,seconds=30)
        try:
            state=create_state(s,rows)
            view=s.request(OPCODES["view.new"],a=state)
            if view["status"]!=0:
                raise AssertionError("Cannot hold actual qualifying State")
            snapshot,counters=snapshot_request(s,state)
            framed=request(snapshot,artifact,family)
            if len(framed)>RAW_MAX:
                raise AssertionError("Actual stock snapshot exceeds the unchanged held fd cap")
            query=artifact+family+struct.pack("<I",len(snapshot))+snapshot
            ref=subprocess.run([rust],input=query,capture_output=True,check=True,env={},timeout=20)
            if ref.stderr:
                raise AssertionError("Unexpected genuine Rust stderr")
            record=json.loads(ref.stdout)
            status=projection if downstream is None else downstream
            expected=bytes.fromhex(record["loaded_body"]) if status==0 else b""
            code,old_out,_=invoke(memory,framed)
            if (code,old_out)!=(status,expected+MARK*(BODY+13-len(expected))):
                raise AssertionError("Actual unchanged named reference disagrees with Rust output/status")
            if downstream is not None and record["original_load"]!={0:"OK",3:"FACTOR_MODEL_METADATA",
                                                                  4:"FACTOR_MODEL_CHUNK",10:"FACTOR_MODEL_HASH"}[status]:
                raise AssertionError("Unexpected genuine Rust outcome")
            if downstream is None and projection in (1,2) and record["status"]!=projection:
                raise AssertionError("Unexpected genuine original selection status")
            run,p=physical_fixture(image,framed)
            if ((run.returncode,run.stdout,run.stderr)!=(0 if status==0 else 74,expected,b"")
                    or (p["offset_before"],p["offset_after"],p["seals"])!=(0,len(framed),ALL_SEALS)
                    or not p["input_bytes_unchanged"]):
                raise AssertionError("Physical HIA result differs from stock original")
            if status==0:
                probe=framed
                (work/"sealed-input.raw").write_bytes(framed)
                (work/"rust-oracle.stdout.raw").write_bytes(ref.stdout)
                (work/"native.stdout.raw").write_bytes(run.stdout)
            if snapshot_request(s,state)!=(snapshot,counters):
                raise AssertionError("Offline query changed stock State or counters")
            dropped=s.request(OPCODES["view.drop"],a=view["result"])
            close=s.request(OPCODES["close"])
            if dropped["status"] or (close["status"],close["live_objects"],close["live_blocks"])!=(0,0,0):
                raise AssertionError("Qualifying stock State did not close")
        finally:
            receipt=s.finish(allow_failure=not s.closed)
        evidence.append({"case":case,"memory_status":code,"transport":p,
                         "original_load":record["original_load"],"snapshot_sha256":digest(snapshot),
                         "original_stdout_sha256":digest(ref.stdout),"stock":receipt})
    if probe is None or len(evidence)!=24:
        raise AssertionError("Actual handoff fixture family changed")
    controls=refuse(image,probe)
    checkout=subprocess.check_output(["git","rev-parse","HEAD"],cwd=Path(__file__).resolve().parents[2],
                                     env={**os.environ,"GIT_NO_LAZY_FETCH":"1"}).decode().strip()
    result={"status":"PASS","checkout_commit":checkout,"named_candidate":proof,"checked_layout":checked,"actual_cases":evidence,
            "physical_refusals":controls,"original_rust":original,"original_owner":owner_proof,
            "runtime_model_execution":False,"runtime_host_shuttle":False,"production_dispatch":False}
    (output/"report.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    return result


class IntegerModelSealedDescriptor(unittest.TestCase):
    def test_pinned_layout_and_seal_refusals(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m06-sealed-") as d:
            root=Path(d)/"sealed"
            image,_=build(root)
            layout(root)
            self.assertEqual(len(refuse(image,b"IMP1"+bytes(76))),8)

    @unittest.skipUnless(os.environ.get("HIA_M06_ORACLE_PREBUILT"),
                         "requires verified original immutable State and genuine locked Rust")
    def test_exact_original_model_bytes_via_sealed_file_descriptor(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m06-sealed-original-") as d:
            r=qualify(Path(d))
            self.assertEqual(len(r["actual_cases"]),24)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    out=p.parse_args().output.absolute()
    bounded(out.parent)
    r=qualify(fresh_directory(out))
    print(json.dumps({"status":r["status"],"cases":len(r["actual_cases"]),
                      "refusals":len(r["physical_refusals"])}))
