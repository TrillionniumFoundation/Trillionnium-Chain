"""Actual native ABI guards and an explicit private handle-exhaustion fixture."""
from __future__ import annotations
import ctypes,json,mmap,struct,traceback
from pathlib import Path
from .cases import command,envelope
from .contract import need,identity,write_json
from .native_io import decode

class Guarded:
    def __init__(self,n,fill=0):
        self.n=n;page=mmap.PAGESIZE;self.span=((n+64+page-1)//page)*page
        self.mapping=mmap.mmap(-1,self.span+2*page,prot=3)
        self.base=ctypes.addressof(ctypes.c_ubyte.from_buffer(self.mapping));self.address=self.base+page
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.libc.mprotect.argtypes=(ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int)
        need(self.libc.mprotect(self.base,page,0)==0,"Guard-page mprotect failed")
        need(self.libc.mprotect(self.base+page+self.span,page,0)==0,"Guard-page mprotect failed")
        ctypes.memset(self.address,fill,n);ctypes.memset(self.address+n,0xa7,64)
    def seal(self):
        need(self.libc.mprotect(self.address,self.span,1)==0,"Input protection failed")
    def bytes(self):
        need(ctypes.string_at(self.address+self.n,64)==b"\xa7"*64,"Native canary changed")
        return ctypes.string_at(self.address,self.n)
    def close(self):self.mapping.close()

def run(image,output,check_sources):
    out=Path(output);out.mkdir(mode=0o700)
    mapping=mmap.mmap(-1,len(image),prot=3);mapping.write(image)
    pointer=ctypes.addressof(ctypes.c_ubyte.from_buffer(mapping))
    libc=ctypes.CDLL(None,use_errno=True);libc.mprotect.argtypes=(ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int)
    need(libc.mprotect(pointer,len(image),5)==0,"Native image RX protection failed")
    fn=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,
        ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)(pointer)
    report={"schema":"trnm.hia.mempool-typed-guarded.v1","status":"FAIL",
        "image":identity(image),"actual_calls":[],"test_only_private_writes":[],
        "production_context_restore_opcode":False,"valid_call_output_preinitialized_by_observer":True,
        "kernel_output_gap_zeroization_claimed":False}
    arena=None
    def call(name,wire,heap,status,output_bytes=32768,unchanged=False):
        case=out/name;case.mkdir();inp=Guarded(len(wire));reply=Guarded(output_bytes,0 if status==0 else 0xa5)
        try:
            before=heap.bytes();ctypes.memmove(inp.address,wire,len(wire));inp.seal()
            returned=fn(inp.address,len(wire),reply.address,reply.n,heap.address,heap.n)
            actual_input=inp.bytes();actual_reply=reply.bytes();after=heap.bytes()
            need(actual_input==wire,"Native modified read-only input")
            row={"name":name,"status":"FAIL","actual_status":returned,"expected_status":status}
            report["actual_calls"].append(row)
            for suffix,raw in (("input.raw",wire),("output.raw",actual_reply),("context-before.raw",before),("context-after.raw",after)):
                (case/suffix).write_bytes(raw);row[suffix]=identity(raw)
            need(returned==status,"Wrong native status: "+name)
            if unchanged:need(after==before,"Rejected call changed private context")
            if returned==0:
                words=struct.unpack_from("<32Q",actual_reply)
                end=words[15]+16*words[14]
                need(end<=len(actual_reply),"Native output extent exceeds buffer")
                row["returned"]=decode(actual_reply[:end])
            row["context_unchanged"]=after==before
            row["status"]="PASS";write_json(case/"receipt.json",row)
            return row
        finally:inp.close();reply.close()
    def raw(command_row):return bytes.fromhex(command_row["input"])
    try:
        check_sources()
        for size in (0,1,7,8,16,24,32,39):
            arena=Guarded(8192);call("short-input-"+str(size),raw(command(0,2,0,32))[:size],arena,64,unchanged=True)
            arena.close();arena=None
        controls=[
            ("bad-magic",b"WRONG001"+raw(command(0,2,0,32))[8:],64,8192,32768),
            ("unknown-op",raw(command(24)),64,8192,32768),
            ("uninitialized-read",raw(command(8)),65,8192,32768),
            ("short-context",raw(command(0,2,0,32)),65,511,32768),
            ("short-output",raw(command(0,2,0,32)),66,8192,1023),
            ("reserved-word",raw(command(8,0,1,0)),64,8192,32768),
            ("oversized-constructor",raw(command(0,(1<<64)-1,0,32)),67,8192,32768)]
        for name,wire,code,heap_size,reply_size in controls:
            arena=Guarded(heap_size);call(name,wire,arena,code,reply_size,True)
            arena.close();arena=None
        arena=Guarded(8192)
        call("handle-new",raw(command(0,2,0,32)),arena,0)
        call("handle-first-admit",raw(envelope(3,tag=41)),arena,0)
        first=call("handle-first-pop",raw(command(6)),arena,0)
        need(first["returned"]["handle"]==1,"First ready handle differs")
        call("handle-first-drop",raw(command(19,1)),arena,0)
        before=arena.bytes();ctypes.memmove(arena.address+96,struct.pack("<Q",(1<<64)-1),8)
        after=arena.bytes()
        need(before[:96]==after[:96] and before[104:]==after[104:],"Private fixture changed extra bytes")
        report["test_only_private_writes"].append({"field":"next_ready_handle","offset":96,"bytes":8,
            "before":identity(before),"after":identity(after),"value":str((1<<64)-1)})
        (out/"private-write-before.raw").write_bytes(before);(out/"private-write-after.raw").write_bytes(after)
        call("handle-last-admit",raw(envelope(3,digest=2,tag=42)),arena,0)
        last=call("handle-last-pop",raw(command(6)),arena,0)
        need(last["returned"]["handle"]==(1<<64)-1,"Last ready handle differs")
        call("handle-last-drop",raw(command(19,(1<<64)-1)),arena,0)
        call("handle-exhausted-admit",raw(envelope(3,digest=3,tag=43)),arena,0)
        call("handle-exhausted-pop",raw(command(6)),arena,67,unchanged=True)
        old=call("handle-old-reference",raw(command(11,1)),arena,0)
        need(old["returned"]["outcome"]==3 and old["returned"]["reason"]==21,"Consumed handle revived")
        close=call("handle-complete-close",raw(command(22)),arena,0)
        need(close["returned"]["events"]==[[15,43]],"Pending cleanup differs")
        need(not any(arena.bytes()),"Private arena not completely zero")
        arena.close();arena=None;check_sources()
        report.update(status="PASS",actual_native_calls=len(report["actual_calls"]),
            handle_exhaustion_calls=11,consumed_handle_never_revived=True,exhaustion_preserves_queue=True,
            complete_private_arena_zero=True)
        return report
    except BaseException as error:
        report["failure"]={"error":repr(error),"traceback":traceback.format_exc()};raise
    finally:
        if arena is not None:arena.close()
        mapping.close()
        failure=None
        try:check_sources();report["source_after"]="MATCH"
        except BaseException as error:report["source_after"]="FAIL";report["status"]="FAIL";failure=error
        write_json(out/"report.json",report)
        if failure is not None:raise failure


def guarded_specifications():
    """Fixed source-derived calls; this is an observer specification, not an owner."""
    from .physical import _reply, _admit_events, _metadata
    def raw(row):
        return bytes.fromhex(row["input"])
    specs = []
    def add(name, wire, status, heap=8192, reply=32768, expected=None, serial=None, unchanged=True):
        specs.append({"name": name, "input": wire, "status": status, "heap": heap, "reply": reply,
            "expected": expected, "serial": serial, "unchanged": unchanged})
    for size in (0, 1, 7, 8, 16, 24, 32, 39):
        add("short-input-" + str(size), raw(command(0, 2, 0, 32))[:size], 64)
    for name, wire, status, heap, reply in (
        ("bad-magic", b"WRONG001" + raw(command(0, 2, 0, 32))[8:], 64, 8192, 32768),
        ("unknown-op", raw(command(24)), 64, 8192, 32768),
        ("uninitialized-read", raw(command(8)), 65, 8192, 32768),
        ("short-context", raw(command(0, 2, 0, 32)), 65, 511, 32768),
        ("short-output", raw(command(0, 2, 0, 32)), 66, 8192, 1023),
        ("reserved-word", raw(command(8, 0, 1, 0)), 64, 8192, 32768),
        ("oversized-constructor", raw(command(0, (1 << 64)-1, 0, 32)), 67, 8192, 32768)):
        add(name, wire, status, heap, reply)
    maximum = (1 << 64)-1
    def reply(op, counts=(0, 0, 0), **kw):
        return _reply(op, counts, limit=32, **kw)
    def owner(name, row, expected, serial, status=0, unchanged=False):
        add(name, raw(row), status, expected=expected, serial=serial, unchanged=unchanged)
    owner("handle-new", command(0, 2, 0, 32), reply(0), (0, 1))
    owner("handle-first-admit", envelope(3, tag=41), reply(3, (1, 0, 1), events=_admit_events()), (1, 1))
    owner("handle-first-pop", command(6), reply(6, handle=1, present=1, metadata=_metadata(body=b"a")), (1, 2))
    owner("handle-first-drop", command(19, 1), reply(19, events=((15, 41),)), (2, 2))
    owner("handle-last-admit", envelope(3, digest=2, tag=42),
          reply(3, (1, 0, 1), events=_admit_events()), (maximum, maximum))
    owner("handle-last-pop", command(6),
          reply(6, handle=maximum, present=1, metadata=_metadata(2, b"a")), (maximum, 0))
    owner("handle-last-drop", command(19, maximum), reply(19, events=((15, 42),)), (0, 0))
    owner("handle-exhausted-admit", envelope(3, digest=3, tag=43),
          reply(3, (1, 0, 1), events=_admit_events()), (0, 0))
    owner("handle-exhausted-pop", command(6), None, (0, 0), status=67, unchanged=True)
    owner("handle-old-reference", command(11, 1),
          reply(11, (1, 0, 1), outcome=3, reason=21), (0, 0), unchanged=True)
    owner("handle-complete-close", command(22), reply(22, events=((15, 43),), fresh=(0, 0)), (0, 0))
    need(len(specs) == 26 and len({x["name"] for x in specs}) == 26, "Guard source roster is incomplete")
    return specs

def verify_guarded(output, image):
    """Read all 26 actual calls, full arenas, and the sole private fixture transition."""
    from .contract import file_bytes, file_identity, load_json
    from .physical import _same_value
    out = Path(output); report = load_json(file_bytes(out / "report.json"))
    need(report.get("schema") == "trnm.hia.mempool-typed-guarded.v1" and report.get("status") == "PASS"
         and report.get("source_after") == "MATCH" and report.get("image") == identity(image),
         "Guarded image or source fence differs")
    need(report.get("production_context_restore_opcode") is False
         and report.get("valid_call_output_preinitialized_by_observer") is True
         and report.get("kernel_output_gap_zeroization_claimed") is False
         and report.get("consumed_handle_never_revived") is True
         and report.get("exhaustion_preserves_queue") is True
         and report.get("complete_private_arena_zero") is True, "Guarded observation scope differs")
    specs = guarded_specifications(); rows = report.get("actual_calls")
    need(isinstance(rows, list) and [r.get("name") for r in rows] == [s["name"] for s in specs]
         and type(report.get("actual_native_calls")) is int and report["actual_native_calls"] == len(rows)
         and type(report.get("handle_exhaustion_calls")) is int and report["handle_exhaustion_calls"] == 11,
         "Guarded complete call roster/order differs")
    fixture_before = file_bytes(out / "private-write-before.raw")
    fixture_after = file_bytes(out / "private-write-after.raw")
    need(len(fixture_before) == len(fixture_after) == 8192
         and struct.unpack_from("<Q", fixture_before, 96)[0] == 2
         and fixture_after == fixture_before[:96] + struct.pack("<Q", (1 << 64)-1) + fixture_before[104:],
         "Private handle fixture changes more than the sole allowed word")
    expected_fixture = [{"field": "next_ready_handle", "offset": 96, "bytes": 8,
        "before": identity(fixture_before), "after": identity(fixture_after), "value": str((1 << 64)-1)}]
    need(_same_value(report.get("test_only_private_writes"), expected_fixture),
         "Private handle fixture declaration differs from its actual bytes")
    files = {"report.json", "private-write-before.raw", "private-write-after.raw"}; previous = None
    for index, (row, spec) in enumerate(zip(rows, specs, strict=True)):
        directory = out / spec["name"]
        need(row.get("status") == "PASS" and type(row.get("actual_status")) is int
             and row["actual_status"] == spec["status"] and type(row.get("expected_status")) is int
             and row["expected_status"] == spec["status"], "Actual native guard status differs from source")
        expected_keys = {"name", "status", "actual_status", "expected_status", "context_unchanged",
            "input.raw", "output.raw", "context-before.raw", "context-after.raw"}
        if spec["status"] == 0:
            expected_keys.add("returned")
        need(set(row) == expected_keys, "Unexpected guarded call fields")
        raw = {name: file_bytes(directory / name)
            for name in ("input.raw", "output.raw", "context-before.raw", "context-after.raw")}
        for name, value in raw.items():
            need(row.get(name) == identity(value), "Guarded actual byte identity differs")
            files.add(spec["name"] + "/" + name)
        files.add(spec["name"] + "/receipt.json")
        need(_same_value(load_json(file_bytes(directory / "receipt.json")), row),
             "Guarded independent call receipt differs")
        before, after, returned = raw["context-before.raw"], raw["context-after.raw"], raw["output.raw"]
        need(raw["input.raw"] == spec["input"] and len(before) == len(after) == spec["heap"]
             and len(returned) == spec["reply"], "Guarded actual input or buffer extent differs")
        need(row.get("context_unchanged") is (before == after)
             and (before == after) is spec["unchanged"], "Native rejected or read-only call changed its arena")
        if index < 15:
            need(not any(before) and before == after and returned == b"\xa5" * spec["reply"],
                 "Fresh rejected native call mutated initialized bytes")
            continue
        if index == 15:
            need(not any(before), "Guarded owner did not begin in a fresh arena")
        elif spec["name"] == "handle-last-admit":
            need(previous == fixture_before and before == fixture_after,
                 "Private fixture is disconnected from the actual owner call history")
        else:
            need(before == previous, "Guarded actual owner arena continuity differs")
        serial_before, serial_after = spec["serial"]
        need(struct.unpack_from("<Q", before, 96)[0] == serial_before
             and struct.unpack_from("<Q", after, 96)[0] == serial_after,
             "Guarded actual handle generation/retirement differs")
        if spec["status"] == 0:
            words = struct.unpack_from("<32Q", returned)
            end = words[15] + 16 * words[14]
            need(256 <= end <= len(returned), "Guarded actual response extent is invalid")
            decoded = decode(returned[:end])
            need(_same_value(decoded, spec["expected"]) and _same_value(row.get("returned"), decoded)
                 and not any(returned[end:]), "Guarded response bytes or initialized tail differ")
        else:
            # f0 writes its empty framing header before tg_pop refuses exhaustion;
            # tg_publish is not called.  Its event base is 256 + max(input, heap-used).
            header = bytearray(256); header[:8] = b"MTOUT001"
            struct.pack_into("<Q", header, 8, 6)
            struct.pack_into("<Q", header, 120, 256 + max(len(spec["input"]), struct.unpack_from("<Q", before, 80)[0]))
            need(spec["name"] == "handle-exhausted-pop"
                 and returned == bytes(header) + b"\xa5" * (spec["reply"]-256),
                 "Handle exhaustion emitted or corrupted unexpected public bytes")
        if spec["name"] == "handle-complete-close":
            need(not any(after), "Native close did not erase the complete private arena")
        previous = after
    actual_files = set()
    for path in out.rglob("*"):
        need(not path.is_symlink(), "Symbolic guarded evidence path")
        if path.is_dir():
            continue
        file_identity(path); actual_files.add(path.relative_to(out).as_posix())
    need(actual_files == files, "Guarded evidence has missing or extra call artifacts")
    return report
