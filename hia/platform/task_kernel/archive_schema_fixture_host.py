"""Only transfers mechanically scoped requests from native M10 to the pinned provider."""
from importlib.util import module_from_spec, spec_from_file_location
import ctypes
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import sys

spec = spec_from_file_location("qualified_sqlite_transport",
                               Path(__file__).resolve().parents[1] / "state_import_sqlite/qualification_host.py")
transport = module_from_spec(spec)
spec.loader.exec_module(transport)


def read_fixture(reader, provider, directory, db, expected, policy=None, audit=None):
    if (directory.resolve(strict=True) != directory or directory.is_symlink()
            or directory.name != "owned" or directory.stat().st_mode & 0o077
            or not directory.parent.name.startswith("m10-archive-schema-")
            or db.parent != directory or db.is_symlink() or not db.is_file()
            or len(expected)!=32):
        raise ValueError("An exact owned disposable M10 archive store is required")
    path = os.fsencode(db)
    if not 1<=len(path)<=512 or b"\0" in path:
        raise ValueError("Bounded canonical owned path required")
    ptr,u64 = ctypes.c_void_p,ctypes.c_uint64
    step = transport.bind(reader,"f0",u64,ptr,u64,ptr,u64,ptr,u64)
    make = transport.bind(provider,"trnm_task_provider_new",ptr)
    free = transport.bind(provider,"trnm_task_provider_free",None,ptr)
    reset = transport.bind(provider,"trnm_task_provider_reset",u64,ptr)
    fetch = transport.bind(provider,"trnm_task_provider",u64,ptr,u64,ptr,u64,ptr,u64)
    n = transport.EXTENT
    state,work,reply = (ctypes.create_string_buffer(n) for _ in range(3))
    addr = ctypes.addressof(state)
    owner = make()
    if not owner:
        raise MemoryError("Mechanical provider allocation")
    raw = expected.hex().upper().encode()+path
    whole_snapshot = policy is not None and audit is not None
    if whole_snapshot:
        if not 114 <= len(policy) <= 626:
            raise ValueError("Original policy has no bounded private representation")
        raw = struct.pack("<Q",len(policy))+policy+raw
    transcript=[]
    try:
        for i in range(160 if whole_snapshot else 96):
            args = ctypes.create_string_buffer(raw)
            rc = step(args,len(raw),state,n,work,n)
            phase,op,length,published = struct.unpack_from("<QQQQ",state)
            if rc != 198:
                extent_matches = 258 <= published <= 40000 if whole_snapshot else published == 240
                if rc not in (0,21,22,100) or (not rc and (not extent_matches or phase!=160)) or (rc and published):
                    raise ValueError(f"Invalid native completion or publication: {rc}")
                released = reset(owner)
                if whole_snapshot and not rc:
                    if released:
                        raise ValueError("Native audit handoff requires prior complete closure")
                    capture = ctypes.string_at(addr+8192,published)
                    audit_result = transport.bind(audit,"f0",u64,ptr,u64,ptr,u64,ptr,u64)
                    out, scratch = ctypes.create_string_buffer(32), ctypes.create_string_buffer(2400)
                    borrowed = ctypes.create_string_buffer(capture)
                    rc = audit_result(borrowed,len(capture),out,32,scratch,2400)
                    if rc>>32 or borrowed.raw[:len(capture)]!=capture or (rc and out.raw!=bytes(32)):
                        raise ValueError("Captured packet was not used as the exact immutable audit input")
                    return {"status":rc,"result":out.raw.hex() if not rc else None,
                            "capture_sha256":hashlib.sha256(capture).hexdigest(),"capture_length":published,
                            "transcript":transcript,"released":released}
                result = ctypes.string_at(addr+4096,published).decode("ascii") if not rc else None
                return {"status":rc,"result":result,"transcript":transcript,"released":released}
            if published or op not in (2,3,5,7,8,9) or not 8<=length<=(2048 if whole_snapshot else 1040):
                raise ValueError("Operation left the exact existing read-only provider ABI")
            if op==2:
                flag,size = struct.unpack_from("<QQ",state,256)
                if i!=0 or flag!=16777217 or size!=len(path) or length!=16+size:
                    raise ValueError("Unexpected native archive OPEN outside read-only profile")
                if ctypes.string_at(addr+272,size)!=path:
                    raise ValueError("Native OPEN does not use the identical owned path")
            if op==5:
                text = ctypes.string_at(addr+272,length-16)
                if not text.startswith((b"SELECT ",b"BEGIN DEFERRED",b"COMMIT")) or b";" in text:
                    raise ValueError("Provider request outside isolated read transaction")
            got = fetch(owner,op,addr+256,length,reply,n)
            if got>n:
                raise ValueError("Invalid mechanical response extent")
            transcript.append((phase,op,got))
            raw = ctypes.string_at(reply,got)
        raise ValueError("Bounded native query did not finish")
    finally:
        free(owner)


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
    msg = json.load(sys.stdin)
    with transport.sealed_library(*msg["reader"]) as reader, transport.sealed_library(*msg["provider"]) as provider:
        args = reader,provider,Path(msg["directory"]),Path(msg["db"]),bytes.fromhex(msg["expected"])
        if "audit" in msg:
            with transport.sealed_library(*msg["audit"]) as audit:
                data = read_fixture(*args,policy=bytes.fromhex(msg["policy"]),audit=audit)
        else:
            data = read_fixture(*args)
    print(json.dumps(data))


if __name__=="__main__":
    main()
