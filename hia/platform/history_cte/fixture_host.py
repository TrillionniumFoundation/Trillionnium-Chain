"""Bounded opaque transport for a generated, process-private SQLite fixture."""
from importlib.util import module_from_spec, spec_from_file_location
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import resource
import struct
import sys

spec = spec_from_file_location("qualified_sqlite_transport",
                               Path(__file__).resolve().parents[1] / "state_import_sqlite/qualification_host.py")
transport = module_from_spec(spec)
spec.loader.exec_module(transport)

SQL = (
    "a43bf20b0f174990a632a7ee7d573f022739fb768b4c6702dc55d869a9a9d164",  # fixture table
    "8f178284da745f10a8190ea718270372e67bba740919275794e28eefef75245a",  # four fixed rows
    "557032bacdb62dd38d519332044850ce24d39f396eabd6550d6134555c261648",  # query-only
    "0f4b704d3d5fee91872834753c4798a8439d96eda94d0904e536e1ef7041a5e0",  # read transaction
    "a91020ba58b5cf16d5436bf509a24ad2d79960dfed49f38edba8859a0c357111",  # frozen CTE
    "79663c1d3b43ceaf9ee728e501c64b57ae2e4d6cb36ff5c65eddcda1de27342f",  # COMMIT
)


def run(reader, provider, mode):
    return drive(reader,provider,mode,8192,100,SQL)


def drive(reader, provider, mode, n, operations, allowed_sql):
    # Bounds and allowed literals are fixed by the private profile entry.
    # They cannot come from the JSON message or native provider responses.
    sig = ctypes.c_void_p, ctypes.c_uint64
    ptr, u64 = sig
    step = transport.bind(reader,"f0",u64,*sig,*sig,*sig)
    make = transport.bind(provider,"trnm_task_provider_new",ptr)
    free = transport.bind(provider,"trnm_task_provider_free",None,ptr)
    reset = transport.bind(provider,"trnm_task_provider_reset",u64,ptr)
    fetch = transport.bind(provider,"trnm_task_provider",u64,ptr,u64,*sig,*sig)
    state = ctypes.create_string_buffer(n)
    response = ctypes.create_string_buffer(128)
    addr = ctypes.addressof(state)
    owner = make()
    if not owner:
        raise MemoryError("Mechanical provider allocation")
    raw = struct.pack("<Q",mode)
    log, statements = [], []
    try:
        for turn in range(operations):
            arg = ctypes.create_string_buffer(raw)
            status = step(arg,len(raw),state,n,None,0)
            phase,op,size,published = struct.unpack_from("<4Q",state)
            if status != 198:
                if status not in (0,100) or (status and published) or (
                        not status and (not 8 <= published <= n-4096 or phase != 7)):
                    raise ValueError("Unexpected fixture publication")
                released = reset(owner)
                if not status and released != 0:
                    raise ValueError("Successful projection must leave no retained provider resources")
                return {"status":status,"released":released,"log":log,"sql":statements,
                        "result":ctypes.string_at(addr+4096,published).hex() if not status else None}
            if published or op not in (2,3,5,6,7,8,9,13) or not 8 <= size <= 1340:
                raise ValueError("Native request outside the fixed provider profile")
            request = ctypes.string_at(addr+256,size)
            if op == 2 and (turn or request != struct.pack("<QQ",6,8)+b":memory:"):
                raise ValueError("Fixture may open its own fixed in-memory database only")
            if op == 5:
                statement = request[16:]
                pin = sha256(statement).hexdigest()
                if len(statements) >= len(allowed_sql) or pin != allowed_sql[len(statements)]:
                    raise ValueError("Outside the six exact statements")
                statements.append(pin)
            length = fetch(owner,op,addr+256,size,response,len(response))
            if not 24 <= length <= len(response):
                raise ValueError("Unrecognized mechanical provider response")
            raw = ctypes.string_at(response,length)
            log.append([phase,op,length,struct.unpack_from("<Q",raw)[0]])
        raise ValueError("Bounded native query did not finish")
    finally:
        free(owner)


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
    msg = json.load(sys.stdin)
    if set(msg) != {"reader","provider","mode"} or type(msg["mode"]) is not int or not 0 <= msg["mode"] <= 3:
        raise ValueError("Only a fixed synthetic fixture mode is supported")
    with transport.sealed_library(*msg["reader"]) as reader, transport.sealed_library(*msg["provider"]) as provider:
        print(json.dumps(run(reader,provider,msg["mode"])))


if __name__=="__main__":
    main()
