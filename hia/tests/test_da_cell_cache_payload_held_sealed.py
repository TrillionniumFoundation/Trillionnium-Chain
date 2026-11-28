"""Exact held-chunk bytes over private fixed sealed FD0, verified offline."""
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest

from hia.platform.cell_cache_held_sealed.build import ADAPTER, ELF, OUT_MAX, PREFIX, RAW_MAX, build
from hia.platform.integer_model_handoff.build import disassemble
from hia.tests.cache_payload_held_original import original
from hia.tests.test_da_cell_cache_payload_held_read import (
    ABSENT, CAP, MAX, canonical, cases, copied, data, request,
)
from hia.tests.test_worker_audit_sealed_query import check_nonpipe_sink
from hia.tests.test_worker_journal_audit_stdin import (
    ADD_SEALS, ALL_SEALS, GET_SEALS, SEAL_WRITE, _sealed_image,
    checked_adapter_readback, physical_fixture,
)


def held_readback(image, payload):
    """Return actual bytes re-read from the same held, sealed description."""
    if len(payload) > RAW_MAX:
        raise ValueError("Use exact physical cap for positive and semantic cases")
    fd = os.memfd_create("private-synthetic-tcm1", os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(payload)
        fcntl.fcntl(fd, ADD_SEALS, ALL_SEALS)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != len(payload):
            raise AssertionError("Unexpected held object")
        if os.lseek(fd,0,os.SEEK_SET) or fcntl.fcntl(fd,GET_SEALS) != ALL_SEALS:
            raise AssertionError("Unexpected held offset or seals")
        with _sealed_image(image) as executable:
            result = subprocess.run([f"/proc/self/fd/{executable}"], stdin=fd,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    pass_fds=(executable,), close_fds=True,
                                    env={}, check=False, timeout=15)
        after = os.fstat(fd)
        if ((before.st_dev,before.st_ino,before.st_size) !=
                (after.st_dev,after.st_ino,after.st_size)
                or os.lseek(fd,0,os.SEEK_CUR) != before.st_size
                or fcntl.fcntl(fd,GET_SEALS) != ALL_SEALS):
            raise AssertionError("Held object identity, seals or exact final offset changed")
        raw = os.pread(fd,before.st_size+1,0)
        if raw != payload or os.lseek(fd,0,os.SEEK_CUR) != before.st_size:
            raise AssertionError("Held bytes differ or readback disturbed cursor")
        if len(result.stdout)>OUT_MAX or result.stderr:
            raise AssertionError("Unexpected pipe bytes")
        return raw,result
    finally:
        os.close(fd)


class DaCellCachePayloadHeldSealed(unittest.TestCase):
    def test_locked_original_from_same_sealed_bytes_static_selfhost(self):
        all_cases = [row for row in cases() if len(row[0]) <= RAW_MAX]
        # Full physical 64 KiB frame, not just a long chunk with uncounted header.
        payload = data(RAW_MAX-20-len(canonical([b"x"],width=CAP,family=b"cap")))
        header = canonical([payload],width=CAP,family=b"cap")
        full = request(header,payload,0,MAX)
        self.assertEqual(len(full),RAW_MAX)
        all_cases.extend(((full,0,copied(0,payload)),
                          (request(header,payload,len(payload)-7,MAX),0,
                           copied(len(payload)-7,payload[-7:])),
                          (request(header,payload[:-1]+b"\xff",0,MAX),ABSENT,b"")))
        with tempfile.TemporaryDirectory(prefix="trnm-cache-held-fd0-") as temp:
            root = Path(temp)
            out = root/"build"
            img,report = build(out)
            self.assertEqual(report["physical_read_max"],RAW_MAX)
            self.assertEqual(len(checked_adapter_readback(out/ELF,root/"adapter.txt")),12)
            path = root/"thunk.raw"
            path.write_bytes(img[ADAPTER:PREFIX])
            rows = disassemble(path)
            allowed = {"push","mov","call","test","jne","cmp","ja","add","pop","ret","xor","nop"}
            self.assertFalse({op for _,op,_ in rows}-allowed)
            decoded = {at:(op,args) for at,op,args in rows}
            self.assertEqual([(i,int(arg,16)) for i,op,arg in rows if op=="call"],[(15,64)])
            self.assertEqual(decoded[20],("test","%rax,%rax"))
            self.assertEqual(decoded[25],("mov","0x8(%rbx),%rax"))
            self.assertEqual(decoded[29],("cmp","$0x10000,%rax"))
            self.assertEqual(decoded[37],("add","$0x10,%rax"))
            self.assertEqual([(at,int(arg,16)) for at,op,arg in rows if op in {"jne","ja"}],
                             [(23,43),(35,43)])
            originals, measured = [], []
            for fixture,code,value in all_cases:
                raw,result = held_readback(img,fixture)
                originals.append(struct.pack("<I",len(raw))+raw)
                measured.append((result,code,value))
            oracle_dir = root/"rust"
            oracle_dir.mkdir()
            raw, source_sha = original(oracle_dir,b"".join(originals))
            self.assertEqual(len(source_sha),64)
            cursor = 0
            for result,code,value in measured:
                self.assertEqual(raw[cursor],code)
                observed = raw[cursor+1:cursor+1+len(value)]
                self.assertEqual(observed,value)
                self.assertEqual((result.returncode,result.stdout,result.stderr),
                                 (0 if code==0 else 74,observed,b""))
                cursor += 1+len(value)
            self.assertEqual(cursor,len(raw))

            for data_,initial,seals,exitcode,offset in (
                (full+b"x",0,ALL_SEALS,71,0),
                (full,0,0,70,0),
                (full,0,ALL_SEALS & ~SEAL_WRITE,70,0),
                (full,1,ALL_SEALS,72,1),
                (b"",0,ALL_SEALS,74,0),
                (full[:19],0,ALL_SEALS,74,19),
            ):
                result,held = physical_fixture(img,data_,initial=initial,seals=seals)
                self.assertEqual((result.returncode,result.stdout,result.stderr,held["offset_after"]),
                                 (exitcode,b"",b"",offset))
                self.assertTrue(held["input_bytes_unchanged"])
            self.assertEqual(check_nonpipe_sink(img,full)["status"],75)
            self.assertEqual(len(hashlib.sha256(img).hexdigest()),64)
