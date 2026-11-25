"""Byte-exact M12 read-only URI kernel against the actual Rust Store function.

This private ABI reads OS pathname bytes (not Unicode or a URI).
It returns output length, 0xffffffff for input longer than 4096 bytes, or
0xfffffffe for insufficient output. Refusals leave output byte-exact. Output
contains no NUL terminator, which is the caller's responsibility if required.
The standard third fixture span (scratch) is never accessed.
This kernel does not open paths, validate sidecars, authorize store access, or
establish an SQLite read transaction. Those original owner gates remain open.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import random
import re
import sqlite3
import subprocess
import tempfile
import unittest
from urllib.parse import quote_from_bytes

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/service_settlement/read_only_store_uri.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-service-settlement/src/store.rs"
ADAPTER = Path(__file__).with_name("rust_settlement_read_only_uri_reference.rs")
ORIGINAL_SHA256 = "9e58c15b67f28baab5f2d4d882eca534fd35a9876ccdf4d37beafceeba4c7091"
MAX_PATH = 4096
SHORT = 0xFFFFFFFE
INVALID = 0xFFFFFFFF


@unittest.skipUnless(os.name == "posix", "original Unix pathname byte qualification")
class SettlementReadOnlyUriTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = tempfile.TemporaryDirectory(prefix="trnm-settlement-native-uri-")
        cls.addClassCleanup(work.cleanup)
        cls.temp = Path(work.name)
        [function] = re.findall(rb"(?ms)^fn read_only_store_uri\(path: &Path\) -> String \{\n.*?^\}\n",
                                ORIGINAL.read_bytes())
        if hashlib.sha256(function).hexdigest() != ORIGINAL_SHA256:
            raise AssertionError("Original Settlement path serialization source differs")
        (cls.temp / "original.rs").write_bytes(b"use std::path::Path;\n" + function)
        cls.rust = cls.temp / "original"
        subprocess.run(["rustc", "--edition=2024", "-Dwarnings", str(ADAPTER), "-o", str(cls.rust)],
                       env={**os.environ, "TRNM_SETTLEMENT_URI_SOURCE_DIR": str(cls.temp)},
                       check=True, timeout=30, capture_output=True)
        cls.modules = {}
        for backend in ("direct", "selfhost"):
            module = NativeModule(SOURCE, byte_exports=("f0",), backend=backend, fixture_owner=Path(__file__))
            cls.addClassCleanup(module.close)
            cls.modules[backend] = module

    @classmethod
    def reference(cls, paths):
        requests = b"".join(path.hex().encode("ascii") + b"\n" for path in paths)
        result = subprocess.run([str(cls.rust)], input=requests, capture_output=True, timeout=30, check=True)
        if result.stderr:
            raise AssertionError(result.stderr)
        rows = result.stdout.splitlines()
        if len(rows) != len(paths):
            raise AssertionError("Original pathname output roster differs")
        return rows

    def test_original_exact_bytes_full_output_and_refusals(self):
        rng = random.Random(933)
        paths = [b"", b"/", b"//", b"///", b"//folder/path", b"/a//b", b"./../name",
                 b"Case-09_./z", b"spaces and \\ plus +", b"q?x#f&mode=rw%2F:\x00",
                 b"\xfe\xffnon-utf8", bytes(range(256)), bytes(reversed(range(256))),
                 b"a" * MAX_PATH, b"\xfe" * MAX_PATH, b"/" * MAX_PATH]
        paths += [b"/" + rng.randbytes(n) for n in (2, 3, 7, 8, 65, 127, 999, 4095)]
        paths += [b"//" + bytes((n,)) + b"/z" for n in range(256)]
        expected = self.reference(paths)
        self.assertEqual(expected[:6], [b"file:?mode=ro", b"file:/?mode=ro", b"file:/%2F?mode=ro",
                                       b"file:/%2F/?mode=ro", b"file:/%2Ffolder/path?mode=ro",
                                       b"file:/a//b?mode=ro"])
        cases = []
        for index, (path, uri) in enumerate(zip(paths, expected, strict=True)):
            marker = bytes([0x5A + index % 11])
            for capacity in (len(uri)-1, len(uri), len(uri)+9):
                before = marker * capacity
                if capacity < len(uri):
                    cases.append((path, before, SHORT, before))
                else:
                    cases.append((path, before, len(uri), uri + before[len(uri):]))
        for path, extent, code in ((b"", 0, SHORT), (b"k" * (MAX_PATH+1), 0, INVALID),
                                   (b"/" * (MAX_PATH+1), MAX_PATH*3+16, INVALID)):
            before = b"\xC7" * extent
            cases.append((path, before, code, before))
        for backend, module in self.modules.items():
            for begin in range(0, len(cases), 32):
                batch = cases[begin:begin+32]
                calls = module.call_many([("f0", [path, buf, bytes([0xe7]) * (i % 5)])
                                          for i, (path, buf, _, _) in enumerate(batch)])
                for pos, (call, (path, _, status, output)) in enumerate(zip(calls, batch, strict=True)):
                    with self.subTest(backend=backend, pos=begin+pos):
                        self.assertEqual(call.require_returned().value, status)
                        self.assertEqual(call.arguments, [path, output, bytes([0xe7]) * (pos % 5)])

    def test_uri_reads_owned_temp_database_under_read_only_mode(self):
        # Use an independently constructed URI only to populate our temporary
        # database, then exercise the exact Rust and both compiled HIA URIs.
        path = os.fsencode(self.temp) + b"/with space ?#&=%+\xff.db"
        create_uri = "file:" + quote_from_bytes(path, safe="/") + "?mode=rwc"
        with sqlite3.connect(create_uri, uri=True) as db:
            db.execute("CREATE TABLE sample(value TEXT)")
            db.execute("INSERT INTO sample VALUES ('retained')")
        db.close()
        [expected] = self.reference([path])
        for backend, module in self.modules.items():
            with self.subTest(backend=backend):
                output = b"\xdd" * 1024
                call = module.call("f0", [path, output, b""]).require_returned()
                emitted = call.arguments[1][:call.value]
                self.assertEqual(emitted, expected)
                self.assertEqual(emitted.split(b"?"), [emitted[:-8], b"mode=ro"])
                with sqlite3.connect(emitted.decode("ascii"), uri=True) as db:
                    self.assertEqual(db.execute("SELECT value FROM sample").fetchall(), [("retained",)])
                    with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                        db.execute("INSERT INTO sample VALUES ('must not write')")
                db.close()
