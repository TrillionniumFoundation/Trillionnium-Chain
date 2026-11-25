"""Exact original/native SQLite operation checks on committed disposable stores."""
import hashlib
import json
import lzma
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute, original_adapter

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/service_settlement"


def frozen_inputs():
    raw = (OWNER / "qualification/fixtures.json.xz").read_bytes()
    if hashlib.sha256(raw).hexdigest() != "bf417e6b3d4086767b0614c9de0094d8794945100a8e6e149823d84869decc26":
        raise ValueError("Exact retained original Settlement corpus required")
    fixture = json.loads(lzma.decompress(raw))["fixtures"][1]
    frame = bytes.fromhex(fixture["input"])
    if fixture["name"] != "complete-clone-replay-lifecycle" or frame[:8] != b"SSO10001":
        raise ValueError("Exact retained fixture actions required")
    at = 16
    for expected in ((0, 0, 0, 882), (1, 0, 10, 868), (1, 0, 11, 900)):
        if struct.unpack_from("<4Q", frame, at) != expected:
            raise ValueError("Original fixture trust/operation framing changed")
        at += 32
        end = at + expected[-1]
        yield frame[at:end]
        at = end


class SettlementOperationReadTests(unittest.TestCase):
    def test_checked_lookup_in_held_original_committed_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-operation-") as tmp, NativeModule(
                OWNER / "operation_read.hepta", byte_exports=("f0",), backend="selfhost") as reader, NativeModule(
                ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                byte_exports=("f0",), backend="selfhost") as uri:
            directory = Path(tmp)
            original, dependency = original_adapter(directory, operation=True)
            provider = ProviderBuild(dependency, directory / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            provider_sha = proof.checked[str(provider)]["sha256"]
            inputs = [directory / name for name in ("trust.bin", "first.bin", "second.bin")]
            for file, raw in zip(inputs, frozen_inputs(), strict=True):
                file.write_bytes(raw)
            owned = directory / "owned"
            owned.mkdir(mode=0o700)
            id_file = directory / "operation-id.bin"

            def seed(name):
                path = owned / name
                result = execute([original, "seed", path, *inputs])
                self.assertEqual((len(result.stdout), result.stderr), (64, b""))
                return path, (result.stdout[:32], result.stdout[32:])

            def reference(path, id_bytes):
                id_file.write_bytes(id_bytes)
                return subprocess.run([original, "lookup", path, id_file],
                                      capture_output=True, timeout=30, check=False)

            def invoke(path, id_bytes, hold=False):
                request = {"uri": [str(uri.library), uri.artifact_sha256],
                           "reader": [str(reader.library), reader.artifact_sha256],
                           "provider": [str(provider), provider_sha], "directory": str(owned),
                           "database": str(path), "writer": str(original) if hold else None,
                           "operation_id": id_bytes.hex()}
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(request).encode(), timeout=45)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            path, ids = seed("genuine committed #?.db")
            self.assertNotEqual(ids[0], ids[1])
            before = path.read_bytes()
            for order, identity in enumerate((*ids, bytes(32)), start=1):
                with self.subTest(order=order):
                    expected = reference(path, identity)
                    self.assertEqual((expected.returncode, expected.stderr), (0, b""))
                    if order == 3:
                        self.assertEqual(expected.stdout, bytes(8))
                    else:
                        self.assertEqual(expected.stdout[:48], struct.pack("<QQ", 1, order) + identity)
                        self.assertEqual(len(expected.stdout), 80)
                    got = invoke(path, identity, hold=order == 2)
                    self.assertEqual((got["status"], got["held"], got["released"]), (0, order == 2, 0), got)
                    self.assertEqual(bytes.fromhex(got["projection"]), expected.stdout)
                    self.assertIn([21, 6, 24], got["transcript"])
                    self.assertEqual(got["transcript"][-1], [31, 3, 24])
                    if order == 3:
                        self.assertFalse(any(phase >= 23 and op == 8 for phase, op, _ in got["transcript"]))
                    self.assertEqual(path.read_bytes(), before)
                    self.assertFalse(path.with_name(path.name + "-journal").exists())
            for i, (mutation, phase) in enumerate((
                    ("sequence=-1", 23), ("execution=zeroblob(1048553)", 25),
                    ("execution=substr(execution,1,length(execution)-1)", 28),
                    ("command=substr(command,1,length(command)-1)", 28),
                    ("receipt=substr(receipt,1,length(receipt)-1)", 28),
                    ("checksum=zeroblob(31)", 28), ("checksum=zeroblob(32)", 28))):
                with self.subTest(mutation=mutation):
                    path, ids = seed(f"drift-{i}.db")
                    db = sqlite3.connect(path)
                    try:
                        db.execute(f"UPDATE operations SET {mutation} WHERE operation_id=?", (ids[0],))
                        db.commit()
                    finally:
                        db.close()
                    before = path.read_bytes()
                    orig = reference(path, ids[0])
                    self.assertNotEqual(orig.returncode, 0)
                    self.assertEqual(orig.stdout, b"")
                    got = invoke(path, ids[0])
                    self.assertEqual((got["status"], got["projection"]), (100, None), got)
                    self.assertEqual(got["transcript"][-1][:2], [phase, 8])
                    self.assertGreater(got["released"], 0)
                    self.assertEqual(path.read_bytes(), before)
