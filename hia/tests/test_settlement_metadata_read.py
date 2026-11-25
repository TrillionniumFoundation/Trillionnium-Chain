"""Compare checksum-checked native M12 metadata with a real original Store."""
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


def frozen_trust():
    raw = (OWNER / "qualification/fixtures.json.xz").read_bytes()
    if hashlib.sha256(raw).hexdigest() != "bf417e6b3d4086767b0614c9de0094d8794945100a8e6e149823d84869decc26":
        raise ValueError("Exact retained Settlement oracle corpus required")
    case = json.loads(lzma.decompress(raw))["fixtures"][1]
    frame = bytes.fromhex(case["input"])
    if case["name"] != "complete-clone-replay-lifecycle" or frame[:8] != b"SSO10001":
        raise ValueError("Exact retained Settlement fixture frame required")
    op, slot, height, length = struct.unpack_from("<4Q", frame, 16)
    if (op, slot, height, length) != (0, 0, 0, 882):
        raise ValueError("Exact retained original trust image required")
    return frame[48:48+length]


class SettlementMetadataReadTests(unittest.TestCase):
    def test_checked_metadata_in_held_original_store_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-metadata-") as tmp, NativeModule(
                OWNER / "metadata_read.hepta", byte_exports=("f0",), backend="selfhost") as reader, NativeModule(
                ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                byte_exports=("f0",), backend="selfhost") as uri:
            directory = Path(tmp)
            original, dependency = original_adapter(directory, metadata=True)
            provider = ProviderBuild(dependency, directory / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            provider_sha = proof.checked[str(provider)]["sha256"]
            trust = directory / "trust.bin"
            trust.write_bytes(frozen_trust())
            owned = directory / "owned"
            owned.mkdir(mode=0o700)

            def seed(name, identity):
                path = owned / name
                result = execute([original, "seed", path, trust, str(identity)])
                self.assertEqual(result.stderr, b"")
                self.assertEqual(len(result.stdout), 914)
                return path, result.stdout

            def invoke(path, expected_config, hold=False):
                req = {"uri": [str(uri.library), uri.artifact_sha256],
                       "reader": [str(reader.library), reader.artifact_sha256],
                       "provider": [str(provider), provider_sha], "directory": str(owned),
                       "database": str(path), "writer": str(original) if hold else None,
                       "metadata_config": expected_config.hex()}
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(req).encode(), timeout=45)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            def reference(path, identity):
                return subprocess.run([original, "verify", path, trust, str(identity)],
                                      capture_output=True, timeout=30, check=False)

            for identity in (61, 62):
                path, config = seed(f"original store {identity} ?#%.db", identity)
                result = reference(path, identity)
                self.assertEqual((result.returncode, result.stderr, len(result.stdout)), (0, b"", 147))
                before = path.read_bytes()
                native = invoke(path, config, hold=identity == 62)
                self.assertEqual((native["status"], native["held"], native["released"]),
                                 (0, identity == 62, 0), native)
                self.assertEqual(bytes.fromhex(native["projection"]), result.stdout)
                self.assertEqual(native["transcript"][-1], [34, 3, 24])
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse(path.with_name(path.name + "-journal").exists())
            for index, (mutation, phase) in enumerate((
                    ("schema_version=3", 22), ("config=zeroblob(length(config))", 23),
                    ("sequence=-1", 24), ("height=-1", 25), ("block_id=zeroblob(31)", 26),
                    ("state=zeroblob(1048553)", 27), ("state=substr(state,1,length(state)-1)", 31),
                    ("state_root=zeroblob(31)", 28),
                    ("journal_root=zeroblob(33)", 29), ("fenced=1", 31),
                    ("checksum=zeroblob(32)", 31))):
                with self.subTest(mutation=mutation):
                    path, config = seed(f"drift-{index}.db", 61)
                    db = sqlite3.connect(path)
                    try:
                        db.execute(f"UPDATE metadata SET {mutation} WHERE singleton=1")
                        db.commit()
                    finally:
                        db.close()
                    before = path.read_bytes()
                    original_result = reference(path, 61)
                    self.assertNotEqual(original_result.returncode, 0)
                    self.assertEqual(original_result.stdout, b"")
                    refused = invoke(path, config)
                    self.assertEqual((refused["status"], refused["projection"]), (100, None), refused)
                    self.assertEqual(refused["transcript"][-1][:2], [phase, 8])
                    self.assertGreater(refused["released"], 0)
                    self.assertEqual(path.read_bytes(), before)
