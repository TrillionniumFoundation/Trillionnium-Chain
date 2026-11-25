"""Actual original committed-block marker checks in a held SQLite snapshot."""
import json
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
from hia.tests.test_settlement_operation_read import frozen_inputs
from hia.tests.test_settlement_schema_read import execute, original_adapter

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "hia/platform/service_settlement"


class SettlementMarkerReadTests(unittest.TestCase):
    def test_checked_markers_and_linkage_in_held_original_store(self):
        with tempfile.TemporaryDirectory(prefix="trnm-m12-marker-") as tmp, NativeModule(
                OWNER / "marker_read.hepta", byte_exports=("f0",), backend="selfhost") as reader, NativeModule(
                ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                byte_exports=("f0",), backend="selfhost") as uri:
            directory = Path(tmp)
            original, dependency = original_adapter(directory, marker=True)
            provider = ProviderBuild(dependency, directory / "provider").run()
            report = Reader()
            check_provider(report.read, provider.parent, ROOT)
            provider_sha = report.checked[str(provider)]["sha256"]
            inputs = [directory / name for name in ("trust.bin", "first.bin", "second.bin")]
            for path, raw in zip(inputs, frozen_inputs(), strict=True):
                path.write_bytes(raw)
            owned = directory / "owned"
            owned.mkdir(mode=0o700)

            def seed(name, *, commands=True, empties=0):
                path = owned / name
                answer = execute([original, "seed", path, inputs[0], str(empties),
                                  *(inputs[1:] if commands else [])], timeout=45)
                self.assertEqual((answer.stderr, len(answer.stdout)), (b"", 104+914))
                return path, answer.stdout

            def reference(path):
                return subprocess.run([original, "verify", path, inputs[0]], capture_output=True, timeout=30)

            def observe(path, binding, *, hold=False):
                req = {"uri": [str(uri.library), uri.artifact_sha256],
                       "reader": [str(reader.library), reader.artifact_sha256],
                       "provider": [str(provider), provider_sha], "directory": str(owned),
                       "database": str(path), "writer": str(original) if hold else None,
                       "marker_binding": binding.hex()}
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(req).encode(), timeout=45)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            for commands, empties, count in ((False, 0, 1), (True, 1, 4), (False, 63, 64), (False, 64, 65)):
                with self.subTest(count=count):
                    path, binding = seed(f"original markers {count} ?#%.db", commands=commands, empties=empties)
                    before = path.read_bytes()
                    expected = reference(path)
                    self.assertEqual((expected.returncode, expected.stderr, len(expected.stdout)), (0, b"", 40))
                    self.assertEqual(struct.unpack_from("<Q", expected.stdout)[0], count)
                    actual = observe(path, binding, hold=count==4)
                    if count > 64:
                        self.assertEqual((actual["status"], actual["projection"]), (100, None), actual)
                        self.assertEqual(actual["transcript"][-1], [21, 7, 24])
                        self.assertGreater(actual["released"], 0)
                    else:
                        self.assertEqual((actual["status"], actual["held"], actual["released"]),
                                         (0, count==4, 0), actual)
                        self.assertEqual(bytes.fromhex(actual["projection"]), expected.stdout)
                        self.assertEqual(actual["transcript"][-1], [25, 3, 24])
                    self.assertEqual(path.read_bytes(), before)
                    self.assertFalse(path.with_name(path.name+"-journal").exists())

            for label, change in (
                    ("no markers", "DELETE FROM committed_blocks"),
                    ("negative sequence", "UPDATE committed_blocks SET source_operation_sequence=-1 WHERE marker_sequence=2"),
                    ("wrong checksum", "UPDATE committed_blocks SET checksum=zeroblob(32) WHERE marker_sequence=2"),
                    ("checksum-valid wrong parent height", None)):
                with self.subTest(label=label):
                    path, binding = seed(f"invalid-{label}.db")
                    if change is None:
                        execute([original, "fixture-parent-height-drift", path, inputs[0]])
                    else:
                        conn = sqlite3.connect(path)
                        try:
                            conn.execute(change)
                            conn.commit()
                        finally:
                            conn.close()
                    before = path.read_bytes()
                    rust = reference(path)
                    self.assertNotEqual(rust.returncode, 0)
                    self.assertEqual(rust.stdout, b"")
                    if change is None:
                        self.assertIn(b"committed-block marker is not the exact direct successor", rust.stderr)
                    actual = observe(path, binding)
                    self.assertEqual((actual["status"], actual["projection"]), (100, None), actual)
                    self.assertGreater(actual["released"], 0)
                    self.assertEqual(path.read_bytes(), before)
