"""Compare native held journal-root streaming to the exact original SQLite operation."""
from contextlib import ExitStack
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


class SettlementJournalReadTests(unittest.TestCase):
    def test_native_ordered_original_receipts_and_held_terminal_join(self):
        with ExitStack() as stack:
            tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-journal-"))
            directory = Path(tmp)
            modules = {name: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                       for name, path in {
                           "journal": OWNER / "journal_read.hepta", "terminal": OWNER / "terminal_join.hepta",
                           "uri": ROOT / "hia/src/service_settlement/read_only_store_uri.hepta",
                       }.items()}
            original, dependency = original_adapter(directory, marker=True)
            provider = ProviderBuild(dependency, directory / "provider").run()
            book = Reader()
            check_provider(book.read, provider.parent, ROOT)
            provider_sha = book.checked[str(provider)]["sha256"]
            inputs = [directory / name for name in ("trust.bin", "first.bin", "second.bin")]
            for file, value in zip(inputs, frozen_inputs(), strict=True):
                file.write_bytes(value)
            owned = directory / "owned"
            owned.mkdir(mode=0o700)

            def seed(name, commands=2, empties=1):
                path = owned / name
                seeded = execute([original, "seed", path, inputs[0], str(empties), *inputs[1:1+commands]],
                                 timeout=45)
                self.assertEqual((seeded.stderr, len(seeded.stdout)), (b"", 1018))
                return path, seeded.stdout

            def reference(path, action="verify-journal"):
                return subprocess.run([original, action, path, inputs[0]],
                                      capture_output=True, timeout=30, check=False)

            def image(name):
                module = modules[name]
                return [str(module.library), module.artifact_sha256]

            def observe(path, binding, *, hold=False, mode="journal"):
                req = {"uri": image("uri"), "reader": image(mode), "provider": [str(provider), provider_sha],
                       "directory": str(owned), "database": str(path),
                       "writer": str(original) if hold else None,
                       mode + "_binding": binding.hex()}
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(req).encode(), timeout=45)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            for number, empty_markers in ((0, 2), (1, 0), (2, 1)):
                with self.subTest(operation_count=number):
                    path, binding = seed(f"original receipt stream {number} #?.db", number, empty_markers)
                    before = path.read_bytes()
                    result = reference(path)
                    self.assertEqual((result.returncode, result.stderr, len(result.stdout)), (0, b"", 219))
                    self.assertEqual(struct.unpack_from("<Q", result.stdout, 42)[0], number)
                    self.assertEqual(result.stdout[-32:], result.stdout[122:154])
                    actual = observe(path, binding, hold=number == 2)
                    self.assertEqual((actual["status"], actual["held"], actual["released"]),
                                     (0, number == 2, 0), actual)
                    self.assertEqual(bytes.fromhex(actual["projection"]), result.stdout)
                    transcript = actual["transcript"]
                    self.assertEqual(sum(op == 2 for _, op, _ in transcript), 1)
                    self.assertEqual(sum(op == 3 for _, op, _ in transcript), 1)
                    self.assertIn([51, 6, 24], transcript)
                    self.assertEqual(sum(p == 53 and op == 8 for p, op, _ in transcript), number)
                    self.assertEqual(sum(p == 54 and op == 8 for p, op, _ in transcript), number)
                    self.assertEqual(transcript[-2:], [[55, 9, 24], [56, 3, 24]])
                    self.assertEqual(path.read_bytes(), before)
                    self.assertFalse(path.with_name(path.name+"-journal").exists())

            for label, phase, op in (("same-count exact original row checksum", 52, 7),
                                     ("oversized receipt before BLOB export", 53, 8)):
                with self.subTest(label=label):
                    path, binding = seed(f"journal drift {phase}.db")
                    intact = reference(path)
                    self.assertEqual((intact.returncode, intact.stderr, len(intact.stdout)), (0, b"", 219))
                    if phase == 52:
                        execute([original, "fixture-same-count-receipt-drift", path, inputs[0]])
                    else:
                        edit = sqlite3.connect(path)
                        try:
                            self.assertEqual(edit.execute(
                                "UPDATE operations SET receipt=zeroblob(1048553) WHERE sequence=1"
                            ).rowcount, 1)
                            edit.commit()
                        finally:
                            edit.close()
                    before = path.read_bytes()
                    unbound = reference(path, "inspect-journal-root")
                    self.assertEqual((unbound.returncode, unbound.stderr, len(unbound.stdout)), (0, b"", 32))
                    self.assertNotEqual(unbound.stdout, intact.stdout[-32:])
                    rejected = reference(path)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertEqual(rejected.stdout, b"")
                    alone = observe(path, binding, mode="terminal")
                    self.assertEqual((alone["status"], alone["released"]), (0, 0), alone)
                    self.assertEqual(bytes.fromhex(alone["projection"]), intact.stdout[:187])
                    native = observe(path, binding)
                    self.assertEqual((native["status"], native["projection"]), (100, None), native)
                    self.assertEqual(native["transcript"][-1][:2], [phase, op])
                    if phase == 53:
                        self.assertFalse(any(p == 54 for p, _, _ in native["transcript"]))
                    self.assertFalse(any(k == 3 for _, k, _ in native["transcript"]))
                    self.assertGreater(native["released"], 0)
                    self.assertEqual(path.read_bytes(), before)
