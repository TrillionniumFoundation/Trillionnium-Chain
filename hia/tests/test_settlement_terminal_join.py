"""Actual original Store terminal linkage, read natively in one held transaction."""
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


class SettlementTerminalJoinTests(unittest.TestCase):
    def test_metadata_marker_tail_and_operation_count_in_one_held_snapshot(self):
        with ExitStack() as stack:
            tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix="trnm-m12-terminal-"))
            directory = Path(tmp)
            modules = {name: stack.enter_context(NativeModule(path, byte_exports=("f0",), backend="selfhost"))
                       for name, path in {
                           "join": OWNER / "terminal_join.hepta", "marker": OWNER / "marker_read.hepta",
                           "metadata": OWNER / "metadata_read.hepta",
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

            def seed(name, *, commands=True, empties=1):
                path = owned / name
                seeded = execute([original, "seed", path, inputs[0], str(empties),
                                  *(inputs[1:] if commands else [])], timeout=45)
                self.assertEqual((seeded.stderr, len(seeded.stdout)), (b"", 1018))
                return path, seeded.stdout

            def reference(path):
                return subprocess.run([original, "verify-join", path, inputs[0]],
                                      capture_output=True, timeout=30, check=False)

            def image(name):
                module = modules[name]
                return [str(module.library), module.artifact_sha256]

            def observe(path, binding, *, hold=False, mode="join"):
                flag = {"join": "terminal_binding", "marker": "marker_binding", "metadata": "metadata_config"}[mode]
                req = {"uri": image("uri"), "reader": image(mode), "provider": [str(provider), provider_sha],
                       "directory": str(owned), "database": str(path),
                       "writer": str(original) if hold else None,
                       flag: (binding[104:] if mode == "metadata" else binding).hex()}
                answer = execute([sys.executable, "-I", "-S", "-B", OWNER / "schema_fixture_host.py"],
                                 input=json.dumps(req).encode(), timeout=45)
                self.assertEqual(answer.stderr, b"")
                return json.loads(answer.stdout)

            for commands, empties, markers, operations in ((False, 0, 1, 0), (False, 2, 3, 0), (True, 1, 4, 2)):
                with self.subTest(markers=markers, operations=operations):
                    path, binding = seed(f"confirmed {markers} #?.db", commands=commands, empties=empties)
                    before = path.read_bytes()
                    result = reference(path)
                    self.assertEqual((result.returncode, result.stderr, len(result.stdout)), (0, b"", 187))
                    self.assertEqual(struct.unpack_from("<Q", result.stdout, 0)[0], markers)
                    self.assertEqual(struct.unpack_from("<Q", result.stdout, 42)[0], operations)
                    actual = observe(path, binding, hold=operations == 2)
                    self.assertEqual((actual["status"], actual["held"], actual["released"]),
                                     (0, operations == 2, 0), actual)
                    self.assertEqual(bytes.fromhex(actual["projection"]), result.stdout)
                    transcript = actual["transcript"]
                    self.assertEqual(sum(op == 2 for _, op, _ in transcript), 1)
                    self.assertEqual(sum(op == 3 for _, op, _ in transcript), 1)
                    self.assertEqual(transcript[-6:], [[40, 5, 24], [41, 7, 24], [42, 8, 32],
                                                        [43, 7, 24], [44, 9, 24], [45, 3, 24]])
                    self.assertEqual(path.read_bytes(), before)
                    self.assertFalse(path.with_name(path.name+"-journal").exists())

            _, binding = seed("private binding split.db", commands=False, empties=0)
            starter = modules["join"].call("f0", [binding, bytes(1 << 20), bytes(1 << 20)])
            self.assertEqual(starter.require_returned().value, 195)
            _, continuation, work = starter.arguments
            expected_config = binding[104:]
            changed = bytes([expected_config[0] ^ 1]) + expected_config[1:]
            refusals = modules["join"].call_many([
                ("f0", [raw, continuation, work]) for raw in (expected_config[:-1], changed)
            ])
            for call in refusals:
                self.assertEqual(call.require_returned().value, 100)
                self.assertEqual(call.arguments[1:], [continuation, work])

            for label, phase, op in (("checksum-valid metadata disagrees with tail", 24, 9),
                                     ("terminal operation count disagrees", 42, 8)):
                with self.subTest(label=label):
                    path, binding = seed(f"refusal {phase}.db")
                    if phase == 24:
                        execute([original, "fixture-metadata-height-drift", path, inputs[0]])
                    else:
                        connection = sqlite3.connect(path)
                        try:
                            self.assertEqual(connection.execute("DELETE FROM operations WHERE sequence=2").rowcount, 1)
                            connection.commit()
                        finally:
                            connection.close()
                    before = path.read_bytes()
                    original_result = reference(path)
                    self.assertNotEqual(original_result.returncode, 0)
                    self.assertEqual(original_result.stdout, b"")
                    if phase == 24:
                        self.assertIn(b"metadata head differs from committed-block journal tail", original_result.stderr)
                    for independent in ("marker", "metadata"):
                        # Each checksum-valid component by itself still reads successfully.
                        individual = observe(path, binding, mode=independent)
                        self.assertEqual((individual["status"], individual["released"]), (0, 0), individual)
                    refused = observe(path, binding)
                    self.assertEqual((refused["status"], refused["projection"]), (100, None), refused)
                    self.assertEqual(refused["transcript"][-1][:2], [phase, op])
                    self.assertFalse(any(k == 3 for _, k, _ in refused["transcript"]))
                    self.assertGreater(refused["released"], 0)
                    self.assertEqual(path.read_bytes(), before)
