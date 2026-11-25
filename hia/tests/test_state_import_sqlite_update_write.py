"""Execute one exact original-compatible existing-row SQLite UPDATE."""
import json
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import unittest

from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests.native_support import NativeModule
from hia.tests.test_state_import_snapshot_shadow import _build_original, _run
from hia.tests.test_state_import_sqlite_cold_read import EXPECTED, OWNER, ROOT, projection
from hia.tests.test_state_import_sqlite_delete_write import original_rows


class StateImportSqliteUpdateWrite(unittest.TestCase):
    def test_native_update_checks_exact_preimage_and_rolls_back_real_row_and_metadata_writes(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-update-delta-") as tmp, NativeModule(
            OWNER / "empty_write.hepta", byte_exports=("f0",), backend="selfhost",
        ) as reader:
            directory = Path(tmp).resolve()
            writer, dependency = _build_original(directory)
            provider_dir = directory / "provider"
            provider = ProviderBuild(dependency, provider_dir).run()
            provenance = Reader()
            check_provider(provenance.read, provider_dir, ROOT)
            provider_digest = provenance.checked[str(provider)]["sha256"]
            cases = directory / "owned"
            cases.mkdir(mode=0o700)

            def seed(name, count):
                db = cases / (name + ".db")
                _run([writer, "seed", db, str(count)])
                return db

            def export(db):
                return _run([writer, "export", db]).stdout

            def call(db, proposal, *, kill=None):
                request = {
                    "reader": [str(reader.library), reader.artifact_sha256],
                    "provider": [str(provider), provider_digest], "directory": str(cases),
                    "database": str(db), "expected": EXPECTED, "empty_delta": proposal.hex(),
                    "advance": None, "kill_after_update": kill == "meta",
                    "kill_after_row": kill == "row",
                }
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(request), text=True, timeout=45, capture_output=True, check=False,
                )
                if kill:
                    self.assertEqual((child.returncode, child.stdout, child.stderr), (-signal.SIGKILL, "", ""))
                    return None
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(child.stderr, "")
                return json.loads(child.stdout)

            for count, value_len in ((1, 128), (17, 0)):
                with self.subTest(count=count, value_len=value_len):
                    oracle = seed(f"original-{count}", count)
                    before = export(oracle)
                    _run([writer, "update-advance", oracle])
                    after = export(oracle)
                    self.assertEqual(int.from_bytes(after[192:200], "big"), count)
                    self.assertEqual(int.from_bytes(after[200:208], "big"), 1)
                    self.assertNotEqual(before[128:160], after[128:160])
                    original = original_rows(before)
                    successor = original_rows(after)
                    n = count // 2
                    ns, key, old_leaf, old_value = original[n]
                    new_ns, new_key, leaf, value = successor[n]
                    self.assertEqual((new_ns, new_key), (ns, key))
                    self.assertEqual(successor[:n] + successor[n + 1:], original[:n] + original[n + 1:])
                    self.assertEqual(len(value), value_len)
                    self.assertNotEqual(value, old_value)
                    self.assertNotEqual(leaf, old_leaf)
                    prefix = b"UPD1M13!" + struct.pack("<QQ", len(ns), len(key))
                    prefix += ns.ljust(64, b"\0") + key.ljust(64, b"\0") + old_leaf
                    prefix += after[128:192] + struct.pack("<QQ", count, len(value))
                    prefix += value.ljust(128, b"\0")
                    proposal = prefix + (projection(before)[:489] + projection(after)[:489]).encode()
                    proposal += after[96:128] + after[208:240]
                    self.assertEqual(len(proposal), 1434)

                    candidate = seed(f"candidate-{count}", count)
                    got = call(candidate, proposal)
                    self.assertEqual((got["status"], got["result"], got["released"]), (0, projection(after), 0))
                    self.assertEqual(got["transcript"][-1], [18, 3, 24])
                    for actual in ([36, 6, 24], [35, 10, 24], [28, 10, 24]):
                        self.assertIn(actual, got["transcript"])
                    self.assertEqual(export(candidate), after)
                    stale = call(candidate, proposal)
                    self.assertEqual((stale["status"], stale["result"]), (100, None))
                    self.assertNotIn([30, 5, 24], stale["transcript"])
                    self.assertEqual(export(candidate), after)

                    for label, offset in (
                        ("missing-key", 88), ("known-prior-leaf", 152),
                        ("successor-digest", 184), ("successor-count", 248),
                    ):
                        refused = seed(f"{label}-{count}", count)
                        bad = proposal[:offset] + bytes((proposal[offset] ^ 0x80,)) + proposal[offset + 1:]
                        denied = call(refused, bad)
                        self.assertEqual((denied["status"], denied["result"]), (100, None))
                        after_row = label.startswith("successor-")
                        self.assertEqual([30, 5, 24] in denied["transcript"], after_row)
                        self.assertEqual([35, 10, 24] in denied["transcript"], after_row)
                        self.assertEqual([28, 10, 24] in denied["transcript"], label == "successor-digest")
                        self.assertNotIn([15, 5, 24], denied["transcript"])
                        self.assertEqual(export(refused), before)

                    same = seed(f"same-value-{count}", count)
                    no_op = proposal[:256] + struct.pack("<Q", len(old_value))
                    no_op += old_value.ljust(128, b"\0") + proposal[392:]
                    refused = call(same, no_op)
                    self.assertEqual((refused["status"], refused["result"]), (100, None))
                    self.assertNotIn([30, 5, 24], refused["transcript"])
                    self.assertEqual(export(same), before)

                    for cut in ("row", "meta"):
                        killed = seed(f"{cut}-interrupted-{count}", count)
                        call(killed, proposal, kill=cut)
                        self.assertEqual(export(killed), before)
