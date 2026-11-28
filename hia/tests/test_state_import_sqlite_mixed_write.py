"""Actual sorted DELETE/INSERT/UPDATE delta on one disposable SQLite generation."""
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


def proposal_record(magic, old, value, after, count):
    ns, key, leaf, _ = old
    prefix = magic + struct.pack("<QQ", len(ns), len(key))
    prefix += ns.ljust(64, b"\0") + key.ljust(64, b"\0") + leaf
    prefix += after[128:192] + struct.pack("<QQ", count, len(value))
    prefix += value.ljust(128, b"\0")
    if len(prefix) != 392:
        raise ValueError("Wrong private mixed fixture record width")
    return prefix


class StateImportSqliteMixedWrite(unittest.TestCase):
    def test_native_exact_mixed_batch_and_real_early_late_rollback(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-mixed-delta-") as tmp, NativeModule(
            OWNER / "empty_write.hepta", byte_exports=("f0",), backend="selfhost",
        ) as reader:
            directory = Path(tmp).resolve()
            original, dependency = _build_original(directory)
            provider = ProviderBuild(dependency, directory / "provider").run()
            proof = Reader()
            check_provider(proof.read, provider.parent, ROOT)
            digest = proof.checked[str(provider)]["sha256"]
            owned = directory / "owned"
            owned.mkdir(mode=0o700)

            def seed(name, count):
                path = owned / (name + ".db")
                _run([original, "seed", path, str(count)])
                return path

            def export(db):
                return _run([original, "export", db]).stdout

            def invoke(db, proposal, *, cut=None):
                req = {
                    "reader": [str(reader.library), reader.artifact_sha256],
                    "provider": [str(provider), digest], "directory": str(owned),
                    "database": str(db), "expected": EXPECTED, "empty_delta": proposal.hex(),
                    "advance": None, "kill_after_update": cut == "metadata",
                    "kill_after_row_index": cut if isinstance(cut, int) else None,
                }
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(req), text=True, timeout=45, capture_output=True, check=False,
                )
                if cut is not None:
                    self.assertEqual((child.returncode, child.stdout, child.stderr), (-signal.SIGKILL, "", ""))
                    return None
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(child.stderr, "")
                return json.loads(child.stdout)

            def replace(wire, at, raw):
                return wire[:at] + raw + wire[at + len(raw):]

            for count in (3, 17):
                with self.subTest(count=count):
                    oracle = seed(f"original-{count}", count)
                    before = export(oracle)
                    _run([original, "mixed-advance", oracle])
                    after = export(oracle)
                    earlier, later = original_rows(before), original_rows(after)
                    self.assertEqual(int.from_bytes(after[192:200], "big"), count)
                    self.assertEqual(int.from_bytes(after[200:208], "big"), 1)
                    self.assertEqual(len(earlier), len(later))
                    self.assertEqual(later[1:-1], earlier[1:-1])
                    self.assertEqual(later[-1][:2], earlier[-1][:2])
                    self.assertNotEqual(later[-1][2:], earlier[-1][2:])
                    self.assertLess(earlier[0][:2], later[0][:2])
                    self.assertLess(later[0][:2], later[-1][:2])
                    self.assertNotIn(later[0][:2], [r[:2] for r in earlier])
                    self.assertEqual(len(later[0][3]), 0 if count == 3 else 128)

                    proposal = b"BAT1M13!"
                    proposal += proposal_record(b"DEL1M13!", earlier[0], b"", after, count)
                    proposal += proposal_record(b"INS1M13!", (*later[0][:2], bytes(32), b""), later[0][3], after, count)
                    proposal += proposal_record(b"UPD1M13!", earlier[-1], later[-1][3], after, count)
                    proposal += (projection(before)[:489] + projection(after)[:489]).encode()
                    proposal += after[96:128] + after[208:240]
                    self.assertEqual(len(proposal), 2226)

                    db = seed(f"candidate-{count}", count)
                    got = invoke(db, proposal)
                    self.assertEqual((got["status"], got["result"], got["released"]), (0, projection(after), 0))
                    self.assertEqual(got["transcript"][-1], [18, 3, 24])
                    self.assertEqual(got["transcript"].count([30, 5, 24]), 3)
                    self.assertEqual(got["transcript"].count([35, 10, 24]), 3)
                    self.assertEqual(got["transcript"].count([28, 10, 24]), 1)
                    self.assertEqual(export(db), after)
                    stale = invoke(db, proposal)
                    self.assertEqual((stale["status"], stale["result"]), (100, None))
                    self.assertNotIn([30, 5, 24], stale["transcript"])
                    self.assertEqual(export(db), after)

                    bad_at = 792 + 152
                    bad_leaf = replace(proposal, bad_at, bytes((proposal[bad_at] ^ 0x80,)))
                    bad_at = 792 + 184
                    bad_after = replace(proposal, bad_at, bytes((proposal[bad_at] ^ 0x80,)))
                    unsorted = replace(proposal, 400 + 88, b"\x01\x00\x00")
                    other_key = earlier[1][1]
                    conflict = replace(proposal, 400 + 16, struct.pack("<Q", len(other_key)))
                    conflict = replace(conflict, 400 + 88, other_key.ljust(64, b"\0"))
                    for label, wire in (("late-preimage", bad_leaf), ("successor-digest", bad_after),
                                        ("key-order", unsorted), ("insert-conflict", conflict)):
                        refused_db = seed(f"{label}-{count}", count)
                        blocked = invoke(refused_db, wire)
                        self.assertEqual((blocked["status"], blocked["result"]), (100, None))
                        self.assertEqual(blocked["transcript"].count([35, 10, 24]), 3 if label == "successor-digest" else 0)
                        if label == "key-order":
                            self.assertEqual(blocked["transcript"], [])
                        self.assertNotIn([15, 5, 24], blocked["transcript"])
                        self.assertEqual(export(refused_db), before)

                    for cut in (1, 3, "metadata"):
                        interrupted = seed(f"kill-{cut}-{count}", count)
                        invoke(interrupted, proposal, cut=cut)
                        self.assertEqual(export(interrupted), before)
