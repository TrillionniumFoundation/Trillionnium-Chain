"""Execute one exact original-compatible DELETE delta on a disposable SQLite file."""
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


def original_rows(frame):
    rows, pos = [], 272
    while pos < len(frame):
        ns_len, k_len, v_len = struct.unpack_from("<III", frame, pos)
        digest = frame[pos + 12:pos + 44]
        pos += 44
        mid, end_key = pos + ns_len, pos + ns_len + k_len
        end = end_key + v_len
        rows.append((frame[pos:mid], frame[mid:end_key], digest, frame[end_key:end]))
        pos = end
    if pos != len(frame):
        raise ValueError("Original retained-row framing changed")
    return rows


class StateImportSqliteDeleteWrite(unittest.TestCase):
    def test_native_delete_commits_one_original_row_and_rolls_back_real_process_death(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-delete-delta-") as tmp, NativeModule(
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
                    "kill_after_delete": kill == "row",
                }
                child = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(OWNER / "qualification_host.py")],
                    input=json.dumps(request), text=True, timeout=45, capture_output=True, check=False,
                )
                if kill is not None:
                    self.assertEqual((child.returncode, child.stdout, child.stderr), (-signal.SIGKILL, "", ""))
                    return None
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(child.stderr, "")
                return json.loads(child.stdout)

            for count in (1, 17):
                with self.subTest(count=count):
                    oracle = seed(f"original-{count}", count)
                    before = export(oracle)
                    _run([writer, "delete-advance", oracle])
                    after = export(oracle)
                    self.assertEqual(int.from_bytes(after[192:200], "big"), count - 1)
                    self.assertEqual(int.from_bytes(after[200:208], "big"), 1)
                    self.assertNotEqual(before[128:160], after[128:160])
                    rows = original_rows(before)
                    n = count // 2
                    ns, key, old_leaf, _ = rows[n]
                    self.assertEqual(original_rows(after), rows[:n] + rows[n + 1:])
                    prefix = b"DEL1M13!" + struct.pack("<QQ", len(ns), len(key))
                    prefix += ns.ljust(64, b"\0") + key.ljust(64, b"\0") + old_leaf
                    prefix += after[128:192] + struct.pack("<Q", count - 1)
                    proposal = prefix + (projection(before)[:489] + projection(after)[:489]).encode()
                    proposal += after[96:128] + after[208:240]
                    self.assertEqual(len(proposal), 1298)

                    candidate = seed(f"candidate-{count}", count)
                    good = call(candidate, proposal)
                    self.assertEqual((good["status"], good["result"], good["released"]), (0, projection(after), 0))
                    self.assertEqual(good["transcript"][-1], [18, 3, 24])
                    self.assertIn([35, 10, 24], good["transcript"])
                    self.assertIn([28, 10, 24], good["transcript"])
                    self.assertEqual(export(candidate), after)
                    stale = call(candidate, proposal)
                    self.assertEqual((stale["status"], stale["result"]), (100, None))
                    self.assertNotIn([30, 5, 24], stale["transcript"])
                    self.assertEqual(export(candidate), after)

                    for label, offset in (("missing-key", 88), ("prior-leaf", 152), ("successor-rows", 184)):
                        denied = seed(f"{label}-{count}", count)
                        invalid = proposal[:offset] + bytes((proposal[offset] ^ 0x80,)) + proposal[offset + 1:]
                        refused = call(denied, invalid)
                        self.assertEqual((refused["status"], refused["result"]), (100, None))
                        self.assertEqual([35, 10, 24] in refused["transcript"], label == "successor-rows")
                        self.assertNotIn([15, 5, 24], refused["transcript"])
                        self.assertEqual(export(denied), before)

                    for cut in ("row", "meta"):
                        killed = seed(f"{cut}-interrupted-{count}", count)
                        call(killed, proposal, kill=cut)
                        self.assertEqual(export(killed), before)
