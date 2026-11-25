"""Actual variable-length ordered StateImport deltas on owned SQLite."""
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
from hia.tests.test_state_import_sqlite_mixed_write import proposal_record


def replace(wire, at, raw):
    return wire[:at] + raw + wire[at + len(raw):]


class StateImportSqliteVectorWrite(unittest.TestCase):
    def test_all_one_to_eight_original_extents_and_real_vector_rollback(self):
        with tempfile.TemporaryDirectory(prefix="m13-sqlite-vector-delta-") as tmp, NativeModule(
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

            cases = [(0, b"I"), (11, b"DDDD"), (17, b"UDIDUIIU")]
            cases.extend((20 + n, b"IUDDIUU"[:n]) for n in (2, 3, 5, 6, 7))
            for count, expected in cases:
                with self.subTest(count=count, kinds=expected):
                    oracle = seed(f"original-{count}", count)
                    before = export(oracle)
                    _run([original, "vector-advance", oracle])
                    after = export(oracle)
                    prior = {r[:2]: r for r in original_rows(before)}
                    target = {r[:2]: r for r in original_rows(after)}
                    self.assertEqual(int.from_bytes(after[192:200], "big"), len(target))
                    self.assertEqual(int.from_bytes(after[200:208], "big"), 1)
                    records, kinds = [], bytearray()
                    for key in sorted(prior.keys() | target.keys()):
                        old, new = prior.get(key), target.get(key)
                        if old == new:
                            continue
                        if new is None:
                            magic, value, kind = b"DEL1M13!", b"", ord("D")
                        elif old is None:
                            magic, value, kind = b"INS1M13!", new[3], ord("I")
                            old = (*key, bytes(32), b"")
                        else:
                            magic, value, kind = b"UPD1M13!", new[3], ord("U")
                        kinds.append(kind)
                        records.append(proposal_record(magic, old, value, after, len(target)))
                    self.assertEqual(bytes(kinds), expected)
                    n = len(records)
                    header = b"VEC1M13!" + struct.pack("<Q", n)
                    metadata = (projection(before)[:489] + projection(after)[:489]).encode()
                    metadata += after[96:128] + after[208:240]
                    proposal = header + b"".join(records) + metadata

                    db = seed(f"candidate-{count}", count)
                    accepted = invoke(db, proposal)
                    self.assertEqual((accepted["status"], accepted["result"], accepted["released"]), (0, projection(after), 0))
                    self.assertEqual(accepted["transcript"][-1], [18, 3, 24])
                    self.assertEqual(accepted["transcript"].count([30, 5, 24]), n)
                    self.assertEqual(accepted["transcript"].count([35, 10, 24]), n)
                    self.assertEqual(accepted["transcript"].count([28, 10, 24]), 1)
                    self.assertEqual(export(db), after)
                    if count >= 20:  # supplementary physical positive extents
                        continue
                    stale = invoke(db, proposal)
                    self.assertEqual((stale["status"], stale["result"]), (100, None))
                    self.assertNotIn([30, 5, 24], stale["transcript"])
                    self.assertEqual(export(db), after)

                    last = 16 + (n-1)*392
                    wrong_digest = replace(proposal, last+184, bytes((proposal[last+184] ^ 0x80,)))
                    controls = [
                        ("bad-final-digest", wrong_digest, n),
                        ("empty-vector", replace(proposal, 8, struct.pack("<Q", 0)), 0),
                        ("too-many-entries", replace(proposal, 8, struct.pack("<Q", 9)), 0),
                    ]
                    if n > 1:
                        controls += [
                            ("wrong-last-leaf", replace(proposal, last+152, bytes((proposal[last+152] ^ 0x80,))), 0),
                            ("noncanonical-order", header + records[1] + records[0] + b"".join(records[2:]) + metadata, 0),
                            ("duplicate-tuple", header + records[0]*2 + b"".join(records[2:]) + metadata, 0),
                        ]
                    for name, wire, changes in controls:
                        fixture = seed(f"{name}-{count}", count)
                        refusal = invoke(fixture, wire)
                        self.assertEqual((refusal["status"], refusal["result"]), (100, None), name)
                        self.assertEqual(refusal["transcript"].count([35, 10, 24]), changes, name)
                        if name in ("noncanonical-order", "duplicate-tuple", "empty-vector", "too-many-entries"):
                            self.assertEqual(refusal["transcript"], [], name)
                        self.assertNotIn([15, 5, 24], refusal["transcript"])
                        self.assertEqual(export(fixture), before, name)

                    for cut in [*sorted({1, n}), "metadata"]:
                        interrupted = seed(f"killed-{cut}-{count}", count)
                        invoke(interrupted, proposal, cut=cut)
                        self.assertEqual(export(interrupted), before)
