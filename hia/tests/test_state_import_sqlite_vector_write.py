"""Actual variable-length ordered StateImport deltas on owned SQLite."""
import hashlib
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


def rollback_bad_successor(proposal, entries, before, after):
    """Self-consistent test framing for a wrong successor, not an authority."""
    bind = lambda domain, *parts: hashlib.sha256(b"".join(
        struct.pack(">Q", len(p)) + p for p in (domain, *parts))).digest()
    leaves = []
    for record in entries:
        n, k = struct.unpack_from("<QQ", record, 8)
        v, = struct.unpack_from("<Q", record, 256)
        write = record[:8] != b"DEL1M13!"
        leaves.append(bind(b"trnm.migration.incremental-delta-row.v0",
                           record[24:24+n], record[88:88+k], bytes((write,)),
                           record[264:264+v] if write else b""))
    while len(leaves) > 1:
        leaves = [bind(b"trnm.migration.incremental-delta-node.v0", leaves[i],
                       leaves[min(i + 1, len(leaves) - 1)]) for i in range(0, len(leaves), 2)]
    wrong_rows = bytes((after[128] ^ 0x80,)) + after[129:160]
    digest = bind(b"trnm.migration.incremental-delta.v0", before[:32], before[32:64],
                  before[96:128], after[96:128], before[128:160], before[160:192],
                  wrong_rows, after[160:192], before[192:200], after[192:200], leaves[0],
                  struct.pack(">Q", len(entries)))
    metadata = 16 + len(entries)*392
    last = metadata - 392
    wire = replace(proposal, last+184, wrong_rows)
    wire = replace(wire, metadata+489+260, wrong_rows.hex().upper().encode())
    wire = replace(wire, metadata+489+424, digest.hex().upper().encode())
    return replace(wire, metadata+1010, digest)


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
                    metadata_at = 16 + n*392
                    wrong_delta = replace(proposal, metadata_at+1010, bytes((proposal[metadata_at+1010] ^ 0x80,)))
                    wrong_context = replace(proposal, metadata_at+978, bytes((proposal[metadata_at+978] ^ 0x80,)))
                    wrong_plan = replace(proposal, metadata_at+489, b"1")
                    wrong_schema = replace(proposal, metadata_at+489+65, b"1")
                    wrong_root = replace(proposal, last+216, bytes((proposal[last+216] ^ 0x80,)))
                    wrong_count = replace(proposal, last+248, struct.pack("<Q", len(target) + 1))
                    # Alter both reviewed digest copies: equality of copies alone is not proof.
                    forged = bytes((after[208] ^ 1,)) + after[209:240]
                    forged_copy = replace(replace(proposal, metadata_at+1010, forged),
                                          metadata_at+489+424, forged.hex().upper().encode())
                    pending = rollback_bad_successor(proposal, records, before, after)
                    controls = [
                        ("bad-final-digest", wrong_digest, 0),
                        ("bad-canonical-delta", wrong_delta, 0),
                        ("bad-canonical-copies", forged_copy, 0),
                        ("typed-context-mismatch", wrong_context, 0),
                        ("typed-root-mismatch", wrong_root, 0),
                        ("reviewed-plan-mismatch", wrong_plan, 0),
                        ("reviewed-schema-mismatch", wrong_schema, 0),
                        ("typed-count-mismatch", wrong_count, 0),
                        ("canonical-but-incorrect-physical-rows", pending, n),
                        ("empty-vector", replace(proposal, 8, struct.pack("<Q", 0)), 0),
                        ("too-many-entries", replace(proposal, 8, struct.pack("<Q", 9)), 0),
                    ]
                    if count == 17:
                        controls.append(("operation-value-changed",
                                         replace(proposal, last+264, bytes((proposal[last+264] ^ 1,))), 0))
                    if n > 1:
                        changed_key = replace(proposal, last+88, bytes((proposal[last+88] ^ 1,)))
                        controls += [
                            ("operation-key-changed", changed_key, 0),
                            ("wrong-last-leaf", replace(proposal, last+152, bytes((proposal[last+152] ^ 0x80,))), 0),
                            ("noncanonical-order", header + records[1] + records[0] + b"".join(records[2:]) + metadata, 0),
                            ("duplicate-tuple", header + records[0]*2 + b"".join(records[2:]) + metadata, 0),
                        ]
                    for name, wire, changes in controls:
                        fixture = seed(f"{name}-{count}", count)
                        refusal = invoke(fixture, wire)
                        self.assertEqual((refusal["status"], refusal["result"]), (100, None), name)
                        self.assertEqual(refusal["transcript"].count([35, 10, 24]), changes, name)
                        if name not in ("wrong-last-leaf", "canonical-but-incorrect-physical-rows"):
                            self.assertEqual(refusal["transcript"], [], name)
                        self.assertNotIn([15, 5, 24], refusal["transcript"])
                        self.assertEqual(export(fixture), before, name)

                    for cut in [*sorted({1, n}), "metadata"]:
                        interrupted = seed(f"killed-{cut}-{count}", count)
                        invoke(interrupted, proposal, cut=cut)
                        self.assertEqual(export(interrupted), before)
