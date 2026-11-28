"""Compare native immutable slot readback to the original private typed verifier."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import MAX_EXTENT, NativeModule
from hia.tests.test_da_chunk_inclusion_path import unchanged_original_observation

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/rs46_committed_slot.hepta"
HARNESS = Path(__file__).with_name("rust_da_rs46_committed_slot_harness.rs")
MARKER = b"TRNM_DA_RS46_COMMITTED_SLOT_COMPARATOR_V1"
SELECTOR = "cell::erasure::custody::hia_da_rs46_committed_slot_fixture::observe_exact_committed_slot"
WORK = 1240
OUT = b"\xa5" * 127
SCRATCH = b"\x6d" * (WORK + 11)


def parse_fixture(raw):
    offset = 0
    while offset < len(raw):
        status, slot, rcb_n, crs_n = struct.unpack_from("<BBII", raw, offset)
        offset += 10
        end_of_input = offset + rcb_n + crs_n
        end = end_of_input + (113 if status == 0 else 0)
        if (status not in {0, 13, 14, 15, 22, 31, 32, 33, 34, 35, 36}
                or not 233 <= rcb_n <= MAX_EXTENT or not 81 <= crs_n <= MAX_EXTENT + 81
                or slot > 7 or end > len(raw)):
            raise ValueError("Invalid private committed-slot witness")
        rcb = raw[offset:offset + rcb_n]
        crs = raw[offset + rcb_n:end_of_input]
        want = raw[end_of_input:end]
        yield (rcb, crs[:81], crs[81:], slot), status, want
        offset = end


class DaRs46CommittedSlot(unittest.TestCase):
    def test_actual_original_private_verify_input_and_both_stock(self):
        with tempfile.TemporaryDirectory(prefix="trnm-original-da-committed-slot-") as tmp:
            raw, rlib_sha = unchanged_original_observation(
                Path(tmp), harness=HARNESS, marker=MARKER, test=SELECTOR,
                capture_limit=3 * MAX_EXTENT, owner="rs46-committed-slot")
        actual = list(parse_fixture(raw))
        counts = Counter(status for _, status, _ in actual)
        self.assertEqual(counts, {0: 20, 13: 3, 14: 3, 15: 3, 22: 3, 31: 3, 32: 3,
                                  33: 3, 34: 3, 35: 3, 36: 36})
        self.assertEqual(len(actual), 83)
        self.assertEqual(sum(len(args[2]) == MAX_EXTENT and status == 0 for args, status, _ in actual), 1)
        for (frame, head, tail, slot), status, want in actual:
            if status == 0:
                self.assertEqual(want[32:], head)
                self.assertEqual(want[:32], hashlib.sha256(b"trnm.cell-rs46-shard.v1\0" + head + tail).digest())
                self.assertEqual(want[:32], frame[len(frame) - 192 + slot * 32:len(frame) - 160 + slot * 32])
        print(json.dumps({"actual_original_private_selector": SELECTOR, "original_rlib_sha256": rlib_sha,
                          "capture_sha256": hashlib.sha256(raw).hexdigest(), "rows": len(actual),
                          "status_counts": dict(sorted(counts.items()))}, sort_keys=True), flush=True)
        sample, sample_status, sample_output = actual[0]
        frame, header, payload, slot = sample
        def pack(parts):
            word, head, tail, selected = parts
            return word + head + tail + struct.pack(">IB", len(word), selected)

        bare = pack(sample)
        self.assertEqual(len(pack(actual[-1][0])), MAX_EXTENT)
        self.assertGreater(len(pack(actual[-2][0])), MAX_EXTENT)
        controls = [
            (bare, OUT[:112], SCRATCH, 102, b""),
            (bare, OUT, SCRATCH[:WORK-1], 102, b""),
            (pack((frame, header[:80], b"", slot)), OUT, SCRATCH, 31, b""),
            (pack((frame, header + b"\0", payload, slot)), OUT, SCRATCH, 35, b""),
            (pack((frame, header, payload, 255)), OUT, SCRATCH, 36, b""),
            (b"", OUT, SCRATCH, 100, b""),
            (bare[:-5] + struct.pack(">IB", len(bare), slot), OUT, SCRATCH, 100, b""),
            (bare, OUT[:113], SCRATCH[:WORK], sample_status, sample_output),
        ]
        for backend in ("direct", "selfhost"):
            profile = [(pack(args), OUT, SCRATCH, status, want) for args, status, want in actual
                       if backend == "selfhost" or len(pack(args)) <= MAX_EXTENT]
            cases = profile + controls
            options = {"max_input_extent": 2 * MAX_EXTENT + 86} if backend == "selfhost" else {}
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend, **options) as native:
                for at in range(0, len(cases), 16):
                    chunk = cases[at:at+16]
                    results = native.call_many([("f0", [wire, out, work])
                                                for wire, out, work, _, _ in chunk], timeout=60)
                    for pos, ((wire, out, work, status, want), result) in enumerate(zip(chunk, results, strict=True), at):
                        self.assertEqual(result.require_returned().value, status, pos)
                        self.assertEqual(result.arguments[0], wire, pos)
                        self.assertEqual(result.arguments[1], want + out[len(want):], pos)
                        self.assertEqual(result.arguments[2][WORK:], work[WORK:], pos)
                print(json.dumps({"backend": backend, "artifact_sha256": native.artifact_sha256,
                                  "original_matches": len(profile), "abi_controls": len(controls),
                                  "wide_original": backend == "selfhost"}, sort_keys=True), flush=True)
