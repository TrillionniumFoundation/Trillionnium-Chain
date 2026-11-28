"""Manual deterministic controls; neither runs native code nor measures performance."""
from pathlib import Path
import json
import os
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from scripts import routed_int257_warm_benchmark as bench


def product(case):
    members = [bytes(i for i, j in enumerate(case.routes) if j == x) for x in range(3)]
    return (bench.direct.HEADER.pack(1542*case.n, 0, sum(map(bool, members)), *map(len, members))
            + b"".join(bench.direct.ROW.pack(0, 0, 0, j, 0, 0, 0, 0) for j in case.routes)
            + b"".join(members))


class HarnessControls(unittest.TestCase):
    def test_fixed_panel_and_frames(self):
        cases = list(bench.panel())
        self.assertEqual(cases, list(bench.panel()))
        self.assertEqual([(x.n, x.distribution) for x in cases],
                         [(1, "one")] + [(n, d) for n in (8, 32, 64)
                                         for d in ("one", "balanced", "skew")])
        self.assertEqual(len({bench.sha(x.frame) for x in cases}), 10)
        self.assertEqual([cases[-1].routes.count(j) for j in range(3)], [62, 1, 1])

    def test_exact_pair_and_route_metadata(self):
        case = list(bench.panel())[-1]
        raw = product(case)
        self.assertEqual(bench.exact_product(case, raw, raw), bench.sha(raw))
        different = raw[:-1] + b"\x00"
        with self.assertRaisesRegex(ValueError, "Product bytes differ"):
            bench.exact_product(case, raw, different)
        with self.assertRaisesRegex(ValueError, "fixture routes"):
            bench.exact_product(case, different, different)
        offset = bench.direct.HEADER.size + struct.calcsize("<qqq")
        wrong_row = raw[:offset] + bytes([2]) + raw[offset + 1:]
        with self.assertRaisesRegex(ValueError, "fixture routes"):
            bench.exact_product(case, wrong_row, wrong_row)

    def test_alternating_paired_blocks_and_no_mid_block_refusal_masking(self):
        positions = []
        def mark(label):
            positions.append(label)
            return 0
        ticks = iter([0, 10, 20, 40, 50, 90, 100, 140])
        blocks = bench.run_blocks(lambda: mark("d"), lambda: mark("g"), 9, 2, "grouped",
                                  clock=lambda: next(ticks))
        self.assertEqual(positions, list("g"*9 + "d"*18 + "g"*9))
        self.assertEqual(blocks, [
            {"order": ("grouped", "direct"), "grouped_ns": 10, "direct_ns": 20},
            {"order": ("direct", "grouped"), "direct_ns": 40, "grouped_ns": 40},
        ])
        for count, pairs in ((8, 2), (2001, 2), (9, 3), (9, 42), (True, 2)):
            with self.assertRaisesRegex(ValueError, "measurement policy"):
                bench.run_blocks(lambda: 0, lambda: 0, count, pairs, "direct")
        status = iter([0, 3, 0])
        with self.assertRaisesRegex(ValueError, "ABI call refused"):
            bench.repeat(lambda: next(status), 3)
        with self.assertRaisesRegex(ValueError, "nonpositive"):
            bench.block(lambda: 0, 9, clock=lambda: 1)

    def test_elf_pins_require_four_unique_canonical_exact_shas(self):
        pins = {"direct": {"direct": "a"*64, "grouped": "b"*64},
                "selfhost": {"direct": "c"*64, "grouped": "d"*64}}
        self.assertEqual(bench.elf_pins(json.dumps(pins)), pins)
        for wrong in ('{"direct":{},"direct":{}}', '{"direct":{},"selfhost":{}}', '[]',
                      json.dumps({**pins, "selfhost": pins["direct"]}),
                      json.dumps({**pins, "selfhost": {"direct": "C"*64, "grouped": "d"*64}})):
            with self.assertRaises(ValueError):
                bench.elf_pins(wrong)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "synthetic"
            path.write_bytes(b"not an ELF; should never reach dlopen")
            kernel = SimpleNamespace(library=path, artifact_sha256=bench.sha(path.read_bytes()))
            with self.assertRaisesRegex(ValueError, "ELF differs"):
                with bench.load_pinned(kernel, "0"*64):
                    self.fail("wrong bytes admitted")

    def test_owned_test_descriptor_cannot_change_after_capture(self):
        marker = b"local deterministic test marker"
        with bench.sealed_image(marker) as fd:
            self.assertEqual(os.pread(fd, len(marker), 0), marker)
            with self.assertRaises(PermissionError):
                os.pwrite(fd, b"X", 0)
            self.assertEqual(os.pread(fd, len(marker), 0), marker)

    def test_exact_inputs_and_head_drift_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            def git(*args):
                return subprocess.run(["git", "-C", td, *args], check=True, capture_output=True)
            git("init", "-q")
            (path / "source").write_bytes(b"exact\n")
            git("add", "source")
            git("-c", "user.email=test@example.test", "-c", "user.name=Fixture", "commit", "-qm", "one")
            snapshot = bench.Source(path)
            with self.assertRaisesRegex(ValueError, "build/source input mismatch"):
                snapshot.exact("source", "0"*64)
            snapshot.exact("source", bench.sha(b"exact\n"))
            snapshot.validate()
            (path / "source").write_bytes(b"dirty\n")
            with self.assertRaisesRegex(ValueError, "input mismatch"):
                snapshot.validate()
            with self.assertRaisesRegex(ValueError, "differs from committed"):
                bench.Source(path).exact("source")
            (path / "source").write_bytes(b"exact\n")
            git("-c", "user.email=test@example.test", "-c", "user.name=Fixture",
                "commit", "--allow-empty", "-qm", "two, same tree")
            with self.assertRaisesRegex(ValueError, "HEAD changed"):
                snapshot.validate()
            current = bench.Source(path)
            self.assertEqual(snapshot.tree, current.tree)
            (path / "source").rename(path / "untracked")
            (path / "source").symlink_to("untracked")
            with self.assertRaisesRegex(ValueError, "linked"):
                current.exact("source")


if __name__ == "__main__":
    unittest.main()
