"""Run native capacity estimates against the original pure Rust methods."""
from pathlib import Path
import random
import re
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/data_availability/cache_capacity.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-data-availability/src"
EXPORTS = ("cache_max_wal_bytes", "cache_max_shm_bytes")
MAX_DB = 2**41
MIN_DB = 2**18
U64_MAX = 2**64 - 1


def original_block(path, pattern):
    # Admit one original, top-level declaration; copy it without rewriting
    # individual methods or importing the SQLite-backed remainder of the file.
    matches = re.findall(r"(?ms)^" + pattern + r".*?^}\n", path.read_text())
    if len(matches) != 1:
        raise ValueError(f"Unrecognized original Rust block: {path} / {pattern}")
    return matches[0]


def build_reference(directory):
    rust = subprocess.run(
        ["rustc", "--version"], capture_output=True, text=True, check=True, timeout=10
    ).stdout.split()
    if rust[:2] != ["rustc", "1.95.0"]:
        raise ValueError("The repository's pinned rustc 1.95.0 is required")
    source = directory / "reference.rs"
    executable = directory / "reference"
    budget = ORIGINAL / "cell/cache_budget.rs"
    source.write_text(
        "use std::io::{self, BufRead};\n"
        "pub enum CellErrorV1 { Invalid(&'static str) }\n"
        "pub type CellResultV1<T> = Result<T, CellErrorV1>;\n"
        + original_block(ORIGINAL / "cell.rs", r"pub\(crate\) fn require\(")
        + "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n"
        + original_block(budget, r"pub struct CellCacheConfigV4 \{\n")
        + original_block(budget, r"impl CellCacheConfigV4 \{\n")
        + r"""
fn capacity(result: CellResultV1<u64>) -> u64 {
    match result {
        Ok(value) if value != 0 => value,
        Ok(_) => panic!("a valid conservative byte estimate is positive"),
        Err(CellErrorV1::Invalid("finite cache configuration")) => 0,
        Err(CellErrorV1::Invalid(other)) => panic!("unexpected original error: {other}"),
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let values = line.unwrap();
        let fields: Vec<u64> = values.split_whitespace()
            .map(|value| value.parse().unwrap()).collect();
        let [max_database_bytes, max_logical_bytes, max_chunk_rows, max_manifest_rows] =
            fields[..] else { panic!("expected four values"); };
        let config = CellCacheConfigV4 {
            max_database_bytes, max_logical_bytes, max_chunk_rows, max_manifest_rows
        };
        println!("{} {}", capacity(config.max_wal_bytes()), capacity(config.max_shm_bytes()));
    }
}
"""
    )
    subprocess.run(
        ["rustc", "--edition=2021", "-C", "overflow-checks=yes", str(source), "-o", str(executable)],
        check=True, capture_output=True, text=True, timeout=30
    )
    return executable


class CacheCapacityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="trnm-cache-rust-reference-")
        cls.addClassCleanup(temporary.cleanup)
        cls.original = build_reference(Path(temporary.name))
        cls.backends = {}
        for backend in ("selfhost", "direct"):
            native = NativeModule(SOURCE, backend=backend)
            cls.addClassCleanup(native.close)
            cls.backends[backend] = native

    def compare(self, rows):
        original = subprocess.run(
            [str(self.original)],
            input="".join(" ".join(map(str, row)) + "\n" for row in rows),
            check=True, capture_output=True, text=True, timeout=20
        )
        self.assertEqual(original.stderr, "")
        expected = [tuple(map(int, line.split())) for line in original.stdout.splitlines()]
        self.assertEqual(len(expected), len(rows))
        self.assertTrue(all(len(pair) == len(EXPORTS) for pair in expected))
        for backend, native in self.backends.items():
            self.assertEqual(native.exports, frozenset(EXPORTS))
            native_calls = [(export, row) for row in rows for export in EXPORTS]
            observed = native.call_many(native_calls)
            self.assertEqual(len(observed), len(native_calls))
            for index, (call, (export, values)) in enumerate(zip(observed, native_calls)):
                call.require_returned()
                self.assertEqual(call.value, expected[index // 2][index % 2],
                                 (backend, export, values))
        return expected

    def test_minimum_maximum_and_wal_index_rounding_boundaries(self):
        pages = {64, MAX_DB // 4096}
        for region in (1, 2, 3, 17, 256, 131072):
            pages.update(region * 4096 - 16 + delta for delta in (-1, 0, 1))
        rows = [(page * 4096, 1, 1, 1) for page in sorted(pages)]
        expected = self.compare(rows)
        self.assertEqual(expected[0], (329632, 65536))
        self.assertEqual(self.compare([(MAX_DB, 2**40, 2**20, 2**20)]),
                         [(2211908223392, 4295032832)])
        below = (4096 - 16) * 4096
        self.assertEqual(self.compare([(below, 1, 1, 1), (below + 4096, 1, 1, 1)]),
                         [(16875552, 65536), (16879672, 98304)])

    def test_independent_invalid_fields_and_non_page_aligned_sizes(self):
        base = (MIN_DB, 1, 1, 1)
        values = (
            (0, MIN_DB - 4096, MIN_DB - 1, MIN_DB + 1, MAX_DB - 1,
             MAX_DB + 1, MAX_DB + 4096, U64_MAX - 4095, U64_MAX),
            (0, 2**40 + 1, U64_MAX),
            (0, 2**20 + 1, U64_MAX),
            (0, 2**20 + 1, U64_MAX),
        )
        rows = [base[:index] + (value,) + base[index+1:]
                for index, candidates in enumerate(values) for value in candidates]
        self.assertEqual(self.compare(rows), [(0, 0)] * len(rows))

    def test_deterministic_full_width_differential(self):
        rng = random.Random(0xCAB4)
        valid = [
            (rng.randrange(64, MAX_DB // 4096 + 1) * 4096,
             rng.randrange(1, 2**40 + 1), rng.randrange(1, 2**20 + 1),
             rng.randrange(1, 2**20 + 1))
            for _ in range(256)
        ]
        broad = [tuple(rng.getrandbits(64) for _ in range(4)) for _ in range(256)]
        observed = self.compare(valid + broad)
        self.assertTrue(all(wal > 0 and shm > 0 for wal, shm in observed[:len(valid)]))
        self.assertEqual(observed[len(valid):], [(0, 0)] * len(broad))


if __name__ == "__main__":
    unittest.main()
