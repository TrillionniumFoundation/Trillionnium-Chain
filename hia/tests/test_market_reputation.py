"""Compare the M2 native value API against unchanged Rust value definitions."""
import itertools
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "hia/src/types/market_reputation.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-types/src/market_reputation.rs"
EXPORTS = ("reputation_score_bps", "reputation_tier")


def build_reference(directory):
    version = subprocess.run(
        ["rustc", "--version"], check=True, capture_output=True, text=True, timeout=10,
    ).stdout.split()
    if version[:2] != ["rustc", "1.95.0"]:
        raise ValueError("Chain's pinned rustc 1.95.0 is required")
    source = ORIGINAL.read_bytes()
    serde_import = b"use serde::{Deserialize, Serialize};\n"
    serde_derives = b", Serialize, Deserialize"
    if source.count(serde_import) != 1 or source.count(serde_derives) != 2:
        raise ValueError("Original source no longer matches the value-only adapter")
    adapted = source.replace(serde_import, b"", 1).replace(serde_derives, b"", 2)
    reference = directory / "reference.rs"
    reference.write_bytes(adapted + b"""
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("read input");
        let fields: Vec<u16> = line.split_whitespace()
            .map(|part| part.parse().expect("valid u16"))
            .collect();
        match fields[..] {
            [score] => println!("{}", match classify_reputation_tier(score) {
                ReputationTier::Trusted => 0,
                ReputationTier::Watch => 1,
                ReputationTier::Restricted => 2,
            }),
            [success_rate_bps, timeout_rate_bps, dispute_rate_bps, penalty_events] =>
                println!("{}", compute_reputation_score_bps(MarketReputationInput {
                    success_rate_bps, timeout_rate_bps, dispute_rate_bps, penalty_events,
                })),
            _ => panic!("expected one or four u16 values"),
        }
    }
}
""")
    binary = directory / "reference"
    subprocess.run(
        ["rustc", "--edition=2021", "-C", "overflow-checks=yes", str(reference), "-o", str(binary)],
        check=True, capture_output=True, text=True, timeout=30,
    )
    return binary


class MarketReputationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="trnm-market-reputation-reference-")
        cls.addClassCleanup(temporary.cleanup)
        cls.original = build_reference(Path(temporary.name))
        cls.backends = {}
        for backend in ("selfhost", "direct"):
            module = NativeModule(NATIVE, backend=backend)
            cls.addClassCleanup(module.close)
            cls.backends[backend] = module

    def compare(self, export, rows):
        result = subprocess.run(
            [str(self.original)],
            input="".join(" ".join(map(str, row)) + "\n" for row in rows),
            check=True, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.stderr, "")
        expected = list(map(int, result.stdout.splitlines()))
        self.assertEqual(len(expected), len(rows))
        for backend, native in self.backends.items():
            self.assertEqual(native.exports, frozenset(EXPORTS))
            for start in range(0, len(rows), 4096):
                batch = rows[start:start + 4096]
                observed = native.call_many([(export, row) for row in batch])
                for offset, (actual, row) in enumerate(zip(observed, batch, strict=True)):
                    actual.require_returned()
                    self.assertEqual(actual.value, expected[start + offset],
                                     (backend, export, row))
        return expected

    def test_every_u16_tier_including_out_of_range(self):
        actual = self.compare(EXPORTS[1], [(score,) for score in range(65536)])
        self.assertEqual([actual.count(tier) for tier in range(3)], [2001, 3000, 60535])
        self.assertEqual([actual[i] for i in (4999, 5000, 7999, 8000, 10000, 10001, 65535)],
                         [2, 1, 1, 0, 0, 2, 2])

    def test_score_rate_caps_cost_weights_and_zero_boundary(self):
        explicit = [
            ((65535, 0, 0, 0), 10000),
            ((9500, 200, 100, 0), 9100),
            ((9500, 200, 100, 3), 8500),
            ((10000, 0, 0, 49), 200),
            ((10000, 0, 0, 50), 0),
            ((10000, 0, 0, 65535), 0),
            ((65535, 65535, 65535, 65535), 0),
            ((10000, 799, 100, 45), 1),
            ((10000, 800, 100, 45), 0),
            ((10000, 801, 100, 45), 0),
        ]
        self.assertEqual(self.compare(EXPORTS[0], [row for row, _ in explicit]),
                         [expected for _, expected in explicit])
        rates = (0, 1, 4999, 5000, 9999, 10000, 10001, 65535)
        penalties = (0, 1, 49, 50, 51, 32768, 65535)
        self.compare(EXPORTS[0], list(itertools.product(rates, rates, rates, penalties)))

    def test_seeded_random_full_width_and_near_saturation(self):
        rng = random.Random(0x4D325250)
        rows = [tuple(rng.randrange(65536) for _ in range(4)) for _ in range(1024)]
        for _ in range(1024):
            timeout, dispute, events = rng.randrange(1000), rng.randrange(1000), rng.randrange(35)
            cost = timeout + dispute * 2 + events * 200
            rows.append((max(0, cost + rng.choice((-2, -1, 0, 1, 2))), timeout, dispute, events))
        self.compare(EXPORTS[0], rows)


if __name__ == "__main__":
    unittest.main()
