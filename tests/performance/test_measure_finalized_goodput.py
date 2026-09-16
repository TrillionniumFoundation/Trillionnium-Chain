import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "trillionnium/scripts/measure_finalized_goodput.py"


def event(tx, submitted, finalized, status="finalized", replay=True, path="canonical", retry=0, rollback=False):
    return {
        "schema": "trnm_e2e_tx_event_v1",
        "tx_id": tx,
        "workload": "classic",
        "execution_path": path,
        "submitted_at_utc": submitted,
        "finalized_at_utc": finalized,
        "finality_status": status,
        "replay_verified": replay,
        "retry_count": retry,
        "rollback": rollback,
        "segment_latency_ms": {"consensus": 10, "execution": 5},
    }


class MeasureGoodputTest(unittest.TestCase):
    def run_tool(self, rows):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "events.jsonl"
            src.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            proc = subprocess.run([sys.executable, str(SCRIPT), str(src)], text=True, capture_output=True)
            return proc

    def test_counts_only_finalized_replay_verified(self):
        rows = [
            event("a", "2026-09-16T00:00:00Z", "2026-09-16T00:00:01Z"),
            event("b", "2026-09-16T00:00:00Z", "2026-09-16T00:00:02Z", replay=False),
            event("c", "2026-09-16T00:00:00Z", None, status="pending", replay=False, retry=1),
            event("d", "2026-09-16T00:00:00Z", None, status="rejected", replay=False, rollback=True),
        ]
        proc = self.run_tool(rows)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["counts"]["submitted"], 4)
        self.assertEqual(result["counts"]["finalized"], 2)
        self.assertEqual(result["counts"]["replay_verified_finalized"], 1)
        self.assertAlmostEqual(result["metrics"]["finalized_goodput_tps"], 1.0, places=6)
        self.assertEqual(result["metrics"]["finality_p50_ms"], 1000.0)
        self.assertEqual(result["metrics"]["finality_p95_ms"], 1000.0)
        self.assertEqual(result["metrics"]["finality_p99_ms"], 1000.0)
        self.assertEqual(result["metrics"]["retry_rate"], 0.25)
        self.assertEqual(result["metrics"]["rollback_rate"], 0.25)

    def test_speculative_path_is_rejected(self):
        proc = self.run_tool([event("x", "2026-09-16T00:00:00Z", "2026-09-16T00:00:01Z", path="speculative")])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("execution_path must be canonical", proc.stderr + proc.stdout)

    def test_no_verified_finality_refuses_claim(self):
        proc = self.run_tool([event("x", "2026-09-16T00:00:00Z", "2026-09-16T00:00:01Z", replay=False)])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no finalized + replay-verified", proc.stderr + proc.stdout)


if __name__ == "__main__":
    unittest.main()
