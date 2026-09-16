#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "trillionnium/scripts/measure_finalized_goodput.py"


def event(tx_id: str, submitted: str, status: str, finalized: str | None, replay: bool) -> dict:
    return {
        "schema": "trnm_e2e_tx_event_v1",
        "tx_id": tx_id,
        "workload": "classic",
        "execution_path": "canonical",
        "submitted_at_utc": submitted,
        "finalized_at_utc": finalized,
        "finality_status": status,
        "replay_verified": replay,
        "retry_count": 0,
        "rollback": False,
        "segment_latency_ms": {},
    }


class GoodputMeasurementTests(unittest.TestCase):
    def run_measurement(self, events: list[dict]) -> dict:
        with tempfile.TemporaryDirectory(prefix="trnm-goodput-") as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in events), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            return json.loads(result.stdout)

    def test_late_pending_submission_extends_observation_window(self) -> None:
        report = self.run_measurement([
            event("a", "2026-09-16T00:00:00Z", "finalized", "2026-09-16T00:00:01Z", True),
            event("b", "2026-09-16T00:01:40Z", "pending", None, False),
        ])
        self.assertEqual(report["schema"], "trnm_finalized_goodput_measurement_v2")
        self.assertEqual(report["window"]["duration_ms"], 100000.0)
        self.assertEqual(report["metrics"]["submit_tps"], 0.02)
        self.assertEqual(report["metrics"]["finalized_goodput_tps"], 0.01)
        self.assertEqual(report["workloads"]["classic"]["duration_ms"], 100000.0)
        self.assertEqual(report["workloads"]["classic"]["finalized_goodput_tps"], 0.01)

    def test_last_finality_extends_window_when_after_last_submission(self) -> None:
        report = self.run_measurement([
            event("a", "2026-09-16T00:00:00Z", "finalized", "2026-09-16T00:00:10Z", True),
            event("b", "2026-09-16T00:00:05Z", "rejected", None, False),
        ])
        self.assertEqual(report["window"]["duration_ms"], 10000.0)
        self.assertEqual(report["metrics"]["submit_tps"], 0.2)
        self.assertEqual(report["metrics"]["finalized_goodput_tps"], 0.1)


if __name__ == "__main__":
    unittest.main()
