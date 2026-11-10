#!/usr/bin/env python3
"""Recheck retained #846 bytes; this never starts a native executable."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "formal/throughput-v1"))
import run_component_observations as runner
import whole_block_cost_metrics as block

ARCHIVE_SHA256 = "a21332e0ff41d47d133bada5048face5142ea9e3bd458ea543404aab6649cd84"


def main():
    archive = Path(__file__).with_name("original-ci-components.zip")
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVE_SHA256
    with zipfile.ZipFile(archive) as source:
        raw = source.read("native/complete-block.stdout")
        stderr = source.read("native/complete-block.stderr")
        receipt = source.read("native/complete-block.record.json")
        rows = block.parse_stdout(raw)
        actual = block.summarize(rows, original_stdout_sha256=hashlib.sha256(raw).hexdigest())
        block.process_receipt(receipt, hashlib.sha256(receipt).hexdigest(),
                              stdout=raw, stderr=stderr, rows=rows)
        retained = json.loads(source.read("native/complete-block-metrics.json"))
        assert actual["cohorts"] == retained["cohorts"]
        summary = json.loads(source.read("native/summary.json"))
        assert summary["component_observations_complete"] is False
        assert summary["results"][0]["status"] == "inventory_failed"
        assert summary["results"][-1]["status"] == "not_run"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "node-test-list.stdout").write_bytes(source.read("native/node-test-list.stdout"))
            selected = runner.selectors(output, "node-test-list", (*runner.UNIT_SUFFIXES, runner.TCP_SUFFIX))
        roots = json.loads(source.read("native/complete-root-observations.json"))
        assert len(roots) == 4 and len({row["observation"]["root"] for row in roots}) == 1
    return {
        "schema": "trnm-throughput-selector-original-ci-recheck-v1",
        "original_head": "24bd150a2683b5a375171d062af8256852db5321",
        "original_run_id": 42634668898,
        "original_artifact_id": 13684603519,
        "original_archive_sha256": ARCHIVE_SHA256,
        "original_component_observations_complete": False,
        "repaired_inventory_selectors": selected,
        "native_tests_started_by_recheck": 0,
        "cohorts": [{
            "senders": row["senders"],
            "reference_wall_median_ns": row["reference_wall_median_ns"],
            "candidate_wall_median_ns": row["candidate_wall_median_ns"],
            "candidate_wall_change_percent": -row["wall_reduction_percent_from_medians"],
            "candidate_faster_pairs": row["candidate_faster_pairs"],
            "retained_pairs": row["retained_pairs"],
            "per_arm_cpu_ns": None,
        } for row in actual["cohorts"]],
        "all_four_roots_equal": True,
        "confirmed_business_tps": None,
        "production_activation": False,
        "qualification": "HOLD_NO_GO",
        "scope": "byte-bound historical readback and repaired inventory resolution; no new native execution or execution authentication",
    }


if __name__ == "__main__":
    print(json.dumps(main(), indent=2, sort_keys=True, allow_nan=False))
