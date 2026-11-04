#!/usr/bin/env python3
"""Run all frozen W1 segments and real recursive completion under declared limits."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


def footprint(directory):
    files = [path for path in directory.rglob("*") if path.is_file()]
    return {"files": len(files), "logical_bytes": sum(p.stat().st_size for p in files),
            "allocated_bytes": sum(p.stat().st_blocks * 512 for p in files)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--r0vm", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--prior-result", type=Path, action="append", default=[])
    parser.add_argument("--total-wall-seconds", type=float, default=5400)
    parser.add_argument("--pause-file", type=Path)
    args = parser.parse_args()
    if not 0 < args.total_wall_seconds <= 7200:
        parser.error("total wall budget must be in (0,7200]")
    args.out.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((args.checkpoint / "manifest.json").read_text())
    count = len(manifest["segments"])
    if not 0 < count <= 4096:
        parser.error("invalid frozen segment count")
    prior = [{"path": str(path), "result": json.loads(path.read_text())} for path in args.prior_result]
    prior_seconds = sum(row["result"]["wall_seconds"] for row in prior)
    declaration = {
        "schema": "TRNM-W1-COMPLETE-STAGED-RUN1", "source_commit": manifest["source_commit"],
        "runner_sha256": manifest["runner_sha256"], "guest_sha256": manifest["guest_sha256"],
        "input_sha256": manifest["input_sha256"], "planned_full_segments": count,
        "total_wall_budget_seconds": args.total_wall_seconds, "prior_bounded_wall_seconds": prior_seconds,
        "prior_runs": prior, "per_new_segment_wall_seconds": 300,
        "free_disk_floor_bytes": 1024**3, "checkpoint_disk_cap_bytes": 256*1024**2,
        "pause_file": str(args.pause_file) if args.pause_file else None,
        "pause_and_controller_wall_consume_budget": True,
        "complete_proof_claim": False,
    }
    (args.out / "declaration.json").write_text(json.dumps(declaration, indent=2) + "\n")
    started = time.monotonic()
    stages = []
    paused_seconds = 0

    def remaining():
        return args.total_wall_seconds - prior_seconds - (time.monotonic() - started)

    def stage(label, command, cap):
        nonlocal paused_seconds
        while args.pause_file and args.pause_file.exists():
            if remaining() <= 6:
                raise RuntimeError("declared wall budget exhausted during coordinated pause")
            now = time.monotonic()
            time.sleep(min(1, remaining() - 6))
            paused_seconds += time.monotonic() - now
        free = shutil.disk_usage(args.checkpoint).free
        size = footprint(args.checkpoint)
        if free < 1024**3 or size["allocated_bytes"] > 256*1024**2:
            raise RuntimeError("declared disk guard reached before next proof stage")
        limit = min(cap, remaining() - 6)
        if limit <= 0:
            raise RuntimeError("declared cumulative wall budget exhausted")
        out = args.out / label
        invocation = [sys.executable, str(Path(__file__).with_name("w1_stage_measure.py")),
                      "--wall-seconds", str(limit), "--out", str(out), "--", *map(str, command)]
        (args.out / "current-stage.json").write_text(json.dumps({"stage": label, "command": invocation, "remaining_seconds": remaining(), "disk_free_bytes": free, "checkpoint": size}, indent=2) + "\n")
        print(json.dumps({"stage": label, "status": "STARTED", "limit_seconds": limit, "remaining_seconds": remaining()}), flush=True)
        result = subprocess.run(invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out / "supervisor.stdout").write_bytes(result.stdout)
        (out / "supervisor.stderr").write_bytes(result.stderr)
        record = {"stage": label, "result": json.loads((out / "result.json").read_text())}
        stages.append(record)
        (args.out / "stages.json").write_text(json.dumps(stages, indent=2) + "\n")
        print(json.dumps({"stage": label, "status": "FINISHED", "returncode": result.returncode, "wall_seconds": record["result"]["wall_seconds"]}), flush=True)
        if result.returncode:
            raise RuntimeError(f"actual stage failed: {label}, returncode={result.returncode}")

    base = [args.runner, "--r0vm", args.r0vm]
    complete = False
    error = None
    try:
        stage("reverify-existing-prefix", [*base, "prove", args.checkpoint, "0"], 180)
        for index in range(count):
            path = args.checkpoint / f"receipt-{index:04}.bin"
            if path.exists():
                continue
            stage(f"prove-{index:04}", [*base, "prove", args.checkpoint, "1"], 300)
            if not path.is_file():
                raise RuntimeError("successful process omitted its required segment receipt")
        stage("complete-recursive-compression", [*base, "compress", args.checkpoint], remaining())
        verifier = args.runner.parent / "trnm-w1-zk-host"
        stage("fresh-process-strict-verification", [verifier, "verify", args.checkpoint / "header.bin", args.checkpoint / "succinct.bin"], 180)
        complete = True
        stage("fixed-receipt-verifier-cost", [verifier, "verify-many", args.checkpoint / "header.bin", args.checkpoint / "succinct.bin"], 180)
        stage("native-full-verifier-cost", [args.runner.parent / "w1-native-cost", args.checkpoint / "input.bin"], 180)
    except (OSError, RuntimeError, ValueError) as failure:
        error = str(failure)
    result = {**declaration, "complete_proof_claim": complete, "error": error, "stages": stages,
              "new_controller_wall_seconds": time.monotonic() - started,
              "cumulative_bounded_wall_seconds": prior_seconds + time.monotonic() - started,
              "coordinated_pause_seconds": paused_seconds, "checkpoint_final": footprint(args.checkpoint),
              "disk_free_final_bytes": shutil.disk_usage(args.checkpoint).free,
              "benefit_gate_passed": None, "prover_p99_established": False,
              "production_qualification": False, "consensus_admission": False}
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"complete_proof_claim": complete, "error": error, "completed_stages": len(stages)}), flush=True)
    return 0 if complete and error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
