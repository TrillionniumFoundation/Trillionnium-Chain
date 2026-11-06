#!/usr/bin/env python3
"""Exercise one actually saved full V2 proof through the finite research owner.

No proof is generated. The original positive must pass before negative controls
are attempted. This campaign cannot qualify Node admission, a public attack
envelope, global worst-case rejection cost or quantum soundness.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time

from w1_v2_supervisor import (ARTIFACT_BYTES, HEADER_BYTES, MAX_RECEIPT, Limits,
                            VerifierOwner, snapshot)


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("verifier", "receipt", "header", "expected-artifacts", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    args = parser.parse_args(argv)
    limits = Limits()
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    deadline, rows, error, initial_work_id = time.monotonic() + 60, [], None, None
    paths = {"receipt": out / "receipt.bin", "header": out / "header.bin", "artifacts": out / "artifacts.bin"}
    write_json(out / "declaration.json", {"schema": "TRNM-W1-V2-SUPERVISOR-CONTROLS1",
               "limits": asdict(limits), "overall_wall_seconds": 60,
               "verifier_sha256": args.verifier_sha256, "new_proofs_generated": 0,
               "one_saved_proof_only": True, "node_cpu_owner_integrated": False})
    owner = None
    try:
        assets = {}
        for name, path, bound, exact in (
                ("header", args.header, HEADER_BYTES, HEADER_BYTES),
                ("artifacts", args.expected_artifacts, ARTIFACT_BYTES, ARTIFACT_BYTES),
                ("receipt", args.receipt, MAX_RECEIPT, None)):
            assets[name] = snapshot(path, paths[name], bound, exact, deadline)
        original = paths["receipt"].read_bytes()
        count = int.from_bytes(original[4:12], "little")
        seal_end = 12 + 4 * count
        if not (original[:4] == (1).to_bytes(4, "little") and count > 0 and seal_end <= len(original)):
            raise ValueError("saved input is not bounded Succinct framing")
        bad_seal = bytearray(original)
        bad_seal[seal_end - 4] ^= 1
        (out / "bad-seal.bin").write_bytes(bad_seal)
        bad_wire = bytearray(original)
        bad_wire[:4] = (0).to_bytes(4, "little")
        (out / "bad-wire.bin").write_bytes(bad_wire)
        bad_header = bytearray(paths["header"].read_bytes())
        bad_header[70] ^= 1
        (out / "bad-header.bin").write_bytes(bad_header)
        bad_artifacts = bytearray(paths["artifacts"].read_bytes())
        bad_artifacts[0] ^= 1
        (out / "bad-artifacts.bin").write_bytes(bad_artifacts)
        requests = [
            ("positive_original", paths["receipt"], paths["header"], paths["artifacts"], "VerifiedResearchStatement", False, "public", None),
            ("bad_seal", out / "bad-seal.bin", paths["header"], paths["artifacts"], "Invalid", False, "public", 22),
            ("same_bad_seal_recovery", out / "bad-seal.bin", paths["header"], paths["artifacts"], "Invalid", True, "recovery", None),
            ("good_proof_same_work_id", paths["receipt"], paths["header"], paths["artifacts"], "VerifiedResearchStatement", False, "history", None),
            ("different_header", paths["receipt"], out / "bad-header.bin", paths["artifacts"], "Invalid", False, "relay", 21),
            ("different_expected_artifacts", paths["receipt"], paths["header"], out / "bad-artifacts.bin", "Invalid", False, "public", 21),
            ("wrong_wire_tag", out / "bad-wire.bin", paths["header"], paths["artifacts"], "Invalid", False, "public", None),
            ("expired_original", paths["receipt"], paths["header"], paths["artifacts"], "Deadline", False, "public", None),
            ("good_proof_after_deadline", paths["receipt"], paths["header"], paths["artifacts"], "VerifiedResearchStatement", False, "public", None),
        ]
        write_json(out / "plan.json", [{"name": req[0], "expected_status": req[4], "cache_hit": req[5],
                   "caller_class": req[6], "expected_returncode": req[7],
                   "assets": {name: {"path": path.name, "sha256": digest(path)}
                              for name, path in zip(("receipt", "header", "artifacts"), req[1:4])}}
                  for req in requests])
        owner = VerifierOwner(args.verifier, args.verifier_sha256, limits)
        for name, receipt, header, expected, status, cache_hit, caller, code in requests:
            request_deadline = time.monotonic() - 1 if name == "expired_original" else deadline
            row = owner.verify(receipt, header, expected, deadline=request_deadline, caller_class=caller)
            passed = (row["status"] == status and row["cache_hit"] is cache_hit
                      and row["owner_after"]["active_workers"] == 0
                      and not row["owner_after"]["blocked_on_unknown_worker"])
            if code is not None:
                passed &= row["returncode"] == code and row["worker_reaped"]
            if status == "VerifiedResearchStatement":
                work_id = row.get("report", {}).get("work_id")
                if initial_work_id is None:
                    initial_work_id = work_id
                passed &= initial_work_id is not None and work_id == initial_work_id and row["worker_reaped"]
            if status == "Deadline" or cache_hit:
                passed &= not row["worker_started"]
            if name == "wrong_wire_tag":
                passed &= row["wire_precheck_rejected"] and not row["worker_started"] and row["returncode"] is None
            row.update(name=name, passed=bool(passed), expected_status=status)
            write_json(out / (name + ".json"), row)
            rows.append(row)
            print(json.dumps({"name": name, "passed": bool(passed), "status": row["status"],
                              "worker_cpu_ns": row["worker_cpu_ns"]}), flush=True)
            if name == "positive_original" and not passed:
                raise ValueError("mandatory actual saved-proof positive failed; remaining controls not run")
        stats = owner.stats()
        if stats["available_cpu_ns"] != (limits.campaign_cpu_ns - stats["settled_worker_cpu_ns"]
                                          - stats["settled_owner_thread_cpu_ns"]):
            raise ValueError("finite owner CPU settlement did not reconcile")
    except (OSError, ValueError, TypeError, KeyError) as failure:
        error = type(failure).__name__ + ": " + str(failure)
    finally:
        stats = owner.stats() if owner else None
        if owner and stats["active_workers"] == 0:
            owner.close()
        complete = len(rows) == 9 and all(row["passed"] for row in rows) and error is None
        write_json(out / "result.json", {"schema": "TRNM-W1-V2-SUPERVISOR-CONTROLS1",
                   "all_controls_passed": complete, "error": error, "planned_controls": 9,
                   "completed_controls": len(rows), "passed_controls": sum(row["passed"] for row in rows),
                   "limits": asdict(limits), "owner_after": stats, "work_id": initial_work_id,
                   "verifier_sha256": args.verifier_sha256, "new_proofs_generated": 0,
                   "native_replay_calls": 0, "node_cpu_owner_integrated": False,
                   "public_service_qualified": False, "production_activation": False,
                   "results": [{"name": row["name"], "passed": row["passed"], "status": row["status"],
                                "worker_cpu_ns": row["worker_cpu_ns"], "wall_seconds": row["wall_seconds"]}
                               for row in rows]})
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
