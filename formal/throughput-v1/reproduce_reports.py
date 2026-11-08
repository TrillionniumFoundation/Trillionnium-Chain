#!/usr/bin/env python3
"""Reproduce the four scoped evidence projections; successful reproduction stays HOLD."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence" / "pon-throughput-20261108"
HISTORY_PATH = ROOT / "evidence/pon-native-fullpath-20261108-a1a69c624/complete-processes.tar.gz"
HISTORY_SHA256 = "c1d4701d6ec353958b178f2838d17ec90a41572b52f62b54b1f9af4ad725efd0"
CELL_MANIFEST_SHA256 = "9e3c64afcd03bb17ac8746d1146a98c78d214000ccaf71ed2aed0ea96a6a3d25"


def require(value, message):
    if not value:
        raise ValueError(message)


def unpack_history(path, destination):
    raw = path.read_bytes()
    require(len(raw) <= 2 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == HISTORY_SHA256,
            "HISTORICAL_ARCHIVE_IDENTITY")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        require(len(members) <= 256 and sum(m.size for m in members) <= 20 * 1024 * 1024,
                "HISTORICAL_ARCHIVE_BOUNDS")
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and str(path) == member.name and
                    all(p not in ("", ".", "..") for p in path.parts) and
                    path.parts[0] == "processes" and member.name not in seen and
                    (member.isdir() or member.isfile()), "HISTORICAL_ARCHIVE_MEMBER")
            seen.add(member.name)
            target = destination / path
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                require(stream is not None, "HISTORICAL_ARCHIVE_FILE")
                data = stream.read(member.size + 1)
                require(len(data) == member.size, "HISTORICAL_ARCHIVE_SIZE")
                with target.open("xb") as output:
                    output.write(data)
    return destination / "processes"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--historical-archive", type=Path, default=HISTORY_PATH)
    args = parser.parse_args()
    output = args.output.absolute()
    require(not output.is_relative_to(ROOT), "OUTPUT_MUST_BE_OUTSIDE_SOURCE")
    output.mkdir(parents=True, exist_ok=False)
    runs = []

    def run(name, command, expected_code, expected_file):
        result = subprocess.run([sys.executable, "-B", *map(str, command)], cwd=ROOT,
                                capture_output=True, timeout=60)
        (output / (name + ".stdout")).write_bytes(result.stdout)
        (output / (name + ".stderr")).write_bytes(result.stderr)
        row = {"name": name, "argv": [sys.executable, "-B", *map(str, command)],
               "exit_code": result.returncode, "expected_exit_code": expected_code,
               "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
               "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
               "reference": str(expected_file.relative_to(ROOT)),
               "reproduced_exact_bytes": result.stdout == expected_file.read_bytes()}
        runs.append(row)
        (output / "commands.json").write_text(json.dumps(runs, indent=2, sort_keys=True) + "\n")
        require(result.returncode == expected_code and row["reproduced_exact_bytes"],
                "REPRODUCTION_FAILED:" + name)
        return json.loads(result.stdout)

    proof = run("proof-cpu", [ROOT / "formal/throughput-v1/proof_cpu_metrics.py", "--evidence-dir",
        EVIDENCE / "proof-cpu"], 0, EVIDENCE / "proof-cpu/report.json")
    require(proof["qualification"] == "HOLD_NO_GO" and proof["qualified_tps"] is None and
            proof["fresh_proof_executions"] == 0, "PROOF_SCOPE")
    cell = run("cell-model", [ROOT / "formal/throughput-v1/cell_model_metrics.py", "--manifest",
        EVIDENCE / "cell-model/input-manifest.json", "--manifest-sha256", CELL_MANIFEST_SHA256],
        0, EVIDENCE / "cell-model/projection.json")
    require(cell["qualification"] == "HOLD_NO_GO" and not cell["public_throughput_qualified"] and
            not cell["model_adoption_qualified"], "CELL_MODEL_SCOPE")
    history = unpack_history(args.historical_archive, output / "historical-originals")
    native = []
    for name, source in (("native-history", history),
                         ("native-fresh", EVIDENCE / "native-fresh/processes")):
        sha = hashlib.sha256((source / "preregistration.json").read_bytes()).hexdigest()
        report = run(name, [ROOT / "formal/pon-native-fullpath-v1/transaction_throughput.py",
            "original", source, "--preregistration-sha256", sha], 1,
            EVIDENCE / name / "transaction-readback.json")
        require(report["qualified_confirmed_tps"] is None and report["qualified_wan_tps"] is None and
                report["production_activation"] is False and report["overall_gate"] == "HOLD",
                "NATIVE_SCOPE")
        require(report["scheduled_starts"] == report["recorded_starts"] == 4 and
                report["observed_unique_packet_transactions"] == 1, "NATIVE_DENOMINATOR")
        native.append(report)
    # These are repeated development fixtures on different hosts, not two
    # independent transactions that can be pooled into a throughput numerator.
    require(native[0]["observed_unique_packet_transaction_ids"] ==
            native[1]["observed_unique_packet_transaction_ids"], "REPEATED_FIXTURE_IDENTITY")
    require(native[0]["observation_window_covered"] is True and
            native[1]["observation_window_covered"] is False and
            native[1]["eligibility_observation_rate"] is None, "WINDOW_SCOPE")
    sys.path.insert(0, str(ROOT / "scripts/ci"))
    import public_host_ci_observation as host
    for name in ("cloud", "desktop"):
        retained = json.loads((EVIDENCE / "host-prerequisites" / (name + "-observation.json")).read_bytes())
        sample = retained["original_observation"]
        violations = host.validate(sample, inside=False, uid=sample["uid"], gid=sample["gid"], cwd=sample["cwd"])
        require(violations == retained["prerequisite_violations"] and violations and
                retained["native_pressure_campaign_started"] is False and
                retained["valid_admissions"] is None and retained["cryptographic_refusals"] is None,
                "HOST_PREREQUISITE_SCOPE")
    summary = {"schema": "trnm-throughput-reproduction-v1", "reproductions": len(runs),
               "reports_match_retained_bytes": True, "historical_record_readbacks": 3,
               "new_native_record_readbacks": 1, "fresh_native_executions_by_reproducer": 0,
               "original_pressure_gate": "NOT_RUN", "qualified_confirmed_tps": None,
               "qualified_wan_tps": None, "production_activation": False, "qualification": "HOLD_NO_GO"}
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0  # Byte reproduction succeeded; qualification above remains HOLD.


if __name__ == "__main__":
    raise SystemExit(main())
