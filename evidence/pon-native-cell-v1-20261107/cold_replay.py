#!/usr/bin/env python3
"""Cold replay retained synthetic fixtures through the ordinary native CLI.

Reads the separately retained owner admission; never derives expected context
from the producer claim. Fixed genesis/settings and verified packet bytes rebuild
native stores. This is a repeat of existing proofs, not independent task demand,
FinalUse, operation consumption, checkpoint publication, or consensus activation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def create(path, raw):
    with path.open("xb") as file:
        file.write(raw)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    cases = args.cases.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    results = []
    for name in ("masked_sampling_training", "history-legacy", "history-authenticated"):
        source = cases / name
        settings = json.loads((source / "settings-and-context.json").read_bytes())
        assert settings["settings_constructor"] == "Settings::development(Some(150))"
        assert settings["genesis_time_unix_seconds"] == 150
        owner = (source / "owner-admission.json").read_bytes()
        assert sha(owner) == settings["owner_admission_sha256"]
        case = output / name
        case.mkdir(mode=0o700)
        own = case / "owner-admission.json"
        fd = os.open(own, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(owner)
        store = case / "native-store"
        common = ["--development", "--genesis-time", "150", "--state-backend",
                  settings["state_backend"], "--store", str(store)]
        ordinal = 0
        def run(command, more):
            nonlocal ordinal
            argv = [str(binary), command, *common, *more]
            started = time.monotonic()
            child = subprocess.run(argv, capture_output=True, timeout=60, check=False)
            prefix = case / ("%02d-%s" % (ordinal, command))
            ordinal += 1
            create(prefix.with_suffix(".stdout"), child.stdout)
            create(prefix.with_suffix(".stderr"), child.stderr)
            create(prefix.with_suffix(".json"), (json.dumps({
                "argv": argv, "returncode": child.returncode,
                "elapsed_seconds": time.monotonic() - started,
                "independent_child_process": True,
            }, sort_keys=True, indent=2) + "\n").encode())
            if child.returncode:
                raise RuntimeError("%s: %s" % (command, child.stderr.decode(errors="replace")))
            return json.loads(child.stdout)
        run("status", ["--logical-now", "150"])
        parent = settings["parent_context"]
        if (source / "parent.packet").is_file():
            run("submit", ["--packet", str(source / "parent.packet"),
                           "--logical-now", str(parent["consensus_time_unix_seconds"])])
        verify_args = [
            "--cell-parent", parent["parent_id"],
            "--cell-expected", str(own),
            "--cell-expected-sha256", settings["owner_admission_sha256"],
            "--cell-claim", str(source / "claim.json"),
        ]
        first = run("cell-verify-historical", verify_args)
        if (source / "successor.packet").is_file():
            run("submit", ["--packet", str(source / "successor.packet"),
                           "--logical-now", "170"])
        second = run("cell-verify-historical", verify_args)
        assert first == second
        result = first["result"]
        assert result["parent_context"] == parent
        assert result["contract_id"] == settings["contract_id"]
        assert result["computed_historical"] is True
        assert result["computed_live"] is False
        assert result["full_w1_proofs_verified"] == 5
        for flag in ("operation_consumed", "checkpoint_committed",
                     "current_owner_authorization_checked", "final_use_granted",
                     "consensus_work_admitted", "production_activation"):
            assert result[flag] is False
        entry = {
            "case": name, "claim_sha256": sha((source / "claim.json").read_bytes()),
            "owner_admission_sha256": settings["owner_admission_sha256"],
            "parent_context": parent, "state_backend": settings["state_backend"],
            "historical_receipts_identical_before_after_successor": True,
        }
        results.append(entry)
        print(json.dumps(entry, sort_keys=True), flush=True)
    summary = {
        "schema": "pon-cell-stateful-native-int257-v1/cold-retained-replay",
        "binary_sha256": sha(binary.read_bytes()),
        "cases": results, "new_proofs_generated": 0, "new_test_count": 0,
        "fixture_only": True, "production_activation": False,
    }
    create(output / "summary.json", (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode())

if __name__ == "__main__":
    main()

