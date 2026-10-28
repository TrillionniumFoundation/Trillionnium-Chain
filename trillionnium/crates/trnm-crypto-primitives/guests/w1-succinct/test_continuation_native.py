#!/usr/bin/env python3
"""Actual retained-range positives/negatives, plus every original native control."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import continuation as c


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(); root = args.out / "native-controls"; root.mkdir()
    subprocess.run([sys.executable, str(c.HERE / "test_native.py"), "--helper", str(args.helper),
                    "--original", str(args.out / "original"), "--out", str(root / "original")], check=True)
    prior = c.inspect_prior(args.out / "prior")
    original = args.out / "original/receipt.bin"
    retained = args.out / "prior/recursion/receipts/range-0-1.bin"
    rows = []
    for case in ("actual_retained", "wrong_range", "changed_seal", "trailing_byte", "symlink", "fifo"):
        with tempfile.TemporaryDirectory(prefix="range-negative-", dir=root) as temporary:
            directory = Path(temporary); candidate = directory / "range.bin"
            a, b = (1, 2) if case == "wrong_range" else (0, 1)
            if case == "symlink":
                candidate.symlink_to(retained)
            elif case == "fifo":
                os.mkfifo(candidate)
            else:
                raw = bytearray(retained.read_bytes())
                if case == "changed_seal":
                    raw[100] ^= 1
                elif case == "trailing_byte":
                    raw.append(0)
                candidate.write_bytes(raw)
            command = [str(args.helper), "verify-range", str(original), str(a), str(b), str(candidate)]
            started = time.monotonic()
            child = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            (root / (case + ".stdout.log")).write_bytes(child.stdout)
            (root / (case + ".stderr.log")).write_bytes(child.stderr)
            row = {"case": case, "returncode": child.returncode, "wall_seconds": time.monotonic() - started,
                   "command": command, "actual_native_execution": True, "new_proof_generated": False}
            if case not in ("symlink", "fifo"):
                row["candidate"] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            rows.append(row)
            c.r.require(child.returncode == (0 if case == "actual_retained" else 1), "actual native range control: " + case)
            if case == "actual_retained":
                result = c.r.strict_json(child.stdout)
                c.retained_result(result, c.BY_NAME["lift-0-1"], prior["stages"]["lift-0-1"]["native"])
    result = {"schema": "pon-w1-succinct-resume-native-controls-v1", "retained_original_controls": 10,
              "new_range_controls": rows, "new_range_passes": 6, "skipped": 0, "proofs_generated": 0}
    c.r.write(root / "result.json", result); print(c.r.json.dumps(result))


if __name__ == "__main__":
    main()
