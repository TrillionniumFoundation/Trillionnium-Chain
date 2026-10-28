#!/usr/bin/env python3
"""Real pinned SDK checks and deliberately damaged actual receipt controls."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import time

import segment_frozen_v2 as source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir()
    policy, manifest = source.load_policy()
    files = source.original_members(policy, manifest)
    source.extract_original(files, args.out / "original")
    session_dir = args.out / "original/segmented/session"
    receipts = args.out / "original/segmented/receipts"
    _, expected = source.check_frozen_session(files, session_dir)
    claims_path = args.out / "claims.json"
    rows = []

    def execute(name, record, success, encoded=None):
        claims_path.write_bytes(encoded if encoded is not None else
            (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
        started = time.monotonic()
        result = subprocess.run([str(args.helper), str(claims_path), str(session_dir), str(receipts), "0", "26"],
            capture_output=True, timeout=300, check=False)
        (args.out / f"{name}.stdout.log").write_bytes(result.stdout)
        (args.out / f"{name}.stderr.log").write_bytes(result.stderr)
        row = {"name": name, "returncode": result.returncode, "wall_seconds": time.monotonic() - started,
               "expected_success": success, "matched": (result.returncode == 0) == success}
        rows.append(row)
        source.write_json(args.out / f"{name}.json", row)
        source.require(row["matched"], f"native frozen receipt control failed: {name}")

    execute("original-26-real-starks", expected, True)
    wrong = copy.deepcopy(expected)
    wrong["segments"][10]["post_state"] = "00" * 32
    wrong["segments"][11]["pre_state"] = "00" * 32
    execute("original-receipt-wrong-frozen-claim", wrong, False)
    for key, value in [("input", "01" * 32), ("output", "01" * 32), ("terminate_state", [0, 0, 0, 0])]:
        wrong = copy.deepcopy(expected); wrong["segments"][10][key] = value
        execute(f"changed-{key}", wrong, False)
    wrong = copy.deepcopy(expected); wrong["journal_hex"] = "00" * 228
    execute("wrong-w1-public-journal", wrong, False)
    canonical = (json.dumps(expected, indent=2, sort_keys=True) + "\n").encode()
    execute("duplicate-json-key", expected, False, canonical.replace(b'"schema":', b'"schema": "discarded", "schema":', 1))
    first = receipts / "segment-0.bin"
    original = first.read_bytes()
    changed = bytearray(original); changed[1000] ^= 1; first.write_bytes(changed)
    execute("corrupt-actual-stark-seal", expected, False)
    first.write_bytes(original + b"x")
    execute("trailing-actual-receipt-bytes", expected, False)
    first.write_bytes((receipts / "segment-1.bin").read_bytes())
    execute("reordered-actual-receipt", expected, False)
    first.unlink()
    execute("missing-actual-receipt", expected, False)
    first.write_bytes(original)
    source.write_json(args.out / "controls.json", {"schema": "pon-w1-native-frozen-controls-v2", "controls": rows,
        "real_original_receipts_verified": 26, "complete_w1_proof_verified": False,
        "additional_pow": False, "helper_sha256": source.sha(source.checked_bytes(args.helper, 64 * 1024 * 1024))})
    print(json.dumps({"controls": len(rows), "all_matched": True, "complete_w1_proof_verified": False}))


if __name__ == "__main__":
    main()
