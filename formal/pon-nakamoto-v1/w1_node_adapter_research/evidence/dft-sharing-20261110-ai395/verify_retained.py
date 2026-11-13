#!/usr/bin/env python3
"""Verify retained bytes and original receiver decisions; no execution attestation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile


BASE_INPUT_COMMIT = "9133a2218890cfca837df34e7d6b892cec780868"
INPUT_PREFIX = "formal/pon-nakamoto-v1/w1_node_adapter_research/fixtures/node-input-v1/"
INPUT_NAMES = {"packet.bin", "statement.bin", "sha.proof.bin", "arith.proof.bin", "operator-plan.json"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--evidence", type=Path, default=Path(__file__).resolve().parent)
    args = p.parse_args()
    evidence = args.evidence.resolve(strict=True)
    summary = json.loads((evidence / "manifest.json").read_text())
    archive = evidence / "records.tar.gz"
    require(archive.stat().st_size == summary["archive_bytes"], "archive byte length mismatch")
    require(sha(archive.read_bytes()) == summary["archive_sha256"], "archive digest mismatch")
    index_bytes = (evidence / "index.json").read_bytes()
    require(len(index_bytes) == summary["index_bytes"]
            and sha(index_bytes) == summary["index_sha256"], "index binding mismatch")
    index = json.loads(index_bytes)
    objects = {}
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            require(member.isfile() and member.name.startswith("objects/"),
                    "unsupported archive member")
            require(member.name not in objects, "duplicate archive member")
            data = tar.extractfile(member).read()
            require(member.name == "objects/" + sha(data), "content-addressed object mismatch")
            objects[member.name] = data
    require(len(objects) == summary["unique_objects"], "unique-object count mismatch")
    fixed, files = {}, {}
    for name, row in index["entries"].items():
        if "fixed_git_input" in row:
            ref = row["fixed_git_input"]
            require(ref["commit"] == BASE_INPUT_COMMIT, "unexpected immutable input commit")
            require(ref["path"] in {INPUT_PREFIX + name for name in INPUT_NAMES},
                    "unexpected immutable fixture path")
            key = ref["commit"] + ":" + ref["path"]
            if key not in fixed:
                data = subprocess.check_output(["git", "show", key], cwd=args.repo)
                blob = subprocess.check_output(["git", "rev-parse", key], cwd=args.repo, text=True).strip()
                require(blob == ref["git_blob"], "immutable Git object mismatch")
                fixed[key] = data
            data = fixed[key]
        else:
            data = objects[row["object"]]
        require(len(data) == row["bytes"] and sha(data) == row["sha256"],
                "retained file binding mismatch: " + name)
        files[name] = data
    require(len(files) == summary["retained_files"], "retained-file count mismatch")
    reader_path = args.repo / "formal/pon-nakamoto-v1/w1_node_adapter_research/run_receiver_comparison.py"
    spec = importlib.util.spec_from_file_location("receiver_reader", reader_path)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)

    def check_raw_measurement(location, measurement):
        for stream, basename in (("stdout", "stdout.jsonl"), ("stderr", "stderr.txt")):
            data = files[location + basename]
            require(len(data) == measurement[stream]["bytes"]
                    and sha(data) == measurement[stream]["sha256"],
                    "measurement raw stream differs: " + location + basename)
        lines = [line for line in files[location + "stdout.jsonl"].decode().splitlines()
                 if line.strip()]
        require(bool(lines), "measurement stdout has no terminal record")
        require(reader.strict_json(lines[-1]) == measurement["receipt"],
                "embedded receipt differs from retained stdout")

    attempts, owner_measurements, outcomes, errors = 0, 0, [], []
    for index_number, arm in enumerate("ABBA"):
        prefix = "receiver-experiment/" + str(index_number) + "-" + arm + "/"
        raw = files[prefix + "manifest.json"]
        manifest = reader.strict_json(raw.decode())
        saved = reader.strict_json(files[prefix + "summary.json"].decode())
        require(saved["manifest_sha256"] == sha(raw), "receiver manifest digest mismatch")
        require({k: v for k, v in saved.items() if k != "manifest_sha256"}
                == reader.summarize(manifest), "original reader decision mismatch")
        outcomes.append(saved["local_receiver_comparison"])
        for row in manifest["receivers"]:
            require(not reader.validate_receiver(row, manifest["plan"]),
                    "receiver semantic validation failed")
            attempts += 1
            location = prefix + "process-%02d-%s/" % (row["index"], row["variant"])
            m = row["measurement"]
            require(m["cpu_seconds"] == m["user_seconds"] + m["system_seconds"],
                    "receiver CPU total mismatch")
            check_raw_measurement(location, m)
        for key, directory in (("owner_init", "owner-init/"), ("owner_status", "owner-status/")):
            check_raw_measurement(prefix + directory, manifest[key])
            owner_measurements += 1
        errors.extend(saved["errors"])
    require(attempts == 32 and owner_measurements == 8,
            "all receiver and owner process measurements are required")
    print(json.dumps({"retained_files_verified": len(files), "unique_objects_verified": len(objects),
        "fixed_git_inputs_used": len(fixed), "receiver_attempts_recomputed": attempts,
        "owner_measurements_checked": owner_measurements,
        "original_comparator_outcomes": outcomes, "original_errors_retained": len(errors),
        "execution_authenticated": False, "qualified_improvement": None,
        "production_activation": False, "qualification": "HOLD_NO_GO"}))


if __name__ == "__main__":
    main()
