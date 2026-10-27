#!/usr/bin/env python3
"""Explicit reuse of one retained real receipt for an identical rebuilt image.

This is a research observation policy, not a required acceptance waiver. An
absent policy selects original proof generation. A declared but unavailable or
mismatching prior receipt fails; it never silently starts another prover.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import urllib.request

HERE = Path(__file__).resolve().parent
REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
REQUIRED_FILES = frozenset({"receipt.bin", "input.bin", "guest.raw.elf", "guest.bin",
    "backend-manifest.json", "source-before.json", "source-after.json",
    "prove.stdout.log", "prove.process.json", "verify.stdout.log", "verify.process.json",
    "audit.stdout.log", "audit.process.json", "checked-observation.json"})


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink(), f"regular artifact file required: {path.name}")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read(path):
    require(path.stat().st_size <= 8 * 1024**2, "JSON observation exceeds cap")
    return json.loads(path.read_text())


def policy():
    path = HERE / "receipt-reuse.json"
    if not path.exists():
        return None
    value = read(path)
    require(value["schema"] == "pon-w1-exact-image-receipt-reuse-v1", "unsupported reuse policy")
    require(value["repository"] == REPOSITORY, "foreign receipt repository")
    require(re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]) is not None, "exact prior source required")
    for key in ["workflow_run_id", "workflow_run_attempt", "artifact_id"]:
        require(type(value[key]) is int and value[key] > 0, f"positive exact {key} required")
    require(value["artifact_name"] == f'complete-w1-real-proof-{value["source_commit"]}-{value["workflow_run_attempt"]}',
            "unexpected prior artifact name")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", value["github_artifact_digest"]) is not None,
            "actual GitHub artifact digest required")
    require(set(value["files"]) == REQUIRED_FILES, "incomplete or extra reuse file inventory")
    for name, item in value["files"].items():
        require(type(item["bytes"]) is int and 0 < item["bytes"] <= 128 * 1024**2,
                f"invalid pinned artifact size: {name}")
        require(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
                f"exact artifact SHA-256 required: {name}")
    require(digest(HERE / "backend-manifest.json") == value["files"]["backend-manifest.json"]["sha256"],
            "current backend profile differs from declared prior proof; review a new proof attempt")
    require(value["new_proof_generated"] is False and value["required_acceptance_waived"] is False,
            "reuse is neither proof generation nor acceptance waiver")
    return value


def verify_github_provenance(selected):
    token = os.environ.get("GH_TOKEN")
    require(token, "read-only GitHub Actions token required to verify the declared original artifact")

    def get(suffix):
        url = f"https://api.github.com/repos/{REPOSITORY}/actions/{suffix}"
        request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "GitHub metadata exceeds cap")
        return json.loads(raw)

    # Pin the historical attempt itself. A later rerun of the same workflow ID
    # must not silently replace the reviewed proof's source or measured cost.
    run = get(f'runs/{selected["workflow_run_id"]}/attempts/{selected["workflow_run_attempt"]}')
    artifact = get(f'artifacts/{selected["artifact_id"]}')
    require(run["id"] == selected["workflow_run_id"]
            and run["head_sha"] == selected["source_commit"]
            and run["run_attempt"] == selected["workflow_run_attempt"]
            and run["path"] == ".github/workflows/pon-complete-w1-proof-research.yml"
            and run["status"] == "completed" and run["conclusion"] == "success",
            "original source/run/attempt is not the declared successful proof run")
    require(artifact["id"] == selected["artifact_id"]
            and artifact["name"] == selected["artifact_name"]
            and artifact["workflow_run"]["id"] == selected["workflow_run_id"]
            and artifact["digest"] == selected["github_artifact_digest"]
            and artifact["expired"] is False, "GitHub artifact provenance differs")


def prepare(out):
    selected = policy()
    require(selected is not None, "no declared prior receipt")
    prior = out / "prior-proof"
    for name, item in selected["files"].items():
        path = prior / name
        require(path.stat().st_size == item["bytes"] and digest(path) == item["sha256"],
                f"prior artifact differs from reviewed bytes: {name}")
    # The original workflow rebuilt these files before this step. Reusing old
    # executables, changing the witness, or changing the guest is not permitted.
    for name in ["guest.raw.elf", "guest.bin", "input.bin", "backend-manifest.json"]:
        require(digest(out / name) == selected["files"][name]["sha256"],
                f"newly rebuilt current input/image differs: {name}")
    for name in ["source-before.json", "source-after.json"]:
        source = read(prior / name)
        require(source["tested_commit"] == selected["source_commit"], "prior source identity mismatch")
    for name in ["prove", "verify", "audit"]:
        process = read(prior / f"{name}.process.json")
        require(process["returncode"] == 0 and process["timed_out"] is False,
                f"original {name} did not complete successfully")
        require(process["source_sha"] == selected["source_commit"], "prior process source mismatch")
    checked = read(prior / "checked-observation.json")
    require(checked["real_proof_verified"] is True, "prior run has no checked real proof")
    with (prior / "receipt.bin").open("rb") as source, (out / "receipt.bin").open("xb") as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
        target.flush()
        os.fsync(target.fileno())
    require(digest(out / "receipt.bin") == selected["files"]["receipt.bin"]["sha256"], "copied receipt changed")
    result = {"schema": "pon-w1-reused-receipt-observation-v1", "policy": selected,
        "current_source_sha": os.environ.get("TRNM_EXPECTED_SOURCE_SHA"),
        "current_workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "current_workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "new_guest_raw_elf_and_program_and_input_identical": True,
        "proof_generated_in_current_run": False,
        "current_cryptographic_verification_completed": False,
        "prior_prover_cost_is_current_runner_measurement": False,
        "required_acceptance_waived": False, "consensus_authority": False}
    with (out / "receipt-reuse-observation.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["select", "prepare"])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.operation == "prepare":
        require(args.out is not None, "explicit observation directory required")
        print(json.dumps(prepare(args.out)))
        return
    selected = policy()
    result = {"mode": "reuse" if selected else "generate", "run_id": "", "artifact_id": ""}
    if selected:
        verify_github_provenance(selected)
        result.update(run_id=str(selected["workflow_run_id"]), artifact_id=str(selected["artifact_id"]))
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf8") as stream:
            for key, value in result.items():
                stream.write(f"{key}={value}\n")
    print(json.dumps({**result, "required_acceptance_waived": False}))


if __name__ == "__main__":
    main()
