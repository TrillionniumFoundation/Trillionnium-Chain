#!/usr/bin/env python3
"""Reverify a real native campaign and every original fleet signed artifact.

The output is candidate evidence. It does not attest host identity, clock
accuracy, peak throughput, fault coverage, A-tier completion or production.
"""
from __future__ import annotations
import argparse
import hashlib
import pathlib
import tempfile
import native_client_campaign_v1 as campaign
import run_consensus_fleet as runner
import run_network_smoke_fleet as base


def verify(*, coordinator: pathlib.Path, deployments: pathlib.Path, output: pathlib.Path,
           binary: pathlib.Path, anchor: str) -> dict:
    coordinator = coordinator.resolve(strict=True)
    deployments = deployments.resolve(strict=True)
    output = output.resolve(strict=True)
    snapshot = runner.checked_coordinator_anchor(coordinator, anchor)
    manifest, _topology, processes = base.load_contract(coordinator, deployments, 7)
    from check_run_material import application_public_paths_v1
    if application_public_paths_v1(manifest) != ("public/native-client-profile.json",):
        raise RuntimeError("checker requires manifest-selected native application")
    binary = base.require_binary(binary, manifest["candidate"]["linux_x86_64_sha256"], "native verifier")
    runner.validate_runner_output_manifest(output, expected_run_id=manifest["run_id"], expected_validator_count=7, expected_coordinator_anchor=anchor)
    summary = base.read_json(output / "consensus-run-summary.json", "runner summary")
    if summary["failure"] is not None or summary["cleanup_failures"] or len(summary["processes"]) != 7 or summary["terminal_agreement"] is None:
        raise RuntimeError("native campaign lacks a successful original fleet artifact chain")
    plan = base.read_json(output / "prestart-plan.json", "plan")
    document = base.read_json(output / campaign.ARTIFACT, "native campaign")
    campaign.validate_document(document, run_id=manifest["run_id"], anchor=anchor, validator_ids={p.validator_id for p in processes})
    profile_bytes = (coordinator / "public/native-client-profile.json").read_bytes()
    digest = hashlib.sha256(profile_bytes).hexdigest()
    if document["profile_sha256"] != digest:
        raise RuntimeError("native campaign profile does not match manifest")
    profile = campaign.strict_json(profile_bytes, "native profile")
    operator = next(s for s in profile["signers"] if s["signer_role"] == "operator")["signer_id"]
    client = next(s for s in profile["signers"] if s["signer_role"] == "hepta")["signer_id"]
    observer = deployments / "observer-public"
    def run(command: list[str]) -> dict:
        return campaign.strict_json(base.run_checked([str(binary), *command], timeout=90).stdout, "independent verifier output")
    artifact_sets = 0
    for process in processes:
        common = [str(observer), str(observer / process.config_relative)]
        for command, directory, suffix in (
            ("verify-consensus-report", "signed-reports", ".json"),
            ("verify-runtime-journal", "signed-runtime-journals", ".jsonl"),
            ("verify-runtime-metrics", "signed-runtime-metrics", ".json"),
            ("verify-runtime-final-state", "signed-runtime-final-states", ".json"),
        ):
            run([command, *common, str(output / directory / (process.validator_id + suffix)), anchor])
        run(["verify-fleet-start-certificate", *common, str(output / "fleet-start-certificates" / (process.validator_id + ".bin")), anchor, str(plan["duration_seconds"]), str(plan["max_blocks"])])
        archive_paths = [str(output / directory / (process.validator_id + suffix)) for directory, suffix in (
            ("signed-replay-archive-contexts", ".json"), ("signed-replay-archive-entries", ".jsonl"), ("signed-replay-archive-heads", ".json"), ("signed-replay-archive-terminal-seals", ".json"))]
        run(["verify-replay-archive", *common, *archive_paths, anchor])
        artifact_sets += 1
    selected = next(p for p in processes if p.validator_id == document["submit_validator_id"])
    with tempfile.TemporaryDirectory(prefix="trnm-native-reverify-") as temporary:
        scratch = pathlib.Path(temporary)
        for index, record in enumerate(document["records"]):
            outer = bytes.fromhex(record["outer_hex"])
            envelope = campaign.strict_json(outer, "signed native body")
            inner = campaign.strict_json(bytes.fromhex(envelope["payload_hex"]), "native transaction")
            expected = {"type": "credit_account", "account": client, "amount": "1000000"} if index == 0 else {"type": "transfer", "to": operator, "amount": "1"}
            if inner["command"] != expected or inner["sender"] != (operator if index == 0 else client) or inner["nonce"] != (1 if index == 0 else index):
                raise RuntimeError("native goodput counts a different business operation")
            response = scratch / f"response-{index}.json"
            exact = scratch / f"outer-{index}.json"
            base.write_new(response, base.canonical_json(record["proof_response"]))
            base.write_new(exact, outer)
            verified = run(["native-client", "verify", str(observer), str(selected.config_relative), anchor, str(response), record["native_tx_hash"], str(exact), digest])
            if verified != record["mac_verification"]:
                raise RuntimeError("offline native proof result differs from Mac verification")
    runner.verify_coordinator_anchor(snapshot)
    runner.validate_runner_output_manifest(output, expected_run_id=manifest["run_id"], expected_validator_count=7, expected_coordinator_anchor=anchor)
    return {"native_candidate_evidence": "passed", "validator_artifact_sets_reverified": artifact_sets, "actual_unique_transfers_verified": document["business_transfer_count"], "actual_funding_verified": 1, "observed_business_goodput_per_second": document["business_goodput_per_second"], "goodput_scope": "sequential SSH and private IPC campaign including proof verification latency", "host_attestation": False, "fault_matrix_completed": False, "performance_acceptance": False, "a_tier_completion": False, "m05_intent_binding": False, "production_activation": False}


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("coordinator", "deployments", "output", "binary"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    parser.add_argument("--anchor", required=True)
    args = parser.parse_args()
    print(base.canonical_json(verify(**vars(args))).decode(), end="")

if __name__ == "__main__":
    main()
