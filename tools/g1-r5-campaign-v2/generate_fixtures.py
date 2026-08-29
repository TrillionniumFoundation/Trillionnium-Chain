#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from typing import Any


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def hash_label(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def pop(validator_id: str, public_key: str) -> str:
    return hashlib.sha256(
        b"trnm.g1-r5.validator-pop.v2\0"
        + bytes.fromhex(validator_id)
        + bytes.fromhex(public_key)
    ).hexdigest()


def build(source: dict[str, Any], campaign: dict[str, Any]) -> dict[str, Any]:
    count = campaign["validator_count"]
    powers = campaign["voting_powers"]
    regions = campaign["regions"]
    validators = []
    for index, power in enumerate(powers, 1):
        validator_id = hash_label(f"validator-{count}-{index}")
        public_key = hash_label(f"pubkey-{count}-{index}")
        validators.append(
            {
                "validator_id": validator_id,
                "public_key": public_key,
                "proof_of_possession": pop(validator_id, public_key),
                "voting_power": power,
                "process_id": f"v{count}-process-{index}",
                "host_id": f"v{count}-host-{index}",
                "operator_id": f"v{count}-operator-{index}",
                "custody_domain": f"v{count}-custody-{index}",
                "region_id": regions[(index - 1) % len(regions)],
            }
        )
    topology = {"validators": validators}
    topology["topology_counts"] = {
        "validators": count,
        "processes": count,
        "hosts": count,
        "operators": count,
        "custody_domains": count,
        "regions": len(set(regions)),
    }
    total = sum(powers)
    topology["total_voting_power"] = total
    topology["quorum_voting_power"] = 2 * total // 3 + 1
    workload = {
        "transport": "authenticated-bounded-p2p",
        "duration_seconds": 900,
        "max_inflight_per_peer": 64,
        "operation_mix": [
            {"operation": "proposal-vote-finality", "weight": 55},
            {"operation": "payload-replay", "weight": 15},
            {"operation": "state-sync-readback", "weight": 15},
            {"operation": "epoch-key-rotation", "weight": 15},
        ],
    }
    common = [
        "normal-finality",
        "minority-offline-rejoin",
        "leader-crash-timeout-certificate",
        "restart-catch-up",
        "trusted-checkpoint-state-sync",
        "epoch-key-rotation",
        "signer-outage-recovery",
        "disk-full-io-fault",
        "commit-response-loss",
    ]
    count_specific = (
        [
            "partition-3-1-progress",
            "partition-2-2-safe-stall",
            "partition-heal-convergence",
        ]
        if count == 4
        else [
            "partition-5-2-progress",
            "partition-weighted-minority-safe-stall",
            "partition-heal-convergence",
        ]
    )
    faults = {
        "scenarios": [
            {
                "id": scenario,
                "trigger": {
                    "after_committed_height": 10 + position,
                    "fault": scenario,
                },
                "expected": {
                    "conflicting_finality": False,
                    "double_sign": False,
                    "root_divergence": False,
                    "progress_or_safe_stall": "safe-by-scenario",
                },
            }
            for position, scenario in enumerate(common + count_specific)
        ]
    }
    identity = {
        "source_commit": source["source_commit"],
        "source_tree": source["source_tree"],
        "binary_sha256": hash_label(f"unbuilt-binary-{count}"),
        "sbom_sha256": hash_label(f"unbuilt-sbom-{count}"),
        "genesis_sha256": hash_label(f"harness-genesis-{count}"),
        "topology_sha256": digest({"validators": validators}),
        "workload_sha256": digest(workload),
        "fault_schedule_sha256": digest(faults),
        "binary_built": False,
    }
    return {
        "schema": "trnm-g1-r5-native-campaign-v2",
        "campaign_id": f"g1-r5-{count}-validator-candidate-v2",
        "validator_count": count,
        "identity": identity,
        "topology": topology,
        "workload": workload,
        "fault_schedule": faults,
        "execution_gate": {
            "campaign_execution_authorized": False,
            "g1_r4_evidence": {
                "status": "missing",
                "g1_r4_exit": False,
                "independent_review_accepted": False,
                "source_commit": None,
                "source_tree": None,
                "evidence_root": None,
                "reviewer_ids": [],
            },
        },
        "non_claims": {
            "g1_r5_exit": False,
            "validator_run_completed": False,
            "network_evidence_accepted": False,
            "production_candidate": False,
            "production_consensus_activation": False,
            "release_ready": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(args.source.read_text())
    if source.get("schema") != "trnm-g1-r5-fixture-source-v2":
        raise SystemExit("invalid fixture source schema")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for campaign in source["campaigns"]:
        value = build(source, campaign)
        path = args.output_dir / f"g1-r5-{campaign['validator_count']}-validator-v2.json"
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
