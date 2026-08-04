#!/usr/bin/env python3
"""Validate and independently encode the PoCO-BFT v0 reference parameters."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib


HASH_PREFIX = b"trnm.cev0.hash.v0"
PARAMETERS_DOMAIN = b"trnm.poco-bft.parameters.v0"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PARAMETERS = REPO_ROOT / "docs/protocol/poco-bft-v0/parameters.toml"
DEFAULT_VECTOR = (
    REPO_ROOT / "docs/protocol/poco-bft-v0/vectors/parameters-v0.json"
)


class ParameterError(ValueError):
    pass


def unsigned(value: object, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParameterError(f"{name} must be an unsigned u{bits} integer")
    if value < 0 or value >= 1 << bits:
        raise ParameterError(f"{name} is outside u{bits}")
    return value


def boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ParameterError(f"{name} must be a boolean")
    return value


def encode_uint(value: object, bits: int, name: str) -> bytes:
    return unsigned(value, bits, name).to_bytes(bits // 8, "big")


def encode_bool(value: object, name: str) -> bytes:
    return b"\x01" if boolean(value, name) else b"\x00"


def frame(value: bytes) -> bytes:
    if len(value) >= 1 << 32:
        raise ParameterError("CEV0 frame exceeds u32 length")
    return len(value).to_bytes(4, "big") + value


def digest(domain: bytes, encoded: bytes) -> bytes:
    return hashlib.sha256(frame(HASH_PREFIX) + frame(domain) + frame(encoded)).digest()


def load_parameters(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)


def table(document: dict[str, object], key: str) -> dict[str, object]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise ParameterError(f"missing table [{key}]")
    return value


def encode_parameters(document: dict[str, object]) -> bytes:
    encoding = table(document, "encoding")
    consensus = table(document, "consensus")
    epoch = table(document, "epoch")
    weights = table(document, "weights")
    rollout = table(document, "rollout")
    accountability = table(document, "accountability")
    light_client = table(document, "light_client")

    if document.get("schema") != "trnm_poco_bft_parameters_v0":
        raise ParameterError("unexpected parameter schema")
    if document.get("profile") != "p0-reference-shadow-only":
        raise ParameterError("unexpected reference profile")
    if encoding.get("canonical_codec") != "CEV0":
        raise ParameterError("canonical codec must be CEV0")
    if encoding.get("hash_algorithm") != "sha256":
        raise ParameterError("hash algorithm must be sha256")
    if encoding.get("signature_scheme") != "ed25519":
        raise ParameterError("signature scheme must be ed25519")
    if weights.get("arithmetic") != "checked-u128-floor":
        raise ParameterError("weight arithmetic must be checked-u128-floor")

    leader_schedules = {"canonical-validator-round-robin": 0}
    rollout_phases = {
        "shadow": 0,
        "eligibility-only": 1,
        "capped-weight": 2,
        "full": 3,
    }
    try:
        leader_schedule = leader_schedules[str(consensus["leader_schedule"])]
        rollout_phase = rollout_phases[str(rollout["current_phase"])]
    except (KeyError, TypeError) as error:
        raise ParameterError("unknown consensus enum value") from error

    parts = [
        encode_uint(0, 16, "schema_version"),
        encode_uint(document.get("protocol_version"), 32, "protocol_version"),
        encode_bool(document.get("production_activation"), "production_activation"),
        encode_uint(encoding.get("max_chain_id_bytes"), 16, "max_chain_id_bytes"),
        encode_uint(encoding.get("max_validator_id_bytes"), 16, "max_validator_id_bytes"),
        encode_uint(encoding.get("max_block_bytes"), 32, "max_block_bytes"),
        encode_uint(
            encoding.get("max_consensus_message_bytes"),
            32,
            "max_consensus_message_bytes",
        ),
        encode_uint(consensus.get("min_validators"), 32, "min_validators"),
        encode_uint(consensus.get("max_validators"), 32, "max_validators"),
        encode_uint(consensus.get("quorum_numerator"), 32, "quorum_numerator"),
        encode_uint(consensus.get("quorum_denominator"), 32, "quorum_denominator"),
        encode_uint(consensus.get("quorum_addend"), 32, "quorum_addend"),
        encode_uint(
            consensus.get("finality_certified_chain_length"),
            8,
            "finality_certified_chain_length",
        ),
        encode_uint(
            consensus.get("max_total_voting_power"), 64, "max_total_voting_power"
        ),
        encode_uint(
            consensus.get("max_block_time_step_ms"), 64, "max_block_time_step_ms"
        ),
        encode_uint(leader_schedule, 8, "leader_schedule"),
        encode_bool(
            consensus.get("require_full_payload_before_vote"),
            "require_full_payload_before_vote",
        ),
        encode_uint(consensus.get("base_timeout_ms"), 64, "base_timeout_ms"),
        encode_uint(
            consensus.get("timeout_multiplier_numerator"),
            32,
            "timeout_multiplier_numerator",
        ),
        encode_uint(
            consensus.get("timeout_multiplier_denominator"),
            32,
            "timeout_multiplier_denominator",
        ),
        encode_uint(consensus.get("timeout_max_ms"), 64, "timeout_max_ms"),
        encode_uint(epoch.get("length_blocks"), 64, "epoch_length_blocks"),
        encode_uint(epoch.get("seal_blocks"), 8, "epoch_seal_blocks"),
        encode_uint(epoch.get("snapshot_lead_blocks"), 64, "snapshot_lead_blocks"),
        encode_bool(
            epoch.get("joint_handoff_old_quorum"), "joint_handoff_old_quorum"
        ),
        encode_bool(
            epoch.get("joint_handoff_new_quorum"), "joint_handoff_new_quorum"
        ),
        encode_uint(epoch.get("upgrade_notice_epochs"), 64, "upgrade_notice_epochs"),
        encode_uint(
            epoch.get("max_protocol_version_jump"), 32, "max_protocol_version_jump"
        ),
        encode_uint(weights.get("scale_ppm"), 64, "scale_ppm"),
        encode_uint(weights.get("maturity_epochs"), 64, "maturity_epochs"),
        encode_uint(
            weights.get("max_certificate_age_epochs"),
            64,
            "max_certificate_age_epochs",
        ),
        encode_uint(
            weights.get("decay_step_ppm_per_epoch"),
            64,
            "decay_step_ppm_per_epoch",
        ),
        encode_uint(
            weights.get("per_certificate_unit_cap"), 128, "per_certificate_unit_cap"
        ),
        encode_uint(
            weights.get("per_consumer_provider_epoch_unit_cap"),
            128,
            "per_consumer_provider_epoch_unit_cap",
        ),
        encode_uint(
            weights.get("per_task_provider_epoch_unit_cap"),
            128,
            "per_task_provider_epoch_unit_cap",
        ),
        encode_uint(
            weights.get("per_provider_epoch_unit_cap"),
            128,
            "per_provider_epoch_unit_cap",
        ),
        encode_uint(weights.get("units_per_power"), 128, "units_per_power"),
        encode_uint(
            weights.get("bond_atomic_units_per_power"),
            128,
            "bond_atomic_units_per_power",
        ),
        encode_uint(weights.get("min_validator_power"), 64, "min_validator_power"),
        encode_uint(weights.get("max_validator_power"), 64, "max_validator_power"),
        encode_uint(
            weights.get("max_validator_share_ppm"), 64, "max_validator_share_ppm"
        ),
        encode_uint(
            weights.get("capped_weight_alpha_ppm"),
            64,
            "capped_weight_alpha_ppm",
        ),
        encode_uint(
            weights.get("full_weight_alpha_ppm"), 64, "full_weight_alpha_ppm"
        ),
        encode_uint(rollout_phase, 8, "rollout_phase"),
        encode_uint(
            rollout.get("minimum_shadow_epochs"), 64, "minimum_shadow_epochs"
        ),
        encode_uint(
            rollout.get("minimum_eligibility_only_epochs"),
            64,
            "minimum_eligibility_only_epochs",
        ),
        encode_uint(
            rollout.get("minimum_capped_weight_epochs"),
            64,
            "minimum_capped_weight_epochs",
        ),
        encode_bool(rollout.get("automatic_promotion"), "automatic_promotion"),
        encode_uint(
            accountability.get("evidence_window_epochs"),
            64,
            "evidence_window_epochs",
        ),
        encode_uint(
            accountability.get("unbonding_delay_epochs"),
            64,
            "unbonding_delay_epochs",
        ),
        encode_uint(
            accountability.get("jail_duration_epochs"), 64, "jail_duration_epochs"
        ),
        encode_uint(
            light_client.get("trusting_period_epochs"),
            64,
            "trusting_period_epochs",
        ),
        encode_bool(
            light_client.get("require_trusting_period_less_than_evidence_window"),
            "require_trusting_period_less_than_evidence",
        ),
        encode_bool(
            light_client.get(
                "require_evidence_window_not_greater_than_unbonding_delay"
            ),
            "require_evidence_window_le_unbonding_delay",
        ),
    ]
    return b"".join(parts)


def validate_semantics(document: dict[str, object]) -> None:
    encoding = table(document, "encoding")
    consensus = table(document, "consensus")
    epoch = table(document, "epoch")
    weights = table(document, "weights")
    rollout = table(document, "rollout")
    accountability = table(document, "accountability")
    light_client = table(document, "light_client")

    if document.get("protocol_version") != 0:
        raise ParameterError("the v0 freeze requires protocol_version = 0")
    if document.get("production_activation") is not False:
        raise ParameterError("the reference profile must remain non-production")
    if encoding.get("hash_bytes") != 32 or encoding.get("public_key_bytes") != 32:
        raise ParameterError("v0 hashes and Ed25519 public keys must be 32 bytes")
    if encoding.get("signature_bytes") != 64:
        raise ParameterError("v0 Ed25519 signatures must be 64 bytes")
    if consensus.get("genesis_height") != 0:
        raise ParameterError("synthetic genesis height must be 0")
    if consensus.get("first_block_height") != 1 or consensus.get("first_view") != 1:
        raise ParameterError("the first non-genesis block and view must be 1")
    if (
        consensus.get("quorum_numerator"),
        consensus.get("quorum_denominator"),
        consensus.get("quorum_addend"),
    ) != (2, 3, 1):
        raise ParameterError("v0 quorum must be floor(2W/3)+1")
    if consensus.get("finality_certified_chain_length") != 3:
        raise ParameterError("v0 finality requires a direct three-certified-block chain")

    minimum = unsigned(consensus.get("min_validators"), 32, "min_validators")
    maximum = unsigned(consensus.get("max_validators"), 32, "max_validators")
    if not 4 <= minimum <= maximum:
        raise ParameterError("validator bounds are inconsistent")
    if unsigned(consensus.get("timeout_multiplier_denominator"), 32, "timeout denominator") == 0:
        raise ParameterError("timeout multiplier denominator must be positive")
    if consensus.get("timeout_multiplier_numerator") <= consensus.get(
        "timeout_multiplier_denominator"
    ):
        raise ParameterError("timeout multiplier must grow")
    if consensus.get("base_timeout_ms") > consensus.get("timeout_max_ms"):
        raise ParameterError("base timeout exceeds timeout maximum")
    if consensus.get("max_block_bytes") is not None:
        raise ParameterError("max_block_bytes belongs only to [encoding]")

    if epoch.get("seal_blocks") != 2:
        raise ParameterError("v0 requires exactly two epoch seal blocks")
    if epoch.get("length_blocks") <= epoch.get("snapshot_lead_blocks") + epoch.get(
        "seal_blocks"
    ):
        raise ParameterError("epoch is too short for snapshot/checkpoint/seal layout")
    if epoch.get("joint_handoff_old_quorum") is not True or epoch.get(
        "joint_handoff_new_quorum"
    ) is not True:
        raise ParameterError("v0 handoff requires both old and new quorums")
    if epoch.get("upgrade_notice_epochs") < 1:
        raise ParameterError("upgrade notice must span at least one epoch")
    if epoch.get("max_protocol_version_jump") != 1:
        raise ParameterError("v0 permits only a one-version jump")

    scale = unsigned(weights.get("scale_ppm"), 64, "scale_ppm")
    if scale == 0:
        raise ParameterError("scale_ppm must be positive")
    caps = [
        unsigned(weights.get("per_certificate_unit_cap"), 128, "certificate cap"),
        unsigned(
            weights.get("per_consumer_provider_epoch_unit_cap"), 128, "consumer cap"
        ),
        unsigned(weights.get("per_task_provider_epoch_unit_cap"), 128, "task cap"),
        unsigned(weights.get("per_provider_epoch_unit_cap"), 128, "provider cap"),
    ]
    if caps != sorted(caps) or caps[0] == 0:
        raise ParameterError("hierarchical unit caps must be positive and nondecreasing")
    if weights.get("units_per_power") <= 0 or weights.get(
        "bond_atomic_units_per_power"
    ) <= 0:
        raise ParameterError("capacity divisors must be positive")
    if not 0 < weights.get("min_validator_power") <= weights.get(
        "max_validator_power"
    ):
        raise ParameterError("validator power bounds are inconsistent")
    if not 0 < weights.get("max_validator_share_ppm") < scale // 3:
        raise ParameterError("validator share cap must be positive and below one third")
    if not 0 <= weights.get("capped_weight_alpha_ppm") <= scale:
        raise ParameterError("capped alpha is outside the ppm scale")
    if weights.get("full_weight_alpha_ppm") != scale:
        raise ParameterError("full rollout alpha must equal scale_ppm")
    max_candidate_power = maximum * weights.get("max_validator_power")
    if max_candidate_power > consensus.get("max_total_voting_power"):
        raise ParameterError("candidate set can exceed max_total_voting_power")
    if rollout.get("current_phase") != "shadow":
        raise ParameterError("the reference profile must remain in shadow")
    if rollout.get("automatic_promotion") is not False:
        raise ParameterError("phase promotion must never be automatic")

    trusting = unsigned(
        light_client.get("trusting_period_epochs"), 64, "trusting_period_epochs"
    )
    evidence = unsigned(
        accountability.get("evidence_window_epochs"), 64, "evidence_window_epochs"
    )
    unbonding = unsigned(
        accountability.get("unbonding_delay_epochs"), 64, "unbonding_delay_epochs"
    )
    if not trusting < evidence <= unbonding:
        raise ParameterError(
            "required relationship is trusting_period < evidence_window <= unbonding_delay"
        )
    if light_client.get("require_trusting_period_less_than_evidence_window") is not True:
        raise ParameterError("trusting/evidence relationship must be enforced")
    if light_client.get(
        "require_evidence_window_not_greater_than_unbonding_delay"
    ) is not True:
        raise ParameterError("evidence/unbonding relationship must be enforced")


def make_vector(path: Path, document: dict[str, object]) -> dict[str, object]:
    encoded = encode_parameters(document)
    try:
        source = path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        source = path.as_posix()
    return {
        "schema": "trnm.poco-bft.parameters-vector.v0",
        "source": source,
        "domain_ascii": PARAMETERS_DOMAIN.decode("ascii"),
        "cev0_length": len(encoded),
        "cev0_hex": encoded.hex(),
        "digest_hex": digest(PARAMETERS_DOMAIN, encoded).hex(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=DEFAULT_PARAMETERS,
    )
    parser.add_argument("--expected-vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument("--emit-vector", action="store_true")
    args = parser.parse_args()

    try:
        document = load_parameters(args.path)
        vector = make_vector(args.path, document)
        validate_semantics(document)
    except (OSError, tomllib.TOMLDecodeError, ParameterError, KeyError, TypeError) as error:
        print(f"parameter check failed: {error}", file=sys.stderr)
        return 1

    if args.emit_vector:
        print(json.dumps(vector, indent=2, sort_keys=True))
    else:
        try:
            expected = json.loads(args.expected_vector.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"parameter vector check failed: {error}", file=sys.stderr)
            return 1
        if expected != vector:
            print(
                "parameter vector check failed: committed vector does not match encoding",
                file=sys.stderr,
            )
            return 1
        print(
            "[ok] PoCO-BFT v0 parameters: "
            f"{vector['cev0_length']} CEV0 bytes, digest {vector['digest_hex']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
