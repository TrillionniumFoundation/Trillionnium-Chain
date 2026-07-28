#!/usr/bin/env python3
"""Build and verify local CometBFT validator-lifecycle fixtures.

The transition command reads CometBFT private-validator keys only to create the
required Ed25519 proof of possession. Private material is kept in memory and is
never written to output or included in diagnostics.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.request import urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HEX_32 = re.compile(r"^[0-9a-f]{64}$")
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class FixtureError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FixtureError(message)


def atomic_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=False)
            handle.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FixtureError(f"cannot read JSON fixture {path}") from exc


def decode_base64(value: Any, label: str) -> bytes:
    require(isinstance(value, str), f"{label} is not a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise FixtureError(f"{label} is not canonical base64") from exc


def normalize_hash(value: Any, label: str) -> str:
    require(isinstance(value, str), f"{label} is not a string")
    value = value.strip()
    if HEX_32.fullmatch(value.lower()):
        return value.lower()
    decoded = decode_base64(value, label)
    require(len(decoded) == 32, f"{label} does not encode 32 bytes")
    return decoded.hex()


def canonical_validators(value: Any) -> list[dict[str, Any]]:
    require(isinstance(value, list) and value, "validator set must be a non-empty list")
    validators: list[dict[str, Any]] = []
    keys: set[str] = set()
    for index, raw in enumerate(value):
        require(isinstance(raw, dict), f"validator {index} is not an object")
        require(
            set(raw) == {"public_key_hex", "voting_power"},
            f"validator {index} has unexpected fields",
        )
        public_key = raw["public_key_hex"]
        power = raw["voting_power"]
        require(
            isinstance(public_key, str) and HEX_32.fullmatch(public_key) is not None,
            f"validator {index} public key is not canonical lowercase Ed25519 hex",
        )
        require(public_key not in keys, f"duplicate validator public key at index {index}")
        require(
            isinstance(power, int) and not isinstance(power, bool) and power > 0,
            f"validator {index} voting power must be positive",
        )
        keys.add(public_key)
        validators.append({"public_key_hex": public_key, "voting_power": power})
    validators.sort(key=lambda validator: validator["public_key_hex"])
    return validators


def load_validators(path: Path) -> list[dict[str, Any]]:
    return canonical_validators(load_json(path))


def framed_hash(domain: str, parts: list[bytes]) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"trnm.domain.hash.v1")
    values = [domain.encode("utf-8"), *parts]
    for value in values:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.digest()


def validator_set_hash(validators: list[dict[str, Any]]) -> bytes:
    encoded = json.dumps(
        canonical_validators(validators),
        separators=(",", ":"),
        sort_keys=False,
    ).encode("utf-8")
    return framed_hash("trnm.cometbft.validator-set.v1", [encoded])


def read_comet_private_key(path: Path) -> tuple[str, Ed25519PrivateKey]:
    raw = load_json(path)
    require(isinstance(raw, dict), f"CometBFT key {path} is not an object")
    public = raw.get("pub_key")
    private = raw.get("priv_key")
    require(isinstance(public, dict), f"CometBFT key {path} has no public key")
    require(isinstance(private, dict), f"CometBFT key {path} has no private key")
    require(
        public.get("type") == "tendermint/PubKeyEd25519",
        f"CometBFT key {path} is not Ed25519",
    )
    require(
        private.get("type") == "tendermint/PrivKeyEd25519",
        f"CometBFT key {path} is not Ed25519",
    )
    expected_public = decode_base64(public.get("value"), f"{path} public key")
    private_bytes = decode_base64(private.get("value"), f"{path} private key")
    require(len(expected_public) == 32, f"CometBFT key {path} public key has wrong length")
    require(
        len(private_bytes) in (32, 64),
        f"CometBFT key {path} private key has wrong length",
    )
    signing_key = Ed25519PrivateKey.from_private_bytes(private_bytes[:32])
    derived_public = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    require(
        derived_public == expected_public,
        f"CometBFT key {path} public/private key mismatch",
    )
    return expected_public.hex(), signing_key


def public_key_from_comet_key(path: Path) -> str:
    raw = load_json(path)
    public = raw.get("pub_key") if isinstance(raw, dict) else None
    require(isinstance(public, dict), f"CometBFT key {path} has no public key")
    require(
        public.get("type") == "tendermint/PubKeyEd25519",
        f"CometBFT key {path} is not Ed25519",
    )
    value = decode_base64(public.get("value"), f"{path} public key")
    require(len(value) == 32, f"CometBFT key {path} public key has wrong length")
    return value.hex()


def command_set(args: argparse.Namespace) -> None:
    validators = [
        {"public_key_hex": public_key_from_comet_key(path), "voting_power": args.power}
        for path in args.key
    ]
    atomic_json(args.output, canonical_validators(validators))


def command_transition(args: argparse.Namespace) -> None:
    base = load_validators(args.base_set)
    target = load_validators(args.target_set)
    base_hash = validator_set_hash(base)
    target_hash = validator_set_hash(target)
    message = framed_hash(
        "trnm.validator-key-possession.v1",
        [
            args.chain_id.encode("utf-8"),
            args.transition_id.encode("utf-8"),
            base_hash,
            args.activation_height.to_bytes(8, "big"),
            target_hash,
        ],
    )
    base_keys = {validator["public_key_hex"] for validator in base}
    target_keys = {validator["public_key_hex"] for validator in target}
    required_keys = target_keys - base_keys
    proofs: dict[str, str] = {}
    for key_path in args.proof_key:
        public_key, signing_key = read_comet_private_key(key_path)
        require(public_key in required_keys, f"proof key {key_path} is not newly added")
        require(public_key not in proofs, f"duplicate proof key {key_path}")
        signature = signing_key.sign(message)
        signing_key.public_key().verify(signature, message)
        proofs[public_key] = signature.hex()
    require(
        set(proofs) == required_keys,
        "proof keys do not exactly cover newly added validator keys",
    )
    transition = {
        "schema": "trnm_validator_set_transition_v1",
        "chain_id": args.chain_id,
        "transition_id": args.transition_id,
        "base_validator_set_hash_hex": base_hash.hex(),
        "activation_height": args.activation_height,
        "target_validators": target,
        "new_validator_proofs": [
            {"public_key_hex": public_key, "signature_hex": proofs[public_key]}
            for public_key in sorted(proofs)
        ],
    }
    atomic_json(args.output, transition)


def rpc_get(rpc_url: str, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
    parsed = urlparse(rpc_url)
    require(
        parsed.scheme == "http" and parsed.hostname in LOOPBACK_HOSTS,
        "fixture RPC must use a loopback HTTP endpoint",
    )
    url = f"{rpc_url.rstrip('/')}/{endpoint}"
    if params:
        url = f"{url}?{urlencode(params)}"
    try:
        with urlopen(url, timeout=5) as response:
            payload = json.load(response)
    except Exception as exc:
        raise FixtureError(f"local RPC request failed for {endpoint}") from exc
    require(isinstance(payload, dict), f"{endpoint} response is not an object")
    require("error" not in payload, f"{endpoint} returned an RPC error")
    result = payload.get("result")
    require(isinstance(result, dict), f"{endpoint} response has no result")
    return result


def command_assert_phase(args: argparse.Namespace) -> None:
    expected = load_validators(args.expected_set)
    status = rpc_get(args.rpc_url, "status", {})
    node_info = status.get("node_info")
    sync_info = status.get("sync_info")
    require(isinstance(node_info, dict), "status has no node_info")
    require(isinstance(sync_info, dict), "status has no sync_info")
    require(node_info.get("network") == args.chain_id, "status chain ID mismatch")
    require(
        int(sync_info.get("latest_block_height", -1)) == args.height,
        "status height does not equal asserted phase height",
    )

    validator_result = rpc_get(
        args.rpc_url,
        "validators",
        {"height": args.height, "page": 1, "per_page": 100},
    )
    observed = []
    for index, validator in enumerate(validator_result.get("validators", [])):
        require(isinstance(validator, dict), f"RPC validator {index} is not an object")
        public = validator.get("pub_key")
        require(isinstance(public, dict), f"RPC validator {index} has no public key")
        require(
            public.get("type") == "tendermint/PubKeyEd25519",
            f"RPC validator {index} is not Ed25519",
        )
        key = decode_base64(public.get("value"), f"RPC validator {index} public key")
        observed.append(
            {
                "public_key_hex": key.hex(),
                "voting_power": int(validator.get("voting_power", 0)),
            }
        )
    observed = canonical_validators(observed)
    require(observed == expected, "RPC validator set differs from expected phase set")

    info = rpc_get(args.rpc_url, "abci_info", {})
    response = info.get("response")
    require(isinstance(response, dict), "ABCI info has no response")
    require(
        int(response.get("last_block_height", -1)) == args.height,
        "ABCI height does not equal asserted phase height",
    )
    abci_hash = normalize_hash(response.get("last_block_app_hash"), "ABCI app hash")

    local = load_json(args.state_path)
    require(isinstance(local, dict), "local application status is not an object")
    require(int(local.get("height", -1)) == args.height, "local app height mismatch")
    local_hash = normalize_hash(local.get("app_hash_hex"), "local app hash")
    require(local_hash == abci_hash, "local and ABCI app hashes differ")

    atomic_json(
        args.json_out,
        {
            "schema": "trnm_validator_lifecycle_phase_evidence_v1",
            "label": args.label,
            "node": args.node,
            "chain_id": args.chain_id,
            "height": args.height,
            "validator_set_hash_hex": validator_set_hash(observed).hex(),
            "validator_count": len(observed),
            "app_hash_hex": abci_hash,
        },
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    validator_set = subparsers.add_parser("validator-set")
    validator_set.add_argument("--key", type=Path, action="append", required=True)
    validator_set.add_argument("--power", type=int, default=10)
    validator_set.add_argument("--output", type=Path, required=True)
    validator_set.set_defaults(handler=command_set)

    transition = subparsers.add_parser("transition")
    transition.add_argument("--chain-id", required=True)
    transition.add_argument("--transition-id", required=True)
    transition.add_argument("--activation-height", type=int, required=True)
    transition.add_argument("--base-set", type=Path, required=True)
    transition.add_argument("--target-set", type=Path, required=True)
    transition.add_argument("--proof-key", type=Path, action="append", default=[])
    transition.add_argument("--output", type=Path, required=True)
    transition.set_defaults(handler=command_transition)

    phase = subparsers.add_parser("assert-phase")
    phase.add_argument("--label", required=True)
    phase.add_argument("--node", required=True)
    phase.add_argument("--chain-id", required=True)
    phase.add_argument("--rpc-url", required=True)
    phase.add_argument("--height", type=int, required=True)
    phase.add_argument("--expected-set", type=Path, required=True)
    phase.add_argument("--state-path", type=Path, required=True)
    phase.add_argument("--json-out", type=Path, required=True)
    phase.set_defaults(handler=command_assert_phase)
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        args.handler(args)
        return 0
    except FixtureError as exc:
        print(f"validator lifecycle fixture failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
