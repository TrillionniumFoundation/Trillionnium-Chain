#!/usr/bin/env python3
"""Verify one private PoCO G3 run-material structure and content addresses.

The Python boundary closes file inventory, workload framing/policy, authority,
and hashes. Every emitted validator root is additionally admitted by the Rust
loader, which performs the authoritative envelope-signature, block-root,
entry-chain-root, and execution-preflight checks before runtime authority can
start.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import tomllib
from typing import Any

from poco_consensus_contract import canonical_lab_genesis_hash


HERE = pathlib.Path(__file__).resolve().parent
INVENTORY = HERE / "inventory.toml"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
RUN_ID = re.compile(r"^poco-g3-(7|31|100)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
KEY_ROLES = ("consensus", "p2p-identity", "operator-recovery")
WORKLOAD_CORPUS_MAGIC = b"trnm-poco-g3-workload-corpus-v1\n"
WORKLOAD_CORPUS_FOOTER = b"trnm-poco-g3-workload-corpus-end-v1\n"
WORKLOAD_ENTRY_BYTES = 8 + 8 + 64 + 64 + 32
MAX_WORKLOAD_HEIGHT = 131_072
MAX_EXECUTION_PREFLIGHT_HEIGHT = 1_024
BOOTSTRAP_RELATIVE_PATHS = (
    "public/bootstrap/h1.proposal",
    "public/bootstrap/h2.proposal",
    "public/bootstrap/h3.proposal",
    "public/bootstrap/finality-proof.cev0",
    "public/bootstrap/bootstrap.json",
)


class MaterialError(ValueError):
    pass


def fail(message: str) -> None:
    raise MaterialError(message)


def exact(value: object, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{field} keys must be exactly {sorted(keys)!r}")
    return value


def safe_relative(value: object, field: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{field} must be one POSIX relative path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{field} escapes the run root")
    return path


def read_json(path: pathlib.Path, field: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"{field} must be one regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{field} is not exact UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be a JSON object")
    return value


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_ref(root: pathlib.Path, value: object, field: str, *, secret: bool) -> pathlib.Path:
    record = exact(value, {"path", "sha256", "bytes"}, field)
    relative = safe_relative(record["path"], f"{field}.path")
    path = root.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():
        fail(f"{field}.path must be a regular non-symlink file")
    expected_hash = record["sha256"]
    if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
        fail(f"{field}.sha256 is not canonical")
    size = record["bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        fail(f"{field}.bytes must be positive")
    if path.stat().st_size != size or sha256_file(path) != expected_hash:
        fail(f"{field} content address mismatch")
    mode = stat.S_IMODE(path.stat().st_mode)
    if secret and mode != 0o600:
        fail(f"{field} secret mode must be exactly 0600")
    if not secret and mode & 0o022:
        fail(f"{field} public file must not be group/world writable")
    return path


def pop_challenge(selected_run_id: str, validator_id: str, role: str) -> bytes:
    if role not in KEY_ROLES:
        fail("unknown validator key role")
    role_bytes = role.encode("ascii")
    run = selected_run_id.encode("ascii")
    validator = validator_id.encode("ascii")
    return b"".join(
        (
            b"TRNM/PoCO/G3/EphemeralKeyRolePoP/v2\0",
            len(role_bytes).to_bytes(4, "big"),
            role_bytes,
            len(run).to_bytes(4, "big"),
            run,
            len(validator).to_bytes(4, "big"),
            validator,
        )
    )


def public_from_secret(secret_path: pathlib.Path) -> bytes:
    public_der = subprocess.run(
        [
            "openssl",
            "pkey",
            "-inform",
            "DER",
            "-in",
            str(secret_path),
            "-pubout",
            "-outform",
            "DER",
        ],
        check=True,
        capture_output=True,
    ).stdout
    if len(public_der) != len(ED25519_SPKI_PREFIX) + 32 or not public_der.startswith(
        ED25519_SPKI_PREFIX
    ):
        fail("secret is not one canonical Ed25519 PKCS#8 key")
    return public_der[-32:]


def verify_pop(public_key: bytes, challenge: bytes, signature: bytes) -> None:
    public_der = ED25519_SPKI_PREFIX + public_key
    with tempfile.NamedTemporaryFile(prefix="poco-g3-pub-", delete=True) as public_file:
        with tempfile.NamedTemporaryFile(prefix="poco-g3-msg-", delete=True) as message_file:
            with tempfile.NamedTemporaryFile(prefix="poco-g3-sig-", delete=True) as sig_file:
                public_file.write(public_der)
                public_file.flush()
                message_file.write(challenge)
                message_file.flush()
                sig_file.write(signature)
                sig_file.flush()
                result = subprocess.run(
                    [
                        "openssl",
                        "pkeyutl",
                        "-verify",
                        "-rawin",
                        "-pubin",
                        "-keyform",
                        "DER",
                        "-inkey",
                        public_file.name,
                        "-in",
                        message_file.name,
                        "-sigfile",
                        sig_file.name,
                    ],
                    capture_output=True,
                )
    if result.returncode != 0:
        fail("ephemeral validator key proof-of-possession is invalid")


def positive_int(value: object, field: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{field} must be one positive integer")
    if maximum is not None and value > maximum:
        fail(f"{field} exceeds its bounded profile")
    return value


def workload_signer(value: object, field: str) -> dict[str, Any]:
    signer = exact(value, {"signer_id", "signer_role", "public_key_hex"}, field)
    if not isinstance(signer["public_key_hex"], str) or not HEX64.fullmatch(
        signer["public_key_hex"]
    ):
        fail(f"{field}.public_key_hex must be one canonical Ed25519 public key")
    return signer


def validate_workload(
    corpus_path: pathlib.Path,
    policy_path: pathlib.Path,
    expected_chain_id: str,
    validator_role_public_keys: set[str],
) -> tuple[str, str, int]:
    policy = exact(
        read_json(policy_path, "workload_policy"),
        {
            "schema_version",
            "schema",
            "corpus_sha256",
            "entry_chain_root",
            "header",
            "execution_preflight_height",
            "application_private_key_retained",
            "application_private_key_deployed",
            "production_activation",
        },
        "workload_policy",
    )
    header = exact(
        policy["header"],
        {
            "schema_version",
            "schema",
            "chain_id",
            "ordinary_start_height",
            "max_height",
            "ordinary_entry_count",
            "genesis_timestamp_ms",
            "block_time_step_ms",
            "validity_width_ms",
            "operator",
            "client",
            "governance_signer_id",
            "credit_amount",
            "task_reward",
            "task_worker_stake",
            "task_deadline_lead",
            "task_challenge_window",
            "max_gas",
            "fee_limit",
        },
        "workload_policy.header",
    )
    operator = workload_signer(header["operator"], "workload_policy.header.operator")
    client = workload_signer(header["client"], "workload_policy.header.client")
    ordinary_start_height = positive_int(
        header["ordinary_start_height"],
        "workload_policy.header.ordinary_start_height",
        maximum=MAX_WORKLOAD_HEIGHT,
    )
    if ordinary_start_height != 4:
        fail("workload ordinary_start_height must follow the fixed empty h1-h3 prefix")
    max_height = positive_int(
        header["max_height"],
        "workload_policy.header.max_height",
        maximum=MAX_WORKLOAD_HEIGHT,
    )
    ordinary_entry_count = positive_int(
        header["ordinary_entry_count"],
        "workload_policy.header.ordinary_entry_count",
        maximum=MAX_WORKLOAD_HEIGHT,
    )
    if ordinary_start_height > max_height:
        fail("workload ordinary_start_height exceeds max_height")
    if ordinary_entry_count != max_height - ordinary_start_height + 1:
        fail("workload ordinary entry count differs from its height range")
    expected_header = {
        **header,
        "schema_version": 1,
        "schema": "trnm_poco_g3_workload_corpus_v1",
        "chain_id": expected_chain_id,
        "genesis_timestamp_ms": 0,
        "block_time_step_ms": 1_000,
        "validity_width_ms": 1,
        "operator": {
            **operator,
            "signer_id": "did:trnm:g3:workload-operator",
            "signer_role": "operator",
        },
        "client": {
            **client,
            "signer_id": "did:trnm:g3:workload-client",
            "signer_role": "hepta",
        },
        "governance_signer_id": "did:trnm:g3:workload-operator",
        "credit_amount": "1000000",
        "task_reward": "1",
        "task_worker_stake": "1",
        "task_deadline_lead": 1_000,
        "task_challenge_window": 10,
        "max_gas": 100_000,
        "fee_limit": "1000000",
    }
    if header != expected_header:
        fail("workload policy header differs from the frozen public campaign profile")
    application_keys = {operator["public_key_hex"], client["public_key_hex"]}
    if len(application_keys) != 2 or application_keys & validator_role_public_keys:
        fail("workload application keys overlap each other or validator role authority")
    if (
        policy["schema_version"] != 1
        or policy["schema"] != "trnm_poco_g3_workload_policy_v1"
        or not isinstance(policy["corpus_sha256"], str)
        or not HEX64.fullmatch(policy["corpus_sha256"])
        or not isinstance(policy["entry_chain_root"], str)
        or not HEX64.fullmatch(policy["entry_chain_root"])
        or policy["execution_preflight_height"]
        != min(
            max_height,
            ordinary_start_height + MAX_EXECUTION_PREFLIGHT_HEIGHT - 1,
        )
        or policy["application_private_key_retained"] is not False
        or policy["application_private_key_deployed"] is not False
        or policy["production_activation"] is not False
    ):
        fail("workload policy retains private authority or crosses its bounded public profile")
    corpus_hash = sha256_file(corpus_path)
    policy_hash = sha256_file(policy_path)
    if policy["corpus_sha256"] != corpus_hash:
        fail("workload policy corpus hash differs from the public corpus")

    content = corpus_path.read_bytes()
    prefix_bytes = len(WORKLOAD_CORPUS_MAGIC) + 4 + 4
    if len(content) < prefix_bytes + 8 + 32 + len(WORKLOAD_CORPUS_FOOTER):
        fail("workload corpus is truncated")
    if not content.startswith(WORKLOAD_CORPUS_MAGIC):
        fail("workload corpus magic differs from the frozen profile")
    offset = len(WORKLOAD_CORPUS_MAGIC)
    version = int.from_bytes(content[offset : offset + 4], "big")
    offset += 4
    header_bytes = int.from_bytes(content[offset : offset + 4], "big")
    offset += 4
    header_end = offset + header_bytes
    if version != 1 or header_bytes <= 0 or header_end + 8 > len(content):
        fail("workload corpus header framing is invalid")
    try:
        corpus_header = json.loads(content[offset:header_end].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"workload corpus header is not exact UTF-8 JSON: {error}")
    if corpus_header != header:
        fail("workload corpus header differs from its public policy")
    entry_count = int.from_bytes(content[header_end : header_end + 8], "big")
    if entry_count != ordinary_entry_count:
        fail("workload corpus entry count differs from policy ordinary_entry_count")
    entries_start = header_end + 8
    entries_end = entries_start + ordinary_entry_count * WORKLOAD_ENTRY_BYTES
    expected_bytes = entries_end + 32 + len(WORKLOAD_CORPUS_FOOTER)
    if len(content) != expected_bytes or content[entries_end + 32 :] != WORKLOAD_CORPUS_FOOTER:
        fail("workload corpus length/footer differs from the frozen profile")
    for index in range(ordinary_entry_count):
        entry_offset = entries_start + index * WORKLOAD_ENTRY_BYTES
        height = int.from_bytes(content[entry_offset : entry_offset + 8], "big")
        timestamp = int.from_bytes(content[entry_offset + 8 : entry_offset + 16], "big")
        expected_height = ordinary_start_height + index
        if height != expected_height or timestamp != expected_height * 1_000:
            fail("workload corpus ordinal-to-height/timestamp schedule is non-canonical")
    # Signature, reconstructed-envelope, block-root, and derived entry-chain
    # verification belong to VerifiedWorkloadCorpusV1 in every Rust validator
    # loader. Deployment integration tests retain fully re-addressed signature
    # mutants so this structural checker is never mistaken for that authority.
    if content[entries_end : entries_end + 32].hex() != policy["entry_chain_root"]:
        fail("workload corpus entry-chain root differs from policy")
    return corpus_hash, policy_hash, ordinary_start_height


def validate_bootstrap(
    root: pathlib.Path,
    public_paths: set[pathlib.Path],
    validator_set: dict[str, Any],
    validator_records: list[dict[str, Any]],
    secret_paths: list[pathlib.Path],
) -> None:
    sidecar_paths = [root / relative for relative in BOOTSTRAP_RELATIVE_PATHS]
    if not set(sidecar_paths).issubset(public_paths):
        fail("manifest does not bind the complete public h1-h3 bootstrap bundle")
    bootstrap = exact(
        read_json(sidecar_paths[-1], "bootstrap"),
        {
            "schema_version",
            "schema",
            "chain_id",
            "genesis_hash",
            "protocol_version",
            "epoch",
            "validator_set_id",
            "consensus_parameters_profile",
            "consensus_parameters_hash",
            "genesis_timestamp_ms",
            "ordinary_start_height",
            "chain_descriptor_hash",
            "signer_policy_commitment",
            "initial_block_id",
            "initial_state_root",
            "initial_commit_id",
            "validator_count",
            "qc_signer_count",
            "all_validator_signers",
            "blocks",
            "finality_proof",
            "finality_proof_id",
            "finalized_height",
            "private_key_material_emitted",
            "production_activation",
        },
        "bootstrap",
    )
    hash_fields = (
        "genesis_hash",
        "validator_set_id",
        "consensus_parameters_hash",
        "chain_descriptor_hash",
        "signer_policy_commitment",
        "initial_block_id",
        "initial_state_root",
        "initial_commit_id",
        "finality_proof_id",
    )
    if any(
        not isinstance(bootstrap[field], str) or not HEX64.fullmatch(bootstrap[field])
        for field in hash_fields
    ):
        fail("bootstrap carries a non-canonical public commitment")
    if (
        bootstrap["schema_version"] != 1
        or bootstrap["schema"] != "trnm.poco.zero-comet-public-bootstrap.v1"
        or bootstrap["chain_id"] != validator_set["chain_id"]
        or bootstrap["genesis_hash"] != validator_set["genesis_hash"]
        or bootstrap["protocol_version"] != 0
        or bootstrap["epoch"] != 0
        or bootstrap["consensus_parameters_profile"] != "reference-shadow-v0"
        or bootstrap["genesis_timestamp_ms"] != 0
        or bootstrap["ordinary_start_height"] != 4
        or bootstrap["initial_block_id"] != bootstrap["genesis_hash"]
        or bootstrap["validator_count"] != len(validator_records)
        or bootstrap["qc_signer_count"] != len(validator_records)
        or bootstrap["all_validator_signers"] is not True
        or bootstrap["finalized_height"] != 1
        or bootstrap["private_key_material_emitted"] is not False
        or bootstrap["production_activation"] is not False
    ):
        fail("bootstrap differs from the fixed chain-only public profile")

    signer_ids = [record["validator_id"] for record in validator_records]
    blocks = bootstrap["blocks"]
    if not isinstance(blocks, list) or len(blocks) != 3:
        fail("bootstrap must carry exactly h1, h2, and h3 metadata")
    expected_parent = bootstrap["initial_block_id"]
    for index, value in enumerate(blocks):
        height = index + 1
        block = exact(
            value,
            {
                "height",
                "view",
                "timestamp_ms",
                "parent_block_id",
                "block_id",
                "proposer_validator_id",
                "payload_root",
                "state_root",
                "receipts_root",
                "evidence_root",
                "proposal",
                "certifying_qc_id",
                "qc_signer_validator_ids",
            },
            f"bootstrap.blocks[{index}]",
        )
        for field in (
            "parent_block_id",
            "block_id",
            "proposer_validator_id",
            "payload_root",
            "state_root",
            "receipts_root",
            "evidence_root",
            "certifying_qc_id",
        ):
            if not isinstance(block[field], str) or not HEX64.fullmatch(block[field]):
                fail(f"bootstrap.blocks[{index}].{field} is not canonical")
        if (
            block["height"] != height
            or block["view"] != height
            or block["timestamp_ms"] != height * 1_000
            or block["parent_block_id"] != expected_parent
            or block["proposer_validator_id"] != signer_ids[index % len(signer_ids)]
            or block["qc_signer_validator_ids"] != signer_ids
        ):
            fail("bootstrap block schedule/parent/leader/all-signer order changed")
        expected_path = root / BOOTSTRAP_RELATIVE_PATHS[index]
        proposal_ref = exact(
            block["proposal"], {"path", "sha256", "bytes"}, f"bootstrap h{height} proposal"
        )
        if (
            proposal_ref["path"] != BOOTSTRAP_RELATIVE_PATHS[index]
            or proposal_ref["sha256"] != sha256_file(expected_path)
            or proposal_ref["bytes"] != expected_path.stat().st_size
        ):
            fail("bootstrap proposal reference differs from its exact public bytes")
        expected_parent = block["block_id"]

    finality_path = root / "public/bootstrap/finality-proof.cev0"
    finality_ref = exact(
        bootstrap["finality_proof"],
        {"path", "sha256", "bytes"},
        "bootstrap.finality_proof",
    )
    if (
        finality_ref["path"] != "public/bootstrap/finality-proof.cev0"
        or finality_ref["sha256"] != sha256_file(finality_path)
        or finality_ref["bytes"] != finality_path.stat().st_size
    ):
        fail("bootstrap finality proof reference differs from exact CEV0 bytes")

    public_bootstrap_bytes = [path.read_bytes() for path in sidecar_paths]
    for secret_path in secret_paths:
        secret = secret_path.read_bytes()
        for forbidden in (secret, secret[-32:]):
            if any(forbidden in public_bytes for public_bytes in public_bootstrap_bytes):
                fail("public bootstrap bundle contains consensus secret material")


def validate(root: pathlib.Path, expected_count: int, *, emit: bool = True) -> None:
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        fail("run root does not exist")
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        fail("run root must be a real directory")
    root = root.resolve(strict=True)
    if stat.S_IMODE(root.stat().st_mode) & 0o077:
        fail("run root must not grant group/world permissions")
    for directory in [root / "secrets", *(root / "secrets" / role for role in KEY_ROLES)]:
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            fail("secret authority directories are incomplete")
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            fail("secret authority directories must be real mode-0700 directories")
    manifest = exact(
        read_json(root / "manifest.json", "manifest"),
        {
            "schema_version",
            "run_id",
            "fleet_id",
            "validator_count",
            "weight_profile",
            "network_scope",
            "geo_wan_evidence",
            "candidate",
            "material_author",
            "validator_set_sha256",
            "public_files",
            "secret_files",
            "production_activation",
        },
        "manifest",
    )
    if manifest["schema_version"] != 2 or manifest["validator_count"] != expected_count:
        fail("manifest schema/cardinality mismatch")
    selected_run_id = manifest["run_id"]
    if not isinstance(selected_run_id, str) or not RUN_ID.fullmatch(selected_run_id):
        fail("manifest run_id is non-canonical")
    if int(selected_run_id.split("-")[2]) != expected_count:
        fail("run_id topology differs from manifest")
    if manifest["network_scope"] != "single-lan" or manifest["geo_wan_evidence"] is not False:
        fail("run material must remain single-lan with geo_wan_evidence=false")
    if manifest["production_activation"] is not False:
        fail("run material must not activate production")
    if manifest["weight_profile"] not in {"equal", "bounded-unequal"}:
        fail("unknown weight profile")
    candidate = exact(
        manifest["candidate"],
        {"source_tree_sha256", "linux_x86_64_sha256", "macos_arm64_sha256"},
        "candidate",
    )
    for field, value in candidate.items():
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            fail(f"candidate.{field} must be canonical SHA-256")
    material_author = exact(
        manifest["material_author"],
        {"binary_sha256", "runtime_deployed"},
        "material_author",
    )
    if (
        not isinstance(material_author["binary_sha256"], str)
        or not HEX64.fullmatch(material_author["binary_sha256"])
        or material_author["binary_sha256"] in set(candidate.values())
        or material_author["runtime_deployed"] is not False
    ):
        fail("material_author must bind one distinct non-deployed author binary")

    public_values = manifest["public_files"]
    secret_values = manifest["secret_files"]
    if not isinstance(public_values, list) or not isinstance(secret_values, list):
        fail("manifest file references must be lists")
    public_paths = [
        verify_ref(root, value, f"public_files[{index}]", secret=False)
        for index, value in enumerate(public_values)
    ]
    secret_paths = [
        verify_ref(root, value, f"secret_files[{index}]", secret=True)
        for index, value in enumerate(secret_values)
    ]
    if (
        len(public_paths) != len(set(public_paths))
        or len(secret_paths) != len(set(secret_paths))
        or set(public_paths) & set(secret_paths)
    ):
        fail("manifest file inventories contain duplicate or cross-authority paths")
    relative_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    referenced = {"manifest.json"} | {
        path.relative_to(root).as_posix() for path in public_paths + secret_paths
    }
    if relative_files != referenced:
        fail("run root contains an unreferenced, missing, or symlink file")

    topology_path = root / "topology.json"
    validator_set_path = root / "public" / "validator-set.json"
    workload_corpus_path = root / "public" / "workload.corpus"
    workload_policy_path = root / "public" / "workload-policy.json"
    if not {
        topology_path,
        validator_set_path,
        workload_corpus_path,
        workload_policy_path,
    }.issubset(public_paths):
        fail("manifest does not bind topology, validator-set, and public workload inputs")
    topology = read_json(topology_path, "topology")
    if (
        topology.get("schema_version") != 1
        or topology.get("fleet_id") != manifest["fleet_id"]
        or topology.get("validator_count") != expected_count
        or topology.get("weight_profile") != manifest["weight_profile"]
        or topology.get("network_scope") != "single-lan"
        or topology.get("geo_wan_evidence") is not False
        or topology.get("test_keys_included") is not False
    ):
        fail("topology differs from the closed run-material boundary")
    with INVENTORY.open("rb") as source:
        inventory = tomllib.load(source)
    known_hosts = {host["id"]: host for host in inventory["hosts"]}
    planned = topology.get("validators")
    if not isinstance(planned, list) or len(planned) != expected_count:
        fail("topology validator cardinality mismatch")
    planned_by_id = {entry.get("validator_id"): entry for entry in planned if isinstance(entry, dict)}
    if len(planned_by_id) != expected_count:
        fail("topology validator identities are not unique")

    validator_set = exact(
        read_json(validator_set_path, "validator_set"),
        {
            "schema_version",
            "run_id",
            "chain_id",
            "genesis_hash",
            "protocol_version",
            "epoch",
            "consensus_parameters_profile",
            "candidate_source_sha256",
            "production_activation",
            "validators",
        },
        "validator_set",
    )
    if validator_set != {
        **validator_set,
        "schema_version": 2,
        "run_id": selected_run_id,
        "chain_id": "trnm-poco-g3-lab-v0",
        "protocol_version": 0,
        "epoch": 0,
        "consensus_parameters_profile": "reference-shadow-v0",
        "candidate_source_sha256": candidate["source_tree_sha256"],
        "production_activation": False,
    }:
        fail("validator-set fixed fields differ from the lab-only v0 contract")
    if not isinstance(validator_set["genesis_hash"], str) or not HEX64.fullmatch(
        validator_set["genesis_hash"]
    ):
        fail("validator-set genesis hash is invalid")
    if sha256_file(validator_set_path) != manifest["validator_set_sha256"]:
        fail("manifest validator_set_sha256 mismatch")

    validator_records = validator_set["validators"]
    if not isinstance(validator_records, list) or len(validator_records) != expected_count:
        fail("validator-set cardinality mismatch")
    validator_by_id: dict[str, dict[str, Any]] = {}
    previous = ""
    all_role_public_keys: set[str] = set()
    total_power = 0
    for index, value in enumerate(validator_records):
        record = exact(
            value,
            {
                "validator_id",
                "consensus_public_key",
                "p2p_identity_public_key",
                "operator_recovery_public_key",
                "voting_power",
                "key_pop_signature",
                "p2p_identity_key_pop_signature",
                "operator_recovery_key_pop_signature",
            },
            f"validators[{index}]",
        )
        validator_id = record["validator_id"]
        if not isinstance(validator_id, str) or not HEX64.fullmatch(validator_id):
            fail("validator IDs must be canonical 32-byte hashes")
        if previous and validator_id <= previous:
            fail("validator-set records must be strictly ID-sorted")
        previous = validator_id
        if validator_id not in planned_by_id:
            fail("validator-set contains a foreign validator")
        role_values = (
            (
                "consensus",
                record["consensus_public_key"],
                record["key_pop_signature"],
            ),
            (
                "p2p-identity",
                record["p2p_identity_public_key"],
                record["p2p_identity_key_pop_signature"],
            ),
            (
                "operator-recovery",
                record["operator_recovery_public_key"],
                record["operator_recovery_key_pop_signature"],
            ),
        )
        for role, public_key, signature in role_values:
            if not isinstance(public_key, str) or not HEX64.fullmatch(public_key):
                fail("validator role public key must be 32 bytes")
            if public_key in all_role_public_keys:
                fail("validator public keys must be unique across all roles")
            all_role_public_keys.add(public_key)
            if not isinstance(signature, str) or not HEX128.fullmatch(signature):
                fail("validator role PoP signature must be 64 bytes")
            verify_pop(
                bytes.fromhex(public_key),
                pop_challenge(selected_run_id, validator_id, role),
                bytes.fromhex(signature),
            )
        power = record["voting_power"]
        if isinstance(power, bool) or not isinstance(power, int) or power <= 0:
            fail("validator voting power must be positive")
        if power != planned_by_id[validator_id]["weight"]:
            fail("validator-set power differs from topology")
        total_power += power
        validator_by_id[validator_id] = record
    if any(record["voting_power"] * 4 > total_power for record in validator_records):
        fail("one validator exceeds the 25 percent voting-power cap")
    try:
        expected_genesis_hash = canonical_lab_genesis_hash(
            validator_set["chain_id"],
            (
                (
                    bytes.fromhex(record["validator_id"]),
                    bytes.fromhex(record["consensus_public_key"]),
                    record["voting_power"],
                )
                for record in validator_records
            ),
        ).hex()
    except (TypeError, ValueError) as error:
        fail(f"validator-set canonical genesis inputs are invalid: {error}")
    if validator_set["genesis_hash"] != expected_genesis_hash:
        fail("validator-set genesis differs from the chain-only canonical derivation")

    (
        workload_corpus_hash,
        workload_policy_hash,
        ordinary_start_height,
    ) = validate_workload(
        workload_corpus_path,
        workload_policy_path,
        validator_set["chain_id"],
        all_role_public_keys,
    )

    secret_by_role_id: dict[tuple[str, str], pathlib.Path] = {}
    for path in secret_paths:
        relative = path.relative_to(root)
        if (
            len(relative.parts) != 3
            or relative.parts[0] != "secrets"
            or relative.parts[1] not in KEY_ROLES
            or path.suffix != ".pk8"
        ):
            fail("secret keys must use the closed secrets/<role>/<validator>.pk8 layout")
        role = relative.parts[1]
        validator_id = path.stem
        if (role, validator_id) in secret_by_role_id:
            fail("duplicate validator role secret")
        secret_by_role_id[(role, validator_id)] = path
    expected_role_secrets = {
        (role, validator_id)
        for role in KEY_ROLES
        for validator_id in validator_by_id
    }
    if set(secret_by_role_id) != expected_role_secrets:
        fail("secret role-key set differs from validator set")
    public_field_by_role = {
        "consensus": "consensus_public_key",
        "p2p-identity": "p2p_identity_public_key",
        "operator-recovery": "operator_recovery_public_key",
    }
    for (role, validator_id), secret_path in secret_by_role_id.items():
        if public_from_secret(secret_path).hex() != validator_by_id[validator_id][
            public_field_by_role[role]
        ]:
            fail("role secret key differs from its public validator descriptor")

    validate_bootstrap(
        root,
        set(public_paths),
        validator_set,
        validator_records,
        secret_paths,
    )

    config_paths = {
        path.stem: path
        for path in public_paths
        if path.parent == root / "public" / "configs" and path.suffix == ".json"
    }
    if set(config_paths) != set(validator_by_id):
        fail("public config set differs from validator set")
    for validator_id, config_path in config_paths.items():
        config = exact(
            read_json(config_path, f"config[{validator_id}]"),
            {
                "schema_version",
                "run_id",
                "validator_id",
                "host_id",
                "lan_ip",
                "p2p_port",
                "metrics_port",
                "weight",
                "consensus_public_key",
                "p2p_identity_public_key",
                "operator_recovery_public_key",
                "validator_set_sha256",
                "binary_sha256",
                "ordinary_start_height",
                "workload_corpus_sha256",
                "workload_policy_sha256",
                "consensus_secret_key_path",
                "p2p_identity_secret_key_path",
                "operator_recovery_secret_key_path",
                "peers",
                "network_scope",
                "geo_wan_evidence",
                "production_activation",
            },
            f"config[{validator_id}]",
        )
        plan = planned_by_id[validator_id]
        host_id = plan["host_id"]
        expected_binary = (
            candidate["linux_x86_64_sha256"]
        )
        expected_fixed = {
            "schema_version": 2,
            "run_id": selected_run_id,
            "validator_id": validator_id,
            "host_id": host_id,
            "lan_ip": plan["lan_ip"],
            "p2p_port": plan["p2p_port"],
            "metrics_port": plan["metrics_port"],
            "weight": plan["weight"],
            "consensus_public_key": validator_by_id[validator_id]["consensus_public_key"],
            "p2p_identity_public_key": validator_by_id[validator_id][
                "p2p_identity_public_key"
            ],
            "operator_recovery_public_key": validator_by_id[validator_id][
                "operator_recovery_public_key"
            ],
            "validator_set_sha256": manifest["validator_set_sha256"],
            "binary_sha256": expected_binary,
            "ordinary_start_height": ordinary_start_height,
            "workload_corpus_sha256": workload_corpus_hash,
            "workload_policy_sha256": workload_policy_hash,
            "consensus_secret_key_path": f"secrets/consensus/{validator_id}.pk8",
            "p2p_identity_secret_key_path": f"secrets/p2p-identity/{validator_id}.pk8",
            "operator_recovery_secret_key_path": f"secrets/operator-recovery/{validator_id}.pk8",
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "production_activation": False,
        }
        for field, expected in expected_fixed.items():
            if config[field] != expected:
                fail(f"config[{validator_id}].{field} differs from trusted inputs")
        peers = config["peers"]
        if not isinstance(peers, list) or len(peers) != topology["peer_degree"]:
            fail(f"config[{validator_id}] peer cardinality mismatch")
        expected_peer_ids = plan["peers"]
        observed_peer_ids = []
        for peer_index, peer_value in enumerate(peers):
            peer = exact(
                peer_value,
                {
                    "validator_id",
                    "lan_ip",
                    "p2p_port",
                    "consensus_public_key",
                    "p2p_identity_public_key",
                    "operator_recovery_public_key",
                },
                f"config[{validator_id}].peers[{peer_index}]",
            )
            peer_id = peer["validator_id"]
            if peer_id not in planned_by_id or peer_id == validator_id:
                fail("config peer is unknown or self")
            peer_plan = planned_by_id[peer_id]
            if peer != {
                "validator_id": peer_id,
                "lan_ip": peer_plan["lan_ip"],
                "p2p_port": peer_plan["p2p_port"],
                "consensus_public_key": validator_by_id[peer_id]["consensus_public_key"],
                "p2p_identity_public_key": validator_by_id[peer_id][
                    "p2p_identity_public_key"
                ],
                "operator_recovery_public_key": validator_by_id[peer_id][
                    "operator_recovery_public_key"
                ],
            }:
                fail("config peer differs from topology/key descriptor")
            observed_peer_ids.append(peer_id)
        if observed_peer_ids != expected_peer_ids:
            fail("config peer order differs from frozen topology")

    observer_plans = {
        participant["host_id"]: participant
        for participant in topology.get("participants", [])
        if isinstance(participant, dict) and participant.get("validator_eligible") is False
    }
    observer_paths = {
        path.stem: path
        for path in public_paths
        if path.parent == root / "public" / "observer-configs" and path.suffix == ".json"
    }
    if set(observer_plans) != {"mac"} or set(observer_paths) != set(observer_plans):
        fail("observer config set must contain the exact bounded macOS participant")
    for host_id, observer_path in observer_paths.items():
        observer = exact(
            read_json(observer_path, f"observer_config[{host_id}]"),
            {
                "schema_version",
                "run_id",
                "host_id",
                "lan_ip",
                "os",
                "arch",
                "run_roles",
                "binary_sha256",
                "candidate_source_sha256",
                "validator_set_sha256",
                "validator_endpoints",
                "network_scope",
                "geo_wan_evidence",
                "production_activation",
            },
            f"observer_config[{host_id}]",
        )
        plan = observer_plans[host_id]
        expected_endpoints = [
            {
                "validator_id": planned["validator_id"],
                "lan_ip": planned["lan_ip"],
                "p2p_port": planned["p2p_port"],
                "metrics_port": planned["metrics_port"],
                "consensus_public_key": validator_by_id[planned["validator_id"]][
                    "consensus_public_key"
                ],
                "p2p_identity_public_key": validator_by_id[planned["validator_id"]][
                    "p2p_identity_public_key"
                ],
                "operator_recovery_public_key": validator_by_id[planned["validator_id"]][
                    "operator_recovery_public_key"
                ],
            }
            for planned in planned
        ]
        if observer != {
            "schema_version": 2,
            "run_id": selected_run_id,
            "host_id": host_id,
            "lan_ip": plan["lan_ip"],
            "os": "macos",
            "arch": "arm64",
            "run_roles": [
                "load-generator",
                "evidence-collector",
                "crypto-cross-verifier",
            ],
            "binary_sha256": candidate["macos_arm64_sha256"],
            "candidate_source_sha256": candidate["source_tree_sha256"],
            "validator_set_sha256": manifest["validator_set_sha256"],
            "validator_endpoints": expected_endpoints,
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "production_activation": False,
        }:
            fail("observer config differs from topology/key/candidate inputs")

    expected_public_paths = {
        "topology.json",
        "public/validator-set.json",
        "public/workload.corpus",
        "public/workload-policy.json",
        *BOOTSTRAP_RELATIVE_PATHS,
        *(
            f"public/configs/{validator_id}.json"
            for validator_id in validator_by_id
        ),
        *(
            f"public/observer-configs/{host_id}.json"
            for host_id in observer_plans
        ),
    }
    if {path.relative_to(root).as_posix() for path in public_paths} != expected_public_paths:
        fail("public file inventory differs from the closed workload/deployment contract")

    if emit:
        print(
            f"poco_g3_run_material=passed validators={expected_count} "
            "validator_hosts=5 mac_observer=true ephemeral_keys=true pop=true private_mode=0600 "
            f"public_workload=true ordinary_start_height={ordinary_start_height} "
            "application_private_keys=false public_bootstrap_bundle=true "
            "bootstrap_runtime_closed=false "
            "production_activation=false geo_wan=false"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7, 31, 100))
    args = parser.parse_args()
    try:
        validate(args.root, args.validators)
    except (MaterialError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"PoCO G3 run material invalid: {error}") from error


if __name__ == "__main__":
    main()
