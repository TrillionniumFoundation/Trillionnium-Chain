#!/usr/bin/env python3
"""Prepare private, ephemeral key/config material for one real G3 LAN run.

The topology committed to the repository is deliberately key-free.  This
tool consumes that frozen placement plan and creates a new private run root:

* one OpenSSL-generated Ed25519 PKCS#8 key per validator (mode 0600),
* one public proof-of-possession and validator-set descriptor,
* one exact per-validator process configuration, and
* one content-addressed manifest binding every generated file.

The output is deployment input, not completed-run evidence.  It must live
outside the source tree and must never be committed.  No production
activation or geo-WAN claim can be selected through this interface.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
INVENTORY = HERE / "inventory.toml"
PLANNER = HERE / "plan_topology.py"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^poco-g3-(7|31|100)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 run material preparation failed: {message}")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_new(path: pathlib.Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run_id(validator_count: int, explicit: str | None) -> str:
    if explicit is not None:
        if not RUN_ID.fullmatch(explicit) or int(explicit.split("-")[2]) != validator_count:
            fail("--run-id does not match the selected topology")
        return explicit
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"poco-g3-{validator_count}-{timestamp}-{secrets.token_hex(4)}"


def require_hash(value: str, field: str) -> str:
    if not HEX64.fullmatch(value):
        fail(f"{field} must be one canonical lowercase SHA-256")
    return value


def new_output_root(path: pathlib.Path) -> pathlib.Path:
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        fail("output root already exists; run material is never overwritten")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        fail("output root parent is not one real directory")
    return parent / path.name


def open_exact_binary(
    path: pathlib.Path, expected_sha256: str, option_name: str
) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        fail(f"{option_name} does not exist")
    except OSError as error:
        fail(f"cannot pin {option_name}: {error}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"{option_name} must be one regular non-symlink file")
        if metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) == 0:
            fail(f"{option_name} must be executable")
        digest = hashlib.sha256()
        offset = 0
        while chunk := os.pread(descriptor, 1024 * 1024, offset):
            digest.update(chunk)
            offset += len(chunk)
        if digest.hexdigest() != expected_sha256:
            fail(f"{option_name} differs from its expected SHA-256")
        proc_path = pathlib.Path(f"/proc/self/fd/{descriptor}")
        if not proc_path.exists():
            fail("pinned executable descriptor is unavailable through /proc")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def planner_output(validator_count: int, profile: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            sys.executable,
            str(PLANNER),
            str(validator_count),
            "--inventory",
            str(INVENTORY),
            "--weight-profile",
            profile,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    topology = json.loads(result.stdout)
    if topology.get("validator_count") != validator_count:
        fail("topology planner returned the wrong cardinality")
    if topology.get("test_keys_included") is not False:
        fail("topology planner must remain key-free")
    return topology


def pop_challenge(selected_run_id: str, validator_id: str) -> bytes:
    run = selected_run_id.encode("ascii")
    validator = validator_id.encode("ascii")
    return b"".join(
        (
            b"TRNM/PoCO/G3/EphemeralKeyPoP/v1\0",
            len(run).to_bytes(4, "big"),
            run,
            len(validator).to_bytes(4, "big"),
            validator,
        )
    )


def generate_key(secret_path: pathlib.Path, challenge: bytes) -> tuple[str, str]:
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-outform",
            "DER",
            "-out",
            str(secret_path),
        ],
        check=True,
        capture_output=True,
    )
    os.chmod(secret_path, 0o600)
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
        fail("OpenSSL returned a non-canonical Ed25519 SubjectPublicKeyInfo")
    with tempfile.NamedTemporaryFile(prefix="poco-g3-pop-", delete=True) as message:
        message.write(challenge)
        message.flush()
        signature = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-keyform",
                "DER",
                "-inkey",
                str(secret_path),
                "-in",
                message.name,
            ],
            check=True,
            capture_output=True,
        ).stdout
    if len(signature) != 64:
        fail("OpenSSL returned a non-canonical Ed25519 signature")
    return public_der[-32:].hex(), signature.hex()


def ref(root: pathlib.Path, path: pathlib.Path) -> dict[str, object]:
    relative = path.relative_to(root).as_posix()
    return {
        "path": relative,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def prepare(args: argparse.Namespace) -> pathlib.Path:
    selected_run_id = run_id(args.validator_count, args.run_id)
    source_hash = require_hash(args.source_sha256, "--source-sha256")
    linux_hash = require_hash(args.linux_sha256, "--linux-sha256")
    macos_hash = require_hash(args.macos_sha256, "--macos-sha256")
    material_builder_hash = require_hash(
        args.material_builder_sha256, "--material-builder-sha256"
    )
    if material_builder_hash in {linux_hash, macos_hash}:
        fail("material builder and runtime binaries must have distinct SHA-256 values")
    if args.ordinary_start_height != 4:
        fail("--ordinary-start-height must be exactly 4 after the fixed empty h1-h3 prefix")
    if args.ordinary_start_height > args.workload_max_height:
        fail("--ordinary-start-height exceeds --workload-max-height")
    ordinary_entry_count = args.workload_max_height - args.ordinary_start_height + 1
    execution_preflight_height = min(
        args.workload_max_height,
        args.ordinary_start_height + 1_024 - 1,
    )
    material_builder_descriptor = open_exact_binary(
        args.material_builder,
        material_builder_hash,
        "--material-builder",
    )
    try:
        validator_binary_descriptor = open_exact_binary(
            args.validator_binary,
            linux_hash,
            "--validator-binary",
        )
    except BaseException:
        os.close(material_builder_descriptor)
        raise
    builder_identity = os.fstat(material_builder_descriptor)
    validator_identity = os.fstat(validator_binary_descriptor)
    if (
        builder_identity.st_dev == validator_identity.st_dev
        and builder_identity.st_ino == validator_identity.st_ino
    ):
        os.close(validator_binary_descriptor)
        os.close(material_builder_descriptor)
        fail("material builder and validator binary must be distinct files")

    output = new_output_root(args.output)
    output.mkdir(parents=True, mode=0o700)
    os.chmod(output, 0o700)
    (output / "public").mkdir(mode=0o700)
    (output / "secrets").mkdir(mode=0o700)

    topology = planner_output(args.validator_count, args.weight_profile)
    topology_bytes = canonical_json(topology)
    topology_path = output / "topology.json"
    write_new(topology_path, topology_bytes, 0o644)

    key_records: dict[str, dict[str, str]] = {}
    secret_paths: dict[str, pathlib.Path] = {}
    for planned in topology["validators"]:
        validator_id = planned["validator_id"]
        secret_path = output / "secrets" / f"{validator_id}.pk8"
        public_key, pop_signature = generate_key(
            secret_path, pop_challenge(selected_run_id, validator_id)
        )
        key_records[validator_id] = {
            "consensus_public_key": public_key,
            "key_pop_signature": pop_signature,
        }
        secret_paths[validator_id] = secret_path

    validators = []
    for planned in sorted(topology["validators"], key=lambda value: value["validator_id"]):
        validator_id = planned["validator_id"]
        validators.append(
            {
                "validator_id": validator_id,
                "consensus_public_key": key_records[validator_id]["consensus_public_key"],
                "voting_power": planned["weight"],
                "key_pop_signature": key_records[validator_id]["key_pop_signature"],
            }
        )
    validator_set_template = {
        "schema_version": 1,
        "run_id": selected_run_id,
        "chain_id": "trnm-poco-g3-lab-v0",
        "protocol_version": 0,
        "epoch": 0,
        "consensus_parameters_profile": "reference-shadow-v0",
        "candidate_source_sha256": source_hash,
        "production_activation": False,
        "validators": validators,
    }
    validator_set_path = output / "public" / "validator-set.json"

    workload_corpus_path = output / "public" / "workload.corpus"
    workload_policy_path = output / "public" / "workload-policy.json"
    try:
        workload_result = subprocess.run(
            [
                f"/proc/self/fd/{material_builder_descriptor}",
                "workload-corpus",
                validator_set_template["chain_id"],
                str(args.ordinary_start_height),
                str(args.workload_max_height),
                str(workload_corpus_path.resolve()),
                str(workload_policy_path.resolve()),
            ],
            check=True,
            capture_output=True,
            text=True,
            pass_fds=(material_builder_descriptor,),
        )
    except BaseException:
        os.close(validator_binary_descriptor)
        os.close(material_builder_descriptor)
        raise
    try:
        workload_summary = json.loads(workload_result.stdout)
    except json.JSONDecodeError as error:
        fail(f"material builder returned invalid workload summary: {error}")
    expected_workload_keys = {
        "schema_version",
        "status",
        "corpus_sha256",
        "policy_sha256",
        "entry_chain_root",
        "operator_public_key_hex",
        "client_public_key_hex",
        "ordinary_start_height",
        "max_height",
        "ordinary_entry_count",
        "execution_preflight_height",
        "application_private_key_retained",
        "application_private_key_deployed",
        "production_activation",
    }
    if not isinstance(workload_summary, dict) or set(workload_summary) != expected_workload_keys:
        fail("material builder workload summary fields differ from the frozen contract")
    for path, label in (
        (workload_corpus_path, "workload corpus"),
        (workload_policy_path, "workload policy"),
    ):
        if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
            fail(f"{label} was not created as one non-empty regular file")
        os.chmod(path, 0o644)
    workload_corpus_hash = sha256_file(workload_corpus_path)
    workload_policy_hash = sha256_file(workload_policy_path)
    consensus_keys = {
        record["consensus_public_key"] for record in validators
    }
    application_keys = {
        workload_summary["operator_public_key_hex"],
        workload_summary["client_public_key_hex"],
    }
    if (
        workload_summary["schema_version"] != 1
        or workload_summary["status"] != "public-pre-signed-workload-corpus-created"
        or workload_summary["corpus_sha256"] != workload_corpus_hash
        or workload_summary["policy_sha256"] != workload_policy_hash
        or not isinstance(workload_summary["entry_chain_root"], str)
        or not HEX64.fullmatch(workload_summary["entry_chain_root"])
        or workload_summary["ordinary_start_height"] != args.ordinary_start_height
        or workload_summary["max_height"] != args.workload_max_height
        or workload_summary["ordinary_entry_count"] != ordinary_entry_count
        or isinstance(workload_summary["execution_preflight_height"], bool)
        or not isinstance(workload_summary["execution_preflight_height"], int)
        or workload_summary["execution_preflight_height"] != execution_preflight_height
        or workload_summary["application_private_key_retained"] is not False
        or workload_summary["application_private_key_deployed"] is not False
        or workload_summary["production_activation"] is not False
        or any(not isinstance(value, str) or not HEX64.fullmatch(value) for value in application_keys)
        or len(application_keys) != 2
        or application_keys & consensus_keys
    ):
        fail("material builder workload summary/content crosses the bounded public profile")

    bootstrap_directory = output / "public" / "bootstrap"
    bootstrap_paths = [
        bootstrap_directory / "h1.proposal",
        bootstrap_directory / "h2.proposal",
        bootstrap_directory / "h3.proposal",
        bootstrap_directory / "finality-proof.cev0",
        bootstrap_directory / "bootstrap.json",
    ]
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".validator-set-author-", dir=output, delete=True
        ) as template_file:
            template_file.write(canonical_json(validator_set_template))
            template_file.flush()
            os.fsync(template_file.fileno())
            bootstrap_result = subprocess.run(
                [
                    f"/proc/self/fd/{material_builder_descriptor}",
                    "zero-comet-bootstrap",
                    str(pathlib.Path(template_file.name).resolve()),
                    str(workload_corpus_path.resolve()),
                    workload_corpus_hash,
                    str(workload_policy_path.resolve()),
                    workload_policy_hash,
                    str((output / "secrets").resolve()),
                    str(validator_set_path.resolve()),
                    str(bootstrap_directory.resolve()),
                ],
                check=True,
                capture_output=True,
                text=True,
                pass_fds=(material_builder_descriptor,),
            )
    finally:
        os.close(validator_binary_descriptor)
        os.close(material_builder_descriptor)
    try:
        bootstrap_summary = json.loads(bootstrap_result.stdout)
    except json.JSONDecodeError as error:
        fail(f"material builder returned invalid bootstrap summary: {error}")
    expected_bootstrap_summary_keys = {
        "schema_version",
        "status",
        "validator_set_sha256",
        "genesis_hash",
        "validator_set_id",
        "bootstrap_sha256",
        "finality_proof_sha256",
        "finality_proof_id",
        "ordinary_start_height",
        "validator_count",
        "qc_signer_count",
        "all_validator_signers",
        "consensus_private_key_retained",
        "consensus_private_key_emitted",
        "production_activation",
    }
    digest_fields = (
        "validator_set_sha256",
        "genesis_hash",
        "validator_set_id",
        "bootstrap_sha256",
        "finality_proof_sha256",
        "finality_proof_id",
    )
    if (
        not isinstance(bootstrap_summary, dict)
        or set(bootstrap_summary) != expected_bootstrap_summary_keys
        or bootstrap_summary["schema_version"] != 1
        or bootstrap_summary["status"] != "public-zero-comet-bootstrap-created"
        or bootstrap_summary["ordinary_start_height"] != 4
        or bootstrap_summary["validator_count"] != args.validator_count
        or bootstrap_summary["qc_signer_count"] != args.validator_count
        or bootstrap_summary["all_validator_signers"] is not True
        or bootstrap_summary["consensus_private_key_retained"] is not False
        or bootstrap_summary["consensus_private_key_emitted"] is not False
        or bootstrap_summary["production_activation"] is not False
        or any(
            not isinstance(bootstrap_summary[field], str)
            or not HEX64.fullmatch(bootstrap_summary[field])
            for field in digest_fields
        )
    ):
        fail("material builder bootstrap summary crosses the frozen public profile")
    for path in [validator_set_path, *bootstrap_paths]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
            fail("material builder omitted one public bootstrap output")
        os.chmod(path, 0o644)
    validator_set_hash = sha256_file(validator_set_path)
    if (
        bootstrap_summary["validator_set_sha256"] != validator_set_hash
        or bootstrap_summary["bootstrap_sha256"]
        != sha256_file(bootstrap_directory / "bootstrap.json")
        or bootstrap_summary["finality_proof_sha256"]
        != sha256_file(bootstrap_directory / "finality-proof.cev0")
    ):
        fail("material builder bootstrap summary hashes differ from emitted public bytes")
    validator_set = json.loads(validator_set_path.read_text(encoding="utf-8"))
    if (
        validator_set.get("genesis_hash") != bootstrap_summary["genesis_hash"]
        or validator_set.get("validators") != validators
    ):
        fail("lab validator changed validator inventory or canonical genesis binding")

    by_id = {entry["validator_id"]: entry for entry in topology["validators"]}
    config_paths: list[pathlib.Path] = []
    for planned in topology["validators"]:
        validator_id = planned["validator_id"]
        peers = []
        for peer_id in planned["peers"]:
            peer = by_id[peer_id]
            peers.append(
                {
                    "validator_id": peer_id,
                    "lan_ip": peer["lan_ip"],
                    "p2p_port": peer["p2p_port"],
                    "consensus_public_key": key_records[peer_id]["consensus_public_key"],
                }
            )
        config = {
            "schema_version": 1,
            "run_id": selected_run_id,
            "validator_id": validator_id,
            "host_id": planned["host_id"],
            "lan_ip": planned["lan_ip"],
            "p2p_port": planned["p2p_port"],
            "metrics_port": planned["metrics_port"],
            "weight": planned["weight"],
            "consensus_public_key": key_records[validator_id]["consensus_public_key"],
            "validator_set_sha256": validator_set_hash,
            "ordinary_start_height": args.ordinary_start_height,
            "workload_corpus_sha256": workload_corpus_hash,
            "workload_policy_sha256": workload_policy_hash,
            "binary_sha256": linux_hash,
            "secret_key_path": f"secrets/{validator_id}.pk8",
            "peers": peers,
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "production_activation": False,
        }
        config_path = output / "public" / "configs" / f"{validator_id}.json"
        write_new(config_path, canonical_json(config), 0o644)
        config_paths.append(config_path)

    observer_paths: list[pathlib.Path] = []
    for participant in topology["participants"]:
        if participant["validator_eligible"]:
            continue
        observer = {
            "schema_version": 1,
            "run_id": selected_run_id,
            "host_id": participant["host_id"],
            "lan_ip": participant["lan_ip"],
            "os": participant["os"],
            "arch": participant["arch"],
            "run_roles": participant["run_roles"],
            "binary_sha256": macos_hash,
            "candidate_source_sha256": source_hash,
            "validator_set_sha256": validator_set_hash,
            "validator_endpoints": [
                {
                    "validator_id": planned["validator_id"],
                    "lan_ip": planned["lan_ip"],
                    "p2p_port": planned["p2p_port"],
                    "metrics_port": planned["metrics_port"],
                    "consensus_public_key": key_records[planned["validator_id"]][
                        "consensus_public_key"
                    ],
                }
                for planned in topology["validators"]
            ],
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "production_activation": False,
        }
        observer_path = (
            output / "public" / "observer-configs" / f"{participant['host_id']}.json"
        )
        write_new(observer_path, canonical_json(observer), 0o644)
        observer_paths.append(observer_path)

    public_refs = [
        ref(output, topology_path),
        ref(output, validator_set_path),
        ref(output, workload_corpus_path),
        ref(output, workload_policy_path),
    ]
    public_refs.extend(ref(output, path) for path in bootstrap_paths)
    public_refs.extend(ref(output, path) for path in sorted(config_paths))
    public_refs.extend(ref(output, path) for path in sorted(observer_paths))
    secret_refs = [ref(output, secret_paths[key]) for key in sorted(secret_paths)]
    manifest = {
        "schema_version": 2,
        "run_id": selected_run_id,
        "fleet_id": topology["fleet_id"],
        "validator_count": args.validator_count,
        "weight_profile": args.weight_profile,
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "candidate": {
            "source_tree_sha256": source_hash,
            "linux_x86_64_sha256": linux_hash,
            "macos_arm64_sha256": macos_hash,
        },
        "material_author": {
            "binary_sha256": material_builder_hash,
            "runtime_deployed": False,
        },
        "validator_set_sha256": validator_set_hash,
        "public_files": public_refs,
        "secret_files": secret_refs,
        "production_activation": False,
    }
    write_new(output / "manifest.json", canonical_json(manifest), 0o600)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("validator_count", type=int, choices=(7, 31, 100))
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument(
        "--weight-profile", choices=("equal", "bounded-unequal"), default="equal"
    )
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--linux-sha256", required=True)
    parser.add_argument("--macos-sha256", required=True)
    parser.add_argument("--material-builder", type=pathlib.Path, required=True)
    parser.add_argument("--material-builder-sha256", required=True)
    parser.add_argument("--validator-binary", type=pathlib.Path, required=True)
    parser.add_argument(
        "--ordinary-start-height", type=int, choices=range(1, 131_073), required=True
    )
    parser.add_argument(
        "--workload-max-height", type=int, choices=range(1, 131_073), required=True
    )
    parser.add_argument("--run-id")
    args = parser.parse_args()
    try:
        output = prepare(args)
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as error:
        fail(str(error))
    print(
        f"poco_g3_run_material=prepared validators={args.validator_count} "
        f"root={output} ordinary_start_height={args.ordinary_start_height} "
        "material_author_hash_bound=true material_author_runtime_deployed=false "
        "public_bootstrap_bundle=true bootstrap_runtime_closed=false "
        "production_activation=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
