#!/usr/bin/env python3
"""Strictly verify least-authority G3 per-validator deployment roots."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import stat
import subprocess
import sys

from poco_consensus_contract import canonical_lab_genesis_hash


HERE = pathlib.Path(__file__).resolve().parent
CHECK_MATERIAL = HERE / "check_run_material.py"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BOOTSTRAP_RELATIVE_PATHS = (
    "public/bootstrap/h1.proposal",
    "public/bootstrap/h2.proposal",
    "public/bootstrap/h3.proposal",
    "public/bootstrap/finality-proof.cev0",
    "public/bootstrap/bootstrap.json",
)


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 validator deployments invalid: {message}")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def exact(value: object, keys: set[str], field: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{field} keys differ from the deployment contract")
    return value


def verify_material_author(value: object, candidate: dict, field: str) -> dict:
    author = exact(value, {"binary_sha256", "runtime_deployed"}, field)
    binary_sha256 = author["binary_sha256"]
    if (
        not isinstance(binary_sha256, str)
        or not HEX64.fullmatch(binary_sha256)
        or binary_sha256 in set(candidate.values())
        or author["runtime_deployed"] is not False
    ):
        fail(f"{field} must bind one distinct non-deployed author binary")
    return author


def verify_chain_only_genesis(path: pathlib.Path, field: str) -> str:
    descriptor = json.loads(path.read_text(encoding="utf-8"))
    validators = descriptor.get("validators") if isinstance(descriptor, dict) else None
    chain_id = descriptor.get("chain_id") if isinstance(descriptor, dict) else None
    genesis_hash = descriptor.get("genesis_hash") if isinstance(descriptor, dict) else None
    if (
        not isinstance(chain_id, str)
        or not isinstance(genesis_hash, str)
        or not HEX64.fullmatch(genesis_hash)
        or not isinstance(validators, list)
    ):
        fail(f"{field} validator set lacks canonical genesis inputs")
    records: list[tuple[bytes, bytes, int]] = []
    for index, value in enumerate(validators):
        if not isinstance(value, dict):
            fail(f"{field} validator[{index}] is not one record")
        validator_id = value.get("validator_id")
        public_key = value.get("consensus_public_key")
        voting_power = value.get("voting_power")
        if (
            not isinstance(validator_id, str)
            or not HEX64.fullmatch(validator_id)
            or not isinstance(public_key, str)
            or not HEX64.fullmatch(public_key)
            or isinstance(voting_power, bool)
            or not isinstance(voting_power, int)
            or voting_power <= 0
        ):
            fail(f"{field} validator[{index}] has invalid canonical genesis inputs")
        records.append(
            (bytes.fromhex(validator_id), bytes.fromhex(public_key), voting_power)
        )
    try:
        expected = canonical_lab_genesis_hash(chain_id, records).hex()
    except (TypeError, ValueError) as error:
        fail(f"{field} canonical genesis inputs are invalid: {error}")
    if genesis_hash != expected:
        fail(f"{field} genesis differs from the chain-only canonical derivation")
    return genesis_hash


def real_directory(path: pathlib.Path, field: str, *, private: bool) -> pathlib.Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"{field} does not exist")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail(f"{field} must be one {'private ' if private else ''}real directory")
    if private and stat.S_IMODE(metadata.st_mode) != 0o700:
        fail(f"{field} mode must be exactly 0700")
    return path.resolve(strict=True)


def validate(coordinator: pathlib.Path, deployments: pathlib.Path, count: int, emit: bool = True) -> None:
    coordinator = real_directory(coordinator, "coordinator root", private=True)
    deployments = real_directory(deployments, "deployment root", private=True)
    subprocess.run(
        [sys.executable, str(CHECK_MATERIAL), str(coordinator), "--validators", str(count)],
        check=True,
        capture_output=True,
        text=True,
    )
    coordinator_manifest_path = coordinator / "manifest.json"
    coordinator_manifest = json.loads(coordinator_manifest_path.read_text(encoding="utf-8"))
    coordinator_genesis_hash = verify_chain_only_genesis(
        coordinator / "public/validator-set.json", "coordinator"
    )
    workload_policy = json.loads(
        (coordinator / "public/workload-policy.json").read_text(encoding="utf-8")
    )
    ordinary_start_height = workload_policy["header"]["ordinary_start_height"]
    coordinator_hash = sha256_file(coordinator_manifest_path)
    topology = json.loads((coordinator / "topology.json").read_text(encoding="utf-8"))
    validator_ids = [record["validator_id"] for record in topology["validators"]]
    actual_roots = sorted(path.name for path in deployments.iterdir())
    if actual_roots != sorted([*validator_ids, "observer-public"]):
        fail("deployment directory set differs from the topology")

    observer_root = deployments / "observer-public"
    if (
        observer_root.is_symlink()
        or not observer_root.is_dir()
        or stat.S_IMODE(observer_root.stat().st_mode) != 0o700
    ):
        fail("observer-public root must be one private regular directory")
    observer_manifest_path = observer_root / "manifest.json"
    try:
        observer_manifest_stat = observer_manifest_path.lstat()
    except FileNotFoundError:
        fail("observer-public manifest is missing")
    if (
        stat.S_ISLNK(observer_manifest_stat.st_mode)
        or not stat.S_ISREG(observer_manifest_stat.st_mode)
        or stat.S_IMODE(observer_manifest_stat.st_mode) != 0o600
    ):
        fail("observer-public manifest must be one private regular non-symlink file")
    observer_keys = {
        "schema_version", "coordinator_manifest_sha256", "run_id", "fleet_id",
        "validator_count", "weight_profile", "network_scope", "geo_wan_evidence",
        "candidate", "material_author", "validator_set_sha256", "public_files",
        "production_activation",
    }
    observer_manifest = exact(
        json.loads(observer_manifest_path.read_text(encoding="utf-8")),
        observer_keys,
        "observer-public manifest",
    )
    observer_coordinator_path = observer_root / "coordinator-manifest.json"
    try:
        observer_coordinator_stat = observer_coordinator_path.lstat()
    except FileNotFoundError:
        fail("observer-public coordinator manifest is missing")
    if (
        stat.S_ISLNK(observer_coordinator_stat.st_mode)
        or not stat.S_ISREG(observer_coordinator_stat.st_mode)
        or stat.S_IMODE(observer_coordinator_stat.st_mode) != 0o600
    ):
        fail(
            "observer-public coordinator manifest must be one private regular "
            "non-symlink file"
        )
    observer_coordinator_bytes = observer_coordinator_path.read_bytes()
    if observer_coordinator_bytes != coordinator_manifest_path.read_bytes():
        fail("observer-public coordinator manifest differs from coordinator input")
    observer_coordinator = exact(
        json.loads(observer_coordinator_bytes),
        {
            "schema_version", "run_id", "fleet_id", "validator_count",
            "weight_profile", "network_scope", "geo_wan_evidence", "candidate",
            "material_author", "validator_set_sha256", "public_files", "secret_files",
            "production_activation",
        },
        "observer-public coordinator manifest",
    )
    if (
        observer_manifest["schema_version"] != 4
        or observer_manifest["coordinator_manifest_sha256"] != coordinator_hash
        or sha256_file(observer_coordinator_path) != coordinator_hash
        or observer_manifest["run_id"] != coordinator_manifest["run_id"]
        or observer_manifest["fleet_id"] != coordinator_manifest["fleet_id"]
        or observer_manifest["validator_count"] != count
        or observer_manifest["weight_profile"] != coordinator_manifest["weight_profile"]
        or observer_manifest["network_scope"] != "single-lan"
        or observer_manifest["geo_wan_evidence"] is not False
        or observer_manifest["candidate"] != coordinator_manifest["candidate"]
        or observer_manifest["material_author"]
        != coordinator_manifest["material_author"]
        or observer_manifest["validator_set_sha256"]
        != coordinator_manifest["validator_set_sha256"]
        or observer_manifest["production_activation"] is not False
    ):
        fail("observer-public manifest differs from coordinator truth")
    observer_material_author = verify_material_author(
        observer_manifest["material_author"],
        observer_manifest["candidate"],
        "observer-public material_author",
    )
    coordinator_material_author = verify_material_author(
        observer_coordinator["material_author"],
        observer_coordinator["candidate"],
        "coordinator material_author",
    )
    if observer_material_author != coordinator_material_author:
        fail("observer-public material_author differs from coordinator truth")
    observer_expected = {
        "topology.json": coordinator / "topology.json",
        "public/validator-set.json": coordinator / "public/validator-set.json",
        "public/workload.corpus": coordinator / "public/workload.corpus",
        "public/workload-policy.json": coordinator / "public/workload-policy.json",
        **{relative: coordinator / relative for relative in BOOTSTRAP_RELATIVE_PATHS},
        **{
            f"public/configs/{validator_id}.json": coordinator
            / f"public/configs/{validator_id}.json"
            for validator_id in validator_ids
        },
        **{
            f"public/observer-configs/{record['host_id']}.json": coordinator
            / f"public/observer-configs/{record['host_id']}.json"
            for record in topology["participants"]
            if record.get("validator_eligible") is False
        },
    }
    coordinator_public_values = observer_coordinator["public_files"]
    coordinator_secret_values = observer_coordinator["secret_files"]
    if (
        observer_coordinator["schema_version"] != 2
        or not isinstance(coordinator_public_values, list)
        or not isinstance(coordinator_secret_values, list)
    ):
        fail("observer-public coordinator manifest is not the frozen schema-2 form")
    coordinator_public_by_path: dict[str, dict] = {}
    for value in coordinator_public_values:
        record = exact(value, {"path", "sha256", "bytes"}, "coordinator public reference")
        path_value = record["path"]
        if (
            not isinstance(path_value, str)
            or path_value in coordinator_public_by_path
            or path_value not in observer_expected
            or not HEX64.fullmatch(record["sha256"])
            or isinstance(record["bytes"], bool)
            or not isinstance(record["bytes"], int)
            or record["bytes"] <= 0
        ):
            fail("observer-public coordinator manifest has an invalid public reference")
        coordinator_public_by_path[path_value] = record
    if set(coordinator_public_by_path) != set(observer_expected):
        fail("observer-public coordinator manifest public inventory is incomplete")
    expected_secret_paths = {f"secrets/{validator_id}.pk8" for validator_id in validator_ids}
    observed_secret_paths: set[str] = set()
    for value in coordinator_secret_values:
        record = exact(value, {"path", "sha256", "bytes"}, "coordinator secret reference")
        path_value = record["path"]
        if (
            not isinstance(path_value, str)
            or path_value in observed_secret_paths
            or path_value not in expected_secret_paths
            or not HEX64.fullmatch(record["sha256"])
            or isinstance(record["bytes"], bool)
            or not isinstance(record["bytes"], int)
            or record["bytes"] <= 0
        ):
            fail("observer-public coordinator manifest has an invalid secret reference")
        observed_secret_paths.add(path_value)
    if observed_secret_paths != expected_secret_paths:
        fail("observer-public coordinator manifest secret inventory is incomplete")
    observer_values = observer_manifest["public_files"]
    if (
        not isinstance(observer_values, list)
        or len(observer_values) != len(observer_expected)
        or {value.get("path") for value in observer_values if isinstance(value, dict)}
        != set(observer_expected)
    ):
        fail("observer-public bundle has a non-exact public file reference set")
    for value in observer_values:
        record = exact(value, {"path", "sha256", "bytes"}, "observer file reference")
        relative = pathlib.PurePosixPath(record["path"])
        if relative.is_absolute() or ".." in relative.parts:
            fail("observer-public file reference escapes its root")
        path = observer_root / relative
        source = observer_expected[record["path"]]
        if path.is_symlink() or not path.is_file() or path.read_bytes() != source.read_bytes():
            fail("observer-public file differs from coordinator input")
        if record["sha256"] != sha256_file(path) or record["bytes"] != path.stat().st_size:
            fail("observer-public content-addressed reference mismatch")
        if record != coordinator_public_by_path[record["path"]]:
            fail("observer-public reference differs from the anchored coordinator manifest")
        if stat.S_IMODE(path.stat().st_mode) != 0o644:
            fail("observer-public file mode must be exactly 0644")
    observer_actual = {
        path.relative_to(observer_root).as_posix()
        for path in observer_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if observer_actual != {
        "manifest.json",
        "coordinator-manifest.json",
        *observer_expected,
    }:
        fail("observer-public bundle has extra, missing, or secret files")
    if not HEX64.fullmatch(observer_manifest["coordinator_manifest_sha256"]):
        fail("observer-public coordinator manifest hash is non-canonical")
    if (
        verify_chain_only_genesis(
            observer_root / "public/validator-set.json", "observer-public"
        )
        != coordinator_genesis_hash
    ):
        fail("observer-public canonical genesis differs from coordinator")

    manifest_keys = {
        "schema_version", "deployment_validator_id", "coordinator_manifest_sha256",
        "run_id", "fleet_id", "validator_count", "weight_profile", "network_scope",
        "geo_wan_evidence", "candidate", "material_author", "validator_set_sha256", "public_files",
        "secret_files", "production_activation",
    }
    for validator_id in validator_ids:
        root = deployments / validator_id
        if root.is_symlink() or not root.is_dir() or stat.S_IMODE(root.stat().st_mode) != 0o700:
            fail(f"deployment root {validator_id} must be a private regular directory")
        manifest_path = root / "manifest.json"
        try:
            manifest_stat = manifest_path.lstat()
        except FileNotFoundError:
            fail(f"deployment manifest {validator_id} is missing")
        if (
            stat.S_ISLNK(manifest_stat.st_mode)
            or not stat.S_ISREG(manifest_stat.st_mode)
            or stat.S_IMODE(manifest_stat.st_mode) != 0o600
        ):
            fail(
                f"deployment manifest {validator_id} must be one private regular non-symlink file"
            )
        manifest = exact(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            manifest_keys,
            f"manifest[{validator_id}]",
        )
        if (
            manifest["schema_version"] != 3
            or manifest["deployment_validator_id"] != validator_id
            or manifest["coordinator_manifest_sha256"] != coordinator_hash
            or manifest["run_id"] != coordinator_manifest["run_id"]
            or manifest["fleet_id"] != coordinator_manifest["fleet_id"]
            or manifest["validator_count"] != count
            or manifest["weight_profile"] != coordinator_manifest["weight_profile"]
            or manifest["network_scope"] != "single-lan"
            or manifest["geo_wan_evidence"] is not False
            or manifest["candidate"] != coordinator_manifest["candidate"]
            or manifest["material_author"] != coordinator_manifest["material_author"]
            or manifest["validator_set_sha256"] != coordinator_manifest["validator_set_sha256"]
            or manifest["production_activation"] is not False
        ):
            fail(f"deployment manifest {validator_id} differs from coordinator truth")
        if verify_material_author(
            manifest["material_author"],
            manifest["candidate"],
            f"manifest[{validator_id}].material_author",
        ) != coordinator_material_author:
            fail(f"deployment manifest {validator_id} material_author differs from coordinator")
        expected_public = {
            "topology.json": coordinator / "topology.json",
            "public/validator-set.json": coordinator / "public/validator-set.json",
            f"public/configs/{validator_id}.json": coordinator / f"public/configs/{validator_id}.json",
            "public/workload.corpus": coordinator / "public/workload.corpus",
            "public/workload-policy.json": coordinator / "public/workload-policy.json",
            **{relative: coordinator / relative for relative in BOOTSTRAP_RELATIVE_PATHS},
        }
        expected_secret = {
            f"secrets/{validator_id}.pk8": coordinator / f"secrets/{validator_id}.pk8"
        }
        for values, expected, secret in (
            (manifest["public_files"], expected_public, False),
            (manifest["secret_files"], expected_secret, True),
        ):
            if (
                not isinstance(values, list)
                or len(values) != len(expected)
                or {value.get("path") for value in values if isinstance(value, dict)}
                != set(expected)
            ):
                fail(f"deployment {validator_id} has a non-minimal file reference set")
            for value in values:
                record = exact(value, {"path", "sha256", "bytes"}, "file reference")
                relative = pathlib.PurePosixPath(record["path"])
                if relative.is_absolute() or ".." in relative.parts:
                    fail("deployment file reference escapes its root")
                path = root / relative
                source = expected[record["path"]]
                if path.is_symlink() or not path.is_file() or path.read_bytes() != source.read_bytes():
                    fail(f"deployment {validator_id} file differs from coordinator input")
                if record["sha256"] != sha256_file(path) or record["bytes"] != path.stat().st_size:
                    fail("deployment content-addressed reference mismatch")
                mode = stat.S_IMODE(path.stat().st_mode)
                if mode != (0o600 if secret else 0o644):
                    fail("deployment file mode differs from its authority class")
        actual_files = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        if actual_files != {"manifest.json", *expected_public, *expected_secret}:
            fail(f"deployment {validator_id} has extra or missing files")
        if (
            verify_chain_only_genesis(
                root / "public/validator-set.json", f"deployment {validator_id}"
            )
            != coordinator_genesis_hash
        ):
            fail(f"deployment {validator_id} canonical genesis differs from coordinator")
        if not HEX64.fullmatch(manifest["coordinator_manifest_sha256"]):
            fail("coordinator manifest hash is non-canonical")
    if emit:
        print(
            f"poco_g3_validator_deployments=passed validators={count} "
            f"ordinary_start_height={ordinary_start_height} "
            "secrets_per_validator=1 public_workload_per_validator=true "
            "public_bootstrap_bundle_per_validator=true "
            "observer_public_bundle=true coordinator_all_secrets_not_deployed=true "
            "application_private_keys=false material_author_hash_bound=true "
            "material_author_runtime_deployed=false bootstrap_runtime_closed=false"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("coordinator_root", type=pathlib.Path)
    parser.add_argument("deployment_root", type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7, 31, 100))
    args = parser.parse_args()
    try:
        validate(args.coordinator_root, args.deployment_root, args.validators)
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
