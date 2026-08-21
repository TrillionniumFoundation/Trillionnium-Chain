#!/usr/bin/env python3
"""Split one verified G3 coordinator root into least-authority validator roots.

The coordinator root contains every ephemeral secret and must never be copied
to a validator host. Each emitted validator deployment contains exactly the
public topology, public validator set, public workload and zero-Comet bootstrap
sidecars, one local config, and exactly one local PKCS#8 secret for each frozen
validator key role. The separate observer
root contains every public coordinator input plus the exact coordinator
manifest, but no secret bytes or application private-key authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
CHECK_MATERIAL = HERE / "check_run_material.py"
BOOTSTRAP_RELATIVE_PATHS = (
    "public/bootstrap/h1.proposal",
    "public/bootstrap/h2.proposal",
    "public/bootstrap/h3.proposal",
    "public/bootstrap/finality-proof.cev0",
    "public/bootstrap/bootstrap.json",
)
KEY_ROLES = ("consensus", "p2p-identity", "operator-recovery")


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 validator deployment preparation failed: {message}")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def new_output_root(path: pathlib.Path) -> pathlib.Path:
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        fail("output root already exists; deployments are never overwritten")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        fail("deployment output parent is not one real directory")
    return parent / path.name


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_new(path: pathlib.Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as output:
        os.fchmod(output.fileno(), mode)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def open_regular_source(source: pathlib.Path) -> int:
    try:
        descriptor = os.open(
            source,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        fail(f"cannot pin source file {source}: {error}")
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        fail(f"source is not one regular file: {source}")
    return descriptor


def read_pinned(source: pathlib.Path, maximum_bytes: int = 64 * 1024 * 1024) -> bytes:
    descriptor = open_regular_source(source)
    try:
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                fail(f"source exceeds the bounded file size: {source}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def require_content_address(content: bytes, reference: dict[str, Any], field: str) -> None:
    if (
        reference.get("bytes") != len(content)
        or reference.get("sha256") != hashlib.sha256(content).hexdigest()
    ):
        fail(f"{field} changed after coordinator verification")


def copy_new(
    source: pathlib.Path,
    target: pathlib.Path,
    mode: int,
    reference: dict[str, Any],
) -> None:
    source_descriptor = open_regular_source(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target_descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except BaseException:
        os.close(source_descriptor)
        raise
    try:
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(source_descriptor, "rb") as input_file, os.fdopen(
            target_descriptor, "wb"
        ) as output:
            os.fchmod(output.fileno(), mode)
            while chunk := input_file.read(1024 * 1024):
                digest.update(chunk)
                total += len(chunk)
                output.write(chunk)
            if reference.get("bytes") != total or reference.get("sha256") != digest.hexdigest():
                fail(f"source changed after coordinator verification: {source}")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise


def ref(root: pathlib.Path, path: pathlib.Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def prepare(coordinator: pathlib.Path, output: pathlib.Path, count: int) -> pathlib.Path:
    try:
        coordinator_metadata = coordinator.lstat()
    except FileNotFoundError:
        fail("coordinator root does not exist")
    if stat.S_ISLNK(coordinator_metadata.st_mode) or not stat.S_ISDIR(
        coordinator_metadata.st_mode
    ):
        fail("coordinator root must be one real directory")
    coordinator = coordinator.resolve(strict=True)
    manifest_path = coordinator / "manifest.json"
    coordinator_manifest_bytes = read_pinned(manifest_path)
    subprocess.run(
        [sys.executable, str(CHECK_MATERIAL), str(coordinator), "--validators", str(count)],
        check=True,
        capture_output=True,
        text=True,
    )
    if read_pinned(manifest_path) != coordinator_manifest_bytes:
        fail("coordinator manifest changed during verification")
    output = new_output_root(output)
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)

    coordinator_manifest = json.loads(coordinator_manifest_bytes.decode("utf-8"))
    coordinator_hash = hashlib.sha256(coordinator_manifest_bytes).hexdigest()
    public_values = coordinator_manifest.get("public_files")
    secret_values = coordinator_manifest.get("secret_files")
    if not isinstance(public_values, list) or not isinstance(secret_values, list):
        fail("coordinator manifest lacks its file inventory")
    public_by_path = {
        value.get("path"): value for value in public_values if isinstance(value, dict)
    }
    secret_by_path = {
        value.get("path"): value for value in secret_values if isinstance(value, dict)
    }
    topology_reference = public_by_path.get("topology.json")
    if not isinstance(topology_reference, dict):
        fail("coordinator manifest lacks the topology reference")
    topology_bytes = read_pinned(coordinator / "topology.json")
    require_content_address(topology_bytes, topology_reference, "topology")
    topology = json.loads(topology_bytes.decode("utf-8"))
    validators = topology.get("validators")
    if not isinstance(validators, list) or len(validators) != count:
        fail("coordinator topology cardinality mismatch")

    observer_root = output / "observer-public"
    observer_root.mkdir(mode=0o700)
    os.chmod(observer_root, 0o700)
    write_new(observer_root / "coordinator-manifest.json", coordinator_manifest_bytes, 0o600)
    observer_public_refs: list[dict[str, Any]] = []
    observer_sources = []
    for value in public_values:
        relative_value = value.get("path") if isinstance(value, dict) else None
        if not isinstance(relative_value, str):
            fail("coordinator manifest contains an invalid public file reference")
        relative = pathlib.PurePosixPath(relative_value)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            fail("coordinator public file reference escapes its root")
        observer_sources.append(
            (
                coordinator.joinpath(*relative.parts),
                observer_root.joinpath(*relative.parts),
                value,
            )
        )
    for source, target, reference in observer_sources:
        copy_new(source, target, 0o644, reference)
        observer_public_refs.append(ref(observer_root, target))
    observer_manifest = {
        "schema_version": 4,
        "coordinator_manifest_sha256": coordinator_hash,
        "run_id": coordinator_manifest["run_id"],
        "fleet_id": coordinator_manifest["fleet_id"],
        "validator_count": coordinator_manifest["validator_count"],
        "weight_profile": coordinator_manifest["weight_profile"],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "candidate": coordinator_manifest["candidate"],
        "material_author": coordinator_manifest["material_author"],
        "validator_set_sha256": coordinator_manifest["validator_set_sha256"],
        "public_files": observer_public_refs,
        "production_activation": False,
    }
    write_new(observer_root / "manifest.json", canonical_json(observer_manifest), 0o600)

    for record in validators:
        validator_id = record.get("validator_id") if isinstance(record, dict) else None
        if not isinstance(validator_id, str):
            fail("coordinator topology contains an invalid validator ID")
        root = output / validator_id
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        targets = [
            (
                coordinator / "topology.json",
                root / "topology.json",
                0o644,
                False,
                public_by_path.get("topology.json"),
            ),
            (
                coordinator / "public/validator-set.json",
                root / "public/validator-set.json",
                0o644,
                False,
                public_by_path.get("public/validator-set.json"),
            ),
            (
                coordinator / f"public/configs/{validator_id}.json",
                root / f"public/configs/{validator_id}.json",
                0o644,
                False,
                public_by_path.get(f"public/configs/{validator_id}.json"),
            ),
            (
                coordinator / "public/workload.corpus",
                root / "public/workload.corpus",
                0o644,
                False,
                public_by_path.get("public/workload.corpus"),
            ),
            (
                coordinator / "public/workload-policy.json",
                root / "public/workload-policy.json",
                0o644,
                False,
                public_by_path.get("public/workload-policy.json"),
            ),
        ]
        for relative in BOOTSTRAP_RELATIVE_PATHS:
            targets.append(
                (
                    coordinator / relative,
                    root / relative,
                    0o644,
                    False,
                    public_by_path.get(relative),
                )
            )
        for role in KEY_ROLES:
            relative = f"secrets/{role}/{validator_id}.pk8"
            targets.append(
                (
                    coordinator / relative,
                    root / relative,
                    0o600,
                    True,
                    secret_by_path.get(relative),
                )
            )
        public_refs: list[dict[str, Any]] = []
        secret_refs: list[dict[str, Any]] = []
        for source, target, mode, secret, reference in targets:
            if not isinstance(reference, dict):
                fail(f"coordinator manifest lacks deployment source {source}")
            copy_new(source, target, mode, reference)
            (secret_refs if secret else public_refs).append(ref(root, target))
        deployment = {
            "schema_version": 3,
            "deployment_validator_id": validator_id,
            "coordinator_manifest_sha256": coordinator_hash,
            "run_id": coordinator_manifest["run_id"],
            "fleet_id": coordinator_manifest["fleet_id"],
            "validator_count": coordinator_manifest["validator_count"],
            "weight_profile": coordinator_manifest["weight_profile"],
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "candidate": coordinator_manifest["candidate"],
            "material_author": coordinator_manifest["material_author"],
            "validator_set_sha256": coordinator_manifest["validator_set_sha256"],
            "public_files": public_refs,
            "secret_files": secret_refs,
            "production_activation": False,
        }
        write_new(root / "manifest.json", canonical_json(deployment), 0o600)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("coordinator_root", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7, 31, 100))
    args = parser.parse_args()
    try:
        output = prepare(args.coordinator_root, args.output, args.validators)
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as error:
        fail(str(error))
    policy = json.loads(
        (output / "observer-public/public/workload-policy.json").read_text(encoding="utf-8")
    )
    ordinary_start_height = policy["header"]["ordinary_start_height"]
    print(
        f"poco_g3_validator_deployments=prepared validators={args.validators} root={output} "
        f"ordinary_start_height={ordinary_start_height} "
        "secrets_per_validator=3 public_workload_per_validator=true "
        "public_bootstrap_bundle_per_validator=true "
        "application_private_keys=false observer_public_bundle=true "
        "material_author_hash_bound=true material_author_runtime_deployed=false "
        "bootstrap_runtime_closed=false "
        "production_activation=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
