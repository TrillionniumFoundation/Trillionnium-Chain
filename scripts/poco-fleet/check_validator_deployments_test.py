#!/usr/bin/env python3
"""Positive, negative, and Rust-loader tests for validator deployments."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
PREPARE_MATERIAL = HERE / "prepare_run_material.py"
PREPARE_DEPLOYMENTS = HERE / "prepare_validator_deployments.py"
CHECK_DEPLOYMENTS = HERE / "check_validator_deployments.py"
SOURCE_SHA256 = "11" * 32
NONCES = {7: "00000007", 31: "0000001f", 100: "00000064"}
REPORT_DOMAIN = b"trnm.poco-g3.network-smoke-report.v1"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def exact_executable(path: pathlib.Path, label: str) -> pathlib.Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise SystemExit(f"{label} binary does not exist") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) == 0
    ):
        raise SystemExit(f"{label} binary must be one executable regular non-symlink file")
    return path.resolve(strict=True)


def run(
    arguments: list[str],
    *,
    expect: str | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise AssertionError(f"command exceeded its absolute test timeout: {arguments!r}") from error
    observed = completed.stdout + completed.stderr
    if expect is None:
        if completed.returncode != 0:
            raise AssertionError(f"command failed ({completed.returncode}): {observed}")
    elif completed.returncode == 0 or expect not in observed:
        raise AssertionError(
            f"negative command returned {completed.returncode} with {observed!r}; "
            f"expected rejection containing {expect!r}"
        )
    return completed


def prepare(
    parent: pathlib.Path,
    material_builder: pathlib.Path,
    validator_binary: pathlib.Path,
    count: int,
) -> tuple[pathlib.Path, pathlib.Path, list[str]]:
    coordinator = parent / f"coordinator-{count}"
    deployments = parent / f"deployments-{count}"
    material_builder_hash = sha256_file(material_builder)
    binary_hash = sha256_file(validator_binary)
    run_id = f"poco-g3-{count}-20260814T000000Z-{NONCES[count]}"
    run(
        [
            sys.executable,
            str(PREPARE_MATERIAL),
            str(count),
            "--output",
            str(coordinator),
            "--weight-profile",
            "bounded-unequal",
            "--source-sha256",
            SOURCE_SHA256,
            "--linux-sha256",
            binary_hash,
            "--macos-sha256",
            binary_hash,
            "--material-builder",
            str(material_builder),
            "--material-builder-sha256",
            material_builder_hash,
            "--validator-binary",
            str(validator_binary),
            "--ordinary-start-height",
            "4",
            "--workload-max-height",
            "6",
            "--run-id",
            run_id,
        ]
    )
    run(
        [
            sys.executable,
            str(PREPARE_DEPLOYMENTS),
            str(coordinator),
            "--output",
            str(deployments),
            "--validators",
            str(count),
        ]
    )
    run(
        [
            sys.executable,
            str(CHECK_DEPLOYMENTS),
            str(coordinator),
            str(deployments),
            "--validators",
            str(count),
        ]
    )
    topology = json.loads((coordinator / "topology.json").read_text(encoding="utf-8"))
    validator_ids = [record["validator_id"] for record in topology["validators"]]
    if len(validator_ids) != count:
        raise AssertionError("generated topology has the wrong validator count")
    coordinator_manifest = json.loads(
        (coordinator / "manifest.json").read_text(encoding="utf-8")
    )
    expected_material_author = {
        "binary_sha256": material_builder_hash,
        "runtime_deployed": False,
    }
    if (
        coordinator_manifest.get("schema_version") != 2
        or coordinator_manifest.get("material_author") != expected_material_author
        or "material_builder_sha256" in coordinator_manifest.get("candidate", {})
    ):
        raise AssertionError("coordinator material_author provenance is not exact")
    observer_manifest = json.loads(
        (deployments / "observer-public/manifest.json").read_text(encoding="utf-8")
    )
    if (
        observer_manifest.get("schema_version") != 4
        or observer_manifest.get("material_author") != expected_material_author
    ):
        raise AssertionError("observer material_author differs from coordinator")
    for validator_id in validator_ids:
        deployment_manifest = json.loads(
            (deployments / validator_id / "manifest.json").read_text(encoding="utf-8")
        )
        if (
            deployment_manifest.get("schema_version") != 3
            or deployment_manifest.get("material_author") != expected_material_author
        ):
            raise AssertionError("validator material_author differs from coordinator")
    if any(
        path.is_file() and "material-builder" in path.name
        for path in deployments.rglob("*")
    ):
        raise AssertionError("material-builder binary entered a runtime deployment")
    shared_public_relatives = (
        pathlib.Path("public/workload.corpus"),
        pathlib.Path("public/workload-policy.json"),
        pathlib.Path("public/bootstrap/h1.proposal"),
        pathlib.Path("public/bootstrap/h2.proposal"),
        pathlib.Path("public/bootstrap/h3.proposal"),
        pathlib.Path("public/bootstrap/finality-proof.cev0"),
        pathlib.Path("public/bootstrap/bootstrap.json"),
    )
    for relative in shared_public_relatives:
        expected = (coordinator / relative).read_bytes()
        observer = deployments / "observer-public" / relative
        if observer.read_bytes() != expected or stat.S_IMODE(observer.stat().st_mode) != 0o644:
            raise AssertionError("observer-public shared public copy differs from coordinator")
        for validator_id in validator_ids:
            deployed = deployments / validator_id / relative
            if deployed.read_bytes() != expected or stat.S_IMODE(deployed.stat().st_mode) != 0o644:
                raise AssertionError("validator shared public copy differs from coordinator")
    return coordinator, deployments, validator_ids


def verify_representative(
    binary: pathlib.Path,
    coordinator: pathlib.Path,
    deployments: pathlib.Path,
    validator_ids: list[str],
) -> tuple[str, dict[str, Any]]:
    validator_id = validator_ids[len(validator_ids) // 2]
    root = deployments / validator_id
    config = root / f"public/configs/{validator_id}.json"
    completed = run([str(binary), "verify-config", str(root), str(config)])
    report = json.loads(completed.stdout)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if (
        report.get("status") != "bounded-runtime-candidate-config-and-wire-verified"
        or report.get("validator_count") != len(validator_ids)
        or report.get("validator_id") != validator_id
        or report.get("coordinator_manifest_sha256")
        != manifest["coordinator_manifest_sha256"]
        or report.get("binary_sha256") != sha256_file(binary)
        or report.get("validator_runtime_started") is not False
        or report.get("g3_evidence_complete") is not False
        or report.get("geo_wan_evidence") is not False
        or report.get("production_candidate") is not False
        or report.get("production_consensus_activation") is not False
    ):
        raise AssertionError("Rust verify-config report crossed the bounded deployment truth")
    return validator_id, report


def verify_consensus_cli_rejects_invalid_bounds_before_effects(
    parent: pathlib.Path,
    binary: pathlib.Path,
    source_deployment: pathlib.Path,
    validator_id: str,
    count: int,
) -> None:
    root = parent / f"consensus-invalid-bounds-{count}-{validator_id}"
    shutil.copytree(source_deployment / validator_id, root)
    config = root / f"public/configs/{validator_id}.json"
    report = parent / f"forbidden-consensus-report-{count}.json"
    before = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    run(
        [
            str(binary),
            "run-consensus",
            str(root),
            str(config),
            "1",
            "1",
            str(report),
        ],
        expect="max-blocks must be in 3..=10000000",
        timeout=5,
    )
    if report.exists() or report.is_symlink():
        raise AssertionError("invalid run-consensus bounds created a report")
    after = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if after != before:
        raise AssertionError("invalid run-consensus bounds crossed the pre-effect boundary")


def verify_rust_material_author_rejected(
    parent: pathlib.Path,
    binary: pathlib.Path,
    deployments: pathlib.Path,
    validator_id: str,
) -> None:
    root = parent / f"rust-material-author-mutant-{validator_id}"
    shutil.copytree(deployments / validator_id, root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["material_author"]["runtime_deployed"] = True
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    config = root / f"public/configs/{validator_id}.json"
    run(
        [str(binary), "verify-config", str(root), str(config)],
        expect="must bind one distinct non-deployed author binary",
        timeout=5,
    )


def readdress_validator_workload_mutant(
    root: pathlib.Path,
    validator_id: str,
    corpus: bytes,
    policy: dict[str, Any],
    *,
    config_start_height: int | None = None,
) -> pathlib.Path:
    corpus_path = root / "public/workload.corpus"
    corpus_path.write_bytes(corpus)
    corpus_hash = hashlib.sha256(corpus).hexdigest()
    policy["corpus_sha256"] = corpus_hash
    policy_path = root / "public/workload-policy.json"
    policy_bytes = json.dumps(policy, separators=(",", ":")).encode("utf-8")
    policy_path.write_bytes(policy_bytes)
    policy_hash = hashlib.sha256(policy_bytes).hexdigest()

    config_path = root / f"public/configs/{validator_id}.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["workload_corpus_sha256"] = corpus_hash
    config["workload_policy_sha256"] = policy_hash
    if config_start_height is not None:
        config["ordinary_start_height"] = config_start_height
    config_path.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_path = {record["path"]: record for record in manifest["public_files"]}
    for relative, path in (
        ("public/workload.corpus", corpus_path),
        ("public/workload-policy.json", policy_path),
        (f"public/configs/{validator_id}.json", config_path),
    ):
        by_path[relative]["sha256"] = sha256_file(path)
        by_path[relative]["bytes"] = path.stat().st_size
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return config_path


def verify_workload_crypto_mutants_rejected(
    parent: pathlib.Path,
    binary: pathlib.Path,
    deployments: pathlib.Path,
    validator_id: str,
) -> None:
    source = deployments / validator_id
    original = (source / "public/workload.corpus").read_bytes()
    magic_bytes = len(b"trnm-poco-g3-workload-corpus-v1\n")
    header_bytes = int.from_bytes(original[magic_bytes + 4 : magic_bytes + 8], "big")
    entries_start = magic_bytes + 8 + header_bytes + 8
    policy_source = json.loads(
        (source / "public/workload-policy.json").read_text(encoding="utf-8")
    )
    ordinary_entry_count = policy_source["header"]["ordinary_entry_count"]
    entry_chain_root = entries_start + ordinary_entry_count * (8 + 8 + 64 + 64 + 32)
    mutants = (
        ("signature", entries_start + 8 + 8, "signature", False),
        ("block-root", entries_start + 8 + 8 + 64 + 64, "workload block root mismatch", False),
        ("entry-chain-root", entry_chain_root, "workload corpus entry-chain root mismatch", True),
    )
    for name, offset, expected, update_policy_root in mutants:
        root = parent / f"workload-{name}-mutant-{validator_id}"
        shutil.copytree(source, root)
        corpus = bytearray(original)
        corpus[offset] ^= 1
        policy = json.loads(
            (root / "public/workload-policy.json").read_text(encoding="utf-8")
        )
        if update_policy_root:
            policy["entry_chain_root"] = bytes(corpus[offset : offset + 32]).hex()
        config_path = readdress_validator_workload_mutant(
            root,
            validator_id,
            bytes(corpus),
            policy,
        )
        run(
            [str(binary), "verify-config", str(root), str(config_path)],
            expect=expected,
            timeout=5,
        )

    wrong_config_root = parent / f"workload-start-config-mutant-{validator_id}"
    shutil.copytree(source, wrong_config_root)
    wrong_config = wrong_config_root / f"public/configs/{validator_id}.json"
    config_value = json.loads(wrong_config.read_text(encoding="utf-8"))
    config_value["ordinary_start_height"] = 5
    wrong_config.write_text(
        json.dumps(config_value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_path = wrong_config_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    config_relative = f"public/configs/{validator_id}.json"
    config_ref = next(
        record for record in manifest["public_files"] if record["path"] == config_relative
    )
    config_ref["sha256"] = sha256_file(wrong_config)
    config_ref["bytes"] = wrong_config.stat().st_size
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    run(
        [str(binary), "verify-config", str(wrong_config_root), str(wrong_config)],
        expect="ordinary_start_height differs from the fixed h1-h3 bootstrap profile",
        timeout=5,
    )

    noncontiguous_root = parent / f"workload-height-gap-mutant-{validator_id}"
    shutil.copytree(source, noncontiguous_root)
    noncontiguous = bytearray(original)
    second_height = entries_start + (8 + 8 + 64 + 64 + 32)
    noncontiguous[second_height : second_height + 8] = (6).to_bytes(8, "big")
    policy = json.loads(
        (noncontiguous_root / "public/workload-policy.json").read_text(encoding="utf-8")
    )
    config_path = readdress_validator_workload_mutant(
        noncontiguous_root,
        validator_id,
        bytes(noncontiguous),
        policy,
    )
    run(
        [str(binary), "verify-config", str(noncontiguous_root), str(config_path)],
        expect="ordinal-to-height mapping is not exact and contiguous",
        timeout=5,
    )

    readdressed_range_root = parent / f"workload-range-readdress-mutant-{validator_id}"
    shutil.copytree(source, readdressed_range_root)
    readdressed = bytearray(original)
    header_start = magic_bytes + 8
    header_end = header_start + header_bytes
    header = json.loads(readdressed[header_start:header_end].decode("utf-8"))
    header["max_height"] = 5
    header["ordinary_entry_count"] = 2
    encoded_header = json.dumps(header, separators=(",", ":")).encode("utf-8")
    if len(encoded_header) != header_bytes:
        raise AssertionError("same-width Rust workload range mutation changed framing")
    readdressed[header_start:header_end] = encoded_header
    policy = json.loads(
        (readdressed_range_root / "public/workload-policy.json").read_text(encoding="utf-8")
    )
    policy["header"] = header
    policy["execution_preflight_height"] = 5
    config_path = readdress_validator_workload_mutant(
        readdressed_range_root,
        validator_id,
        bytes(readdressed),
        policy,
    )
    run(
        [str(binary), "verify-config", str(readdressed_range_root), str(config_path)],
        expect="workload corpus entry count differs from header",
        timeout=5,
    )


def compact_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sign_report(report: dict[str, Any], secret: pathlib.Path) -> dict[str, Any]:
    body = compact_json(report)
    root = hashlib.sha256(
        REPORT_DOMAIN + len(body).to_bytes(8, "big") + body
    ).digest()
    with tempfile.NamedTemporaryFile(prefix="poco-g3-report-root-", delete=True) as message:
        message.write(root)
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
                str(secret),
                "-in",
                message.name,
            ],
            check=True,
            capture_output=True,
        ).stdout
    if len(signature) != 64:
        raise AssertionError("OpenSSL returned a non-canonical report signature")
    return {"report": report, "signature": signature.hex()}


def write_json(path: pathlib.Path, value: object) -> None:
    path.write_bytes(compact_json(value))
    path.chmod(0o600)


def build_signed_report(
    coordinator: pathlib.Path,
    deployments: pathlib.Path,
    validator_id: str,
    config_report: dict[str, Any],
) -> dict[str, Any]:
    config_path = coordinator / f"public/configs/{validator_id}.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    topology_path = coordinator / "topology.json"
    topology = json.loads(topology_path.read_text(encoding="utf-8"))
    manifest_path = coordinator / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sessions: list[dict[str, Any]] = []
    for peer in config["peers"]:
        remote = peer["validator_id"]
        sessions.append(
            {
                "remote_validator_id": remote,
                "direction": "outbound",
                "remote_addr": f"{peer['lan_ip']}:{peer['p2p_port']}",
                "session_id": hashlib.sha256(
                    f"outbound:{validator_id}:{remote}".encode("ascii")
                ).hexdigest(),
                "messages_sent": 3,
                "messages_received": 3,
            }
        )
    incoming = [
        record
        for record in topology["validators"]
        if validator_id in record["peers"]
    ]
    for index, peer in enumerate(incoming):
        remote = peer["validator_id"]
        sessions.append(
            {
                "remote_validator_id": remote,
                "direction": "inbound",
                "remote_addr": f"{peer['lan_ip']}:{49152 + index}",
                "session_id": hashlib.sha256(
                    f"inbound:{validator_id}:{remote}".encode("ascii")
                ).hexdigest(),
                "messages_sent": 3,
                "messages_received": 3,
            }
        )
    sessions.sort(key=lambda value: (value["remote_validator_id"], value["direction"]))
    if len(sessions) != 2 * len(config["peers"]):
        raise AssertionError("directed report inventory is not balanced")
    report = {
        "schema_version": 1,
        "run_id": config["run_id"],
        "protocol_id": "poco-bft-v0",
        "profile": "frozen-v0-lab-network-smoke",
        "network_scope": "single-lan",
        "validator_id": validator_id,
        "validator_set_id": config_report["validator_set_id"],
        "validator_set_sha256": config["validator_set_sha256"],
        "topology_sha256": sha256_file(topology_path),
        "coordinator_manifest_sha256": sha256_file(manifest_path),
        "candidate_source_sha256": manifest["candidate"]["source_tree_sha256"],
        "binary_sha256": config["binary_sha256"],
        "config_sha256": sha256_file(config_path),
        "host_id": config["host_id"],
        "process_id": 1,
        "listen_addr": f"{config['lan_ip']}:{config['p2p_port']}",
        "started_unix_ms": 1,
        "ended_unix_ms": 2,
        "rounds_per_peer": 3,
        "peer_sessions": sessions,
        "authenticated_fresh_session_runtime": True,
        "core_runtime": False,
        "safety_store_runtime": False,
        "signer_journal_runtime": False,
        "native_execution_runtime": False,
        "validator_run_completed": False,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    return sign_report(
        report,
        deployments / validator_id / f"secrets/{validator_id}.pk8",
    )


def report_command(
    binary: pathlib.Path,
    observer_root: pathlib.Path,
    config: pathlib.Path,
    report: pathlib.Path,
    anchor: str,
) -> list[str]:
    return [
        str(binary),
        "verify-network-report",
        str(observer_root),
        str(config),
        str(report),
        anchor,
    ]


def verify_signed_report(
    parent: pathlib.Path,
    binary: pathlib.Path,
    coordinator: pathlib.Path,
    deployments: pathlib.Path,
    validator_id: str,
    config_report: dict[str, Any],
) -> tuple[pathlib.Path, dict[str, Any]]:
    signed = build_signed_report(
        coordinator,
        deployments,
        validator_id,
        config_report,
    )
    report_path = parent / f"signed-report-{len(config_report)}-{validator_id}.json"
    write_json(report_path, signed)
    observer = deployments / "observer-public"
    config = observer / f"public/configs/{validator_id}.json"
    anchor = sha256_file(coordinator / "manifest.json")
    completed = run(report_command(binary, observer, config, report_path, anchor))
    result = json.loads(completed.stdout)
    if (
        result.get("status")
        != "network-smoke-report-signature-and-semantics-verified"
        or result.get("validator_id") != validator_id
        or result.get("coordinator_manifest_sha256") != anchor
        or result.get("validator_run_completed") is not False
        or result.get("g3_evidence_complete") is not False
        or result.get("geo_wan_evidence") is not False
        or result.get("production_activation") is not False
    ):
        raise AssertionError("Rust public report verifier crossed its bounded truth")
    return report_path, signed


def observer_manifest_symlink(root: pathlib.Path, _first: str, _second: str) -> None:
    manifest = root / "observer-public/manifest.json"
    external = root.parent / "external-identical-observer-manifest.json"
    shutil.copyfile(manifest, external)
    external.chmod(0o600)
    manifest.unlink()
    manifest.symlink_to(external)


def observer_coordinator_manifest_symlink(
    root: pathlib.Path, _first: str, _second: str
) -> None:
    manifest = root / "observer-public/coordinator-manifest.json"
    external = root.parent / "external-identical-coordinator-manifest.json"
    shutil.copyfile(manifest, external)
    external.chmod(0o600)
    manifest.unlink()
    manifest.symlink_to(external)


def observer_extra_secret(root: pathlib.Path, first: str, _second: str) -> None:
    source = root / first / f"secrets/{first}.pk8"
    target = root / "observer-public/secrets/leaked.pk8"
    target.parent.mkdir()
    shutil.copyfile(source, target)
    target.chmod(0o600)


def observer_missing_config(root: pathlib.Path, first: str, _second: str) -> None:
    (root / "observer-public" / f"public/configs/{first}.json").unlink()


def observer_cross_config(root: pathlib.Path, first: str, second: str) -> None:
    source = root / "observer-public" / f"public/configs/{second}.json"
    target = root / "observer-public" / f"public/configs/{first}.json"
    shutil.copyfile(source, target)


def clone_observer(
    parent: pathlib.Path,
    source: pathlib.Path,
    name: str,
) -> pathlib.Path:
    target = parent / f"observer-mutant-{name}"
    shutil.copytree(source, target)
    return target


def exercise_public_report_negatives(
    parent: pathlib.Path,
    binary: pathlib.Path,
    prepared: dict[int, tuple[pathlib.Path, pathlib.Path, list[str]]],
    representatives: dict[int, tuple[str, dict[str, Any]]],
    report_path: pathlib.Path,
    signed: dict[str, Any],
) -> None:
    coordinator, deployments, validator_ids = prepared[7]
    validator_id, _ = representatives[7]
    observer = deployments / "observer-public"
    config_relative = pathlib.Path(f"public/configs/{validator_id}.json")
    config = observer / config_relative
    anchor = sha256_file(coordinator / "manifest.json")
    wrong_anchor = report_command(binary, observer, config, report_path, "ff" * 32)
    run(wrong_anchor, expect="observer-public manifest differs", timeout=3)

    missing = clone_observer(parent, observer, "missing-public-config")
    missing_id = next(value for value in validator_ids if value != validator_id)
    (missing / f"public/configs/{missing_id}.json").unlink()
    run(
        report_command(binary, missing, missing / config_relative, report_path, anchor),
        expect="No such file or directory",
        timeout=3,
    )

    extra = clone_observer(parent, observer, "extra-public-config")
    extra_path = extra / "public/configs/uncommitted.json"
    extra_path.write_text("{}", encoding="utf-8")
    extra_path.chmod(0o644)
    run(
        report_command(binary, extra, extra / config_relative, report_path, anchor),
        expect="extra or missing file",
        timeout=3,
    )

    substitute_coordinator, substitute_deployments, _ = prepared[31]
    substitute_id, _ = representatives[31]
    substitute_observer = substitute_deployments / "observer-public"
    run(
        report_command(
            binary,
            substitute_observer,
            substitute_observer / f"public/configs/{substitute_id}.json",
            report_path,
            sha256_file(substitute_coordinator / "manifest.json"),
        ),
        expect="network-smoke report",
        timeout=3,
    )

    unknown = json.loads(report_path.read_text(encoding="utf-8"))
    unknown["report"]["uncommitted_claim"] = True
    unknown_path = parent / "signed-report-unknown-field.json"
    write_json(unknown_path, unknown)
    run(
        report_command(binary, observer, config, unknown_path, anchor),
        expect="decode strict network-smoke report",
        timeout=3,
    )

    symlink_path = parent / "signed-report-symlink.json"
    symlink_path.symlink_to(report_path)
    run(
        report_command(binary, observer, config, symlink_path, anchor),
        expect="open pinned network-smoke report",
        timeout=3,
    )

    fifo_path = parent / "signed-report.fifo"
    os.mkfifo(fifo_path, 0o600)
    run(
        report_command(binary, observer, config, fifo_path, anchor),
        expect="not a regular file",
        timeout=3,
    )

    semantic = json.loads(json.dumps(signed))
    semantic["report"]["core_runtime"] = True
    semantic = sign_report(
        semantic["report"],
        deployments / validator_id / f"secrets/{validator_id}.pk8",
    )
    semantic_path = parent / "signed-report-resigned-semantic-drift.json"
    write_json(semantic_path, semantic)
    run(
        report_command(binary, observer, config, semantic_path, anchor),
        expect="exact bounded semantic profile",
        timeout=3,
    )

def checker_arguments(
    coordinator: pathlib.Path, deployments: pathlib.Path
) -> list[str]:
    return [
        sys.executable,
        str(CHECK_DEPLOYMENTS),
        str(coordinator),
        str(deployments),
        "--validators",
        "7",
    ]


def expect_mutant(
    source: pathlib.Path,
    coordinator: pathlib.Path,
    validator_ids: list[str],
    name: str,
    expected: str,
    mutate,
) -> None:
    target = source.parent / f"mutant-{name}"
    shutil.copytree(source, target)
    mutate(target, validator_ids[0], validator_ids[1])
    run(checker_arguments(coordinator, target), expect=expected)


def manifest_symlink(root: pathlib.Path, first: str, _second: str) -> None:
    manifest = root / first / "manifest.json"
    external = root.parent / "external-identical-manifest.json"
    shutil.copyfile(manifest, external)
    external.chmod(0o600)
    manifest.unlink()
    manifest.symlink_to(external)


def open_manifest_mode(root: pathlib.Path, first: str, _second: str) -> None:
    (root / first / "manifest.json").chmod(0o640)


def wrong_coordinator(root: pathlib.Path, first: str, _second: str) -> None:
    manifest_path = root / first / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["coordinator_manifest_sha256"] = "ff" * 32
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def wrong_material_author(root: pathlib.Path, first: str, _second: str) -> None:
    manifest_path = root / first / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["material_author"]["runtime_deployed"] = True
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def observer_wrong_material_author(root: pathlib.Path, _first: str, _second: str) -> None:
    manifest_path = root / "observer-public/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["material_author"]["binary_sha256"] = "ff" * 32
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def extra_secret(root: pathlib.Path, first: str, second: str) -> None:
    source = root / second / f"secrets/{second}.pk8"
    target = root / first / f"secrets/{second}.pk8"
    shutil.copyfile(source, target)
    target.chmod(0o600)


def missing_config(root: pathlib.Path, first: str, _second: str) -> None:
    (root / first / f"public/configs/{first}.json").unlink()


def cross_validator_config(root: pathlib.Path, first: str, second: str) -> None:
    source = root / second / f"public/configs/{second}.json"
    target = root / first / f"public/configs/{first}.json"
    shutil.copyfile(source, target)


def missing_validator_workload(root: pathlib.Path, first: str, _second: str) -> None:
    (root / first / "public/workload.corpus").unlink()


def tampered_validator_policy(root: pathlib.Path, first: str, _second: str) -> None:
    policy = root / first / "public/workload-policy.json"
    policy.write_bytes(policy.read_bytes() + b"tamper")


def observer_missing_workload(root: pathlib.Path, _first: str, _second: str) -> None:
    (root / "observer-public/public/workload-policy.json").unlink()


def missing_validator_bootstrap(root: pathlib.Path, first: str, _second: str) -> None:
    (root / first / "public/bootstrap/h2.proposal").unlink()


def tampered_validator_bootstrap(root: pathlib.Path, first: str, _second: str) -> None:
    sidecar = root / first / "public/bootstrap/finality-proof.cev0"
    sidecar.write_bytes(sidecar.read_bytes() + b"tamper")


def observer_substituted_bootstrap(root: pathlib.Path, _first: str, _second: str) -> None:
    sidecar = root / "observer-public/public/bootstrap/h3.proposal"
    sidecar.write_bytes((root / "observer-public/public/bootstrap/h2.proposal").read_bytes())


def application_private_key_leak(root: pathlib.Path, first: str, _second: str) -> None:
    source = root / first / f"secrets/{first}.pk8"
    target = root / first / "secrets/workload-application.pk8"
    shutil.copyfile(source, target)
    target.chmod(0o600)


def duplicate_validator_workload_reference(
    root: pathlib.Path, first: str, _second: str
) -> None:
    manifest_path = root / first / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["public_files"].append(
        next(
            dict(reference)
            for reference in manifest["public_files"]
            if reference["path"] == "public/workload.corpus"
        )
    )
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--material-builder", required=True, type=pathlib.Path)
    parser.add_argument("--validator-binary", required=True, type=pathlib.Path)
    args = parser.parse_args()
    material_builder = exact_executable(args.material_builder, "material-builder")
    binary = exact_executable(args.validator_binary, "lab-validator")
    if (
        material_builder.samefile(binary)
        or sha256_file(material_builder) == sha256_file(binary)
    ):
        raise SystemExit("material-builder and lab-validator binaries must be distinct")

    with tempfile.TemporaryDirectory(prefix="poco-g3-validator-deployment-test-") as temporary:
        parent = pathlib.Path(temporary)
        prepared: dict[int, tuple[pathlib.Path, pathlib.Path, list[str]]] = {}
        representatives: dict[int, tuple[str, dict[str, Any]]] = {}
        signed_reports: dict[int, tuple[pathlib.Path, dict[str, Any]]] = {}
        for count in (7, 31, 100):
            prepared[count] = prepare(parent, material_builder, binary, count)
            representatives[count] = verify_representative(binary, *prepared[count])
            coordinator_for_count, deployments_for_count, _ = prepared[count]
            validator_id, config_report = representatives[count]
            signed_reports[count] = verify_signed_report(
                parent,
                binary,
                coordinator_for_count,
                deployments_for_count,
                validator_id,
                config_report,
            )
            verify_consensus_cli_rejects_invalid_bounds_before_effects(
                parent,
                binary,
                deployments_for_count,
                validator_id,
                count,
            )
            verify_workload_crypto_mutants_rejected(
                parent,
                binary,
                deployments_for_count,
                validator_id,
            )
            if count == 7:
                verify_rust_material_author_rejected(
                    parent,
                    binary,
                    deployments_for_count,
                    validator_id,
                )

        coordinator, deployments, validator_ids = prepared[7]
        coordinator_symlink = parent / "coordinator-root-symlink"
        coordinator_symlink.symlink_to(coordinator, target_is_directory=True)
        run(
            checker_arguments(coordinator_symlink, deployments),
            expect="coordinator root must be one private real directory",
        )
        deployment_symlink = parent / "deployment-root-symlink"
        deployment_symlink.symlink_to(deployments, target_is_directory=True)
        run(
            checker_arguments(coordinator, deployment_symlink),
            expect="deployment root must be one private real directory",
        )
        run(
            [
                sys.executable,
                str(PREPARE_DEPLOYMENTS),
                str(coordinator_symlink),
                "--output",
                str(parent / "forbidden-symlink-coordinator-output"),
                "--validators",
                "7",
            ],
            expect="coordinator root must be one real directory",
        )
        run(
            [
                sys.executable,
                str(PREPARE_DEPLOYMENTS),
                str(coordinator),
                "--output",
                str(deployments),
                "--validators",
                "7",
            ],
            expect="deployments are never overwritten",
        )
        deployment_output_symlink = parent / "deployment-output-symlink"
        deployment_output_symlink.symlink_to(
            parent / "missing-deployment-output", target_is_directory=True
        )
        run(
            [
                sys.executable,
                str(PREPARE_DEPLOYMENTS),
                str(coordinator),
                "--output",
                str(deployment_output_symlink),
                "--validators",
                "7",
            ],
            expect="output root already exists",
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "manifest-symlink",
            "private regular non-symlink file",
            manifest_symlink,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "manifest-mode",
            "private regular non-symlink file",
            open_manifest_mode,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "coordinator-substitution",
            "differs from coordinator truth",
            wrong_coordinator,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "validator-material-author-substitution",
            "differs from coordinator truth",
            wrong_material_author,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "observer-material-author-substitution",
            "differs from coordinator truth",
            observer_wrong_material_author,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "extra-secret",
            "extra or missing files",
            extra_secret,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "missing-config",
            "file differs from coordinator input",
            missing_config,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "cross-validator-config",
            "file differs from coordinator input",
            cross_validator_config,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "observer-manifest-symlink",
            "private regular non-symlink file",
            observer_manifest_symlink,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "observer-coordinator-manifest-symlink",
            "coordinator manifest must be one private regular non-symlink file",
            observer_coordinator_manifest_symlink,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "observer-secret-leak",
            "extra, missing, or secret files",
            observer_extra_secret,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "observer-missing-config",
            "file differs from coordinator input",
            observer_missing_config,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "observer-cross-validator-config",
            "file differs from coordinator input",
            observer_cross_config,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "missing-validator-workload",
            "file differs from coordinator input",
            missing_validator_workload,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "tampered-validator-policy",
            "file differs from coordinator input",
            tampered_validator_policy,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "observer-missing-workload",
            "file differs from coordinator input",
            observer_missing_workload,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "missing-validator-bootstrap",
            "file differs from coordinator input",
            missing_validator_bootstrap,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "tampered-validator-bootstrap",
            "file differs from coordinator input",
            tampered_validator_bootstrap,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "observer-substituted-bootstrap",
            "file differs from coordinator input",
            observer_substituted_bootstrap,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "application-private-key-leak",
            "extra or missing files",
            application_private_key_leak,
        )
        expect_mutant(
            deployments,
            coordinator,
            validator_ids,
            "duplicate-validator-workload-reference",
            "non-minimal file reference set",
            duplicate_validator_workload_reference,
        )
        exercise_public_report_negatives(
            parent,
            binary,
            prepared,
            representatives,
            *signed_reports[7],
        )

    print(
        "poco_g3_validator_deployment_self_test=passed "
        "topology_positives=3 rust_verify_config_positives=3 "
        "rust_public_report_positives=3 rust_consensus_cli_fail_closed_positives=3 negatives=53 "
        "least_authority=true public_workload_everywhere=true public_bootstrap_everywhere=true "
        "ordinary_start_height=4 "
        "ordinal_nonce=true application_private_keys=false "
        "rust_workload_crypto_mutants_rejected=18 "
        "observer_public_bundle=true "
        "coordinator_manifest_anchor=true signed_report_semantics=true "
        "manifest_symlink_rejected=true report_fifo_rejected=true "
        "root_symlinks_rejected=true generator_output_symlink_rejected=true "
        "material_builder_validator_binary_distinct=true "
        "material_author_hash_bound=true material_author_runtime_deployed=false "
        "secret_leakage_rejected=true bootstrap_runtime_closed=false "
        "multihost_observed=false geo_wan=false production_activation=false"
    )


if __name__ == "__main__":
    main()
