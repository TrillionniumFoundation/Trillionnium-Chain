#!/usr/bin/env python3
"""No-Cargo fixture and mutation controls for the scoped Stage0 bundle."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import tomllib
import types


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import assemble_stage0_direct_seven_bundle_v1 as assembler  # noqa: E402
import check_run_bundle_test as bundle_fixture  # noqa: E402
import check_source_candidate  # noqa: E402
import check_stage0_direct_seven_bundle_v1 as checker  # noqa: E402
import collect_no_fault_run_bundle_v1_test as runner_fixture  # noqa: E402
import run_consensus_fleet as consensus_runner  # noqa: E402


def run(arguments: list[str]) -> None:
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name)
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {result.stdout}{result.stderr}"
        )


def write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(checker.canonical_json(value))


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_rust_json(
    path: pathlib.Path, value: dict, keys: tuple[str, ...]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(checker.compact_ordered_json(value, keys) + b"\n")


def sign_fixture(secret_bytes: bytes, message: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="poco-stage0-replay-sign-") as raw:
        root = pathlib.Path(raw)
        secret = root / "secret.pk8"
        payload = root / "payload.bin"
        secret.write_bytes(secret_bytes)
        payload.write_bytes(message)
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
                str(payload),
            ],
            check=True,
            capture_output=True,
        ).stdout
    if len(signature) != 64:
        raise AssertionError("fixture terminal-seal signature is not Ed25519")
    return signature.hex()


def install_authenticated_replay_fixtures(base: pathlib.Path) -> None:
    coordinator = base / "coordinator"
    runner = base / "runner"
    validator_set = read_json(coordinator / "public/validator-set.json")
    plan = read_json(runner / "prestart-plan.json")
    summary_path = runner / "consensus-run-summary.json"
    summary = read_json(summary_path)
    process_by_id = {
        process["validator_id"]: process for process in summary["processes"]
    }
    set_id = checker.signed_evidence.validator_set_id(validator_set)
    validator_by_id = {
        validator["validator_id"]: validator
        for validator in validator_set["validators"]
    }
    anchor = digest(coordinator / "manifest.json")
    candidate_sha256 = digest(base / "supplies/source.artifact")
    validator_set_sha256 = digest(coordinator / "public/validator-set.json")
    topology_sha256 = digest(coordinator / "topology.json")
    signer_lifetime = plan["signer_lifetime"]
    archive_lifetime = plan["signed_replay_archive_lifetime"]

    for validator_id in sorted(validator_by_id):
        process = process_by_id[validator_id]
        validator = validator_by_id[validator_id]
        config_path = coordinator / f"public/configs/{validator_id}.json"
        config = read_json(config_path)
        context = {
            "schema_version": 1,
            "run_id": summary["run_id"],
            "chain_id": validator_set["chain_id"],
            "genesis_hash": validator_set["genesis_hash"],
            "validator_set_id": set_id,
            "local_validator_id": validator_id,
            "local_consensus_public_key": validator["consensus_public_key"],
            "coordinator_manifest_sha256": anchor,
            "validator_set_sha256": validator_set_sha256,
            "topology_sha256": topology_sha256,
            "config_sha256": digest(config_path),
            "candidate_source_sha256": candidate_sha256,
            "binary_sha256": config["binary_sha256"],
            "workload_corpus_sha256": config["workload_corpus_sha256"],
            "workload_policy_sha256": config["workload_policy_sha256"],
            "ordinary_start_height": config["ordinary_start_height"],
            "maximum_timeout_view_advances": signer_lifetime[
                "maximum_timeout_view_advances"
            ],
            "maximum_proposal_entries": archive_lifetime[
                "maximum_proposal_entries"
            ],
            "maximum_quorum_certificate_entries": archive_lifetime[
                "maximum_quorum_certificate_entries"
            ],
            "maximum_archive_entries": archive_lifetime["maximum_total_entries"],
            "context_sha256": "",
        }
        numeric = (
            context["ordinary_start_height"],
            context["maximum_timeout_view_advances"],
            context["maximum_proposal_entries"],
            context["maximum_quorum_certificate_entries"],
            context["maximum_archive_entries"],
        )
        context_digest = checker.hash_parts(
            checker.REPLAY_CONTEXT_DOMAIN,
            (
                context["run_id"].encode("utf-8"),
                context["chain_id"].encode("utf-8"),
                *(bytes.fromhex(context[field]) for field in (
                    "genesis_hash",
                    "validator_set_id",
                    "local_validator_id",
                    "local_consensus_public_key",
                    "coordinator_manifest_sha256",
                    "validator_set_sha256",
                    "topology_sha256",
                    "config_sha256",
                    "candidate_source_sha256",
                    "binary_sha256",
                    "workload_corpus_sha256",
                    "workload_policy_sha256",
                )),
                *(int(value).to_bytes(8, "big") for value in numeric),
            ),
        )
        context["context_sha256"] = context_digest.hex()
        context_path = (
            runner / f"signed-replay-archive-contexts/{validator_id}.json"
        )
        write_rust_json(context_path, context, checker.REPLAY_CONTEXT_KEYS)

        prior = checker.hash_parts(checker.REPLAY_GENESIS_DOMAIN, (context_digest,))
        entry_lines: list[bytes] = []
        proposal_count = 8
        quorum_certificate_count = 2
        for sequence in range(1, proposal_count + quorum_certificate_count + 1):
            kind = "proposal" if sequence <= proposal_count else "quorum-certificate"
            kind_code = b"\x01" if kind == "proposal" else b"\x02"
            payload = hashlib.sha256(
                f"{validator_id}:{kind}:{sequence}".encode("ascii")
            ).digest()
            block_id = hashlib.sha256(b"block:" + payload).digest()
            content_digest = checker.hash_parts(
                checker.REPLAY_CONTENT_DOMAIN, (kind_code, payload)
            )
            record_digest = checker.hash_parts(
                checker.REPLAY_RECORD_DOMAIN,
                (
                    context_digest,
                    sequence.to_bytes(8, "big"),
                    prior,
                    kind_code,
                    sequence.to_bytes(8, "big"),
                    sequence.to_bytes(8, "big"),
                    block_id,
                    content_digest,
                ),
            )
            entry = {
                "schema_version": 1,
                "sequence": sequence,
                "context_sha256": context_digest.hex(),
                "previous_record_sha256": prior.hex(),
                "kind": kind,
                "height": sequence,
                "view": sequence,
                "block_id": block_id.hex(),
                "content_sha256": content_digest.hex(),
                "payload_hex": payload.hex(),
                "record_sha256": record_digest.hex(),
            }
            entry_lines.append(
                checker.compact_ordered_json(entry, checker.REPLAY_ENTRY_KEYS) + b"\n"
            )
            prior = record_digest
        entries_path = (
            runner / f"signed-replay-archive-entries/{validator_id}.jsonl"
        )
        entries_path.write_bytes(b"".join(entry_lines))
        head = {
            "schema_version": 1,
            "sequence": len(entry_lines),
            "context_sha256": context_digest.hex(),
            "record_sha256": prior.hex(),
        }
        head_path = runner / f"signed-replay-archive-heads/{validator_id}.json"
        write_rust_json(head_path, head, checker.REPLAY_HEAD_KEYS)

        final_state = read_json(
            runner / f"signed-runtime-final-states/{validator_id}.json"
        )
        journal_lines = (
            runner / f"signed-runtime-journals/{validator_id}.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        clean_stop = json.loads(journal_lines[-1])
        journal_verification = process["observer_journal_verification"]
        journal_verification["runtime_event_sequence"] = clean_stop["sequence"]
        journal_verification["runtime_event_sha256"] = clean_stop["event_sha256"]
        replay = process["observer_replay_archive_verification"]
        seal = {
            "schema_version": 1,
            "run_id": summary["run_id"],
            "validator_id": validator_id,
            "validator_set_id": set_id,
            "validator_set_sha256": validator_set_sha256,
            "topology_sha256": topology_sha256,
            "coordinator_manifest_sha256": anchor,
            "candidate_source_sha256": candidate_sha256,
            "binary_sha256": config["binary_sha256"],
            "config_sha256": digest(config_path),
            "fleet_start_certificate_sha256": digest(
                runner / f"fleet-start-certificates/{validator_id}.bin"
            ),
            "process_instance": final_state["process_instance_count"],
            "clean_stop_journal_sequence": clean_stop["sequence"],
            "clean_stop_journal_sha256": clean_stop["event_sha256"],
            "finalized_height": final_state["finalized_height"],
            "finalized_block_id": final_state["finalized_block_id"],
            "finalized_state_root": final_state["finalized_state_root"],
            "finalized_chain_root": final_state["finalized_chain_root"],
            "finality_proof_id": replay["finality_proof_id"],
            "finality_child_block_id": replay["finality_child_block_id"],
            "finality_grandchild_block_id": replay["finality_grandchild_block_id"],
            "archive_context_sha256": context_digest.hex(),
            "archive_context_file_sha256": digest(context_path),
            "archive_context_file_bytes": context_path.stat().st_size,
            "archive_entries_file_sha256": digest(entries_path),
            "archive_entries_file_bytes": entries_path.stat().st_size,
            "archive_head_file_sha256": digest(head_path),
            "archive_head_file_bytes": head_path.stat().st_size,
            "terminal_archive_sequence": len(entry_lines),
            "terminal_archive_record_sha256": prior.hex(),
            "proposal_count": proposal_count,
            "quorum_certificate_count": quorum_certificate_count,
            "body_sha256": "",
            "signature": "",
        }
        seal_body = checker.hash_parts(
            checker.REPLAY_TERMINAL_BODY_DOMAIN,
            (checker.compact_ordered_json(seal, checker.REPLAY_TERMINAL_SEAL_KEYS),),
        )
        seal["body_sha256"] = seal_body.hex()
        secret_bytes = bundle_fixture.validator_auth(
            summary["run_id"], validator_id, "consensus"
        )[2]
        seal["signature"] = sign_fixture(
            secret_bytes,
            checker.hash_parts(
                checker.REPLAY_TERMINAL_SIGNATURE_DOMAIN, (seal_body,)
            ),
        )
        seal_path = (
            runner / f"signed-replay-archive-terminal-seals/{validator_id}.json"
        )
        write_rust_json(seal_path, seal, checker.REPLAY_TERMINAL_SEAL_KEYS)

        process["replay_archive_context_sha256"] = digest(context_path)
        process["replay_archive_entries_sha256"] = digest(entries_path)
        process["replay_archive_head_sha256"] = digest(head_path)
        process["replay_archive_terminal_seal_sha256"] = digest(seal_path)
        for field in (
            "fleet_start_certificate_sha256",
            "clean_stop_journal_sequence",
            "clean_stop_journal_sha256",
            "finalized_height",
            "finalized_block_id",
            "finalized_state_root",
            "finalized_chain_root",
            "finality_proof_id",
            "finality_child_block_id",
            "finality_grandchild_block_id",
            "archive_context_sha256",
            "archive_context_file_sha256",
            "archive_entries_file_sha256",
            "archive_head_file_sha256",
            "terminal_archive_sequence",
            "terminal_archive_record_sha256",
            "proposal_count",
            "quorum_certificate_count",
        ):
            replay[field] = seal[field]

    write_json(summary_path, summary)
    (runner / "runner-output-manifest.json").unlink()
    consensus_runner.write_runner_output_manifest(
        runner,
        run_id=summary["run_id"],
        validator_count=summary["validator_count"],
        coordinator_anchor=anchor,
    )


def init_candidate(root: pathlib.Path) -> pathlib.Path:
    repository = root / "candidate-repository"
    repository.mkdir()
    run(["git", "-C", str(repository), "init", "-q"])
    run(["git", "-C", str(repository), "config", "user.email", "test@invalid"])
    run(["git", "-C", str(repository), "config", "user.name", "PoCO fixture"])
    (repository / "trillionnium").mkdir()
    (repository / "trillionnium/Cargo.lock").write_text(
        "# Stage0 fixture lock\nversion = 4\n", encoding="utf-8"
    )
    (repository / "candidate.txt").write_text(
        "scoped direct-seven fixture\n", encoding="utf-8"
    )
    run(["git", "-C", str(repository), "add", "."])
    run(["git", "-C", str(repository), "commit", "-qm", "fixture"])
    candidate = root / "source.tar"
    run(
        [
            sys.executable,
            str(HERE / "prepare_source_candidate.py"),
            str(repository),
            "--output",
            str(candidate),
            "--require-clean",
        ]
    )
    return candidate


def rewrite_aggregate(path: pathlib.Path, candidate: pathlib.Path) -> None:
    report = read_json(path)
    facts = check_source_candidate.validate(candidate, require_clean=True)
    report.update(
        {
            "source_tree_sha256": facts["source_candidate_sha256"],
            "source_candidate_profile": facts["source_profile"],
            "source_base_commit": facts["base_commit"],
            "source_git_object_format": facts["git_object_format"],
            "source_git_tree_oid": facts["git_tree_oid"],
            "source_git_status_sha256": facts["git_status_sha256"],
            "cargo_lock_path": facts["cargo_lock_path"],
            "cargo_lock_sha256": facts["cargo_lock_sha256"],
            "cargo_lock_bytes": facts["cargo_lock_bytes"],
        }
    )
    write_json(path, report)


def preflight_documents(inventory_path: pathlib.Path) -> tuple[dict, dict]:
    with inventory_path.open("rb") as source:
        inventory = tomllib.load(source)
    run_start = int(
        datetime.datetime(
            2026, 8, 13, 12, 0, 0, tzinfo=datetime.timezone.utc
        ).timestamp()
    )
    probe_epoch = run_start - 10
    readiness_epoch = run_start - 5
    hosts = inventory["hosts"]
    lan_ips = [host["lan_ip"] for host in hosts]
    probe_observations = []
    readiness_observations = []
    for host in hosts:
        system = "Darwin" if host["os"] == "macos" else "Linux"
        probe_observations.append(
            {
                "id": host["id"],
                "lan_ip": host["lan_ip"],
                "management": host["management"],
                "round_trip_ns": 1,
                "facts": {
                    "hostname": f"fixture-{host['id']}",
                    "kernel": f"{system} fixture-kernel",
                    "arch": host["arch"],
                    "cpu_threads": str(host["cpu_threads"]),
                    "memory_bytes": str(host["memory_bytes"]),
                    "epoch_ns": str(probe_epoch * 1_000_000_000),
                },
            }
        )
        facts = {
            "hostname": f"fixture-{host['id']}",
            "os": system,
            "arch": host["arch"],
            "tmp_free_bytes": str(8 * 1024**3),
            "nofile_soft": "65536",
            "nofile_hard": "65536",
            "python3": "/usr/bin/python3",
            "tar": "/usr/bin/tar",
            "sha256": "/usr/bin/sha256sum",
            "cargo": "/usr/bin/cargo",
            "rustc": "/usr/bin/rustc",
            "sudo_nopass": "ok",
            "network_fault_tool": (
                "/sbin/pfctl"
                if host["os"] == "macos"
                else "/usr/sbin/tc+/usr/sbin/nft"
            ),
            "process_inspector": (
                "/usr/sbin/lsof" if host["os"] == "macos" else "/usr/bin/ss"
            ),
            "epoch": str(readiness_epoch),
            "poco_listeners": "0",
        }
        facts.update({f"ping_{ip}": "ok" for ip in lan_ips})
        readiness_observations.append(
            {"id": host["id"], "lan_ip": host["lan_ip"], "facts": facts}
        )
    probe = {
        "schema_version": 1,
        "fleet_id": inventory["fleet_id"],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "observed_at_epoch_ns": probe_epoch * 1_000_000_000,
        "observations": probe_observations,
        "failures": [],
    }
    readiness = {
        "schema_version": 2,
        "fleet_id": inventory["fleet_id"],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "validator_run_completed": False,
        "probe_completed_at_epoch": readiness_epoch,
        "observed_epoch_spread_seconds": 0,
        "observations": readiness_observations,
        "failures": [],
    }
    return probe, readiness


def prepare(root: pathlib.Path) -> dict[str, pathlib.Path | str]:
    candidate = init_candidate(root)
    candidate_bytes = candidate.read_bytes()
    original_artifact = bundle_fixture.artifact
    original_fixture_digest = bundle_fixture.evidence_test.digest

    def candidate_artifact(
        target: pathlib.Path,
        role: str,
        subject: str,
        relative: str,
        payload: bytes,
    ) -> dict:
        if role == "candidate_source":
            payload = candidate_bytes
        elif role in {"workload_policy", "bootstrap_manifest"}:
            # The older run-bundle fixture treats these as opaque bytes.  This
            # checker also exercises exact-JSON framing for their real suffix.
            payload = b"{}\n"
        return original_artifact(target, role, subject, relative, payload)

    def fixture_digest(value: str) -> str:
        if value == "source":
            return hashlib.sha256(candidate_bytes).hexdigest()
        if value == "workload-policy":
            return hashlib.sha256(b"{}\n").hexdigest()
        return original_fixture_digest(value)

    bundle_fixture.artifact = candidate_artifact
    bundle_fixture.evidence_test.digest = fixture_digest
    base = root / "evidence"
    base.mkdir()
    try:
        runner_fixture.prepare(base)
    finally:
        bundle_fixture.artifact = original_artifact
        bundle_fixture.evidence_test.digest = original_fixture_digest
    rewrite_aggregate(base / "supplies/build-report.json", candidate)
    install_authenticated_replay_fixtures(base)
    macos_builder = base / "supplies/macos-material-builder.bin"
    macos_builder.write_bytes(b"macos-material-builder")
    macos_builder.chmod(0o755)
    inventory = HERE / "inventory.toml"
    probe, readiness = preflight_documents(inventory)
    probe_path = root / "probe-fleet-v1.json"
    readiness_path = root / "run-readiness-v2.json"
    write_json(probe_path, probe)
    write_json(readiness_path, readiness)
    return {
        "candidate_source": base / "supplies/source.artifact",
        "aggregate_build_report": base / "supplies/build-report.json",
        "linux_validator_binary": base / "supplies/linux.bin",
        "linux_material_builder_binary": base / "supplies/material-builder.bin",
        "macos_validator_binary": base / "supplies/macos.bin",
        "macos_material_builder_binary": macos_builder,
        "fleet_inventory": inventory,
        "probe_fleet": probe_path,
        "run_readiness": readiness_path,
        "coordinator_root": base / "coordinator",
        "runner_output": base / "runner",
        "coordinator_manifest_sha256": digest(base / "coordinator/manifest.json"),
    }


def assemble_case(source: dict[str, pathlib.Path | str], output: pathlib.Path) -> None:
    assembler.assemble(**source, output=output)


def refresh_outer(bundle: pathlib.Path) -> None:
    manifest_path = bundle / "manifest.json"
    manifest = read_json(manifest_path)
    expected = checker.expected_artifact_identities(bundle)
    records = []
    for relative, (role, subject) in expected.items():
        path = bundle.joinpath(*pathlib.PurePosixPath(relative).parts)
        records.append(
            {
                "role": role,
                "subject": subject,
                "path": relative,
                "sha256": digest(path),
                "bytes": path.stat().st_size,
            }
        )
    records.sort(key=lambda item: (item["role"], item["subject"], item["path"]))
    manifest["artifacts"] = records
    manifest["ordered_artifact_root"] = checker.ordered_artifact_root(records)
    manifest_path.chmod(0o600)
    write_json(manifest_path, manifest)


def refresh_runner(bundle: pathlib.Path) -> None:
    root = bundle / "runner"
    summary = read_json(root / "consensus-run-summary.json")
    (root / "runner-output-manifest.json").unlink()
    consensus_runner.write_runner_output_manifest(
        root,
        run_id=summary["run_id"],
        validator_count=summary["validator_count"],
        coordinator_anchor=summary["coordinator_manifest_sha256"],
    )
    refresh_outer(bundle)


def refresh_outer_path_reference(bundle: pathlib.Path, relative: str) -> None:
    """Refresh one nested content address without parsing the mutated JSON."""

    manifest_path = bundle / "manifest.json"
    manifest = read_json(manifest_path)
    for artifact in manifest["artifacts"]:
        if artifact["path"] == relative:
            path = bundle.joinpath(*pathlib.PurePosixPath(relative).parts)
            artifact["sha256"] = digest(path)
            artifact["bytes"] = path.stat().st_size
            break
    else:
        raise AssertionError(f"outer manifest omits {relative}")
    manifest["ordered_artifact_root"] = checker.ordered_artifact_root(
        manifest["artifacts"]
    )
    manifest_path.chmod(0o600)
    write_json(manifest_path, manifest)


def reject(
    positive: pathlib.Path,
    root: pathlib.Path,
    label: str,
    mutation,
    expected: str,
) -> None:
    case = root / f"case-{label}"
    shutil.copytree(positive, case)
    mutation(case)
    try:
        checker.validate(case, emit=False)
    except SystemExit as error:
        if expected not in str(error):
            raise AssertionError(
                f"{label} expected {expected!r}, observed {error!s}"
            ) from error
    else:
        raise AssertionError(f"mutant {label!r} unexpectedly passed")


def duplicate_manifest_key(bundle: pathlib.Path) -> None:
    path = bundle / "manifest.json"
    raw = path.read_bytes()
    path.chmod(0o600)
    path.write_bytes(raw.replace(b'{\n  "artifacts"', b'{\n  "artifacts": [],\n  "artifacts"', 1))


def trailing_manifest(bundle: pathlib.Path) -> None:
    path = bundle / "manifest.json"
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b" \n")


def duplicate_role(bundle: pathlib.Path) -> None:
    path = bundle / "manifest.json"
    manifest = read_json(path)
    manifest["artifacts"][1]["role"] = manifest["artifacts"][0]["role"]
    manifest["artifacts"][1]["subject"] = manifest["artifacts"][0]["subject"]
    manifest["artifacts"].sort(
        key=lambda item: (item["role"], item["subject"], item["path"])
    )
    manifest["ordered_artifact_root"] = checker.ordered_artifact_root(
        manifest["artifacts"]
    )
    path.chmod(0o600)
    write_json(path, manifest)


def stale_probe(bundle: pathlib.Path) -> None:
    path = bundle / "preflight/probe-fleet-v1.json"
    value = read_json(path)
    value["observed_at_epoch_ns"] -= (
        checker.MAXIMUM_PREFLIGHT_AGE_SECONDS + 1
    ) * 1_000_000_000
    path.chmod(0o600)
    write_json(path, value)
    refresh_outer(bundle)


def aggregate_mac_builder_substitution(bundle: pathlib.Path) -> None:
    path = bundle / "candidate/aggregate-build-report.json"
    value = read_json(path)
    value["macos_material_builder_first_sha256"] = "f" * 64
    value["macos_material_builder_second_sha256"] = "f" * 64
    path.chmod(0o600)
    write_json(path, value)
    refresh_outer(bundle)


def runner_failure(bundle: pathlib.Path) -> None:
    path = bundle / "runner/consensus-run-summary.json"
    value = read_json(path)
    value["failure"] = "fixture failure"
    path.chmod(0o600)
    write_json(path, value)
    refresh_runner(bundle)


def runner_cleanup_failure(bundle: pathlib.Path) -> None:
    path = bundle / "runner/consensus-run-summary.json"
    value = read_json(path)
    value["cleanup_failures"] = ["fixture cleanup failure"]
    path.chmod(0o600)
    write_json(path, value)
    refresh_runner(bundle)


def observer_verification_removed(bundle: pathlib.Path) -> None:
    path = bundle / "runner/consensus-run-summary.json"
    value = read_json(path)
    value["processes"][0]["observer_report_verification"][
        "signature_verified"
    ] = False
    path.chmod(0o600)
    write_json(path, value)
    refresh_runner(bundle)


def raw_replay_substitution(bundle: pathlib.Path) -> None:
    """Reproduce the legacy summary-only replay acceptance attack."""

    root = bundle / "runner"
    summary_path = root / "consensus-run-summary.json"
    summary = read_json(summary_path)
    process = summary["processes"][0]
    validator_id = process["validator_id"]
    replacements = (
        (
            "signed-replay-archive-contexts",
            ".json",
            "replay_archive_context_sha256",
            "archive_context_file_sha256",
        ),
        (
            "signed-replay-archive-entries",
            ".jsonl",
            "replay_archive_entries_sha256",
            "archive_entries_file_sha256",
        ),
        (
            "signed-replay-archive-heads",
            ".json",
            "replay_archive_head_sha256",
            "archive_head_file_sha256",
        ),
    )
    for directory, suffix, process_field, observer_field in replacements:
        artifact = root / directory / f"{validator_id}{suffix}"
        artifact.chmod(0o600)
        artifact.write_bytes(b"{}\n")
        replacement_hash = digest(artifact)
        process[process_field] = replacement_hash
        process["observer_replay_archive_verification"][observer_field] = (
            replacement_hash
        )
    terminal = (
        root / f"signed-replay-archive-terminal-seals/{validator_id}.json"
    )
    terminal.chmod(0o600)
    terminal.write_bytes(b"{}\n")
    process["replay_archive_terminal_seal_sha256"] = digest(terminal)
    summary_path.chmod(0o600)
    write_json(summary_path, summary)
    refresh_runner(bundle)


def replay_entry_content_mutation(bundle: pathlib.Path) -> None:
    root = bundle / "runner"
    summary_path = root / "consensus-run-summary.json"
    summary = read_json(summary_path)
    process = summary["processes"][0]
    validator_id = process["validator_id"]
    entries = root / f"signed-replay-archive-entries/{validator_id}.jsonl"
    lines = entries.read_bytes().splitlines()
    first = json.loads(lines[0])
    first["payload_hex"] = ("00" if first["payload_hex"][:2] != "00" else "01") + first[
        "payload_hex"
    ][2:]
    lines[0] = checker.compact_ordered_json(first, checker.REPLAY_ENTRY_KEYS)
    entries.chmod(0o600)
    entries.write_bytes(b"\n".join(lines) + b"\n")
    replacement_hash = digest(entries)
    process["replay_archive_entries_sha256"] = replacement_hash
    process["observer_replay_archive_verification"][
        "archive_entries_file_sha256"
    ] = replacement_hash
    summary_path.chmod(0o600)
    write_json(summary_path, summary)
    refresh_runner(bundle)


def terminal_seal_signature_mutation(bundle: pathlib.Path) -> None:
    root = bundle / "runner"
    summary_path = root / "consensus-run-summary.json"
    summary = read_json(summary_path)
    process = summary["processes"][0]
    validator_id = process["validator_id"]
    seal_path = root / f"signed-replay-archive-terminal-seals/{validator_id}.json"
    seal = read_json(seal_path)
    seal["signature"] = "00" * 64
    seal_path.chmod(0o600)
    write_rust_json(seal_path, seal, checker.REPLAY_TERMINAL_SEAL_KEYS)
    process["replay_archive_terminal_seal_sha256"] = digest(seal_path)
    summary_path.chmod(0o600)
    write_json(summary_path, summary)
    refresh_runner(bundle)


def terminal_disagreement(bundle: pathlib.Path) -> None:
    path = bundle / "runner/consensus-run-summary.json"
    value = read_json(path)
    value["terminal_agreement"]["finalized_height"] += 1
    path.chmod(0o600)
    write_json(path, value)
    refresh_runner(bundle)


def completion_inflation(bundle: pathlib.Path) -> None:
    path = bundle / "runner/consensus-run-summary.json"
    value = read_json(path)
    value["validator_run_completed"] = True
    path.chmod(0o600)
    write_json(path, value)
    # The runner manifest writer itself must reject this legacy truth inflation.
    root = bundle / "runner"
    (root / "runner-output-manifest.json").unlink()
    try:
        consensus_runner.write_runner_output_manifest(
            root,
            run_id=value["run_id"],
            validator_count=value["validator_count"],
            coordinator_anchor=value["coordinator_manifest_sha256"],
        )
    except SystemExit:
        # Leave an invalid/missing inner manifest for the independent checker.
        pass


def symlink_artifact(bundle: pathlib.Path) -> None:
    path = bundle / "preflight/probe-fleet-v1.json"
    saved = bundle / "saved-probe.json"
    path.rename(saved)
    path.symlink_to(saved.name)


def extra_secret(bundle: pathlib.Path) -> None:
    path = bundle / "coordinator/secrets/consensus/fixture.pk8"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"must-not-be-bundled")


def outer_schema(bundle: pathlib.Path, value: object) -> None:
    path = bundle / "manifest.json"
    manifest = read_json(path)
    manifest["schema_version"] = value
    path.chmod(0o600)
    write_json(path, manifest)


def runner_schema(bundle: pathlib.Path, value: object) -> None:
    relative = "runner/runner-output-manifest.json"
    path = bundle / relative
    manifest = read_json(path)
    manifest["schema_version"] = value
    path.chmod(0o600)
    write_json(path, manifest)
    refresh_outer_path_reference(bundle, relative)


def assert_system_exit(action, expected: str) -> None:
    try:
        action()
    except SystemExit as error:
        if expected not in str(error):
            raise AssertionError(
                f"expected rejection containing {expected!r}, observed {error!s}"
            ) from error
    else:
        raise AssertionError("negative control unexpectedly passed")


def assembler_public_secret_prewrite_rejection(
    source: dict[str, pathlib.Path | str], root: pathlib.Path
) -> None:
    coordinator = root / "malicious-coordinator"
    shutil.copytree(pathlib.Path(source["coordinator_root"]), coordinator)
    manifest_path = coordinator / "manifest.json"
    manifest = read_json(manifest_path)
    manifest["public_files"].append(dict(manifest["secret_files"][0]))
    manifest_path.chmod(0o600)
    write_json(manifest_path, manifest)
    malicious = dict(source)
    malicious["coordinator_root"] = coordinator
    malicious["coordinator_manifest_sha256"] = digest(manifest_path)
    output = root / "must-remain-absent-public-secret"
    assert_system_exit(
        lambda: assemble_case(malicious, output),
        "public/secret inventory is not closed",
    )
    if output.exists() or output.is_symlink():
        raise AssertionError("malicious public secret created output bytes")


def assembler_oversized_prewrite_rejection(
    source: dict[str, pathlib.Path | str], root: pathlib.Path
) -> None:
    oversized = root / "oversized-validator.bin"
    with oversized.open("wb") as stream:
        stream.truncate(checker.MAXIMUM_FILE_BYTES + 1)
    oversized.chmod(0o755)
    malicious = dict(source)
    malicious["linux_validator_binary"] = oversized
    output = root / "must-remain-absent-oversized"
    assert_system_exit(
        lambda: assemble_case(malicious, output),
        "bounded regular non-symlink",
    )
    if output.exists() or output.is_symlink():
        raise AssertionError("oversized input created output bytes")


def assembler_low_disk_prewrite_rejection(
    source: dict[str, pathlib.Path | str], root: pathlib.Path
) -> None:
    output = root / "must-remain-absent-low-disk"
    original = assembler._OUTPUT_STATVFS_V1
    assembler._OUTPUT_STATVFS_V1 = lambda _descriptor: types.SimpleNamespace(
        f_bavail=0,
        f_frsize=4096,
    )
    try:
        assert_system_exit(
            lambda: assemble_case(source, output),
            "output filesystem lacks the bounded bundle plus safety reserve",
        )
    finally:
        assembler._OUTPUT_STATVFS_V1 = original
    if output.exists() or output.is_symlink():
        raise AssertionError("low-disk admission created output bytes")


def assembler_double_slash_disjoint_rejection(
    source: dict[str, pathlib.Path | str], root: pathlib.Path
) -> None:
    coordinator = pathlib.Path(source["coordinator_root"])
    output = pathlib.Path(
        "//" + (coordinator / "nested-output-must-not-exist").as_posix().lstrip("/")
    )
    assert_system_exit(
        lambda: assemble_case(source, output),
        "output must remain disjoint from every input path",
    )
    if output.exists() or output.is_symlink():
        raise AssertionError("double-leading-slash alias created nested input output")


def tree_entry_count_boundary_rejection(root: pathlib.Path) -> None:
    tree = root / "tree-entry-count-boundary"
    tree.mkdir()
    for index in range(checker.MAXIMUM_FILE_COUNT + 1):
        (tree / f"entry-{index:05d}").touch()
    assert_system_exit(
        lambda: checker.tree_files(tree),
        "file/directory entry-count bound",
    )
    deep_root = root / "tree-depth-boundary"
    cursor = deep_root
    for index in range(checker.MAXIMUM_TREE_DEPTH + 1):
        cursor /= f"d{index:02d}"
        cursor.mkdir(parents=True)
    assert_system_exit(
        lambda: checker.tree_files(deep_root),
        "directory-depth bound",
    )


def ancestor_swap_controls(root: pathlib.Path) -> None:
    def one_source(label: str) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, object]:
        base = root / label
        ancestor = base / "ancestor"
        victim = ancestor / "nested/artifact.bin"
        victim.parent.mkdir(parents=True)
        victim.write_bytes(b"same bounded bytes")
        held = base / "held"

        def swap() -> None:
            ancestor.rename(held)
            replacement = ancestor / "nested/artifact.bin"
            replacement.parent.mkdir(parents=True)
            replacement.write_bytes(b"same bounded bytes")

        return ancestor, victim, held, swap

    def restore(ancestor: pathlib.Path, held: pathlib.Path) -> None:
        shutil.rmtree(ancestor)
        held.rename(ancestor)

    ancestor, victim, held, swap = one_source("read-ancestor-swap")
    try:
        assert_system_exit(
            lambda: checker.read_pinned(
                victim,
                "ancestor-swap read",
                allow_empty=False,
                capture=True,
                _after_ancestors_pinned=swap,
            ),
            "pinned ancestor path was replaced",
        )
    finally:
        restore(ancestor, held)

    ancestor, victim, held, swap = one_source("tree-ancestor-swap")
    try:
        assert_system_exit(
            lambda: checker.tree_files(
                ancestor,
                _after_root_ancestors_pinned=swap,
            ),
            "pinned ancestor path was replaced",
        )
    finally:
        restore(ancestor, held)

    ancestor, victim, held, swap = one_source("copy-ancestor-swap")
    output = assembler.OutputTree.create(root / "copy-race-output")
    try:
        assert_system_exit(
            lambda: assembler.copy_pinned(
                victim,
                output,
                "artifact.bin",
                "ancestor-swap copy",
                _after_source_ancestors_pinned=swap,
            ),
            "pinned ancestor path was replaced",
        )
        if checker.tree_files(output.path):
            raise AssertionError("source ancestor swap created copied output bytes")
    finally:
        restore(ancestor, held)
        output.cleanup()
        output.close()

    target_source = root / "copy-target-source.bin"
    target_source.write_bytes(b"target ancestor swap bytes")
    target_output = assembler.OutputTree.create(root / "copy-target-race-output")
    held_target = target_output.path / "held-nested"

    def swap_target_ancestor() -> None:
        nested = target_output.path / "nested"
        nested.rename(held_target)
        nested.mkdir()

    try:
        assert_system_exit(
            lambda: assembler.copy_pinned(
                target_source,
                target_output,
                "nested/artifact.bin",
                "target-ancestor-swap copy",
                _after_target_ancestors_pinned=swap_target_ancestor,
            ),
            "output-relative ancestor was replaced",
        )
        if (target_output.path / "nested/artifact.bin").exists():
            raise AssertionError("target ancestor swap redirected copied bytes")
    finally:
        target_output.cleanup()
        target_output.close()

    base = root / "output-parent-ancestor-swap"
    parent = base / "parent"
    parent.mkdir(parents=True)
    held_parent = base / "held"

    def swap_output_parent() -> None:
        parent.rename(held_parent)
        parent.mkdir()

    try:
        assert_system_exit(
            lambda: assembler.OutputTree.create(
                parent / "bundle",
                _after_parent_ancestors_pinned=swap_output_parent,
            ),
            "pinned ancestor path was replaced",
        )
        if (parent / "bundle").exists():
            raise AssertionError("output-parent ancestor swap created an output")
    finally:
        shutil.rmtree(parent)
        held_parent.rename(parent)

    create_base = root / "output-create-replacement"
    create_base.mkdir()
    create_path = create_base / "bundle"
    held_create = create_base / "held"

    def replace_created_output() -> None:
        create_path.rename(held_create)
        create_path.mkdir()

    assert_system_exit(
        lambda: assembler.OutputTree.create(
            create_path,
            _after_output_opened=replace_created_output,
        ),
        "output directory path was replaced",
    )
    if not create_path.is_dir() or not held_create.is_dir():
        raise AssertionError("create failure removed a foreign replacement inode")
    create_path.rmdir()
    held_create.rmdir()

    cleanup_base = root / "output-cleanup-replacement"
    cleanup_base.mkdir()
    cleanup_path = cleanup_base / "bundle"
    held_cleanup = cleanup_base / "held"
    cleanup_tree = assembler.OutputTree.create(cleanup_path)

    def replace_cleanup_output() -> None:
        cleanup_path.rename(held_cleanup)
        cleanup_path.mkdir()

    try:
        assert_system_exit(
            lambda: cleanup_tree.cleanup(
                _before_final_remove=replace_cleanup_output
            ),
            "refusing to remove a substituted output directory",
        )
        if not cleanup_path.is_dir() or not held_cleanup.is_dir():
            raise AssertionError("cleanup removed a foreign replacement inode")
    finally:
        cleanup_tree.close()
        cleanup_path.rmdir()
        held_cleanup.rmdir()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-stage0-direct-seven-") as raw:
        root = pathlib.Path(raw)
        source = prepare(root)
        positive = root / "positive"
        assemble_case(source, positive)
        manifest = checker.validate(positive, emit=False)
        if (
            manifest["claims"] != checker.CLAIMS
            or manifest["derived_observation"][
                "runner_legacy_validator_run_completed"
            ]
            is not False
            or manifest["derived_observation"][
                "stage0_direct_seven_observed"
            ]
            is not True
        ):
            raise AssertionError("positive scoped truth boundary differs")
        if (positive / "coordinator/secrets").exists():
            raise AssertionError("assembler copied private coordinator keys")

        assembler_public_secret_prewrite_rejection(source, root)
        assembler_oversized_prewrite_rejection(source, root)
        assembler_low_disk_prewrite_rejection(source, root)
        assembler_double_slash_disjoint_rejection(source, root)
        tree_entry_count_boundary_rejection(root)
        ancestor_swap_controls(root)

        reject(
            positive,
            root,
            "content-address",
            lambda bundle: (
                (bundle / "preflight/probe-fleet-v1.json").chmod(0o600),
                (bundle / "preflight/probe-fleet-v1.json").write_bytes(b"{}\n"),
            ),
            "content address differs",
        )
        reject(positive, root, "symlink", symlink_artifact, "symbolic link")
        reject(positive, root, "extra-secret", extra_secret, "unreferenced")
        reject(
            positive,
            root,
            "duplicate-json",
            duplicate_manifest_key,
            "duplicate JSON object name",
        )
        reject(
            positive,
            root,
            "trailing-json",
            trailing_manifest,
            "trailing bytes",
        )
        reject(
            positive,
            root,
            "outer-schema-bool",
            lambda bundle: outer_schema(bundle, True),
            "scoped direct-seven identity",
        )
        reject(
            positive,
            root,
            "outer-schema-float",
            lambda bundle: outer_schema(bundle, 1.0),
            "scoped direct-seven identity",
        )
        reject(
            positive,
            root,
            "runner-schema-bool",
            lambda bundle: runner_schema(bundle, True),
            "schema_version must be the exact integer 1",
        )
        reject(
            positive,
            root,
            "runner-schema-float",
            lambda bundle: runner_schema(bundle, 1.0),
            "schema_version must be the exact integer 1",
        )
        reject(
            positive,
            root,
            "duplicate-role",
            duplicate_role,
            "identities must be unique",
        )
        reject(
            positive,
            root,
            "stale-preflight",
            stale_probe,
            "not fresh and pre-run",
        )
        reject(
            positive,
            root,
            "mac-builder-substitution",
            aggregate_mac_builder_substitution,
            "differs from candidate and all four binaries",
        )
        reject(
            positive,
            root,
            "runner-failure",
            runner_failure,
            "successful no-fault execution",
        )
        reject(
            positive,
            root,
            "cleanup-failure",
            runner_cleanup_failure,
            "successful no-fault execution",
        )
        reject(
            positive,
            root,
            "observer-verification",
            observer_verification_removed,
            "successful, non-production macOS verification",
        )
        reject(
            positive,
            root,
            "raw-replay-substitution",
            raw_replay_substitution,
            "replay context",
        )
        reject(
            positive,
            root,
            "replay-entry-content",
            replay_entry_content_mutation,
            "content digest differs",
        )
        reject(
            positive,
            root,
            "terminal-seal-signature",
            terminal_seal_signature_mutation,
            "signature failed",
        )
        reject(
            positive,
            root,
            "terminal-disagreement",
            terminal_disagreement,
            "terminal agreement differs",
        )
        reject(
            positive,
            root,
            "completion-inflation",
            completion_inflation,
            "cannot open runner output manifest",
        )
    print(
        "poco_g3_stage0_direct_seven_bundle_v1_test=passed cargo_executed=false "
        "fixture_only=true deep_candidate=true cargo_lock_member=true dual_arch_binaries=4 "
        "symlink=blocked duplicate_json=blocked trailing=blocked "
        "ancestor_dirfd_swap=blocked foreign_cleanup_inode=preserved "
        "double_slash_disjoint=blocked public_secret_prewrite=blocked "
        "oversized_128m_plus_one_prewrite=blocked low_disk_prewrite=blocked "
        "tree_entries_4096_plus_one=blocked tree_depth_64_plus_one=blocked "
        "stage0_profile_max_file_bytes=134217728 "
        "runner_generic_512m_compatibility_claim=false exact_json_integers=blocked "
        "manifest_complete=true roles_unique=true failure=blocked cleanup=blocked "
        "observer_set=7 replay_sets=7 raw_replay_substitution=blocked "
        "raw_replay_hash_chain=blocked terminal_seal_signature=verified "
        "terminal_seal_signature_mutation=blocked terminal_agreement=exact "
        "proposal_qc_finality_semantics_independently_decoded=false "
        "runner_validator_run_completed=false stage0_direct_seven_observed=scoped "
        "validator_run_7_completed_observed=true "
        "fault_matrix=false performance=false g3_lan=false geo_wan=false production=false"
    )


if __name__ == "__main__":
    main()
