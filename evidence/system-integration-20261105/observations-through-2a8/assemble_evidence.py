#!/usr/bin/env python3
"""Read-only aggregation of local, source-scoped evidence; writes to this directory only."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import zipfile
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
BASE = "6ee529046d295e3175f09112492abee373f1f54c"
ELF = "2534c56e2c15d2c31a1e829e369bee84aec4be2f"
INCOMING = "0841750c6716189121d5e630de218dd5b02981b3"
COMPOSED = "98897a742c5c8798239e760f4b776d034bbf5792"
LATE_INCOMING = "dda4cc47362065819e9591f11f713933e7a853bf"
LATEST = "eaacd1ef4245f48cae5f16cf03d2fd7c3d2cd4f5"
GROWTH = "657bf2a462ff13a6101ebcb4fbe0fb91c515c972"
PUBLISHED = "2a8fee974b41fab6e2c4e662dcce1807fcd19bdd"
FIXED_ZIP_TIME = (2026, 11, 5, 0, 0, 0)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def stable_read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular file: {path}")
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError(f"source changed while being read: {path}")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=HERE.parent)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    repo = workspace / "chain"
    payload: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    origins: dict[str, dict] = {}
    pending = []

    def add(name: str, data: bytes, origin: dict, executable: bool = False) -> None:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or not name.startswith("raw/"):
            raise ValueError(f"unsafe archive path: {name}")
        if name in payload and payload[name] != data:
            raise ValueError(f"conflicting evidence: {name}")
        payload[name] = data
        modes[name] = 0o755 if executable else 0o644
        origins[name] = origin

    def add_local(path: Path, name: str | None = None, origin: dict | None = None) -> None:
        if name is None:
            name = "raw/" + path.relative_to(workspace).as_posix()
        add(name, stable_read(path), origin or {"kind": "original_local_file", "workspace_relative_path": path.relative_to(workspace).as_posix()}, bool(path.stat().st_mode & 0o111))

    # These are finite, explicitly selected directories. Never recurse into a provider build root.
    for directory in ("execution", "w1-inputs", "settlement-input", "evolution-receipts"):
        for path in sorted((workspace / directory).rglob("*")):
            if path.is_symlink():
                raise ValueError(f"symlink in evidence directory: {path}")
            if path.is_file():
                add_local(path)
    liveness_allowlist = (
        "source-before.stdout", "source-after-execution.json", "missing-evidence-before.json",
        "missing-evidence-restoration.json", "restore_head_evidence.py", "source-after.json",
        "source-before.stderr", "source-after.stdout", "source-after.stderr", "verify_existing_pq_provider.py",
        "provider-review-20261105/provider-fixed.env", "provider-review-20261105/review.json",
        "provider-review-20261105/static-libcrypto-probe.c", "provider-review-20261105/static-libcrypto-probe",
    )
    for name in liveness_allowlist:
        add_local(workspace / "liveness-work" / name)
    for path in sorted((HERE / "packaging-audit").glob("*.json")):
        add_local(path, "raw/packaging-audit/" + path.name, {"kind": "packaging_validation_observation"})

    # Preserve the snapshot made before retries; a changed original is added under a distinct name.
    snapshot = HERE / "_raw_snapshot" / "verification"
    if snapshot.exists():
        for path in sorted(snapshot.iterdir()):
            if path.is_file():
                add_local(path, "raw/verification/" + path.name, {"kind": "preserved_pre_retry_snapshot", "original_relative_path": "verification/" + path.name})

    for path in sorted((workspace / "verification").glob("*.json")):
        data = stable_read(path)
        record = json.loads(data)
        if isinstance(record, dict) and record.get("status") == "running":
            pending.append({"receipt": "verification/" + path.name, "status": "running", "included_as_completed": False})
            continue
        name = "raw/verification/" + path.name
        if name in payload and payload[name] != data:
            name = "raw/verification/revisions/" + digest(data)[:16] + "/" + path.name
        add(name, data, {"kind": "completed_receipt_or_metadata", "workspace_relative_path": "verification/" + path.name})
        if isinstance(record, dict) and record.get("log_file") and record.get("log_sha256"):
            log = workspace / "verification" / record["log_file"]
            logdata = stable_read(log)
            if digest(logdata) != record["log_sha256"] or len(logdata) != record.get("log_bytes", len(logdata)):
                raise ValueError(f"receipt/log mismatch: {path.name}")
            logname = str(PurePosixPath(name).parent / log.name)
            add(logname, logdata, {"kind": "receipt_bound_log", "receipt": name})
    for filename in ("growth-incoming-pins-before.log", "growth-incoming-pins-after.log"):
        add_local(workspace / "verification" / filename)

    for filename in (
        "chain-code-commit.json", "chain-incoming-commit.json", "chain-incoming-compare.json",
        "chain-incoming-files.json", "chain-composition.json", "chain-composition-initial-index-missing-logs.json",
        "chain-integrated-code-commit.json", "chain-final-code-commit.json", "chain-incoming-modes.json",
        "chain-late-composition-input.json", "chain-late-composition.json",
        "chain-publication-composition-input.json", "chain-publication-composition.json", "chain-published-code-commit.json",
        "source-after-materialization.json", "local-observation-summary.json",
    ):
        add_local(workspace / filename, "raw/provenance/" + filename)
    for filename in ("chain-publication-receipt.json", "chain-published-ref-readback.json"):
        if (workspace / filename).exists():
            add_local(workspace / filename, "raw/provenance/" + filename)

    # Exact bytes of observed task binaries and cached toolchain observation; not a signed build attestation.
    add_local(workspace / "target/release/examples/pon_shared_material_v1", "raw/binaries/pon_shared_material_v1")
    add_local(workspace / "host-tools/pkgconf", "raw/host-tools/pkgconf")
    add_local(workspace / "target/.rustc_info.json", "raw/toolchain/rustc-info-observation.json")

    provider_receipt = Path("/workspace/scratch/fee7901564fd-next/validation-native799/prepare-provider-attempt1/pq-provider/provider.json")
    add_local(provider_receipt, "raw/provider-origin/provider.json", {"kind": "existing_provider_build_receipt", "identity_also_embedded_in": "raw/liveness-work/provider-review-20261105/review.json"})
    provider_build_log = provider_receipt.parent / "build-and-smoke.log"
    if provider_build_log.exists():
        add_local(provider_build_log, "raw/provider-origin/build-and-smoke.log", {"kind": "existing_provider_build_log", "fresh_rebuild_in_this_task": False})

    def git_bytes(commit: str, path: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{path}"])

    first = json.loads(payload["raw/execution/cell-t0-full-limb/report.json"])
    exact_base_paths = set(first["execution_source"]["files_sha256"])
    exact_base_paths.update((
        "rust-toolchain.toml", "trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
        "trillionnium/crates/trnm-crypto-primitives/Cargo.toml",
        "trillionnium/crates/trnm-crypto-primitives/examples/pon_shared_material_v1.rs",
        "scripts/ci/run_shared_material_security_v1.py", "scripts/ci/record_pq_native_command.py",
        "scripts/ci/verify_ci_source.py", "scripts/ci/prepare_pq_provider.sh",
        "scripts/llm_runtime_release.py", "scripts/test_llm_runtime_release.py",
        "formal/pon-nakamoto-v1/experiments/settle_model.py",
        "config/pon/pq-cross-branch-corpus-v1.json",
    ))
    source_files = []
    growth_composition = json.loads(payload["raw/provenance/chain-publication-composition.json"])
    published_paths = {"rust-toolchain.toml", "trillionnium/Cargo.toml", "trillionnium/Cargo.lock", "config/pon/pq-cross-branch-corpus-v1.json", "scripts/llm_runtime_release.py", "scripts/test_llm_runtime_release.py"}
    published_paths.update(row["path"] for row in growth_composition["pin_updates"])
    for commit, paths in (
        (BASE, sorted(exact_base_paths)),
        (ELF, ["scripts/llm_runtime_release.py", "scripts/test_llm_runtime_release.py"]),
        (COMPOSED, ["rust-toolchain.toml", "trillionnium/Cargo.toml", "trillionnium/Cargo.lock", "config/pon/pq-cross-branch-corpus-v1.json", "scripts/llm_runtime_release.py", "scripts/test_llm_runtime_release.py"]),
        (LATEST, ["rust-toolchain.toml", "trillionnium/Cargo.toml", "trillionnium/Cargo.lock", "config/pon/pq-cross-branch-corpus-v1.json", "scripts/llm_runtime_release.py", "scripts/test_llm_runtime_release.py", "scripts/ci/check_native_constants_roster.py", "scripts/ci/test_native_constants_roster.py", ".github/workflows/pon-branch-encoding-acceptance.yml"]),
        (PUBLISHED, sorted(published_paths)),
    ):
        for source_path in paths:
            data = git_bytes(commit, source_path)
            git_blob = subprocess.check_output(["git", "-C", str(repo), "rev-parse", f"{commit}:{source_path}"], text=True).strip()
            name = f"raw/source-inputs/{commit}/{source_path}"
            add(name, data, {"kind": "exact_git_blob", "commit": commit, "path": source_path, "git_blob": git_blob})
            source_files.append({"path": name, "commit": commit, "source_path": source_path, "git_blob": git_blob, "sha256": digest(data), "bytes": len(data)})
            expected = first["execution_source"]["files_sha256"].get(source_path) if commit == BASE else None
            if expected is not None and expected != digest(data):
                raise ValueError(f"measured source input differs from Git object: {source_path}")

    publication_receipt = json.loads(payload["raw/verification/chain-code-publication.json"])
    assert publication_receipt["published_code_commit"] == PUBLISHED
    assert publication_receipt["readback"]["object"]["sha"] == PUBLISHED
    assert publication_receipt["force"] is False and publication_receipt["connector_update_result"]["success"] is True
    native_availability = json.loads(payload["raw/verification/published-native-availability.json"])
    assert native_availability["code_commit"] == PUBLISHED
    assert native_availability["status"] == "PENDING_RESOURCE_SCHEDULING"
    assert native_availability["native_child_started"] is False and native_availability["child_exit_code"] is None
    anchors = []
    for role, commit in (("native_cost_and_original_tests", BASE), ("elf_fix_tested_code_object", ELF), ("concurrent_incoming", INCOMING), ("composed_tested_code_object", COMPOSED), ("later_concurrent_ci_incoming", LATE_INCOMING), ("tested_pre_growth_code_object", LATEST), ("current_growth_incoming", GROWTH), ("fixed_published_chain_input", PUBLISHED)):
        commitdata = subprocess.check_output(["git", "-C", str(repo), "cat-file", "commit", commit])
        add("raw/source-identities/" + commit + ".commit", commitdata, {"kind": "git_commit_object", "commit": commit})
        header = commitdata.split(b"\n\n", 1)[0].decode()
        tree = next(line.split()[1] for line in header.splitlines() if line.startswith("tree "))
        parents = [line.split()[1] for line in header.splitlines() if line.startswith("parent ")]
        anchors.append({"role": role, "commit": commit, "tree": tree, "parents": parents, "publication_attested": commit == PUBLISHED, "production_activation_attested": False})

    # Check all retained originals for actual PEM private-key blocks, not filenames or deleted temp argv.
    private_key = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
    secret_hits = [name for name, data in payload.items() if private_key.search(data)]
    incoming = json.loads(payload["raw/provenance/chain-incoming-files.json"])
    import base64
    for item in incoming:
        if item.get("content") and private_key.search(base64.b64decode(item["content"])):
            secret_hits.append("decoded incoming blob: " + item["path"])
    later = json.loads(payload["raw/provenance/chain-late-composition-input.json"])
    for item in later["files"]:
        if item.get("content") and private_key.search(base64.b64decode(item["content"])):
            secret_hits.append("decoded later incoming blob: " + item["path"])
    publication = json.loads(payload["raw/provenance/chain-publication-composition-input.json"])
    for item in publication["files"]:
        if item.get("content") and private_key.search(base64.b64decode(item["content"])):
            secret_hits.append("decoded growth incoming blob: " + item["path"])
    if secret_hits:
        raise ValueError("private-key marker requires review (contents not printed): " + repr(secret_hits))

    commands = []
    for path, data in sorted(payload.items()):
        if path.startswith("raw/verification/") and path.endswith(".json"):
            record = json.loads(data)
            if isinstance(record, dict) and record.get("schema") == "trnm-pq-native-command-v1":
                before, after = record.get("before", {}), record.get("after", {})
                commands.append({
                    "receipt": path, "status": record["status"], "exit_code": record["exit_code"],
                    "argv": record["argv"], "started_utc": record.get("started_utc"), "elapsed_ns": record.get("elapsed_ns"),
                    "tested_commit": before.get("tested_commit"), "tested_tree": before.get("tested_tree"),
                    "source_identity_before_after_equal": bool(before) and before == after,
                    "tracked_entries": before.get("tracked_entries"), "tracked_bytes": before.get("tracked_bytes"),
                    "log": str(PurePosixPath(path).parent / record["log_file"]), "log_sha256": record.get("log_sha256"),
                    "production_or_whole_chain_qualification": False,
                })

    cost_runs = []
    for case in ("cell-t0-full-limb", "cell-t0-transposed", "cell-t1-full-limb", "cell-t1-transposed"):
        name = f"raw/execution/{case}/report.json"
        report = json.loads(payload[name])
        assert report["execution_source"]["git_head"] == BASE
        assert report["execution_source"]["native_runner_sha256"] == digest(payload["raw/binaries/pon_shared_material_v1"])
        cost_runs.append({
            "case": case, "report": name, "status": report["status"], "execution_source": report["execution_source"],
            "execution_parameters": report["execution_parameters"], "costs": report["costs"],
            "baseline": {key: report["baseline"][key] for key in ("implementation", "cost_scope", "preparation_ns", "first_execution_ns", "cold_preparation_plus_execution_ns", "warm_median_ns", "warm_min_ns", "warm_p95_ns", "repetitions", "logical_multiply_adds")},
            "phases_ns": report["phases_ns"], "outputs": report["outputs"], "geometry": report["geometry"],
            "native_children": len(report["native"]),
            "native_winners": sum(row["native_summary"]["winners"] for row in report["native"]),
            "native_attempts": sum(row["native_summary"]["attempts"] for row in report["native"]),
            "native_child_exit_codes": [row["returncode"] for row in report["native"]],
            "outer_batch_wrapper_recorded": case != "cell-t0-full-limb",
            "claims": report["claims"],
        })

    attack_runs = []
    for case in ("security-t0", "security-t1"):
        name = f"raw/execution/{case}/report.json"
        report = json.loads(payload[name])
        rows = [json.loads(line) for p, data in payload.items() if p.startswith(f"raw/execution/{case}/tile-") and p.endswith("/stdout.jsonl") for line in data.splitlines()]
        native = [row for row in rows if row["kind"] == "attack_native_verifier"]
        cache = [row for row in rows if row["kind"] == "attack_cache_verifier"]
        assert {row["path"] for row in native} == {"native", "scalar-reference"}
        assert all(row["expected_refusal_observed"] and row["outcome"] == "Transcript" for row in native)
        assert all(row["expected_path_observed"] and row["outcome"] == "Transcript" for row in cache)
        attack_runs.append({
            "case": case, "report": name, "status": report["status"], "source_execution": report["source_execution"],
            "cycles": report["cycles"], "totals": report["totals"], "raw_native_to_attacker_cpu_ratio": report["raw_native_to_attacker_cpu_ratio"],
            "records_by_kind": dict(collections.Counter(row["kind"] for row in rows)),
            "native_refusal_calls": sum(row["path"] == "native" for row in native),
            "scalar_refusal_calls": sum(row["path"] == "scalar-reference" for row in native),
            "cache_refusal_calls": len(cache), "all_recorded_refusals_observed": True,
            "control_failures": sum(row["control_failures"] for row in rows if row["kind"] == "summary"),
            "physical_recovery_qualified": False, "cheapest_work_qualified": False,
        })

    restoration = json.loads(payload["raw/liveness-work/missing-evidence-restoration.json"])
    settlement = json.loads(payload["raw/execution/model-settlement/report.json"])
    evaluation = json.loads(payload["raw/settlement-input/report.json"])
    evaluations = {partition: {k: value.get(k) for k in ("samples", "composed_correct", "strong_reference_correct", "strong_reference", "whole_gain")} for partition, value in evaluation["results"].items()}
    provider = json.loads(payload["raw/liveness-work/provider-review-20261105/review.json"])
    assert provider["status"] == "PASS_WITH_RECORDED_SCOPE"
    assert provider["pinned_version"] == "3.5.9"
    assert provider["pinned_archive_sha256"] == "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
    assert all(provider["fresh_smoke"][key] is True for key in ("correct_message_verified", "ml_dsa_65_key_generation", "sign", "wrong_message_rejected"))
    assert provider["fresh_smoke"]["private_key_retained"] is False
    assert provider["static_headers_and_archive_link_verified"] is True
    assert digest(payload["raw/provider-origin/provider.json"]) == "47e29ef3e9f4627de90f8da7995f92b66fbc17a4cb5e1d4952b632ec1eb488b0"
    assert restoration["restored_count"] == 213 and restoration["restored_bytes"] == 781622789
    assert restoration["index_stage_sha256_before"] == restoration["index_stage_sha256_after"]

    add("raw/provenance/aggregation-origins.json", json_bytes(origins), {"kind": "packaging_inventory"})
    add("raw/provenance/aggregation-secret-scan.json", json_bytes({
        "schema": "local-evidence-private-key-marker-review-v1", "scope": "Selected raw file bytes and decoded incoming source blobs; this is not a general security audit",
        "private_key_pem_markers_found": secret_hits, "provider_build_root_recursively_included": False,
        "fresh_provider_smoke_private_keys_retained": False,
        "provider_review_allowlist": ["provider-fixed.env", "review.json", "static-libcrypto-probe", "static-libcrypto-probe.c"],
    }), {"kind": "packaging_check"})

    archive = HERE / "raw.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | modes[name]) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    artifact_manifest = [{"path": name, "bytes": len(data), "sha256": digest(data), "mode": oct(modes[name])} for name, data in sorted(payload.items())]
    evidence = {
        "schema": "trnm-local-system-evidence-aggregation-v1",
        "status": "HOLD_NO_GO_COMPONENT_OBSERVATIONS_ONLY",
        "evidence_date_utc": "2026-11-05",
        "assembled_at_utc": datetime.now(timezone.utc).isoformat(),
        "final_chain_commit": PUBLISHED, "final_hepta_commit": None,
        "final_chain_commit_meaning": "Fixed already-published Chain code input for this round; not release acceptance or a claim that later concurrent branch tips equal it.",
        "published_composition": {"receipt": "raw/provenance/chain-publication-composition.json", "publication_and_ref_readback": "raw/verification/chain-code-publication.json", "runtime_changed_from_tested_parent": True, "prior_native_results_apply_to_published_tree": False, "standalone_native_results_must_name_published_commit": True},
        "published_native_availability": {"receipt": "raw/verification/published-native-availability.json", "observation": native_availability, "scope": "Scheduling status, not a started child result or current resource-refusal proof; six selectors are expected to select fourteen cases."},
        "scope": "Read-only packaging of original local observations, exact code-object checks, failures and repair provenance. No remote writes or activation by the packager.",
        "source_anchors": anchors,
        "all_component_results_may_be_combined_as_release_acceptance": False,
        "gate_closed": {"P0-1": False, "P0-2": False, "P0-3": False, "P0-4": False, "P1-1": False, "P1-2": False, "independent_system_acceptance": False},
        "production_activation": False,
        "source_fenced_commands": commands,
        "pending_at_collection": pending,
        "elf_closure": {
            "original_five_regressions": {"receipt": "raw/evolution-receipts/elf-closure-red-v2.json", "failed": 5, "passed_abi_control": 1},
            "pie_regression_against_first_candidate": {"receipt": "raw/evolution-receipts/elf-closure-pie-red-v2.json", "failed": 1},
            "incorrect_interpreter_positive_hypothesis_retained": "raw/evolution-receipts/elf-closure-pie-red.json",
            "final_local_module": {"receipt": "raw/evolution-receipts/elf-closure-pie-green.json", "passed": 20, "skipped": 0},
            "valid_wire_compatibility": json.loads(payload["raw/evolution-receipts/elf-closure-pie-compatible.json"]),
            "patch": {"path": "raw/evolution-receipts/elf-closure-fix-v2.patch", "sha256": digest(payload["raw/evolution-receipts/elf-closure-fix-v2.patch"])},
            "universal_non_pie_interpreter_rule_added": False,
            "full_loader_semantics_or_model_service_qualified": False,
            "unauthorized_pq_effect_demonstrated": False,
        },
        "complete_operator": {
            "executed_source_commit": BASE, "runs": cost_runs,
            "host_observations": first["host"],
            "material_provenance": {k: first["provenance"][k] for k in ("source_commit", "model_artifact", "model_sha256", "evaluation_bundle", "evaluation_bundle_sha256", "tasks_file_sha256", "batch_size", "batch_offset", "partition")},
            "ratio_scope": "Native child-exchange wall time divided by one optimized ordinary warm batch median. Includes local proof/verification/startup/diagnostic costs; does not establish minimum solver cost, WAN costs, energy or application end-to-end latency.",
            "native_wall_to_warm_ratio_range": [min(row["costs"]["native_wall_to_one_ordinary_warm_batch_ratio"] for row in cost_runs), max(row["costs"]["native_wall_to_one_ordinary_warm_batch_ratio"] for row in cost_runs)],
            "predeclared_security_or_benefit_budget_satisfied": False,
            "failed_nonce_attempt_records_retained": True,
            "stale_production_work_observed": False,
            "stale_work_economic_budget_accepted": False,
        },
        "same_material_attack": {
            "runs": attack_runs,
            "false_candidates": sum(row["totals"]["candidates"] for row in attack_runs),
            "native_refusal_calls": sum(row["native_refusal_calls"] for row in attack_runs),
            "scalar_refusal_calls": sum(row["scalar_refusal_calls"] for row in attack_runs),
            "cache_refusal_calls": sum(row["cache_refusal_calls"] for row in attack_runs),
            "total_refusal_calls": sum(row["native_refusal_calls"] + row["scalar_refusal_calls"] + row["cache_refusal_calls"] for row in attack_runs),
            "calls_are_independent_attack_samples": False,
            "owner_recreation_is_physical_or_durable_recovery": False,
        },
        "settlement": {"report": "raw/execution/model-settlement/report.json", "observation": settlement, "fixed_corpus_evaluation": evaluations, "public_money_transfer_proved": False},
        "source_restoration": {"receipt": "raw/liveness-work/missing-evidence-restoration.json", "receipt_fields": restoration, "restored_history_content_duplicated_in_archive": False, "scope": "213 exact already-committed blobs recovered from local object database; full source check before/after is preserved, not a business-liveness pass."},
        "provider_environment": {
            "system_pkgconf_diagnostic": "raw/verification/host-pkgconf.json",
            "system_openssl_version": "3.0.13", "system_discovery_is_pq_acceptance": False,
            "pinned_provider_review": "raw/liveness-work/provider-review-20261105/review.json",
            "pinned_provider_version": "3.5.9", "provider_rebuilt_in_this_task": False,
            "fresh_mldsa65_cli_smoke_and_static_probe_observed": True,
            "provider_source_archive_sha256": "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a",
            "original_provider_receipt_sha256": digest(payload["raw/provider-origin/provider.json"]),
            "provider_env_portable_without_rebinding_paths": False,
            "independent_administrator_proved": False, "private_keys_included": False,
        },
        "build_and_configuration_provenance": {
            "exact_git_inputs": source_files,
            "native_binary": {"path": "raw/binaries/pon_shared_material_v1", "bytes": len(payload["raw/binaries/pon_shared_material_v1"]), "sha256": digest(payload["raw/binaries/pon_shared_material_v1"]), "source_commit_recorded_in_experiments": BASE, "signed_reproducible_build_attestation": False},
            "compiler_observation": {"path": "raw/toolchain/rustc-info-observation.json", "scope": "Cached Cargo rustc fingerprint output at packaging; pinned Rust 1.95.0, not a signed compiler/build-time attestation."},
            "native_release_build_record": {"source": "raw/provenance/local-observation-summary.json", "standalone_build_stdout_receipt_present": False},
        },
        "not_executed_or_not_qualified": [
            "One fixed Chain/Hepta/lockfile/binary/config combination passing ordinary product calls and all acceptance gates",
            "Full account/governance/release/recovery/CURRENT/FinalUse/consumption authorization under the current PQ root",
            "Original no-attack business baseline, original four-second/sixteen-adversary conditions, independent fixed-host F0 acceptance",
            "Minimum strong legal solver cost, global precomputation reuse bound, WAN and energy cost, stale-work economic budget",
            "Independent evaluator administration, prospective future window, full ordinary install/next-task/settlement/recovery loop",
            "Model archive service complete closure under author offline, independent replicas or erasure coding, loss/restart/WAN, funding/renewal/repair/GC",
            "Physical power-loss recovery, long-duration operation and independent release administrator acceptance",
        ],
        "raw_archive": {"path": "raw.zip", "bytes": archive.stat().st_size, "sha256": digest(archive.read_bytes()), "entry_count": len(artifact_manifest), "uncompressed_bytes": sum(row["bytes"] for row in artifact_manifest), "entries": artifact_manifest, "fixed_entry_timestamp": "2026-11-05T00:00:00", "original_raw_bytes_preserved": True},
    }
    (HERE / "evidence.json").write_bytes(json_bytes(evidence))
    print(json.dumps({"archive": str(archive), "entries": len(artifact_manifest), "bytes": archive.stat().st_size, "sha256": evidence["raw_archive"]["sha256"], "completed_source_fenced_commands": len(commands), "pending": pending}, ensure_ascii=False))


if __name__ == "__main__":
    main()
