#!/usr/bin/env python3
"""Verify one explicitly profiled, content-addressed PoCO G3 run bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_run_evidence  # noqa: E402
import check_raw_run_artifacts  # noqa: E402
import check_signed_runtime_evidence  # noqa: E402
import evidence_bundle_profiles_v1 as evidence_profiles  # noqa: E402


HEX64 = re.compile(r"^[0-9a-f]{64}$")
FAULTS = check_run_evidence.REQUIRED_FAULTS
_LEGACY_VOCABULARY = evidence_profiles.role_vocabulary(
    evidence_profiles.NO_FAULT_V1
)
# Compatibility exports for legacy fixture helpers. Validation itself always
# selects the closed vocabulary by evidence profile below.
SINGLETON_ROLES = set(_LEGACY_VOCABULARY.singleton)
VALIDATOR_ROLES = set(_LEGACY_VOCABULARY.validator)
HOST_ROLES = set(_LEGACY_VOCABULARY.host)
OBSERVER_ROLES = set(_LEGACY_VOCABULARY.observer)
FAULT_ROLES = set(_LEGACY_VOCABULARY.fault)


def role_vocabulary(profile: str) -> evidence_profiles.BundleRoleVocabulary:
    try:
        return evidence_profiles.role_vocabulary(profile)
    except ValueError as error:
        fail(str(error))


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 run bundle invalid: {message}")


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject RFC 8259 object-name ambiguity instead of accepting last-wins."""
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            fail(f"duplicate JSON object name {key!r}")
        value[key] = child
    return value


def read_json(path: pathlib.Path, field: str) -> dict:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{field} is not one exact UTF-8 JSON document: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    return value


def exact_keys(value: object, expected: set[str], field: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{field} keys must be exactly {sorted(expected)!r}")
    return value


def safe_relative(raw: object, field: str) -> pathlib.PurePosixPath:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        fail(f"{field} must be a non-empty POSIX relative path")
    path = pathlib.PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{field} must remain inside the bundle")
    return path


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_ref(root: pathlib.Path, ref: dict, field: str) -> tuple[pathlib.Path, str]:
    exact_keys(ref, {"path", "sha256", "bytes"}, field)
    relative = safe_relative(ref["path"], f"{field}.path")
    path = root.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():
        fail(f"{field}.path must name one regular non-symlink file")
    size = ref["bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        fail(f"{field}.bytes must be positive")
    if path.stat().st_size != size:
        fail(f"{field}.bytes mismatch")
    expected = ref["sha256"]
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        fail(f"{field}.sha256 must be canonical lowercase sha256")
    observed = sha256_file(path)
    if observed != expected:
        fail(f"{field}.sha256 mismatch")
    return path, str(relative)


def ordered_input_root(profile: str, artifacts: list[dict]) -> str:
    try:
        selected_profile = evidence_profiles.require_known(profile)
    except ValueError as error:
        fail(str(error))
    digest = hashlib.sha256()
    digest.update(b"TRNM/PoCO/G3/RunBundleInputs/v1\0")
    encoded_profile = selected_profile.encode("ascii")
    digest.update(len(encoded_profile).to_bytes(4, "big"))
    digest.update(encoded_profile)
    for item in sorted(
        (entry for entry in artifacts if entry["role"] != "collector_report"),
        key=lambda entry: (entry["role"], entry["subject"], entry["path"]),
    ):
        for value in (item["role"], item["subject"], item["path"]):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
        digest.update(bytes.fromhex(item["sha256"]))
        digest.update(item["bytes"].to_bytes(8, "big"))
    return digest.hexdigest()


def validate(
    root: pathlib.Path,
    expected_count: int,
    *,
    profile: str,
    coordinator_manifest_sha256: str,
    emit: bool = True,
) -> None:
    try:
        selected_profile = evidence_profiles.require_active(profile)
    except (ValueError, RuntimeError) as error:
        fail(str(error))
    vocabulary = role_vocabulary(selected_profile)
    if root.is_symlink() or not root.is_dir():
        fail("bundle root must be a real directory")
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail("manifest.json must be a regular non-symlink file")
    document = read_json(manifest_path, "manifest")
    exact_keys(
        document,
        {
            "schema_version",
            "evidence_profile",
            "run_id",
            "validator_count",
            "network_scope",
            "geo_wan_evidence",
            "completed_run_summary",
            "artifacts",
        },
        "manifest",
    )
    if document["schema_version"] != 1:
        fail("schema_version must be 1")
    if document["evidence_profile"] != selected_profile:
        fail("manifest evidence_profile differs from the explicit CLI profile")
    if document["validator_count"] != expected_count or expected_count not in {7, 31, 100}:
        fail("validator_count mismatch")
    if document["network_scope"] != "single-lan" or document["geo_wan_evidence"] is not False:
        fail("bundle must remain single-lan with geo_wan_evidence=false")
    if (
        not isinstance(coordinator_manifest_sha256, str)
        or not HEX64.fullmatch(coordinator_manifest_sha256)
    ):
        fail("coordinator manifest out-of-band anchor must be canonical SHA-256")

    summary_ref = document["completed_run_summary"]
    summary_path, summary_relative = verify_ref(
        root, summary_ref, "completed_run_summary"
    )
    summary = read_json(summary_path, "completed_run_summary")
    if summary.get("run_id") != document["run_id"]:
        fail("manifest run_id differs from completed-run summary")
    check_run_evidence.validate(
        summary_path, expected_count, profile=selected_profile, emit=False
    )
    validator_ids = {item["validator_id"] for item in summary["validators"]}

    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        fail("artifacts must be a non-empty list")
    seen_paths = {"manifest.json", summary_relative}
    seen_role_subject: set[tuple[str, str]] = set()
    role_subjects: dict[str, set[str]] = {}
    collector_path: pathlib.Path | None = None
    raw_records: dict[tuple[str, str], tuple[dict, pathlib.Path]] = {}
    for index, artifact in enumerate(artifacts):
        exact_keys(
            artifact,
            {"role", "subject", "path", "sha256", "bytes"},
            f"artifacts[{index}]",
        )
        role = artifact["role"]
        subject = artifact["subject"]
        if role not in vocabulary.all_roles:
            fail(f"artifacts[{index}] has unknown role")
        if not isinstance(subject, str):
            fail(f"artifacts[{index}].subject must be a string")
        if role in vocabulary.singleton and subject:
            fail(f"singleton role {role} must have an empty subject")
        if role in vocabulary.validator and subject not in validator_ids:
            fail(f"role {role} subject is not a run validator")
        if role in vocabulary.host and subject not in vocabulary.host_subjects:
            fail(f"{role} subject is not one frozen physical host")
        if role in vocabulary.observer and subject != "mac":
            fail(f"{role} subject must be the frozen mac observer")
        if role in vocabulary.fault and subject not in FAULTS:
            fail(f"{role} subject is not a mandatory fault kind")
        if role in vocabulary.fault:
            fail(f"{selected_profile} forbids fault artifact smuggling")
        pair = (role, subject)
        if pair in seen_role_subject:
            fail("role/subject pairs must be unique")
        seen_role_subject.add(pair)
        role_subjects.setdefault(role, set()).add(subject)
        path, relative = verify_ref(
            root,
            {key: artifact[key] for key in ("path", "sha256", "bytes")},
            f"artifacts[{index}]",
        )
        if relative in seen_paths:
            fail("bundle paths must be unique")
        seen_paths.add(relative)
        if role == "collector_report":
            collector_path = path
        else:
            raw_records[pair] = (artifact, path)

    for role in vocabulary.singleton:
        if role_subjects.get(role) != {""}:
            fail(f"bundle requires exactly one {role}")
    for role in vocabulary.validator:
        if role_subjects.get(role) != validator_ids:
            fail(f"bundle requires one {role} per validator")
    for role in vocabulary.host:
        if role_subjects.get(role) != vocabulary.host_subjects:
            fail(f"bundle requires one {role} per frozen physical host")
    for role in vocabulary.observer:
        if role_subjects.get(role) != {"mac"}:
            fail(f"bundle requires exactly one {role} for mac")
    if any(role_subjects.get(role) for role in vocabulary.fault):
        fail(f"{selected_profile} forbids fault artifacts")

    coordinator_ref, _ = raw_records[("coordinator_manifest", "")]
    if coordinator_ref["sha256"] != coordinator_manifest_sha256:
        fail("coordinator manifest differs from the out-of-band pre-run anchor")

    signed_runtime = check_signed_runtime_evidence.validate(
        root,
        expected_count,
        coordinator_manifest_sha256,
        profile=selected_profile,
        emit=False,
    )
    check_raw_run_artifacts.validate(
        summary, raw_records, signed_runtime, profile=selected_profile
    )

    actual_files = {
        str(path.relative_to(root).as_posix())
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_files != seen_paths:
        fail("bundle contains an unreferenced, missing, or symlink artifact")

    assert collector_path is not None
    collector = read_json(collector_path, "collector_report")
    exact_keys(
        collector,
        {
            "schema_version",
            "evidence_profile",
            "run_id",
            "validator_count",
            "summary_sha256",
            "ordered_input_root",
            "derived_from_raw_artifacts",
        },
        "collector_report",
    )
    if collector != {
        "schema_version": 1,
        "evidence_profile": selected_profile,
        "run_id": document["run_id"],
        "validator_count": expected_count,
        "summary_sha256": summary_ref["sha256"],
        "ordered_input_root": ordered_input_root(selected_profile, artifacts),
        "derived_from_raw_artifacts": True,
    }:
        fail("collector report does not bind the summary and every raw input")
    if emit:
        print(
            f"poco_g3_run_bundle=passed validators={expected_count} "
            f"profile={selected_profile} artifacts={len(artifacts)} faults=0 "
            "geo_wan=false"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7, 31, 100))
    parser.add_argument(
        "--profile", required=True, choices=sorted(evidence_profiles.KNOWN_PROFILES)
    )
    parser.add_argument(
        "--coordinator-manifest-sha256",
        required=True,
        help="out-of-band SHA-256 recorded before deployment",
    )
    args = parser.parse_args()
    validate(
        args.bundle,
        args.validators,
        profile=args.profile,
        coordinator_manifest_sha256=args.coordinator_manifest_sha256,
    )


if __name__ == "__main__":
    main()
