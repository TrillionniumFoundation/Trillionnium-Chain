#!/usr/bin/env python3
"""No-Cargo positive and mutation controls for Stage0 build evidence."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import pathlib
import py_compile
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable


HERE = pathlib.Path(__file__).resolve().parent
CHECKER_PATH = HERE / "check_stage0_reproducible_build_evidence.py"
SPEC = importlib.util.spec_from_file_location(
    "check_stage0_reproducible_build_evidence",
    CHECKER_PATH,
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load Stage0 reproducible-build evidence checker")
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


def elf64_x86_64_fixture(role: bytes) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    header[16:18] = (3).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    header[52:54] = (64).to_bytes(2, "little")
    return bytes(header) + b"fixture:" + role + b"\n"


VALIDATOR_BYTES = elf64_x86_64_fixture(b"validator")
MATERIAL_BYTES = elf64_x86_64_fixture(b"material-builder")
RUSTC_HASH = hashlib.sha256(b"rustc 1.89.0 fixture\n").hexdigest()
SOURCE_CANDIDATE: dict[str, object] = {
    "archive_bytes": 73_328_640,
    "base_commit": "6dc18e34d94d595705fd750cae91e5169fddce50",
    "cargo_lock_bytes": 50_286,
    "cargo_lock_path": "trillionnium/Cargo.lock",
    "cargo_lock_sha256": (
        "3e2352127ef45a35f808a549cf459959b17054f615744382c0f00a3a6a29b6da"
    ),
    "file_count": 3_270,
    "geo_wan_evidence": False,
    "git_object_format": "sha1",
    "git_status_sha256": hashlib.sha256(b"").hexdigest(),
    "git_tree_oid": "c2dd63e861b3b8a495424d84a939a993cde0f126",
    "production_activation": False,
    "source_bytes": 69_291_448,
    "source_candidate_sha256": (
        "d550d8ef344047704be102e86efc000552b16c233c586b38df2cfb8f8c7cc3aa"
    ),
    "source_profile": "clean-commit-v1",
}
EVIDENCE_ID = "trnm-poco-g3-stage0-linux-x86_64-repro-6dc18e34-20260820"
CACHE_RECORD: dict[str, object] = {
    "format": "cargo-home-registry-tar-gzip-v1",
    "sha256": hashlib.sha256(b"fixture offline registry cache\n").hexdigest(),
    "bytes": 61_465_388,
    "bundled": False,
}


@dataclass
class Fixture:
    base: pathlib.Path
    root: pathlib.Path
    source_candidate: pathlib.Path
    validator_binary: pathlib.Path
    material_builder: pathlib.Path


def canonical_manifest(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def canonical_report(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")


def content_ref(subject: str, payload: bytes) -> dict[str, object]:
    return {
        "subject": subject,
        "path": f"{subject}.json",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def report(subject: str) -> dict[str, object]:
    candidate = SOURCE_CANDIDATE
    return {
        "schema_version": 3,
        "source_candidate_sha256": candidate["source_candidate_sha256"],
        "source_candidate_profile": candidate["source_profile"],
        "source_base_commit": candidate["base_commit"],
        "source_git_object_format": candidate["git_object_format"],
        "source_git_tree_oid": candidate["git_tree_oid"],
        "source_git_status_sha256": candidate["git_status_sha256"],
        "cargo_lock_path": candidate["cargo_lock_path"],
        "cargo_lock_sha256": candidate["cargo_lock_sha256"],
        "cargo_lock_bytes": candidate["cargo_lock_bytes"],
        "validator_binary_sha256": hashlib.sha256(VALIDATOR_BYTES).hexdigest(),
        "validator_binary_bytes": len(VALIDATOR_BYTES),
        "material_builder_binary_sha256": hashlib.sha256(MATERIAL_BYTES).hexdigest(),
        "material_builder_binary_bytes": len(MATERIAL_BYTES),
        "host_triple": "x86_64-unknown-linux-gnu",
        "rustc_vv_sha256": RUSTC_HASH,
        "reproducible_build": True,
        "independent_build_count": 2,
        "output_validator_binary": (
            f"/tmp/trnm-stage0-repro-7cd808b3.fixture/{subject}/trnm-poco-lab-validator"
        ),
        "output_material_builder_binary": (
            f"/tmp/trnm-stage0-repro-7cd808b3.fixture/{subject}/"
            "trnm-poco-lab-material-builder"
        ),
        "production_activation": False,
        "geo_wan_evidence": False,
    }


def make_fixture(base: pathlib.Path) -> Fixture:
    root = base / "evidence"
    root.mkdir()
    reports: list[dict[str, object]] = []
    for subject in ("build-a", "build-b"):
        payload = canonical_report(report(subject))
        (root / f"{subject}.json").write_bytes(payload)
        reports.append(content_ref(subject, payload))
    manifest = {
        "schema_version": 1,
        "evidence_id": EVIDENCE_ID,
        "evidence_profile": checker.PROFILE,
        "source_candidate": copy.deepcopy(SOURCE_CANDIDATE),
        "operator_recorded_tools": copy.deepcopy(checker.EXPECTED_TOOLS),
        "operator_recorded_offline_dependency_cache": copy.deepcopy(CACHE_RECORD),
        "runner_record": {
            "runner_label": "x230-self-hosted",
            "transport": "manual-ssh",
            "paid_ci_used": False,
            "cryptographic_host_attestation": False,
            "tool_and_cache_use_cryptographically_attested": False,
            "builder_invocation_count": 2,
            "independent_cargo_build_count": 4,
            "host_triple": "x86_64-unknown-linux-gnu",
            "rustc_vv_sha256": RUSTC_HASH,
        },
        "build_reports": reports,
        "binary_outputs": [
            {
                "role": "validator",
                "sha256": hashlib.sha256(VALIDATOR_BYTES).hexdigest(),
                "bytes": len(VALIDATOR_BYTES),
                "bundled": False,
            },
            {
                "role": "material_builder",
                "sha256": hashlib.sha256(MATERIAL_BYTES).hexdigest(),
                "bytes": len(MATERIAL_BYTES),
                "bundled": False,
            },
        ],
        "claims": copy.deepcopy(checker.CLAIM_VALUES),
    }
    (root / "manifest.json").write_bytes(canonical_manifest(manifest))

    source_candidate = base / "source-candidate.tar"
    source_candidate.write_bytes(b"strict candidate fixture placeholder\n")
    validator_binary = base / "trnm-poco-lab-validator"
    validator_binary.write_bytes(VALIDATOR_BYTES)
    validator_binary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    material_builder = base / "trnm-poco-lab-material-builder"
    material_builder.write_bytes(MATERIAL_BYTES)
    material_builder.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return Fixture(
        base=base,
        root=root,
        source_candidate=source_candidate,
        validator_binary=validator_binary,
        material_builder=material_builder,
    )


def load_manifest(fixture: Fixture) -> dict:
    return json.loads((fixture.root / "manifest.json").read_text(encoding="utf-8"))


def save_manifest(fixture: Fixture, value: dict) -> None:
    (fixture.root / "manifest.json").write_bytes(canonical_manifest(value))


def change_manifest(fixture: Fixture, mutation: Callable[[dict], None]) -> None:
    value = load_manifest(fixture)
    mutation(value)
    save_manifest(fixture, value)


def load_report(fixture: Fixture, subject: str) -> dict:
    return json.loads(
        (fixture.root / f"{subject}.json").read_text(encoding="utf-8")
    )


def refresh_report_ref(fixture: Fixture, subject: str, payload: bytes) -> None:
    manifest = load_manifest(fixture)
    ref = next(item for item in manifest["build_reports"] if item["subject"] == subject)
    ref["sha256"] = hashlib.sha256(payload).hexdigest()
    ref["bytes"] = len(payload)
    save_manifest(fixture, manifest)


def change_report(
    fixture: Fixture,
    subject: str,
    mutation: Callable[[dict], None],
    *,
    canonical: bool = True,
) -> None:
    value = load_report(fixture, subject)
    mutation(value)
    if canonical:
        payload = canonical_report(value)
    else:
        payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (fixture.root / f"{subject}.json").write_bytes(payload)
    refresh_report_ref(fixture, subject, payload)


def assert_failure(action: Callable[[], object], label: str) -> None:
    try:
        action()
    except SystemExit as error:
        if not str(error).startswith(
            "PoCO G3 Stage0 reproducible-build evidence invalid:"
        ):
            raise AssertionError(f"{label}: unexpected error {error}") from error
        return
    raise AssertionError(f"{label}: mutation was accepted")


def fixture_failure(
    mutation: Callable[[Fixture], None],
    label: str,
    *,
    deep: bool = False,
) -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-stage0-repro-test-") as raw:
        fixture = make_fixture(pathlib.Path(raw))
        mutation(fixture)
        if deep:
            original_loader = checker.load_pinned_source_candidate_validator
            checker.load_pinned_source_candidate_validator = (
                lambda _source: (
                    lambda _path, *, require_clean=False: (
                        copy.deepcopy(SOURCE_CANDIDATE)
                        if require_clean
                        else (_ for _ in ()).throw(
                            AssertionError("require_clean missing")
                        )
                    )
                )
            )
            try:
                action = lambda: checker.validate(
                    fixture.root,
                    source_candidate=fixture.source_candidate,
                    validator_binary=fixture.validator_binary,
                    material_builder=fixture.material_builder,
                    emit=False,
                )
                assert_failure(action, label)
            finally:
                checker.load_pinned_source_candidate_validator = original_loader
            return
        else:
            action = lambda: checker.validate(fixture.root, emit=False)
        assert_failure(action, label)


def main() -> None:
    positives = 0
    negatives = 0

    with tempfile.TemporaryDirectory(prefix="poco-g3-stage0-repro-positive-") as raw:
        fixture = make_fixture(pathlib.Path(raw))
        shallow = checker.validate(fixture.root, emit=False)
        assert shallow["report_set_consistent"] is True
        assert shallow["binary_bytes_rehashed"] is False
        assert shallow["source_candidate_bytes_rehashed"] is False
        assert shallow["report_bound_elf64_le_x86_64_header_rehashed"] is False
        assert shallow["builder_reports_claim_reproducible_build"] is True
        assert (
            shallow["operator_records_native_linux_x86_64_build_execution"] is True
        )
        assert shallow["build_execution_cryptographically_attested"] is False
        assert shallow["runner_identity_cryptographically_attested"] is False
        assert (
            shallow["tool_and_cache_use_cryptographically_attested"] is False
        )
        completed = subprocess.run(
            [sys.executable, str(CHECKER_PATH), str(fixture.root)],
            check=True,
            capture_output=True,
            text=True,
        )
        cli = json.loads(completed.stdout)
        assert cli == shallow
        positives += 1

        original_loader = checker.load_pinned_source_candidate_validator
        checker.load_pinned_source_candidate_validator = (
            lambda _source: (
                lambda _path, *, require_clean=False: (
                    copy.deepcopy(SOURCE_CANDIDATE)
                    if require_clean
                    else (_ for _ in ()).throw(
                        AssertionError("require_clean missing")
                    )
                )
            )
        )
        try:
            deep = checker.validate(
                fixture.root,
                source_candidate=fixture.source_candidate,
                validator_binary=fixture.validator_binary,
                material_builder=fixture.material_builder,
                emit=False,
            )
        finally:
            checker.load_pinned_source_candidate_validator = original_loader
        assert deep["binary_bytes_rehashed"] is True
        assert deep["source_candidate_bytes_rehashed"] is True
        assert deep["report_bound_elf64_le_x86_64_header_rehashed"] is True
        assert deep["build_execution_cryptographically_attested"] is False
        positives += 1

    with tempfile.TemporaryDirectory(prefix="poco-g3-stage0-repro-generic-") as raw:
        fixture = make_fixture(pathlib.Path(raw))
        alternate = copy.deepcopy(SOURCE_CANDIDATE)
        alternate.update(
            base_commit="1" * 40,
            git_tree_oid="2" * 40,
            source_candidate_sha256="3" * 64,
            cargo_lock_sha256="4" * 64,
            archive_bytes=73_328_641,
            source_bytes=69_291_449,
        )
        manifest = load_manifest(fixture)
        manifest["evidence_id"] = (
            "trnm-poco-g3-stage0-linux-x86_64-repro-11111111-20260821"
        )
        manifest["source_candidate"] = alternate
        save_manifest(fixture, manifest)
        for subject in ("build-a", "build-b"):
            change_report(
                fixture,
                subject,
                lambda value, candidate=alternate: value.update(
                    source_candidate_sha256=candidate["source_candidate_sha256"],
                    source_base_commit=candidate["base_commit"],
                    source_git_tree_oid=candidate["git_tree_oid"],
                    cargo_lock_sha256=candidate["cargo_lock_sha256"],
                ),
            )
        generic = checker.validate(fixture.root, emit=False)
        assert generic["evidence_id"].endswith("11111111-20260821")
        assert generic["binary_bytes_rehashed"] is False
        positives += 1

    manifest_mutations: list[tuple[str, Callable[[dict], None]]] = [
        ("extra_manifest_key", lambda value: value.update(extra=False)),
        ("wrong_evidence_id", lambda value: value.update(evidence_id="wrong")),
        (
            "invalid_evidence_date",
            lambda value: value.update(
                evidence_id=(
                    "trnm-poco-g3-stage0-linux-x86_64-repro-6dc18e34-20260230"
                )
            ),
        ),
        (
            "source_object_format_type",
            lambda value: value["source_candidate"].update(git_object_format=[]),
        ),
        (
            "source_commit_flip",
            lambda value: value["source_candidate"].update(base_commit="0" * 40),
        ),
        (
            "source_tree_flip",
            lambda value: value["source_candidate"].update(git_tree_oid="0" * 40),
        ),
        (
            "source_lock_flip",
            lambda value: value["source_candidate"].update(cargo_lock_sha256="0" * 64),
        ),
        (
            "source_false_as_integer",
            lambda value: value["source_candidate"].update(geo_wan_evidence=0),
        ),
        (
            "tool_hash_flip",
            lambda value: value["operator_recorded_tools"][0].update(
                sha256="0" * 64
            ),
        ),
        (
            "cache_hash_flip",
            lambda value: value["operator_recorded_offline_dependency_cache"].update(
                sha256="0" * 64
            ),
        ),
        (
            "cross_architecture_claim",
            lambda value: value["claims"].update(
                native_cross_architecture_build_observed=True
            ),
        ),
        (
            "validator_run_claim",
            lambda value: value["claims"].update(validator_run_7_completed=True),
        ),
        (
            "claim_false_as_integer",
            lambda value: value["claims"].update(production_activation=0),
        ),
        (
            "runner_attestation_claim",
            lambda value: value["runner_record"].update(
                cryptographic_host_attestation=True
            ),
        ),
        (
            "tool_cache_attestation_claim",
            lambda value: value["runner_record"].update(
                tool_and_cache_use_cryptographically_attested=True
            ),
        ),
        (
            "runner_build_count",
            lambda value: value["runner_record"].update(
                independent_cargo_build_count=2
            ),
        ),
        (
            "unsafe_report_path",
            lambda value: value["build_reports"][0].update(path="../build-a.json"),
        ),
        (
            "report_ref_hash",
            lambda value: value["build_reports"][0].update(sha256="0" * 64),
        ),
        (
            "report_ref_bytes",
            lambda value: value["build_reports"][0].update(bytes=1),
        ),
        (
            "binary_manifest_hash",
            lambda value: value["binary_outputs"][0].update(sha256="0" * 64),
        ),
        (
            "binary_bundled_claim",
            lambda value: value["binary_outputs"][0].update(bundled=True),
        ),
    ]
    for label, mutation in manifest_mutations:
        fixture_failure(lambda fixture, m=mutation: change_manifest(fixture, m), label)
        negatives += 1

    report_mutations: list[tuple[str, str, Callable[[dict], None], bool]] = [
        ("report_extra_key", "build-a", lambda value: value.update(extra=False), True),
        (
            "report_source_sha",
            "build-a",
            lambda value: value.update(source_candidate_sha256="0" * 64),
            True,
        ),
        (
            "report_status_sha",
            "build-a",
            lambda value: value.update(source_git_status_sha256="0" * 64),
            True,
        ),
        ("report_schema2", "build-a", lambda value: value.update(schema_version=2), True),
        (
            "report_legacy_profile",
            "build-a",
            lambda value: value.update(source_candidate_profile="legacy-v1"),
            True,
        ),
        (
            "report_host_architecture",
            "build-a",
            lambda value: value.update(host_triple="aarch64-unknown-linux-gnu"),
            True,
        ),
        (
            "report_rustc_divergence",
            "build-b",
            lambda value: value.update(rustc_vv_sha256="1" * 64),
            True,
        ),
        (
            "report_validator_hash_divergence",
            "build-b",
            lambda value: value.update(validator_binary_sha256="2" * 64),
            True,
        ),
        (
            "report_validator_size_divergence",
            "build-b",
            lambda value: value.update(validator_binary_bytes=999),
            True,
        ),
        (
            "report_role_hash_collision",
            "build-a",
            lambda value: value.update(
                material_builder_binary_sha256=value["validator_binary_sha256"]
            ),
            True,
        ),
        (
            "report_independent_count",
            "build-a",
            lambda value: value.update(independent_build_count=1),
            True,
        ),
        (
            "report_reproducible_false",
            "build-a",
            lambda value: value.update(reproducible_build=False),
            True,
        ),
        (
            "report_production_claim",
            "build-a",
            lambda value: value.update(production_activation=True),
            True,
        ),
        (
            "report_geo_claim",
            "build-a",
            lambda value: value.update(geo_wan_evidence=True),
            True,
        ),
        (
            "report_shared_output_path",
            "build-b",
            lambda value: value.update(
                output_validator_binary=report("build-a")["output_validator_binary"]
            ),
            True,
        ),
        (
            "report_relative_output_path",
            "build-a",
            lambda value: value.update(output_validator_binary="relative/binary"),
            True,
        ),
        (
            "report_non_normalized_output_path",
            "build-a",
            lambda value: value.update(
                output_validator_binary="/tmp/./trnm-poco-lab-validator"
            ),
            True,
        ),
        (
            "report_double_slash_anchor_alias",
            "build-a",
            lambda value: value.update(
                output_validator_binary="//tmp/trnm-poco-lab-validator"
            ),
            True,
        ),
        (
            "report_noncanonical",
            "build-a",
            lambda _value: None,
            False,
        ),
    ]
    for label, subject, mutation, canonical in report_mutations:
        fixture_failure(
            lambda fixture, s=subject, m=mutation, c=canonical: change_report(
                fixture, s, m, canonical=c
            ),
            label,
        )
        negatives += 1

    def duplicate_manifest_key(fixture: Fixture) -> None:
        path = fixture.root / "manifest.json"
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b"{\n", b'{\n  "schema_version": 1,\n', 1))

    fixture_failure(duplicate_manifest_key, "duplicate_manifest_key")
    negatives += 1

    def duplicate_report_key(fixture: Fixture) -> None:
        path = fixture.root / "build-a.json"
        raw = path.read_bytes().replace(b"{", b'{"schema_version": 3, ', 1)
        path.write_bytes(raw)
        refresh_report_ref(fixture, "build-a", raw)

    fixture_failure(duplicate_report_key, "duplicate_report_key")
    negatives += 1

    def noncanonical_manifest(fixture: Fixture) -> None:
        value = load_manifest(fixture)
        (fixture.root / "manifest.json").write_bytes(
            (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
        )

    fixture_failure(noncanonical_manifest, "noncanonical_manifest")
    negatives += 1

    def symlink_report(fixture: Fixture) -> None:
        report_path = fixture.root / "build-a.json"
        target = fixture.base / "build-a-target.json"
        report_path.replace(target)
        report_path.symlink_to(target)

    fixture_failure(symlink_report, "symlink_report")
    negatives += 1

    with tempfile.TemporaryDirectory(prefix="poco-g3-stage0-repro-root-link-") as raw:
        fixture = make_fixture(pathlib.Path(raw))
        linked = fixture.base / "linked-evidence"
        linked.symlink_to(fixture.root, target_is_directory=True)
        assert_failure(
            lambda: checker.validate(linked, emit=False),
            "symlink_evidence_root",
        )
        negatives += 1

    with tempfile.TemporaryDirectory(prefix="poco-g3-stage0-repro-pyc-") as raw:
        base = pathlib.Path(raw)
        fixture = make_fixture(base)
        fake_root = base / "repository"
        fake_fleet = fake_root / "scripts" / "poco-fleet"
        fake_fleet.mkdir(parents=True)
        fake_checker = fake_fleet / CHECKER_PATH.name
        fake_checker.write_bytes(CHECKER_PATH.read_bytes())
        for tool in checker.EXPECTED_TOOLS:
            relative = pathlib.PurePosixPath(tool["path"])
            source = checker.REPOSITORY_ROOT.joinpath(*relative.parts)
            destination = fake_root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        marker = base / "unchecked-pyc-executed"
        malicious_source = base / "malicious-check-source-candidate.py"
        malicious_source.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
            "def validate(*_args, **_kwargs):\n"
            "    return {}\n",
            encoding="utf-8",
        )
        clean_source = fake_root / checker.EXPECTED_TOOLS[1]["path"]
        malicious_pyc = pathlib.Path(importlib.util.cache_from_source(str(clean_source)))
        malicious_pyc.parent.mkdir(parents=True)
        py_compile.compile(
            str(malicious_source),
            cfile=str(malicious_pyc),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
        completed = subprocess.run(
            [sys.executable, str(fake_checker), str(fixture.root)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
        assert not marker.exists(), "unchecked local pyc executed before source pinning"
        deep_completed = subprocess.run(
            [
                sys.executable,
                str(fake_checker),
                str(fixture.root),
                "--source-candidate",
                str(fixture.source_candidate),
                "--validator-binary",
                str(fixture.validator_binary),
                "--material-builder",
                str(fixture.material_builder),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert deep_completed.returncode != 0
        assert "source candidate failed strict deep verification" in deep_completed.stderr
        assert not marker.exists(), "deep mode executed unchecked local pyc"
        negatives += 1

    with tempfile.TemporaryDirectory(prefix="poco-g3-stage0-repro-partial-") as raw:
        fixture = make_fixture(pathlib.Path(raw))
        assert_failure(
            lambda: checker.validate(
                fixture.root,
                source_candidate=fixture.source_candidate,
                emit=False,
            ),
            "partial_deep_arguments",
        )
        negatives += 1

    with tempfile.TemporaryDirectory(prefix="poco-g3-stage0-repro-source-") as raw:
        fixture = make_fixture(pathlib.Path(raw))
        original_loader = checker.load_pinned_source_candidate_validator
        mutated = copy.deepcopy(SOURCE_CANDIDATE)
        mutated["base_commit"] = "0" * 40
        checker.load_pinned_source_candidate_validator = (
            lambda _source: (
                lambda _path, *, require_clean=False: copy.deepcopy(mutated)
            )
        )
        try:
            assert_failure(
                lambda: checker.validate(
                    fixture.root,
                    source_candidate=fixture.source_candidate,
                    validator_binary=fixture.validator_binary,
                    material_builder=fixture.material_builder,
                    emit=False,
                ),
                "deep_source_candidate_mismatch",
            )
        finally:
            checker.load_pinned_source_candidate_validator = original_loader
        negatives += 1

    def deep_validator_mismatch(fixture: Fixture) -> None:
        fixture.validator_binary.write_bytes(b"mutated validator\n")
        fixture.validator_binary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    fixture_failure(
        deep_validator_mismatch,
        "deep_validator_binary_mismatch",
        deep=True,
    )
    negatives += 1

    def deep_non_elf_validator(fixture: Fixture) -> None:
        payload = b"executable bytes that are deliberately not ELF\n"
        digest = hashlib.sha256(payload).hexdigest()
        fixture.validator_binary.write_bytes(payload)
        fixture.validator_binary.chmod(
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
        )
        for subject in ("build-a", "build-b"):
            change_report(
                fixture,
                subject,
                lambda value, d=digest, n=len(payload): value.update(
                    validator_binary_sha256=d,
                    validator_binary_bytes=n,
                ),
            )
        change_manifest(
            fixture,
            lambda value: value["binary_outputs"][0].update(
                sha256=digest,
                bytes=len(payload),
            ),
        )

    fixture_failure(
        deep_non_elf_validator,
        "deep_non_elf_validator",
        deep=True,
    )
    negatives += 1

    def deep_material_symlink(fixture: Fixture) -> None:
        target = fixture.base / "material-target"
        fixture.material_builder.replace(target)
        fixture.material_builder.symlink_to(target)

    fixture_failure(deep_material_symlink, "deep_material_symlink", deep=True)
    negatives += 1

    print(
        "poco_g3_stage0_reproducible_build_evidence_test=passed "
        f"positives={positives} negatives={negatives} "
        "shallow_binary_bytes_rehashed=false deep_binary_bytes_rehashed=true "
        "operator_recorded_execution=true cryptographic_execution_attestation=false "
        "duplicate_json=fail-closed unchecked_pyc=ignored "
        "unsafe_paths=fail-closed symlinks=fail-closed "
        "actual_build_executed=false production_activation=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
