#!/usr/bin/env python3
"""Focused positive and negative controls for the v1 run-bundle assembler."""

from __future__ import annotations

import copy
import json
import pathlib
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import assemble_run_bundle_v1 as assembler  # noqa: E402
import check_run_bundle as checker  # noqa: E402
import check_run_bundle_test as fixture  # noqa: E402
import check_run_evidence  # noqa: E402
import evidence_bundle_profiles_v1 as profiles  # noqa: E402


def expect_failure(action, contains: str) -> None:
    try:
        action()
    except SystemExit as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError("negative control unexpectedly succeeded")


def source_spec(source: pathlib.Path) -> tuple[dict, str]:
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    summary = manifest["completed_run_summary"]
    artifacts = [
        {
            "role": item["role"],
            "subject": item["subject"],
            "source": str((source / item["path"]).absolute()),
            "path": item["path"],
        }
        for item in manifest["artifacts"]
        if item["role"] != "collector_report"
    ]
    coordinator_anchor = next(
        item["sha256"]
        for item in manifest["artifacts"]
        if item["role"] == "coordinator_manifest"
    )
    return (
        {
            "schema_version": 1,
            "evidence_profile": manifest["evidence_profile"],
            "run_id": manifest["run_id"],
            "validator_count": manifest["validator_count"],
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "completed_run_summary": {
                "source": str((source / summary["path"]).absolute()),
                "path": summary["path"],
            },
            "artifacts": artifacts,
        },
        coordinator_anchor,
    )


def save(path: pathlib.Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def normalized(
    path: pathlib.Path,
    value: dict,
    *,
    profile: str = profiles.NO_FAULT_V1,
) -> dict:
    save(path, value)
    return assembler.normalize_spec(path, profile=profile)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-poco-g3-assembler-v1-") as raw:
        root = pathlib.Path(raw)
        source = root / "source-bundle"
        source.mkdir()
        fixture.build(source, 7)
        spec, anchor = source_spec(source)
        spec_path = root / "assembly-spec.json"
        document = normalized(spec_path, spec)
        assembly_plan = assembler.plan(document, anchor)
        assert assembly_plan["profile"] == "poco-g3-run-bundle-assembly-plan-v2"
        assert assembly_plan["evidence_profile"] == profiles.NO_FAULT_V1
        assert assembly_plan["validator_count"] == 7
        assert assembly_plan["creates_runtime_evidence"] is False
        assert assembly_plan["g3_evidence_complete"] is False
        assert assembly_plan["coordinator_manifest_sha256"] == anchor
        assert assembly_plan["active_assembly_supported"] is True
        assert assembly_plan["authority_blockers"] == []
        assert assembly_plan["fault_evidence_policy"] == []

        # Plan construction is strictly read-only: no output root is created.
        planned_output = root / "plan-only-output"
        assert not planned_output.exists()
        assembler.validate_output_root(planned_output)
        assert not planned_output.exists()

        output = root / "assembled"
        assembled = assembler.assemble(document, output, anchor)
        assert assembled == output.absolute()
        manifest = json.loads((assembled / "manifest.json").read_text())
        assert manifest["evidence_profile"] == profiles.NO_FAULT_V1
        collector = json.loads((assembled / "collector-report.json").read_text())
        assert collector["evidence_profile"] == profiles.NO_FAULT_V1

        existing = root / "existing"
        existing.mkdir()
        expect_failure(
            lambda: assembler.validate_output_root(existing), "already exists"
        )

        escaped = copy.deepcopy(spec)
        escaped["artifacts"][0]["path"] = "../escape"
        expect_failure(
            lambda: normalized(spec_path, escaped), "remain inside the new bundle"
        )

        duplicate_pair = copy.deepcopy(spec)
        duplicate_pair["artifacts"].append(copy.deepcopy(duplicate_pair["artifacts"][0]))
        duplicate_pair["artifacts"][-1]["path"] = "duplicate.bin"
        expect_failure(
            lambda: normalized(spec_path, duplicate_pair), "role/subject pairs"
        )

        duplicate_path = copy.deepcopy(spec)
        duplicate_path["artifacts"][1]["path"] = duplicate_path["artifacts"][0]["path"]
        expect_failure(
            lambda: normalized(spec_path, duplicate_path), "destination paths"
        )

        reserved = copy.deepcopy(spec)
        reserved["completed_run_summary"]["path"] = "manifest.json"
        expect_failure(
            lambda: normalized(spec_path, reserved), "reserved output path"
        )

        symlinked = copy.deepcopy(spec)
        original = pathlib.Path(symlinked["artifacts"][0]["source"])
        link = root / "source-link"
        link.symlink_to(original)
        symlinked["artifacts"][0]["source"] = str(link)
        expect_failure(
            lambda: normalized(spec_path, symlinked), "regular, non-symlink"
        )

        wrong_anchor_output = root / "wrong-anchor"
        expect_failure(
            lambda: assembler.assemble(document, wrong_anchor_output, "00" * 32),
            "coordinator manifest differs",
        )
        assert not wrong_anchor_output.exists()

        omitted_profile = copy.deepcopy(spec)
        omitted_profile.pop("evidence_profile")
        expect_failure(
            lambda: normalized(spec_path, omitted_profile),
            "assembly spec keys must be exactly",
        )

        legacy_summary_source = root / "legacy-schema2-summary.json"
        legacy_summary = json.loads(
            pathlib.Path(spec["completed_run_summary"]["source"]).read_text()
        )
        legacy_summary["schema_version"] = 2
        for field in check_run_evidence.SOURCE_PROVENANCE_KEYS:
            legacy_summary["candidate"].pop(field)
        save(legacy_summary_source, legacy_summary)
        legacy_summary_spec = copy.deepcopy(spec)
        legacy_summary_spec["completed_run_summary"]["source"] = str(
            legacy_summary_source.absolute()
        )
        expect_failure(
            lambda: normalized(spec_path, legacy_summary_spec),
            "schema_version must be 3",
        )
        legacy_plan_summary = copy.deepcopy(legacy_summary)
        legacy_plan_summary["evidence_profile"] = (
            profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1
        )
        legacy_plan_summary_source = root / "legacy-schema2-plan-summary.json"
        save(legacy_plan_summary_source, legacy_plan_summary)
        legacy_plan_spec = copy.deepcopy(spec)
        legacy_plan_spec["evidence_profile"] = (
            profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1
        )
        legacy_plan_spec["completed_run_summary"]["source"] = str(
            legacy_plan_summary_source.absolute()
        )
        expect_failure(
            lambda: normalized(
                spec_path,
                legacy_plan_spec,
                profile=profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1,
            ),
            "schema_version must be 3",
        )

        build_item = next(
            item for item in spec["artifacts"] if item["role"] == "build_report"
        )
        legacy_build_source = root / "legacy-schema2-build-report.json"
        legacy_build = json.loads(pathlib.Path(build_item["source"]).read_text())
        legacy_build["schema_version"] = 2
        for field in check_run_evidence.SOURCE_PROVENANCE_KEYS:
            legacy_build.pop(field)
        save(legacy_build_source, legacy_build)
        legacy_build_spec = copy.deepcopy(spec)
        next(
            item
            for item in legacy_build_spec["artifacts"]
            if item["role"] == "build_report"
        )["source"] = str(legacy_build_source.absolute())
        legacy_build_document = normalized(spec_path, legacy_build_spec)
        legacy_build_output = root / "legacy-build-active"
        expect_failure(
            lambda: assembler.assemble(
                legacy_build_document, legacy_build_output, anchor
            ),
            "aggregate build report keys must be exactly",
        )
        assert not legacy_build_output.exists()

        substituted_profile = copy.deepcopy(spec)
        substituted_profile["evidence_profile"] = (
            profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
        )
        expect_failure(
            lambda: normalized(spec_path, substituted_profile),
            "differs from the explicit CLI profile",
        )

        smuggled_fault = copy.deepcopy(spec)
        smuggled_fault["artifacts"].append(
            {
                "role": "fault_schedule",
                "subject": "leader_loss",
                "source": smuggled_fault["artifacts"][0]["source"],
                "path": "faults/legacy-leader-loss.json",
            }
        )
        expect_failure(
            lambda: normalized(spec_path, smuggled_fault),
            "legacy primary fault artifacts are forbidden",
        )

        mixed_summary_source = root / "mixed-plan-summary.json"
        mixed_summary = json.loads(
            pathlib.Path(spec["completed_run_summary"]["source"]).read_text()
        )
        mixed_summary["evidence_profile"] = (
            profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
        )
        save(mixed_summary_source, mixed_summary)
        mixed_spec = copy.deepcopy(spec)
        mixed_spec["evidence_profile"] = profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
        mixed_spec["completed_run_summary"]["source"] = str(
            mixed_summary_source.absolute()
        )
        mixed_document = normalized(
            spec_path,
            mixed_spec,
            profile=profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1,
        )
        mixed_plan = assembler.plan(mixed_document, anchor)
        assert mixed_plan["active_assembly_supported"] is False
        assert len(mixed_plan["authority_blockers"]) == 6
        policies = {item["kind"]: item for item in mixed_plan["fault_evidence_policy"]}
        assert policies["leader_loss"]["primary_journal_applied_recovered"] is True
        assert policies["validator_process_kill"]["primary_journal_applied_recovered"] is False
        mixed_output = root / "mixed-active"
        expect_failure(
            lambda: assembler.assemble(mixed_document, mixed_output, anchor),
            "legacy exact-eight Applied/Recovered contract is not authoritative",
        )
        assert not mixed_output.exists()

        a_summary_source = root / "a-tier-plan-summary.json"
        a_summary = json.loads(
            pathlib.Path(spec["completed_run_summary"]["source"]).read_text()
        )
        a_summary["evidence_profile"] = (
            profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1
        )
        save(a_summary_source, a_summary)
        legacy_role_smuggle = copy.deepcopy(spec)
        legacy_role_smuggle["evidence_profile"] = (
            profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1
        )
        legacy_role_smuggle["completed_run_summary"]["source"] = str(
            a_summary_source.absolute()
        )
        legacy_role_smuggle["artifacts"] = [
            next(
                item
                for item in legacy_role_smuggle["artifacts"]
                if item["role"] == "validator_event_log"
            )
        ]
        expect_failure(
            lambda: normalized(
                spec_path,
                legacy_role_smuggle,
                profile=profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1,
            ),
            "outside the bundle vocabulary",
        )

        for selected_profile, blocker_count in (
            (profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1, 2),
            (profiles.NO_FAULT_SIGNED_RUNTIME_EXTERNAL_LOAD_V1, 3),
        ):
            plan_document = copy.deepcopy(document)
            plan_document["evidence_profile"] = selected_profile
            profile_plan = assembler.plan(plan_document, anchor)
            assert profile_plan["active_assembly_supported"] is False
            assert len(profile_plan["authority_blockers"]) == blocker_count
            profile_output = root / f"active-{selected_profile}"
            expect_failure(
                lambda d=plan_document, o=profile_output: assembler.assemble(
                    d, o, anchor
                ),
                "plan-only",
            )
            assert not profile_output.exists()

    print(
        "poco_g3_run_bundle_assembler_v1_test=passed positives=13 negatives=14 "
        "no_fault_active_assembly=true mixed_plan_only=true "
        "mixed_active_assembly=fail-closed no_partial_output=true "
        "creates_runtime_evidence=false g3_complete=false geo_wan=false "
        "production_activation=false"
    )


if __name__ == "__main__":
    main()
