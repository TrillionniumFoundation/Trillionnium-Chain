#!/usr/bin/env python3
"""Run the retained CEV1 registry/catalog drift mutants.

Each mutant is applied to a temporary copy of the candidate registry set and
the production checker is executed as a subprocess.  The committed registry
is never modified, and accepting a malformed/misaligned candidate is treated
as a harness failure.  This is bounded negative evidence; it is not a
normative-freeze or implementation claim.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_REL = Path("docs/protocol/poco-ai-native-v1/registry")
CATALOG_REL = Path("docs/protocol/poco-ai-native-v1/schema/object-catalog-v1.toml")
CHECKER_REL = Path("scripts/ci/check_cev1_registry_spec_v1.py")
MUTANTS_REL = REGISTRY_REL / "cev1-registry-mutants-v1.json"
REGISTRY_FILES = (
    "operation-registry-v1.json",
    "object-registry-v1.json",
    "domain-registry-v1.json",
    "error-registry-v1.json",
    "limit-registry-v1.json",
    "verification-profile-registry-v1.json",
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"cev1 registry retained mutants: FAIL: {message}")


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")


def write_json(path: Path, value: Any) -> None:
    try:
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=False, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        fail(f"cannot write temporary mutant {path}: {error}")


def reset_sandbox(source_root: Path, sandbox: Path) -> None:
    registry = sandbox / REGISTRY_REL
    registry.mkdir(parents=True, exist_ok=True)
    for name in REGISTRY_FILES:
        shutil.copy2(source_root / REGISTRY_REL / name, registry / name)
    catalog = sandbox / CATALOG_REL
    catalog.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_root / CATALOG_REL, catalog)


def mutate(sandbox: Path, mutation: str) -> None:
    registry = sandbox / REGISTRY_REL
    object_path = registry / "object-registry-v1.json"
    if mutation == "duplicate_schema_key":
        raw = object_path.read_text(encoding="utf-8")
        needle = '"schema":"trnm-cev1-object-registry-v1"'
        if needle not in raw:
            fail("duplicate-schema-key mutant lost its insertion anchor")
        object_path.write_text(
            raw.replace(
                needle,
                '"schema":"mutant","schema":"trnm-cev1-object-registry-v1"',
                1,
            ),
            encoding="utf-8",
        )
        return

    if mutation == "change_first_plane":
        # This mutation is selected by the caller's target.  For object JSON,
        # changing the first row is enough; catalog TOML is handled below.
        if object_path.exists():
            document = read_json(object_path)
            document["objects"][0]["plane"] = "compute-verify"
            write_json(object_path, document)
            return
        fail("object registry missing for plane mutant")

    if mutation == "change_catalog_first_plane":
        catalog_path = sandbox / CATALOG_REL
        raw = catalog_path.read_text(encoding="utf-8")
        needle = 'plane = "agent"'
        if needle not in raw:
            fail("catalog-plane mutant lost its insertion anchor")
        catalog_path.write_text(raw.replace(needle, 'plane = "compute-verify"', 1), encoding="utf-8")
        return

    document = read_json(object_path)
    objects = document.get("objects")
    if not isinstance(objects, list) or not objects:
        fail("object registry has no rows to mutate")
    if mutation == "remove_last_object":
        objects.pop()
    elif mutation == "append_unknown_object":
        objects.append(
            {
                "id": "UnexpectedObjectV1",
                "plane": "agent",
                "authority": "mutant",
                "wire": "unassigned",
            }
        )
    elif mutation == "duplicate_first_object_id":
        objects[1]["id"] = objects[0]["id"]
    elif mutation == "swap_first_two_objects":
        objects[0], objects[1] = objects[1], objects[0]
    elif mutation == "enable_global_activation":
        document["global_activation"] = True
    elif mutation == "enable_first_operation":
        operation_path = registry / "operation-registry-v1.json"
        operation = read_json(operation_path)
        operation["operations"][0]["enabled"] = True
        write_json(operation_path, operation)
        return
    elif mutation == "enable_fallback":
        profile_path = registry / "verification-profile-registry-v1.json"
        profile = read_json(profile_path)
        profile["fallback_allowed"] = True
        write_json(profile_path, profile)
        return
    else:
        fail(f"unknown mutation recipe: {mutation}")
    write_json(object_path, document)


def run_checker(checker: Path, sandbox: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(checker), "--root", str(sandbox)],
        check=False,
        capture_output=True,
        text=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    source_root = args.root.resolve()
    fixture_path = source_root / MUTANTS_REL
    checker = source_root / CHECKER_REL
    fixture = read_json(fixture_path)
    if not isinstance(fixture, dict) or fixture.get("schema") != "trnm-cev1-registry-mutants-v1":
        fail("mutant fixture schema mismatch")
    cases = fixture.get("cases")
    if not isinstance(cases, list) or not cases:
        fail("mutant fixture has no cases")

    with tempfile.TemporaryDirectory(prefix="trnm-cev1-registry-mutants-") as temporary:
        sandbox = Path(temporary)
        reset_sandbox(source_root, sandbox)
        baseline = run_checker(checker, sandbox)
        if baseline.returncode != 0:
            fail(
                "baseline candidate rejected before mutations: "
                + (baseline.stdout + baseline.stderr).strip()
            )
        for index, case in enumerate(cases):
            if not isinstance(case, dict):
                fail(f"case {index} is not an object")
            case_id = case.get("id")
            mutation = case.get("mutation")
            target = case.get("target")
            expected = case.get("expected")
            if not all(isinstance(value, str) and value for value in (case_id, mutation, target, expected)):
                fail(f"case {index} has malformed metadata")
            reset_sandbox(source_root, sandbox)
            if mutation == "change_first_plane":
                if target == "object-catalog-v1.toml":
                    mutate(sandbox, "change_catalog_first_plane")
                elif target == "object-registry-v1.json":
                    mutate(sandbox, mutation)
                else:
                    fail(f"{case_id}: unsupported plane-mutant target {target}")
            else:
                mutate(sandbox, mutation)
            result = run_checker(checker, sandbox)
            output = result.stdout + result.stderr
            if result.returncode == 0:
                fail(f"mutant unexpectedly accepted: {case_id}")
            if expected not in output:
                fail(
                    f"{case_id}: rejection did not contain {expected!r}; "
                    f"output={output.strip()!r}"
                )
    print(f"cev1 registry retained mutants: ok cases={len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
