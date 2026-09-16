#!/usr/bin/env python3
"""Check the single canonical protocol profile and explicit candidate boundaries."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "config/protocol-profile-registry-v1.toml"


class ProfileRegistryError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileRegistryError(message)


def load(path: Path | None = None) -> dict:
    with (path or REGISTRY).open("rb") as handle:
        return tomllib.load(handle)


def validate(data: dict) -> dict:
    require(data.get("schema_version") == 1, "schema_version drift")
    require(data.get("registry_id") == "trnm-protocol-profile-registry-v1", "registry id drift")
    ids = [row.get("id") for row in data.get("profiles", [])]
    require(ids == ["bft-v0", "pcc1", "ai-v1", "legacy-ledger-observation"], "profile inventory drift")
    require(len(ids) == len(set(ids)), "duplicate profile id")
    canonical = data.get("canonical_profile")
    require(canonical == "bft-v0", "canonical profile must be bft-v0")
    require(data.get("default_build_profiles") == [canonical], "default build must select canonical profile")
    require(data.get("default_check_profiles") == [canonical], "default checks must select canonical profile")
    rows = {row["id"]: row for row in data["profiles"]}
    require(rows[canonical]["status"] == "canonical", "canonical status drift")
    require(rows[canonical]["default_build"] is True and rows[canonical]["default_check"] is True,
            "canonical default boundary drift")
    require(rows[canonical]["activation"] is False, "production activation must remain false")
    for profile_id in ids[1:]:
        row = rows[profile_id]
        require(row["status"] in {"candidate", "archived"}, f"{profile_id}: invalid lifecycle status")
        require(row["default_build"] is False and row["default_check"] is False,
                f"{profile_id}: candidate/archive leaked into default path")
        require(row["activation"] is False, f"{profile_id}: activation must remain false")
    require(rows["pcc1"].get("wire_schema_ref") == canonical, "pcc1 wire schema must import canonical v0")
    require(rows["pcc1"].get("error_namespace_ref") == canonical,
            "pcc1 errors must import canonical v0 namespace")
    require("wire_schema" not in rows["pcc1"] and "error_namespace" not in rows["pcc1"],
            "pcc1 must not duplicate v0 schema/error mappings")
    return {"canonical_profile": canonical, "default_build_profiles": [canonical],
            "default_check_profiles": [canonical], "profile_count": len(ids), "result": "PASS"}


def main() -> int:
    report = validate(load())
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, tomllib.TOMLDecodeError, ProfileRegistryError) as error:
        print(f"protocol profile registry failed: {error}", file=sys.stderr)
        raise SystemExit(2)
