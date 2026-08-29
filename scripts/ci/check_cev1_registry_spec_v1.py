#!/usr/bin/env python3
"""Fail-closed structural checker for the candidate CEV1 registry set."""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REG = ROOT / "docs/protocol/poco-ai-native-v1/registry"


def load(name: str) -> dict:
    value = json.loads((REG / name).read_text(encoding="utf-8"))
    if value.get("status") != "candidate-non-normative":
        raise SystemExit(f"{name}: status drift")
    return value


def unique(rows: list[dict], key: str, label: str) -> None:
    values = [row[key] for row in rows]
    if len(values) != len(set(values)):
        raise SystemExit(f"duplicate {label}")


ops = load("operation-registry-v1.json")
objects = load("object-registry-v1.json")
domains = load("domain-registry-v1.json")
errors = load("error-registry-v1.json")
limits = load("limit-registry-v1.json")
profiles = load("verification-profile-registry-v1.json")

rows = ops["operations"]
if ops.get("slot_count") != 30 or sorted(row["kind"] for row in rows) != list(range(30)):
    raise SystemExit("operation registry must contain exactly kinds 0..29")
unique(rows, "name", "operation name")
if any(row.get("enabled") is not False for row in rows):
    raise SystemExit("candidate operation unexpectedly enabled")
if rows[-1].get("status") != "disabled" or rows[-1].get("canonical_error") != "ERR_OPERATION_DISABLED":
    raise SystemExit("kind 29 must be explicit disabled rejection")

unique(objects["objects"], "id", "object id")
unique(domains["domains"], "id", "domain id")
unique(domains["domains"], "value", "domain value")
for row in domains["domains"]:
    value = row["value"]
    if not value.isascii() or not value.startswith("trnm.poco-ai.") or not value.endswith(".v1"):
        raise SystemExit(f"noncanonical domain: {value}")

unique(errors["errors"], "code", "error code")
error_codes = {row["code"] for row in errors["errors"]}
for required in {
    "ERR_OPERATION_DISABLED", "ERR_PROFILE_DISABLED", "ERR_PROFILE_EXPIRED",
    "ERR_PROFILE_EVIDENCE_MISSING", "ERR_ASSET_CONSERVATION",
    "ERR_CHECKPOINT_ROLLBACK", "ERR_STATE_ROOT_DIVERGENCE"
}:
    if required not in error_codes:
        raise SystemExit(f"missing required error: {required}")

for name, value in limits["limits"].items():
    numeric = int(value)
    if numeric <= 0:
        raise SystemExit(f"nonpositive limit: {name}")

unique(profiles["profiles"], "id", "profile id")
if profiles.get("fallback_allowed") is not False:
    raise SystemExit("verification fallback must remain false")
if any(row.get("globally_enabled") is not False for row in profiles["profiles"]):
    raise SystemExit("candidate profile unexpectedly enabled")
subjective = next(row for row in profiles["profiles"] if row["id"] == "subjective-v1")
if subjective.get("objective_settlement_forbidden") is not True or subjective.get("poco_weight_forbidden") is not True:
    raise SystemExit("subjective profile authority boundary drift")

print("cev1 registry candidate: ok")
