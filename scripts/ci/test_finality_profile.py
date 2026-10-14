#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main() -> None:
    profile = json.loads((ROOT / "config/finality-profile-v1.json").read_text())
    assert profile["status"] == "specified-disabled"
    assert profile["activation"] is False
    assert profile["legacy_profile_bridge"] is False
    assert profile["automatic_fallback"] is False
    committee = profile["committee"]
    assert committee["minimum_members"] >= 3 * committee["fault_bound_f"] + 1
    assert committee["quorum_members"] >= 2 * committee["fault_bound_f"] + 1
    assert profile["migration"]["new_namespace_required"] is True
    assert profile["migration"]["fresh_genesis_required"] is True
    assert profile["effect_gate"]["chain_confirmation_grants_final_use"] is False
    print(json.dumps({"result": "PASS", "profile": profile["profile_id"], "activation": False}))


if __name__ == "__main__":
    main()
