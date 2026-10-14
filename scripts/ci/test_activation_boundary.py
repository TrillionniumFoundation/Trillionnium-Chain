#!/usr/bin/env python3
"""Fail closed until every production/effect gate is independently qualified."""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY = ROOT / "config" / "activation-policy-v1.json"


def main() -> int:
    policy = json.loads(POLICY.read_text())
    if policy["mode"] != "experimental-deny-by-default":
        raise SystemExit("activation policy must remain experimental-deny-by-default")
    if policy["promotion_allowlist"]:
        raise SystemExit("promotion allowlist must remain empty")
    truth = json.loads((ROOT / "config/consensus-mainline.json").read_text())
    pon = json.loads((ROOT / "config/pon-nakamoto-v1.json").read_text())
    values = {**truth, **pon, **pon["implementation"], **pon["work_profile"]}
    missing = [name for name in policy["required_false_flags"] if name not in values]
    if missing:
        raise SystemExit(f"activation flags missing: {', '.join(missing)}")
    enabled = [name for name in policy["required_false_flags"] if values[name] is not False]
    if enabled:
        raise SystemExit(f"activation flags enabled: {', '.join(enabled)}")
    if truth["active_consensus_implementation"] is not None:
        raise SystemExit("active consensus implementation must remain null")
    if pon["work_profile"]["status"] != "implemented-experimental-not-security-qualified":
        raise SystemExit("PoN work profile is no longer marked experimental")
    print(json.dumps({"result": "PASS", "mode": policy["mode"], "activation": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
