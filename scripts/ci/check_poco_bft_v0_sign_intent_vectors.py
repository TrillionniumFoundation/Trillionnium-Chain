#!/usr/bin/env python3
"""Check the machine-readable v0 signer-intent candidate vector.

The checker validates exact widths and the canonical envelope's root/fingerprint
placement. It is a fixture-integrity gate; it does not promote this corpus to
independent protocol acceptance.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "docs/protocol/poco-bft-v0/vectors/canonical-sign-intent-v0.json"


def main() -> int:
    document = json.loads(VECTOR.read_text(encoding="utf-8"))
    if document.get("schema") != "trnm.poco-bft.canonical-sign-intent-vector.v0":
        raise SystemExit("unexpected signer-intent vector schema")
    if document.get("status") != "candidate-fixture":
        raise SystemExit("signer-intent vector must remain candidate-fixture")
    if document.get("independent_implementation_required") is not True:
        raise SystemExit("signer-intent vector must retain independent-review requirement")
    for name, width in (("vote", 287), ("timeout_vote", 335)):
        case = document[name]
        encoded = bytes.fromhex(case["canonical_bytes_hex"])
        root = bytes.fromhex(case["signing_root_hex"])
        fingerprint = bytes.fromhex(case["fingerprint_hex"])
        if len(encoded) != width or len(root) != 32 or len(fingerprint) != 32:
            raise SystemExit(f"{name}: candidate vector width drift")
        if encoded[-64:-32] != root or encoded[-32:] != fingerprint:
            raise SystemExit(f"{name}: root/fingerprint placement drift")
    print("PoCO-BFT v0 candidate canonical sign-intent vectors verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
