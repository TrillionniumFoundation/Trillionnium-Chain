#!/usr/bin/env python3
"""Independent light-client proof-bundle verifier.

No import from the whole-node model or TRNM implementation is permitted.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import Any

class Invalid(ValueError):
    pass

EXPECTED = {"order", "da", "execution", "result", "settlement", "upgrade"}

def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Invalid(f"duplicate-key:{key}")
        out[key] = value
    return out

def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates,
                      parse_constant=lambda x: (_ for _ in ()).throw(Invalid(x)))

def verify(bundle: dict[str, Any]) -> dict[str, Any]:
    if set(bundle) != {"schema", "checkpoint", "families"}:
        raise Invalid("top-level-shape")
    if bundle["schema"] != "trnm-light-client-proof-bundle-v1":
        raise Invalid("schema")
    checkpoint = bundle["checkpoint"]
    if not isinstance(checkpoint, str) or len(checkpoint) != 64:
        raise Invalid("checkpoint")
    families = bundle["families"]
    if not isinstance(families, dict) or set(families) != EXPECTED:
        raise Invalid("families")

    key = None
    for name in sorted(EXPECTED):
        value = families[name]
        if not isinstance(value, dict):
            raise Invalid(f"family-type:{name}")
        current = (value.get("chain_id"), value.get("height"),
                   value.get("block_id"), value.get("application_root"))
        if not isinstance(current[1], int) or current[1] <= 0 or not all((current[0], current[2], current[3])):
            raise Invalid(f"binding:{name}")
        if key is None:
            key = current
        elif current != key:
            raise Invalid(f"cross-family-binding:{name}")

    order = families["order"]
    if order.get("finality_chain_length") != 3 or order.get("quorum") is not True:
        raise Invalid("order")
    da = families["da"]
    if da.get("mode") != "DA-FULLREP-V1" or da.get("complete_retrieval") is not True:
        raise Invalid("da")
    execution = families["execution"]
    if execution.get("jmt_inclusion") is not True or execution.get("composite_root") is not False:
        raise Invalid("execution")
    result = families["result"]
    if result.get("profile") != "deterministic-reexecution-v1" or result.get("mature") is not True:
        raise Invalid("result")
    settlement = families["settlement"]
    if settlement.get("exactly_once") is not True or settlement.get("conserved") is not True:
        raise Invalid("settlement")
    if settlement.get("poco_weight") is not False:
        raise Invalid("poco-weight")
    upgrade = families["upgrade"]
    if upgrade.get("no_downgrade") is not True or upgrade.get("trusted_checkpoint") != checkpoint:
        raise Invalid("upgrade")
    return {"chain_id": key[0], "height": key[1], "block_id": key[2],
            "application_root": key[3], "checkpoint": checkpoint}

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--bundle", type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(verify(load(args.bundle)), sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
