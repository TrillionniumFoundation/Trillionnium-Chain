#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "docs/protocol/poco-ai-native-v1/registry/operation-registry-v1.json"

LINKS_BY_PLANE = {
    "agent": ["W0","W1","W2","W3","W4","W7"],
    "market-task": ["W0","W1","W2","W3","W4","W7"],
    "compute-verify": ["W0","W1","W2","W3","W4","W5","W7"],
    "data-availability": ["W0","W1","W2","W3","W7"],
    "execution": ["W0","W1","W2","W3","W4","W7"],
    "settlement": ["W0","W1","W2","W3","W4","W5","W6","W7"],
    "order": ["W0","W3","W7"],
    "upgrade": ["W0","W1","W3","W4","W7"],
    "sync": ["W0","W3","W4","W7"],
    "light-client": ["W0","W7"],
    "governance": ["W0","W1","W2","W3","W4","W7"],
    "reserved": ["W0"],
}


def load_registry() -> dict:
    value = json.loads(REGISTRY.read_text(encoding="utf-8"))
    rows = value["operations"]
    if sorted(row["kind"] for row in rows) != list(range(30)):
        raise SystemExit("registry does not cover 0..29")
    return value


def generate() -> dict:
    registry = load_registry()
    rows = []
    for op in registry["operations"]:
        plane = op["plane"]
        if plane not in LINKS_BY_PLANE:
            raise SystemExit(f"unknown plane: {plane}")
        required = LINKS_BY_PLANE[plane]
        row = {
            "kind": op["kind"],
            "name": op["name"],
            "plane": plane,
            "status": "disabled" if op["status"] == "disabled" else "candidate-assigned",
            "required_links": required,
            "schema_hash": None,
            "domain_id": None,
            "maximum_bytes": None,
            "maximum_nested_items": None,
            "maximum_signature_work": None,
            "static_authority": op.get("authority"),
            "nonce_lane": op.get("nonce_lane"),
            "access_set": None,
            "implementation_owner": None,
            "evidence": {link: None for link in required},
        }
        rows.append(row)
    return {
        "schema": "trnm-w0-w7-operation-matrix-v1",
        "status": "candidate-non-normative",
        "source_registry": str(REGISTRY.relative_to(ROOT)),
        "rows": rows,
        "g2_0_complete": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    value = generate()
    raw = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(raw, encoding="utf-8")
    else:
        print(raw, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
