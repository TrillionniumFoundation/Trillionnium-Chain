#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

try:
    from traceability_gate import strict_loads
except ImportError:  # pragma: no cover - direct module execution fallback
    from tools.w0_w7_codegen.traceability_gate import strict_loads

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
    "order-coordination-settlement": ["W0","W3","W4","W7"],
}


def load_registry(path: Path = REGISTRY) -> dict:
    try:
        value = strict_loads(path.read_bytes(), str(path))
    except (OSError, ValueError) as error:
        raise SystemExit(f"registry rejected: {error}") from error
    if not isinstance(value, dict) or not isinstance(value.get("operations"), list):
        raise SystemExit("registry must contain an operations array")
    rows = value["operations"]
    if len(rows) != 30 or [row.get("kind") if isinstance(row, dict) else None for row in rows] != list(range(30)):
        raise SystemExit("registry does not cover ordered slots 0..29")
    return value


def generate(registry_path: Path = REGISTRY) -> dict:
    registry = load_registry(registry_path)
    rows = []
    for op in registry["operations"]:
        if not isinstance(op, dict) or op.get("enabled") is not False:
            raise SystemExit("registry operation rows must be explicit enabled=false objects")
        if op.get("status") not in {"candidate-assigned", "disabled"}:
            raise SystemExit("registry operation has an unknown status")
        if not isinstance(op.get("body_type"), str) or not op["body_type"].endswith("V1"):
            raise SystemExit("registry operation body_type is missing or non-canonical")
        plane = op["plane"]
        if plane not in LINKS_BY_PLANE:
            raise SystemExit(f"unknown plane: {plane}")
        # Disabled rows terminate at W0 regardless of their planning plane.
        # This deliberately does not assume that kind 29 is the sentinel;
        # corrected A08 tables disable the profile-specific slots instead.
        required = ["W0"] if op.get("status") == "disabled" else LINKS_BY_PLANE[plane]
        row_digest = hashlib.sha256(
            json.dumps(
                {"operation": op, "required_links": required},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        row = {
            "kind": op["kind"],
            "name": op["name"],
            "body_type": op.get("body_type"),
            "plane": plane,
            "status": "disabled" if op["status"] == "disabled" else "candidate-assigned",
            "enabled": False,
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
            "evidence_id": f"g20-row-{int(op['kind']):02d}-{row_digest[:32]}",
            "evidence_status": "missing",
        }
        if op.get("canonical_error") is not None:
            row["canonical_error"] = op["canonical_error"]
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
