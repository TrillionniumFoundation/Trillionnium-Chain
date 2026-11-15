#!/usr/bin/env python3
"""Verify this evidence archive's exact entry set and SHA-256 hashes; no binaries executed."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

root = Path(__file__).resolve().parent
evidence = json.loads((root / "evidence.json").read_text())
spec = evidence["raw_archive"]
archive = root / spec["path"]
assert archive.stat().st_size == spec["bytes"], "archive length differs"
assert hashlib.sha256(archive.read_bytes()).hexdigest() == spec["sha256"], "archive hash differs"
expected = {row["path"]: row for row in spec["entries"]}
assert len(expected) == len(spec["entries"]) == spec["entry_count"], "duplicate manifest entry"
with zipfile.ZipFile(archive) as z:
    names = z.namelist()
    assert len(names) == len(set(names)), "duplicate ZIP member"
    assert set(names) == set(expected), "ZIP member set differs"
    for name in names:
        path = PurePosixPath(name)
        assert not path.is_absolute() and ".." not in path.parts and name.startswith("raw/"), "unsafe ZIP path"
        content = z.read(name)
        assert len(content) == expected[name]["bytes"], f"length differs: {name}"
        assert hashlib.sha256(content).hexdigest() == expected[name]["sha256"], f"hash differs: {name}"
    for command in evidence["source_fenced_commands"]:
        receipt = json.loads(z.read(command["receipt"]))
        assert receipt["exit_code"] == command["exit_code"]
        assert receipt["before"] == receipt["after"]
        assert receipt["before"]["tested_commit"] == command["tested_commit"]
        assert receipt["before"]["tested_tree"] == command["tested_tree"]
        assert hashlib.sha256(z.read(command["log"])).hexdigest() == receipt["log_sha256"]
assert evidence["final_chain_commit"] == "2a8fee974b41fab6e2c4e662dcce1807fcd19bdd"
assert evidence["final_hepta_commit"] is None
assert any(anchor["role"] == "fixed_published_chain_input" and anchor["commit"] == evidence["final_chain_commit"] for anchor in evidence["source_anchors"])
assert not any(evidence["gate_closed"].values()) and evidence["production_activation"] is False
assert evidence["same_material_attack"]["false_candidates"] == 80
assert evidence["same_material_attack"]["total_refusal_calls"] == 360
print(json.dumps({"status": "PASS_ARCHIVE_INTEGRITY_ONLY", "entries": len(expected), "source_fenced_receipts": len(evidence["source_fenced_commands"]), "raw_zip_sha256": spec["sha256"], "release_or_business_acceptance_executed": False}, sort_keys=True))
