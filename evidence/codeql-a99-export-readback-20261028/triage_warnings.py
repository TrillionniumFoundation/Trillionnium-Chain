"""Read-only source-location triage; no CodeQL predicate or source changes."""
import collections
import difflib
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
source = Path(sys.argv[1])
inputs = json.loads(gzip.decompress((ROOT / "provenance-input.json.gz").read_bytes()))
warnings = json.loads((ROOT / "warning-locations-no-snippets.json").read_text())
trees = json.loads(gzip.decompress((ROOT / "tree-inventories.json.gz").read_bytes()))
assert trees["head_tree"]["truncated"] is False
assert trees["base_tree"]["truncated"] is False
head_tree = {r["path"]: r for r in trees["head_tree"]["tree"]}
base_tree = {r["path"]: r for r in trees["base_tree"]["tree"]}
base_sources = {r["path"]: r for r in inputs["changed_base_files"]}
cfg_test_ranges = {
    "trillionnium/crates/trnm-types/src/relay.rs": (545, 1064),
    "trillionnium/crates/trnm-transport/src/lib.rs": (409, 645),
    "trillionnium/crates/trnm-types/src/transcript/mod.rs": (84, 202),
    "trillionnium/crates/trnm-worker-agent/src/workflow_ops.rs": (89, 160),
    "trillionnium/crates/trnm-pon-node/src/ancestry_index.rs": (642, 873),
    "trillionnium/crates/trnm-pon-node/src/ingress.rs": (2194, 3756),
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pure_pon.rs": (82, 418),
}

def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

records = []
locations = []
for row in inputs["rows"]:
    path = row["path"]
    data = (source / path).read_bytes()
    assert git_blob(data) == row["head_sha"] == head_tree[path]["sha"]
    assert row["base_sha"] == base_tree.get(path, {}).get("sha")
    lines = data.decode().splitlines()
    located = [r for r in warnings if r["path"] == path]
    assert len(located) == row["alerts"]
    for r in located:
        assert 1 <= r["start_line"] <= r["end_line"] <= len(lines)
    if path in cfg_test_ranges:
        start, end = cfg_test_ranges[path]
        assert lines[start - 1].strip() == "#[cfg(test)]"
        assert lines[start].strip() == "mod tests {"
        assert end <= len(lines) and lines[end - 1].strip() == "}"
        assert all(start < r["start_line"] <= r["end_line"] <= end for r in located)
        classification = "cfg_test_module"
        basis = {"cfg_test_line": start, "module_start_line": start + 1, "reviewed_module_end_line": end}
    elif "/examples/" in path:
        classification = "example_or_research_fixture"
        basis = {"path_scope": "Cargo example target or its support module"}
    elif "/tests/" in path or "/tests.rs" in path or path.endswith("_tests.rs") or "/tests_" in path or "/fuzz/" in path:
        classification = "test_or_fuzz_target"
        basis = {"path_scope": "test or fuzz source"}
    else:
        assert path == "trillionnium/crates/trnm-pon-node/src/main.rs"
        assert [(r["rule"], r["start_line"]) for r in located] == [("rust/cleartext-logging", 2610)]
        classification = "runtime_cli_output"
        basis = {"function": "main result printer", "line": 2610}
    mapping = {}
    base_readback = None
    if path in base_sources:
        base_data = base_sources[path]["content"].encode()
        assert git_blob(base_data) == row["base_sha"]
        baseline = base_data.decode().splitlines()
        for block in difflib.SequenceMatcher(None, baseline, lines, autojunk=False).get_matching_blocks():
            for i in range(block.size):
                mapping[block.b + i + 1] = block.a + i + 1
        base_readback = {"bytes": len(base_data), "sha256": hashlib.sha256(base_data).hexdigest(), "git_blob_sha1": git_blob(base_data)}
    elif row["base_sha"] == row["head_sha"]:
        mapping = {i: i for i in range(1, len(lines) + 1)}
    assert path not in inputs["latest_commit_files"]
    for r in located:
        span = range(r["start_line"], r["end_line"] + 1)
        matched = [mapping.get(i) for i in span]
        unchanged = bool(matched and all(i is not None for i in matched) and matched == list(range(matched[0], matched[0] + len(matched))))
        locations.append({**r, "classification": classification, "latest_a99_commit_changes_file": False,
            "main_base_file_status": row["status"], "exact_line_text_mapped_to_main_base": unchanged,
            "main_base_start_line_if_mapped": matched[0] if unchanged else None,
            "line_text_sha256": hashlib.sha256("\n".join(lines[r["start_line"]-1:r["end_line"]]).encode()).hexdigest()})
    records.append({**row, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "source_git_blob_verified": True, "classification": classification, "classification_basis": basis,
        "rule_counts": dict(collections.Counter(r["rule"] for r in located)), "latest_a99_commit_changes_file": False,
        "base_source_readback": base_readback})
summary = {
    "schema": "codeql-a99-warning-location-source-triage-v1", "head": inputs["head"], "main_base": inputs["base"],
    "head_tree": trees["head_tree"]["sha"], "base_tree": trees["base_tree"]["sha"],
    "head_tree_entries": len(head_tree), "base_tree_entries": len(base_tree), "both_recursive_trees_complete": True,
    "locations": locations, "files": records, "result_count": len(locations), "file_count": len(records),
    "class_counts": dict(collections.Counter(r["classification"] for r in locations)),
    "rule_counts": dict(collections.Counter(r["rule"] for r in locations)),
    "main_base_file_status_counts": dict(collections.Counter(r["main_base_file_status"] for r in locations)),
    "latest_commit_file_count": len(inputs["latest_commit_files"]), "latest_commit_files": inputs["latest_commit_files"],
    "latest_a99_commit_changes_any_warning_file": False,
    "scope": "Location and exact source-byte provenance, not a false-positive dismissal or proof of no secret exposure. Exact unchanged line text does not prove unchanged data flow. File absence at the main base does not date introduction within the 649-commit PR. Original API SARIF is a subset; this is not the full CodeQL database or all historical branch alerts. No source or security predicate was modified.",
}
(ROOT / "warning-provenance.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps({k: summary[k] for k in ("result_count", "file_count", "class_counts", "rule_counts", "main_base_file_status_counts", "latest_a99_commit_changes_any_warning_file")}, sort_keys=True))
print(json.dumps({"changed_file_locations": len([r for r in locations if r["main_base_file_status"] == "changed_blob_from_main_base"]), "changed_file_exact_line_matches": len([r for r in locations if r["main_base_file_status"] == "changed_blob_from_main_base" and r["exact_line_text_mapped_to_main_base"]])}))
