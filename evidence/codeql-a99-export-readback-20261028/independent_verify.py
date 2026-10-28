"""Offline verification of the exact successful export and location inventory.

Usage: python3 independent_verify.py [--source-root /path/to/exact-source]
No network, mutation of repository sources, scanner or benchmark execution.
"""
import argparse
import collections
import datetime
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

ROOT = Path(__file__).resolve().parent
HEAD = "a99ef8e333b6f1b7486b33e820464cf824fec273"
BASE = "9fedf7ecbbe07177069c030592b4e03dcffebb81"
TREE = "f996fa2ad8cfa4426b6a7b2e04c5fd858025f8fe"
ARCHIVE_SHA = "6e6f9b6545f288dd90a5c83d1158a96d1342da0e593689e39cfb1de23c3c818f"

def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

def decode(raw):
    return json.loads(raw, object_pairs_hook=no_duplicates)

parser = argparse.ArgumentParser()
parser.add_argument("--source-root", type=Path)
args = parser.parse_args()
raw = (ROOT / "original.zip").read_bytes()
assert len(raw) == 280064 and hashlib.sha256(raw).hexdigest() == ARCHIVE_SHA
with zipfile.ZipFile(ROOT / "original.zip") as z:
    names = z.namelist()
    assert len(names) == len(set(names)) == 145
    assert sum(r.file_size for r in z.infolist()) < 8 * 1024 * 1024
    all_bytes = {}
    for name in names:
        path = PurePosixPath(name)
        assert not path.is_absolute() and ".." not in path.parts and not name.endswith("/")
        all_bytes[name] = z.read(name)
    outer = decode(all_bytes["sha256.json"])
    inner = decode(all_bytes["analysis/sha256.json"])
    assert set(outer) == {n for n in names if PurePosixPath(n).name != "sha256.json"}
    assert set(inner) == {n.removeprefix("analysis/") for n in names if n.startswith("analysis/") and n != "analysis/sha256.json"}
    assert len(outer) == 143 and len(inner) == 139
    for name, digest in outer.items():
        assert hashlib.sha256(all_bytes[name]).hexdigest() == digest
    for name, digest in inner.items():
        assert hashlib.sha256(all_bytes["analysis/" + name]).hexdigest() == digest
    source = decode(all_bytes["exporter-source-before.json"])
    assert source == decode(all_bytes["exporter-source-after.json"])
    assert source["tested_commit"] == HEAD and source["tested_tree"] == TREE
    assert source["tracked_worktree_verified"] is True
    assert source["tracked_entries"] == 5959 and source["tracked_bytes"] == 767617754
    result = decode(all_bytes["analysis/result.json"])
    assert result["complete"] is True and result["error"] is None
    assert result["security_gate_changed"] is False
    assert result["target_pr_gate_authenticated"] is False and result["target_pr_gate_verdict"] is None
    assert result["full_original_sarif_upload"] is False and result["all_branch_historical_alerts"] is False
    target = result["target"]
    assert target["pr"] == 533 and target["head"] == HEAD and target["base"] == BASE
    assert target["head_ref"] == "refs/pull/533/head"
    seconds = (datetime.datetime.fromisoformat(result["finished_utc"]) - datetime.datetime.fromisoformat(result["started_utc"])).total_seconds()
    assert 0 < seconds <= 1200
    selections = [decode(all_bytes["analysis/" + name + "/selection.json"]) for name in ("poll-023", "poll-024", "poll-024-after-export")]
    assert selections[0] == selections[1] == selections[2]
    stable = selections[0]
    assert stable["ready"] is True
    analyses = stable["analyses"]
    assert {r["category"] for r in analyses} == {"/language:actions", "/language:python", "/language:rust"}
    assert {r["id"] for r in analyses} == {2041899112, 2041904174, 2041935511}
    for row in analyses:
        assert row["commit_sha"] == HEAD and row["ref"] == "refs/pull/533/head"
        assert not row["error"] and not row["warning"]
        assert row["tool"]["name"] == "CodeQL" and row["tool"]["version"] == "2.27.3"
    assert len(stable["checks"]) == 1
    check = stable["checks"][0]
    assert check["id"] == 122605175751 and check["head_sha"] == HEAD
    assert check["app"]["id"] == 57789 and check["app"]["slug"] == "github-advanced-security"
    assert check["status"] == "completed" and check["conclusion"] == "success"
    assert any(p["number"] == 533 and p["head"]["sha"] == HEAD and p["base"]["sha"] == BASE for p in check["pull_requests"])
    warnings = []
    for row in analyses:
        sarif = decode(all_bytes[f"analysis/analyses/{row['id']}.sarif"])
        actual = [r for run in sarif["runs"] for r in run.get("results", [])]
        assert len(actual) == row["results_count"]
        for warning in actual:
            loc = warning["locations"][0]["physicalLocation"]
            warnings.append((warning["ruleId"], warning.get("level", "warning"), loc["artifactLocation"]["uri"], loc["region"]["startLine"], loc["region"].get("endLine", loc["region"]["startLine"])))
    provenance = decode((ROOT / "warning-provenance.json").read_bytes())
    supplied = [(r["rule"], r["level"], r["path"], r["start_line"], r["end_line"]) for r in provenance["locations"]]
    assert collections.Counter(warnings) == collections.Counter(supplied)
    assert len(warnings) == 322 and len(provenance["files"]) == 40
    assert collections.Counter(r[0] for r in warnings) == {"rust/hard-coded-cryptographic-value": 299, "rust/cleartext-logging": 23}
    assert collections.Counter(r["classification"] for r in provenance["locations"]) == {"cfg_test_module": 88, "test_or_fuzz_target": 228, "example_or_research_fixture": 5, "runtime_cli_output": 1}
    trees = decode(gzip.decompress((ROOT / "tree-inventories.json.gz").read_bytes()))
    assert trees["head_tree"]["sha"] == TREE and trees["base_tree"]["sha"] == "af52e79d69de2224fa709309704ba6a971453579"
    assert trees["head_tree"]["truncated"] is False and trees["base_tree"]["truncated"] is False
    assert len(trees["head_tree"]["tree"]) == 6593 and len(trees["base_tree"]["tree"]) == 1267
    head = {r["path"]: r for r in trees["head_tree"]["tree"]}
    base = {r["path"]: r for r in trees["base_tree"]["tree"]}
    verified = 0
    for row in provenance["files"]:
        assert row["head_sha"] == head[row["path"]]["sha"]
        assert row["base_sha"] == base.get(row["path"], {}).get("sha")
        assert row["path"] not in provenance["latest_commit_files"]
        if args.source_root:
            data = (args.source_root / row["path"]).read_bytes()
            assert len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"]
            assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["head_sha"]
            verified += 1
    output = {"schema": "codeql-a99-offline-independent-verify-v1", "pass": True,
        "archive_sha256": ARCHIVE_SHA, "members_crc_and_sha_verified": len(names), "outer_manifest_entries": len(outer),
        "inner_manifest_entries": len(inner), "source_before_after_equal": source, "poll_23_equals_24_equals_after_export": True,
        "export_elapsed_seconds": seconds, "source_check_id": check["id"], "source_check_success": True,
        "api_sarif_warning_count": len(warnings), "warning_files": 40, "exact_local_source_files_verified": verified,
        "full_repo_zero_alerts_claim": False, "target_pr_gate_authenticated_claim": False}
    print(json.dumps(output, indent=2, sort_keys=True))
