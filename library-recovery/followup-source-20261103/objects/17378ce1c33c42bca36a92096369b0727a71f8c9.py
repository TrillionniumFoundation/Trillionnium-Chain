#!/usr/bin/env python3
"""Audit original ARM64 complete W1 cost grid. Read-only; no ELF execution/network.

Requires the original ZIP and the eight exact E source files listed in PINS.
It validates those bytes before importing the two original reduction helpers.
"""
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import zipfile

HEAD = "974932be6dcfe830ce1ce92d58cb10e89cb8358d"
TREE = "d4435ebdecac15e9a3fb2852eb1f835b336e452e"
ARCHIVE_SHA = "fca8cd190f756c151c26c552eca6b81ae3dcd713d6a780384704e2797ab6f6c6"
ARCHIVE_BYTES = 10213454
PINS = [
  {
    "path": "scripts/ci/check_pure_pon_cost_campaign.py",
    "blob": "397ab4e10b59f264fcac4521050e90ff7bcf32d2",
    "sha256": "596fb6becc08e3f2026801c541bf395e06133c3e2d28c780300f2b24ec09abe5",
    "bytes": 9854
  },
  {
    "path": "scripts/ci/summarize_pure_pon_cost_campaign.py",
    "blob": "bde741a9c7561b247688b584937ed7c4c17815ee",
    "sha256": "a38bbb37d997eba07492289c4115b56e9a84f4d3366664f0dd4b4623469a441a",
    "bytes": 4839
  },
  {
    "path": "scripts/ci/capture_pure_pon_campaign.py",
    "blob": "1d82eca0b64c85691c7a2ef279b2db835eb59968",
    "sha256": "bc411dc18cdd354c26a3b19f365680356c6a44f211ead0cb85226a74f875eb4a",
    "bytes": 7543
  },
  {
    "path": "trillionnium/crates/trnm-pon-node/examples/pon_pure_cost_campaign.rs",
    "blob": "934278331e2f68cc2c71b311e7ff592805164196",
    "sha256": "203304c581a455c71bf5bee923c8d59fc9883a2f5365d399454f7b33493ce95b",
    "bytes": 23593
  },
  {
    "path": "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "blob": "1eac3ef6b9933992e1e0cab061b075a77ac1a31e",
    "sha256": "af9f9415bda1a0770f2f19cb10140010b1243cef30a7586b9e4d66c3728c9c52",
    "bytes": 75798
  },
  {
    "path": "trillionnium/crates/trnm-crypto-primitives/src/pon_work/low_rank_prefix.rs",
    "blob": "c359642f95dc5f2fa6981fd52c775785d223effa",
    "sha256": "83007c8d1395ba38328f4546cb88da89786c7aa5e1048f76a7568787d28732c5",
    "bytes": 13950
  },
  {
    "path": "trillionnium/Cargo.lock",
    "blob": "c9abb10fa48a32e14cb1b0d153fe7e6e2b99583e",
    "sha256": "ffb27b48e8a2f8bc7582d0e505ded50b81380e0fb26044dbbebb9cf115fdbe6c",
    "bytes": 63902
  },
  {
    "path": "trillionnium/Cargo.toml",
    "blob": "44df8f8d5eec880d10da42c12a903c03658cfc65",
    "sha256": "48e0094090202b3b6d12331965be846a34c2a454ff3dc3717a532f228e4dd50b",
    "bytes": 2204
  }
]
MATERIALS = {"periodic-dense-fixture", "full-rank-field", "zero", "identity",
             "rank-one", "sparse-diagonal", "genesis-maintenance",
             "zero-left-rank-one-right", "rank-one-left-zero-right"}

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def natural(value):
    return type(value) is int and value >= 0

def read_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))

def original_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def audit(archive_path, source_root):
    require(not archive_path.is_symlink(), "archive symlink")
    raw_zip = archive_path.read_bytes()
    require(len(raw_zip) == ARCHIVE_BYTES and sha(raw_zip) == ARCHIVE_SHA, "ZIP binding")
    source_bytes = {}
    for pin in PINS:
        path = source_root / pin["path"]
        require(path.is_file() and not path.is_symlink(), "source input")
        raw = path.read_bytes()
        require(len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], "source SHA256")
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                == pin["blob"], "source Git blob")
        source_bytes[pin["path"]] = raw
    checked_module = original_module("check_pure_pon_cost_campaign",
                                     source_root / PINS[0]["path"])
    summary_module = original_module("summarize_pure_pon_cost_campaign",
                                     source_root / PINS[1]["path"])
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
        entries = archive.infolist()
        require(len(entries) == 18 and len({i.filename for i in entries}) == 18, "ZIP entries")
        contents = {}
        inventory = []
        for entry in entries:
            require(entry.file_size <= 40 * 1024 * 1024, "member bound")
            raw = archive.read(entry)  # ZIP CRC checked by the standard library.
            contents[entry.filename] = raw
            inventory.append({"path": entry.filename, "bytes": len(raw), "sha256": sha(raw)})
    before = read_json(contents["source-before.json"])
    after = read_json(contents["source-after.json"])
    require(before == after, "source before/after")
    require(before["tested_commit"] == HEAD and before["tested_tree"] == TREE
            and before["tracked_worktree_verified"] is True, "source head/tree")
    capture = read_json(contents["cost/capture.json"])
    require(capture["source"]["commit"] == HEAD and capture["source"]["tree"] == TREE, "capture source")
    require(capture["exit_code"] == 0 and capture["timed_out"] is False
            and capture["machine"] == "aarch64", "successful native ARM64 capture")
    require(capture["argv"][1:] == ["--searches", "256", "--attempts", "8", "--rounds", "2",
                                   "--seed", "1", "--seconds", "1800"], "exact experiment")
    require(capture["package_opt_levels"] == {"trnm-pon-node": 3,
            "trnm-crypto-primitives": 3, "trnm-mvcc-fee": 1}, "actual declared build profile")
    binary = contents["pon_pure_cost_campaign.arm64"]
    require(binary.startswith(b"\x7fELF") and int.from_bytes(binary[18:20], "little") == 183,
            "actual AArch64 ELF")
    require(sha(binary) == capture["binary_sha256_before"] == capture["binary_sha256_after"],
            "stable captured ELF")
    embedded = {}
    for path in [PINS[i]["path"] for i in (3, 4, 5, 6)]:
        embedded[path] = source_bytes[path] in binary
        require(embedded[path], "compiled source bytes absent from retained ELF")
    compressed = contents["cost/stdout.jsonl.gz"]
    require(len(compressed) == capture["stdout_gzip_bytes"]
            and sha(compressed) == capture["stdout_gzip_sha256"], "compressed raw binding")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    require(len(raw) <= 32 * 1024 * 1024 and raw.endswith(b"\n"), "raw bound")
    require(len(raw) == capture["stdout_bytes"]
            and sha(raw) == capture["stdout_uncompressed_sha256"], "raw stream binding")
    require(sha(contents["cost/stderr.log"]) == capture["stderr_sha256"], "stderr binding")
    rows = [read_json(line) for line in raw.splitlines()]
    checked = checked_module.check(rows, source_root)
    archived_consistency = read_json(contents["cost/consistency.json"])
    compare = dict(checked, compiled_source_bytes_matched=False, input_sha256=sha(raw))
    require(compare == archived_consistency, "recomputed original consistency")
    summary = summary_module.summarize(rows)
    summary["input_sha256"] = sha(raw)
    require(summary == read_json(contents["cost/summary.json"]), "recomputed fixed-group summary")
    begin, terminal = rows[0], rows[-1]
    require((begin["rounds"], begin["max_horizon"], begin["attempt_budget"], begin["seed"])
            == (2, 256, 8, 1), "plan")
    require(terminal["cohorts"] == 4032, "complete Cartesian grid")
    materials = [r for r in rows if r["kind"] == "material"]
    require({r["name"] for r in materials} == MATERIALS and len(materials) == 9, "materials")
    material_by_name = {r["name"]: r for r in materials}
    cohorts = [r for r in rows if r["kind"] == "cohort"]
    unique_trials, unique_winners, native_winners = set(), set(), set()
    native_calls = 0
    outcome_keys = {}
    independently_summed = Counter()
    lowrank_support = {}
    for row in cohorts:
        key = (row["material"], row["target"], row["round"], row["horizon"], row["reuse"])
        if row["strategy"].startswith("low-rank-prefix"):
            supported = row["status"] == "complete"
            expected = max(material_by_name[row["material"]][k] for k in ("rank_a", "rank_b")) <= 8
            require(supported == expected, "low-rank support against recorded material ranks")
            lowrank_support[row["material"]] = supported
        if row["status"] == "unsupported":
            independently_summed["unsupported_cohorts"] += 1
            independently_summed["unsupported_probe_setup_cpu_ns"] += row["setup_cpu_ns"]
            independently_summed["unsupported_probe_setup_wall_ns"] += row["setup_wall_ns"]
            continue
        independently_summed["supported_cohorts"] += 1
        searches = row["searches"]
        require(all(natural(s["search_cpu_ns"]) and natural(s["search_wall_ns"]) for s in searches),
                "unknown observed clocks")
        require(row["total_producer_cpu_ns"] == row["setup_cpu_ns"]
                + sum(s["search_cpu_ns"] for s in searches), "independent CPU denominator")
        require(row["total_producer_wall_ns"] == row["setup_wall_ns"]
                + sum(s["search_wall_ns"] for s in searches), "independent wall denominator")
        outcomes = [(s["attempts"], s["winner"], s["last_ticket"]) for s in searches]
        require(outcome_keys.setdefault(key, outcomes) == outcomes, "paired exact search outcomes")
        for s in searches:
            trial_key = (row["material"], row["target"], row["round"], s["search"])
            require((int(s["last_ticket"], 16) <= int(row["target"], 16)) is s["winner"],
                    "independent exact target comparison")
            for attempt in range(s["attempts"]):
                unique_trials.add(trial_key + (attempt,))
            if s["winner"]:
                winner = trial_key + (s["attempts"] - 1,)
                unique_winners.add(winner)
                if row["material"] == "genesis-maintenance" and row["target"] == begin["native_target"]:
                    native_winners.add(winner)
        for field in ("attempts", "winners", "exhausted", "native_accepted_calls",
                      "total_producer_cpu_ns", "setup_cpu_ns"):
            independently_summed[field] += row[field]
        native_calls += row["native_accepted_calls"]
    require(independently_summed["attempts"] == summary["attempts"]
            and independently_summed["winners"] == summary["winning_calls"]
            and independently_summed["exhausted"] == summary["exhausted_searches"], "independent totals")
    selected = [g for g in summary["groups"] if g["reuse"] is True and g["horizon"] == 256]
    return {
        "schema": "pon-pure-arm64-v2-974932be-independent-audit-v1",
        "all_checks_passed": True, "source_commit": HEAD, "source_tree": TREE,
        "original_run": 40845715711, "artifact_id": 12886355199,
        "archive_sha256": ARCHIVE_SHA, "archive_bytes": ARCHIVE_BYTES,
        "all_member_crcs_checked": True, "archive_inventory": inventory,
        "source_pins": PINS, "compiled_sources_present_in_retained_elf": embedded,
        "source_observation": before, "capture": capture,
        "host": read_json(contents["host.json"]), "materials": materials,
        "cartesian_grid": {"materials": 9, "strategies": 14, "reuse_policies": 2,
                           "horizons": [1, 8, 64, 256], "rounds": 2, "targets": 2,
                           "cohorts": 4032},
        "independent_totals": dict(independently_summed),
        "unique_observed_trial_header_keys": len(unique_trials),
        "unique_observed_winning_header_keys": len(unique_winners),
        "repeated_native_cohort_admit_calls": native_calls,
        "bootstrap_seed_native_admit_calls": 1,
        "unique_observed_native_winning_header_keys": len(native_winners),
        "low_rank_prefix_support_for_both_kernels": lowrank_support,
        "all_fixed_H256_reuse_groups_both_rounds": selected,
        "late_product_rejection": checked["late_product_rejection"],
        "scope": [
            "Raw accounting and fixed original reader/reduction independently replayed; retained ELF not executed.",
            "Four source inputs are bound both to E Git blobs and byte occurrences inside the retained ELF. This is not a trusted compiler or hardware attestation.",
            "Only genesis-maintenance at the native target reaches Node::admit; other materials/targets remain primitive-only, with no installed task/admission claim.",
            "Native calls repeat shared header streams across strategies, reuse policies and nested horizons; counts are not distinct tickets, first admissions or active-chain rewards.",
            "Costs include preparation and all attempts including misses, but exclude validation, native admission, stream hashing, report IO and some harness overhead.",
            "Aggregate producer/setup totals sum supported cohorts only. Unsupported constructor probe CPU/wall is retained separately; the complete process capture includes those probes and the separate bootstrap seed admission.",
            "The generic grid has no scalar-original arm and uses a test profile, so its ratios must not replace V5 scalar/end-to-end or ticket-first release-profile ratios.",
            "Captured RUSAGE_CHILDREN CPU differences are original observations. ru_maxrss is a cumulative child maximum, not a separately isolated complete-family peak for this driver.",
            "Source-before/after records attest their tracked checks; this audit does not reconstruct every Git tree file or independently recompute W1 proofs.",
            "No energy, GPU/ASIC, exclusive-host, global least-cost or hardness qualification."
        ]
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = audit(args.archive, args.source_root)
    result["audit_script_sha256"] = sha(Path(__file__).read_bytes())
    with args.output.open("x") as out:
        json.dump(result, out, indent=2, allow_nan=False)
        out.write("\n")
    print(json.dumps({"all_checks_passed": result["all_checks_passed"],
                      "cohorts": result["cartesian_grid"]["cohorts"],
                      "totals": result["independent_totals"],
                      "unique_native_winners": result["unique_observed_native_winning_header_keys"],
                      "output": str(args.output)}))

if __name__ == "__main__":
    main()

