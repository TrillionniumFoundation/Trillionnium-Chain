#!/usr/bin/env python3
"""Read retained legal factorial records; never execute a producer or verifier.

The compressed archive is streamed and only one legal shard is materialized at
a time. All original archive members are hashed, not extracted by their paths.
"""
import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
import pon_w1_legal_strategy_reader_v3 as reader

HISTORICAL = ROOT / "evidence/pon-w1-factorial-v3-20261102"
NATIVE_COMMIT = "2b250859e7c07088e6c3c01f75006372c684de61"
PREFIX = "successful-2b250859/w1-legal-strategy-v3/"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def file_identity(path):
    return {"bytes": path.stat().st_size, "sha256": digest(path)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main(out):
    out.mkdir(parents=True, exist_ok=True)
    require(not any((out / name).exists() for name in ("rates.json", "provenance.json")),
            "use a fresh output directory; retained evidence must not be overwritten")
    input_names = ("archive-index.json", "legal-execution-manifest.json", "analysis/completed/analysis.json")
    inputs = {name: file_identity(HISTORICAL / name) for name in input_names}
    published = json.loads((HISTORICAL / "manifest.json").read_text())
    for name, identity in inputs.items():
        require(identity == published["files"][name], "historical input hash: " + name)
    index = json.loads((HISTORICAL / input_names[0]).read_text())
    archive = next(a for a in index["archives"] if a.get("source_commit") == NATIVE_COMMIT)
    execution = json.loads((HISTORICAL / input_names[1]).read_text())
    historical_analysis = json.loads((HISTORICAL / input_names[2]).read_text())
    require(execution["source_before"] == execution["source_after"]
            and execution["source_before"]["commit"] == NATIVE_COMMIT
            and execution["result"] == "PASS" and not execution["source_changed"], "native source receipt")
    source_paths = (ROOT / "scripts/pon_w1_legal_strategy_reader_v3.py",
                    ROOT / "scripts/pon_w1_cost_matrix_reader.py", reader.common.PROFILE,
                    Path(__file__).resolve())
    sources = {str(p.relative_to(ROOT)): file_identity(p) for p in source_paths}
    old = {s["observation"]["stdout"]: s["reader"] for s in execution["shards"]}
    archive_digest = hashlib.sha256()
    for part in archive["parts"]:
        path = HISTORICAL / part["name"]
        require(file_identity(path) == {k: part[k] for k in ("bytes", "sha256")}, "archive part hash")
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                archive_digest.update(chunk)
    require(archive_digest.hexdigest() == archive["sha256"], "assembled archive hash")
    cat = subprocess.Popen(["cat", "--", *(str(HISTORICAL / p["name"]) for p in archive["parts"])],
                           stdout=subprocess.PIPE)
    decoder = subprocess.Popen(["zstd", "-dc"], stdin=cat.stdout, stdout=subprocess.PIPE)
    cat.stdout.close()
    reports, fingerprints, members, legal_inputs = [], {}, set(), []
    try:
        with tempfile.TemporaryDirectory(prefix=".legal-readback-", dir=out) as temporary:
            shard_path = Path(temporary) / "one-shard.stdout"
            with tarfile.open(fileobj=decoder.stdout, mode="r|") as stream:
                for member in stream:
                    if member.isdir():
                        continue
                    require(member.isfile() and member.name in archive["entries"]
                            and member.name not in members, "archive member type/name/duplication")
                    members.add(member.name)
                    expected = archive["entries"][member.name]
                    require(member.size == expected["bytes"], "archive member length")
                    legal = re.fullmatch(re.escape(PREFIX) + r"campaign-\d{2}\.stdout", member.name) is not None
                    hasher, size = hashlib.sha256(), 0
                    destination = shard_path.open("wb") if legal else None
                    try:
                        with stream.extractfile(member) as source:
                            while chunk := source.read(1024 * 1024):
                                size += len(chunk)
                                hasher.update(chunk)
                                if destination is not None:
                                    destination.write(chunk)
                    finally:
                        if destination is not None:
                            destination.close()
                    require(size == expected["bytes"] and hasher.hexdigest() == expected["sha256"],
                            "archive member digest: " + member.name)
                    if not legal:
                        continue
                    report = reader.analyze_shard(shard_path)
                    shard_path.unlink()
                    require(report["input_sha256"] == expected["sha256"], "reader input identity")
                    original = old[Path(member.name).name]
                    for key, value in original.items():
                        if key == "strategy_costs":
                            for before, after in zip(value, report[key], strict=True):
                                require(all(after[k] == v for k, v in before.items()), "historical strategy output changed")
                        else:
                            require(report[key] == value, "historical output changed: " + key)
                    choice = report["selection"]
                    for searched in report["search_fingerprints"]:
                        key = choice["class"], choice["target_index"], searched["sample"], searched["search_index"]
                        require(key not in fingerprints or fingerprints[key] == searched, "shared horizon prefix changed")
                        fingerprints[key] = searched
                    legal_inputs.append({"archive_member": member.name, **expected, "selection": choice})
                    reports.append(report)
        require(decoder.wait() == 0 and cat.wait() == 0, "archive decompression failed")
    finally:
        decoder.stdout.close()
        for process in (decoder, cat):
            if process.poll() is None:
                process.terminate()
                process.wait()
    require(members == set(archive["entries"]), "incomplete archive inventory")
    expected_grid = {(c, t, h) for c in reader.CLASSES for t in range(len(reader.TARGETS)) for h in reader.HORIZONS}
    actual_grid = [(r["selection"]["class"], r["selection"]["target_index"], r["selection"]["reuse_winners"]) for r in reports]
    require(len(actual_grid) == len(set(actual_grid)) == len(expected_grid)
            and set(actual_grid) == expected_grid, "incomplete/duplicate factorial grid")
    reports.sort(key=lambda r: (reader.CLASSES.index(r["selection"]["class"]),
                               r["selection"]["target_index"], r["selection"]["reuse_winners"]))
    totals, outcomes, variations = Counter(), Counter(), []
    for report in reports:
        for costs in report["strategy_costs"]:
            for key in ("actual_setup_calls", "actual_searches", "attempts", "target_hits", "exhausted_searches"):
                totals[key] += costs[key]
            for case, counts in costs["native_outcome_counts"].items():
                for verdict, count in counts.items():
                    outcomes[case + ":" + verdict] += count
            samples = costs["per_sample_denominators"]
            cpus = sorted(s["inclusive_cohort_total"]["cpu_ns"] for s in samples)
            median = Fraction(cpus[3] + cpus[4], 2)
            for sample in samples:
                if sample["inclusive_cohort_total"]["cpu_ns"] > 2 * median:
                    variations.append({**report["selection"], "strategy": costs["strategy"],
                        "sample": sample["sample"], "cpu_ns": sample["inclusive_cohort_total"]["cpu_ns"],
                        "group_median_cpu_ns": {"numerator": median.numerator, "denominator": median.denominator}})
    retained = []
    for report in reports:
        retained.append({k: report[k] for k in ("selection", "input_sha256", "input_bytes", "record_counts",
            "semantic_alerts", "material_setup", "required_target_weight", "rate_diagnostic_scope", "strategy_costs")})
    result = {"schema": "pon-w1-retrospective-legal-rates-v1", "record_consistency": "PASS",
        "qualification_status": "HOLD", "complete_shards": len(reports), "strategy_groups": len(reports) * 4,
        "sample_cohorts_retained": len(reports) * 4 * reader.SAMPLES, "sample_cohorts_removed": 0,
        "historical_descriptive_timing_flagged_groups_retained": len(historical_analysis["descriptive_timing_flags"]),
        "sample_cohorts_above_twice_group_median_cpu_retained": len(variations),
        "variation_scope": "raw cohort CPU includes different paid attempt counts; descriptive only; no sample removal",
        "descriptive_variations": variations, "actual_invocation_totals": dict(totals),
        "totals_scope": "actual recorded invocations including repeated strategy/horizon streams; no pooled rate or independent-work claim",
        "native_recorded_outcome_counts": dict(outcomes), "unique_indexed_search_streams": len(fingerprints),
        "semantic_alerts": [{"selection": r["selection"], **a} for r in reports for a in r["semantic_alerts"]],
        "shards": retained, "new_native_execution": False, "w1_transcript_replayed": False, **reader.FALSE_FLAGS}
    require(sources == {str(p.relative_to(ROOT)): file_identity(p) for p in source_paths}, "reader changed during readback")
    (out / "rates.json").write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    provenance = {"schema": "pon-w1-retrospective-legal-rate-provenance-v1",
        "historical_native_source": execution["source_before"],
        "historical_native_binary_sha256": execution["binary_sha256_before"],
        "reader_source_files": sources, "reader_source_state": "working-tree bytes identified above; no final candidate commit inferred",
        "historical_evidence_root": str(HISTORICAL.relative_to(ROOT)), "historical_inputs": inputs,
        "historical_manifest": file_identity(HISTORICAL / "manifest.json"),
        "archive": {k: archive[k] for k in ("archive", "archive_bytes", "sha256", "parts")},
        "archive_members_verified": len(members), "legal_shard_inputs": legal_inputs,
        "historical_reader_fields_exactly_preserved": True, "complete_grid_and_common_prefixes_checked": True,
        "execution": "reader.analyze_shard on all thirty retained legal shards; no native producer/verifier executed",
        "output": {"rates.json": file_identity(out / "rates.json")}, "qualification_status": "HOLD"}
    (out / "provenance.json").write_text(json.dumps(provenance, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("shards", "descriptive_variations")}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    main(parser.parse_args().out.resolve())
