#!/usr/bin/env python3
"""Read retained normal-service evidence; never execute the downloaded binary."""

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parent
HEAD = "1b0d60d574c4b3e2172f314cd2655644373b0a27"
TREE = "afe7c0f29c224c7262755d38d69930bf5030b8a0"
ZIP_SHA256 = "503f4da52f81b4d126af6da17399bfadcdf4956650160538576067b27024874e"
BASELINE_SHA256 = "94305c8f020321b9912087df172b2ed767c6494e7a05f5a9d08494e7947917d5"


def require(condition):
    if not condition:
        raise ValueError("retained baseline evidence does not match its declared identity or shape")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def derive(raw, result):
    require(digest(raw) == BASELINE_SHA256)
    require(result["head"] == HEAD and result["tree"] == TREE)
    baseline = json.loads(raw)
    require(baseline["mode"] == "baseline")
    require(baseline["attacker_processes_requested"] == 0)
    require(baseline["attacker_processes_ready"] == 0)
    require(baseline["duration_seconds"] == 30)
    require(baseline["state_backend"] == "authenticated-v1")
    rounds = [r for r in result["all_planned_rounds"] if r["phase"] == "baseline"]
    require([r["round"] for r in rounds] == [0, 1, 2])
    require([r["scheduled_offset_ns"] for r in rounds] == [10**9, 5 * 10**9, 9 * 10**9])
    packets = [r for r in result["all_planned_business_packets"] if r["phase"] == "baseline"]
    require([r["packet_index"] for r in packets] == list(range(21)))
    history = []
    checkpoint = dict(calls_started=0, calls_completed=0, thread_cpu_ns=0, wall_ns=0)
    imports = dict(thread_cpu_ns=0, wall_ns=0)
    for index, row in enumerate(baseline["history"]):
        imported = row["client_import"]
        observation = imported["native_import_observation"]
        require(observation["cpu_intervals_are_nested_not_additive"] is True)
        require(observation["measurement_failures"] == 0)
        current = [v for v in observation["host_checks"] if v["phase"] == "checkpoint"]
        require(len(current) == 1)
        current = current[0]
        for key in checkpoint:
            require(isinstance(current[key], int) and current[key] >= 0)
            checkpoint[key] += current[key]
        for key in imports:
            require(isinstance(imported[key], int) and imported[key] >= 0)
            imports[key] += imported[key]
        history.append(dict(index=index, **{
            key: imported[key] for key in
            ("started_ns", "ended_ns", "thread_cpu_ns", "wall_ns", "error", "succeeded")
        }, checkpoint={key: current[key] for key in checkpoint}))
    before = baseline["client_native_history_arithmetic_before"]
    after = baseline["client_native_history_arithmetic_after"]
    require(before["stage_observation_failed"] is False)
    require(after["stage_observation_failed"] is False)
    before = {v["stage"]: v["totals"] for v in before["stages"]}
    after = {v["stage"]: v["totals"] for v in after["stages"]}
    require(set(before) == set(after))
    stages = {}
    for stage in after:
        stages[stage] = {key: after[stage][key] - before[stage][key]
                         for key in ("calls", "cpu_ns", "wall_ns", "cpu_unknown_calls")}
        require(all(value >= 0 for value in stages[stage].values()))
    return dict(
        schema="pon-original-baseline-readback-v1", source_head=HEAD, source_tree=TREE,
        workflow_run=41635095044, workflow_job=125914169978, artifact_id=13230750887,
        artifact_zip_sha256=ZIP_SHA256, baseline_sha256=BASELINE_SHA256,
        binary=result["binary"], phase="baseline", extra_request_processes=0,
        original_window_seconds=30, planned_business_packets=21, planned_rounds=3,
        timely_network_acknowledgements=sum(r["timely_network_ack"] is True for r in packets),
        observed_rounds=sum(r["observed_exactly_once"] is True for r in rounds),
        original_four_second_successes=sum(r["four_second_slo_met"] is True for r in rounds),
        confirmations_inside_original_window=sum(
            r["confirmed_inside_original_window"] is True for r in rounds),
        rounds=rounds, history_imports=history,
        successful_imports=sum(r["succeeded"] is True for r in history),
        failed_imports=sum(r["succeeded"] is False for r in history),
        original_verifier_errors=baseline["verifier_errors"],
        total_checkpoint_observations=checkpoint, total_client_import_observations=imports,
        nested_client_stage_deltas=stages,
        interpretation=[
            "Read-only extraction of the existing exact-head artifact; no campaign executed here.",
            "The failed final import remains in totals; its completed-work amount is censored.",
            "Missing rounds remain missing and count against the original three-round denominator.",
            "Network acknowledgement is not confirmation or local import success.",
            "Stage and Host intervals overlap; their totals must not be added.",
            "Importer CPU excludes scoped-worker CPU; Host spans cover each actual invoking thread.",
            "Different completed cohorts or different heads do not form a paired speedup estimate.",
        ],
        new_candidate_runtime_qualified=False, public_service_qualified=False,
        work_hardness_qualified=False, independent_operators_qualified=False,
        production_activation=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-zip", type=Path)
    args = parser.parse_args()
    if args.capture_zip is not None:
        archive = args.capture_zip.read_bytes()
        require(digest(archive) == ZIP_SHA256)
        with zipfile.ZipFile(args.capture_zip) as source:
            raw = source.read("execution/raw/baseline.json")
            result_raw = source.read("execution/results.json")
        result = json.loads(result_raw)
        summary = derive(raw, result)
        compressed = gzip.compress(raw, mtime=0)
        manifest = dict(schema="pon-baseline-raw-preservation-v1", source_head=HEAD,
                        artifact_id=13230750887, artifact_zip_sha256=ZIP_SHA256,
                        raw_bytes=len(raw), raw_sha256=digest(raw),
                        gzip_bytes=len(compressed), gzip_sha256=digest(compressed),
                        result_bytes=len(result_raw), result_sha256=digest(result_raw))
        files = {
            "baseline.json.gz.base64": base64.encodebytes(compressed),
            "original-f0-result.json": result_raw,
            "baseline-raw-manifest.json": encoded(manifest),
            "baseline-readback.json": encoded(summary),
        }
        for name, content in files.items():
            with (ROOT / name).open("xb") as output:
                output.write(content)
    else:
        manifest = json.loads((ROOT / "baseline-raw-manifest.json").read_bytes())
        compressed = base64.b64decode((ROOT / "baseline.json.gz.base64").read_bytes())
        require(len(compressed) == manifest["gzip_bytes"])
        require(digest(compressed) == manifest["gzip_sha256"])
        raw = gzip.decompress(compressed)
        require(len(raw) == manifest["raw_bytes"])
        require(digest(raw) == manifest["raw_sha256"])
        result_raw = (ROOT / "original-f0-result.json").read_bytes()
        require(len(result_raw) == manifest["result_bytes"])
        require(digest(result_raw) == manifest["result_sha256"])
        summary = derive(raw, json.loads(result_raw))
        require(encoded(summary) == (ROOT / "baseline-readback.json").read_bytes())
    print(json.dumps({key: summary[key] for key in
                      ("source_head", "planned_rounds", "original_four_second_successes",
                       "successful_imports", "failed_imports", "public_service_qualified")}))


if __name__ == "__main__":
    main()
