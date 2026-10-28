#!/usr/bin/env python3
"""Build a non-double-counting resource ledger from actual W1 stage records.

Successful wait4 stages are primary. For an interrupted stage only, an
independent /proc process-lifetime observation can raise the CPU lower bound;
the two measurements are compared with max(), never added. This reports
an evidence lower bound, not an invented exact interrupted-stage bill.
"""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def observed_stage_cpu(observer):
    manifest = json.loads((observer/"declaration.json").read_text())
    hz = manifest["clock_ticks_per_second"]
    lifetimes = {}
    with (observer/"samples.jsonl").open() as stream:
        for line in stream:
            row = json.loads(line)
            for proc in row["processes"]:
                key = (proc["pid"],proc["birth_ticks"])
                ticks = proc["user_ticks"]+proc["system_ticks"]
                lifetime = lifetimes.setdefault(key,{"max_ticks":0,"stages":set()})
                lifetime["max_ticks"] = max(lifetime["max_ticks"],ticks)
                if row["stage"] is not None:
                    lifetime["stages"].add(row["stage"])
    result = {}
    ambiguous = []
    for (pid,birth),lifetime in lifetimes.items():
        stages = lifetime["stages"]
        if len(stages) == 1:
            stage = next(iter(stages))
            result[stage] = result.get(stage,0)+lifetime["max_ticks"]/hz
        else:
            # A /proc lifetime can straddle a label update at stage exit.
            # Never copy its cumulative CPU into two stages or add it again
            # to successfully reaped wait4 costs. Ambiguity lowers the bound.
            ambiguous.append({"pid":pid,"birth_ticks":birth,
                "observed_stage_labels":sorted(stages),
                "sampled_cpu_lower_bound_seconds":lifetime["max_ticks"]/hz,
                "added_to_any_stage":False})
    return result,{"observer":str(observer),"unique_process_lifetimes":len(lifetimes),
        "ambiguous_or_unlabelled_lifetimes_excluded":ambiguous,
        "same_process_cpu_added_to_multiple_stages":False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--round",type=Path,action="append",required=True)
    parser.add_argument("--observer",type=Path,action="append",default=[])
    parser.add_argument("--out",type=Path,required=True)
    args = parser.parse_args()
    if len(args.observer) not in (0,len(args.round)):
        parser.error("provide one observer directory per proof round, or none")
    rows = []
    counted_prior = set()
    rounds = []
    observer_attribution = []
    for ordinal,folder in enumerate(args.round):
        result_path = folder/"result.json"
        if not result_path.is_file():
            parser.error(f"round not finished: {folder}")
        result = json.loads(result_path.read_text())
        if args.observer:
            observed, attribution = observed_stage_cpu(args.observer[ordinal])
            observer_attribution.append(attribution)
        else:
            observed = {}
        for prior in result.get("prior_runs",[]):
            path = Path(prior["path"])
            key = digest(path)
            if key in counted_prior:
                continue
            counted_prior.add(key)
            record = prior["result"]
            cpu = record["rusage"]["user_seconds"]+record["rusage"]["system_seconds"]
            rows.append({"round":"prior", "stage":str(path), "wait4_cpu_seconds":cpu,
                "paid_cpu_lower_bound_seconds":cpu,"wall_seconds":record["wall_seconds"],
                "timed_out":record["timed_out"],"returncode":record["returncode"],
                "source":"prior raw stage record","record_sha256":key,
                "max_single_process_rss_bytes":record["rusage"]["max_single_process_rss_bytes"]})
        for item in result["stages"]:
            record = item["result"]
            cpu = record["rusage"]["user_seconds"]+record["rusage"]["system_seconds"]
            sampled = observed.get(item["stage"])
            interrupted = (record["timed_out"] or record["returncode"] < 0
                or record.get("process_group_remaining_after_child_exit", False))
            # A completed, normally reaped stage already includes its reaped
            # server CPU. Adding samples would charge the same work twice.
            bound = max(cpu,sampled or 0) if interrupted else cpu
            rows.append({"round":ordinal+1,"stage":item["stage"],
                "wait4_cpu_seconds":cpu,"sampled_cpu_lower_bound_seconds":sampled,
                "paid_cpu_lower_bound_seconds":bound,"wall_seconds":record["wall_seconds"],
                "timed_out":record["timed_out"],"returncode":record["returncode"],
                "interrupted_stage_cpu_is_lower_bound":interrupted,
                "max_single_process_rss_bytes":record["rusage"]["max_single_process_rss_bytes"]})
        rounds.append({"path":str(folder),"record_sha256":digest(result_path),
            "declared_wall_budget_seconds":result["total_wall_budget_seconds"],
            "new_controller_wall_seconds":result["new_controller_wall_seconds"],
            "coordinated_pause_seconds":result["coordinated_pause_seconds"],
            "complete_proof_claim":result["complete_proof_claim"],"error":result["error"]})
    report = {"schema":"TRNM-W1-ACTUAL-PROOF-RESOURCE-LEDGER1","rounds":rounds,"stages":rows,
        "observer_stage_attribution":observer_attribution,
        "paid_cpu_lower_bound_seconds":sum(row["paid_cpu_lower_bound_seconds"] for row in rows),
        "raw_wait4_cpu_sum_seconds":sum(row["wait4_cpu_seconds"] for row in rows),
        "stage_wall_sum_seconds":sum(row["wall_seconds"] for row in rows),
        "controller_and_prior_wall_seconds":sum(row["new_controller_wall_seconds"] for row in rounds)
            +sum(row["wall_seconds"] for row in rows if row["round"]=="prior"),
        "coordinated_pause_seconds":sum(row["coordinated_pause_seconds"] for row in rounds),
        "maximum_single_process_rss_bytes":max(row.get("max_single_process_rss_bytes",0) for row in rows),
        "prover_p99_established":False,"independent_proof_trials":1,
        "scope":"Actual frozen-W1 pipeline and its retained setup/import/lift records. Separate build, security-control and historical pre-prototype failure costs are not silently merged into a proof-trial latency.",
        "production_qualification":False}
    with args.out.open("x") as stream:
        json.dump(report,stream,indent=2)
        stream.write("\n")
    print(json.dumps({key:value for key,value in report.items() if key not in ["stages","rounds"]}))


if __name__ == "__main__":
    main()
