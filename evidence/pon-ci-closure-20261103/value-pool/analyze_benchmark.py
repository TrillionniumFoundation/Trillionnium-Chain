#!/usr/bin/env python3
"""Analyze all preregistered samples, without retry, exclusion, or threshold edits."""
import collections
import hashlib
import json
from pathlib import Path
import re
import statistics

BASE = Path(__file__).resolve().parent
PLAN = json.loads((BASE / "benchmark-plan.json").read_text())
FREEZE = json.loads((BASE / "benchmark-execution-freeze.json").read_text())
DATA = BASE / "measurements"
LEDGER = json.loads((DATA / "execution.json").read_text())
ISSUES = []


def check(condition, message):
    if not condition:
        ISSUES.append(message)
    return condition


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def number(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def phases(case):
    values = [("cold", 0, 0)] + [("warm", index, 0) for index in range(8)]
    values += [("changed", 0, 1), ("restored", 0, 0)]
    if case == "repeated":
        values += [("late_grammar", 0, 2), ("late_wire", 0, 3)]
    return values


def expected_labels():
    return [(case, api, phase, index) for case in PLAN["grid"]["case_order"]
            for api in ["root", "commitment"] for phase, index, _ in phases(case)]


def parse(path):
    rows = collections.defaultdict(list)
    for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        match = re.search(r"VALUE_POOL_(BEGIN|SETUP|SAMPLE|END) (.*)$", line)
        if not match:
            continue
        try:
            rows[match.group(1)].append(json.loads(match.group(2)))
        except json.JSONDecodeError as error:
            ISSUES.append(f"{path.name}:{line_number}: invalid JSON {error}")
    return rows


expected_order = [(pair, variant) for pair, order in enumerate(PLAN["grid"]["process_order"]) for variant in order]
check([(r["pair"], r["variant"]) for r in LEDGER["records"]] == expected_order, "execution order/count differs from fixed ten processes")
check(LEDGER.get("retries") == 0, "unexpected retries")
check(LEDGER.get("plan_sha256") == sha(BASE / "benchmark-plan.json"), "plan identity changed")
check(LEDGER.get("execution_freeze_sha256") == sha(BASE / "benchmark-execution-freeze.json"), "execution freeze changed")
check(LEDGER.get("identity_errors") == [], "postexecution source/ELF identity failed or missing")
check(LEDGER.get("frozen_files_after") == FREEZE["frozen_files"], "frozen file checks incomplete or changed")
for name, expected in FREEZE["frozen_files"].items():
    check(sha(BASE / name) == expected, f"frozen file changed: {name}")

samples = {}
processes = []
expected = expected_labels()
root_reference = {}
for record in LEDGER["records"]:
    pair, variant = record["pair"], record["variant"]
    label = f"pair{pair}/{variant}"
    check(record.get("returncode") == 0, f"{label}: nonzero/missing return code")
    check(record.get("timed_out") is False and record.get("exception") is None, f"{label}: timeout or invocation error")
    for stream in ["stdout", "stderr"]:
        path = DATA / record[stream]
        check(sha(path) == record[f"{stream}_sha256"], f"{label}: {stream} hash changed")
    rows = parse(DATA / record["stdout"])
    check(len(rows["BEGIN"]) == 1, f"{label}: requires exactly one BEGIN")
    if rows["BEGIN"]:
        begin = rows["BEGIN"][0]
        for field, value in {"pair": pair, "variant": variant, "rows": 2100, "width": 4080,
                             "root_budget": 2097152, "warm_calls": 8, "planned_samples": 70}.items():
            check(begin.get(field) == value, f"{label}: BEGIN {field} mismatch")
    check(len(rows["END"]) == 1, f"{label}: requires exactly one END")
    if rows["END"]:
        end = rows["END"][0]
        check(end.get("valid") is True and end.get("samples") == 70, f"{label}: END is invalid/incomplete")
        check(end.get("pair") == pair and end.get("variant") == variant, f"{label}: END identity")
    setups = rows["SETUP"]
    check([s.get("case") for s in setups] == PLAN["grid"]["case_order"], f"{label}: setup order/count")
    for setup in setups:
        case = setup.get("case")
        check(setup.get("pair") == pair and setup.get("variant") == variant, f"{label}: setup identity")
        check(number(setup.get("cpu_ns")) and number(setup.get("wall_ns")), f"{label}/{case}: setup clock unknown")
        wanted = PLAN["inputs"].get(case, [])
        inputs = setup.get("inputs", [])
        check(len(inputs) == len(wanted), f"{label}/{case}: setup input count")
        for index, (actual, declared) in enumerate(zip(inputs, wanted)):
            check(actual.get("digest") == declared["sha256"] and actual.get("json_bytes") == declared["json_bytes"],
                  f"{label}/{case}/{index}: complete input digest/bytes mismatch")
            key = (case, index)
            value = (actual.get("expected_root"), actual.get("expected_error"))
            if key in root_reference:
                check(root_reference[key] == value, f"{label}/{case}/{index}: original reference changed across processes")
            else:
                root_reference[key] = value
    observed_labels = [(s.get("case"), s.get("api"), s.get("phase"), s.get("index")) for s in rows["SAMPLE"]]
    check(observed_labels == expected, f"{label}: sample sequence or unique-label count differs from 70")
    for sample in rows["SAMPLE"]:
        case, api, phase, index = (sample.get(k) for k in ["case", "api", "phase", "index"])
        key = (pair, variant, case, api, phase, index)
        check(key not in samples, f"{label}: duplicate sample {key}")
        samples[key] = sample
        check(sample.get("pair") == pair and sample.get("variant") == variant, f"{label}: sample identity")
        check(sample.get("matches_reference") is True, f"{key}: differs from original reference")
        check(number(sample.get("cpu_ns")) and number(sample.get("wall_ns")), f"{key}: unknown CPU/wall clock")
        mapping = {(p, i): which for p, i, which in phases(case)} if case in PLAN["inputs"] else {}
        which = mapping.get((phase, index))
        if which is None:
            ISSUES.append(f"{key}: unregistered phase")
            continue
        check(sample.get("input_digest") == PLAN["inputs"][case][which]["sha256"], f"{key}: wrong measured input")
        if which < 2:
            check(sample.get("error") is None and sample.get("root") == root_reference.get((case, which), (None, None))[0],
                  f"{key}: successful root/error mismatch")
        else:
            check(sample.get("root") is None and sample.get("error") is not None, f"{key}: negative unexpectedly successful")
            check(sample.get("error") == root_reference.get((case, which), (None, None))[1], f"{key}: negative error differs from independent original reference")
        if api == "root":
            before, after = sample.get("before"), sample.get("after")
            check(sample.get("budget_ok") is True and isinstance(after, dict), f"{key}: budget invalid")
            if isinstance(after, dict):
                charge = after.get("retained_payload_bytes")
                check(number(charge) and charge <= PLAN["limits"]["root_retained_bytes"], f"{key}: original 2 MiB bound exceeded")
                if sample.get("error") is None:
                    hashes, hits, observed = [after.get(k) for k in ["leaf_hashes_computed", "exact_string_hits", "input_keys"]]
                    check(all(number(v) for v in [hashes, hits, observed]) and hashes + hits == observed == 2100,
                          f"{key}: actual hashes/exact hits/full observed inputs inconsistent")
                    enc = after.get("string_encodings_reused")
                    check(number(enc) and enc <= hits, f"{key}: encoding reuse exceeds exact input hits")
                else:
                    check(before == after and sample.get("unchanged_on_error") is True, f"{key}: failed input published cache/observation")
        elif api == "commitment" and sample.get("error") is None:
            commitment = sample.get("commitment", {})
            check(commitment.get("method") == "FullRoot(PayloadBudget)", f"{key}: original fallback changed")
            check(commitment.get("actual_keys") == 2100 and commitment.get("actual_payload_bytes", 0) > 8 * 1024 * 1024,
                  f"{key}: wrong large-state commitment workload")
            check(commitment.get("snapshot_present") is False, f"{key}: unexpected snapshot retention")
            check(commitment.get("arithmetic_retained_charge_bytes") is None, f"{key}: private charge fabricated")
    processes.append({"pair": pair, "variant": variant, "returncode": record.get("returncode"),
                      "timed_out": record.get("timed_out"), "samples": len(rows["SAMPLE"]),
                      "successes": sum(s.get("error") is None for s in rows["SAMPLE"]),
                      "expected_errors": sum(s.get("error") is not None for s in rows["SAMPLE"]),
                      "missing_samples": max(0, 70 - len(rows["SAMPLE"])),
                      "end": rows["END"][0] if len(rows["END"]) == 1 else None,
                      "setup": setups, "wall_ns": record.get("wall_ns"),
                      "stdout_sha256": record["stdout_sha256"], "stderr_sha256": record["stderr_sha256"]})

check(len(samples) == PLAN["grid"]["total_planned_samples"], "total unique samples differs from 700")
for pair in range(5):
    for case, api, phase, index in expected:
        a = samples.get((pair, "baseline", case, api, phase, index))
        b = samples.get((pair, "candidate", case, api, phase, index))
        if a is None or b is None:
            check(False, f"pair{pair}/{case}/{api}/{phase}/{index}: missing side")
            continue
        fields = ["input_digest", "root", "error"]
        if api == "commitment":
            fields.append("commitment")
        for field in fields:
            check(a.get(field) == b.get(field), f"pair{pair}/{case}/{api}/{phase}/{index}: cross-side {field} differs")


def group(case, api, phase, clock):
    result = []
    indices = range(8) if phase == "warm" else range(1)
    for pair in range(5):
        totals = {}
        for variant in ["baseline", "candidate"]:
            rows = [samples.get((pair, variant, case, api, phase, index)) for index in indices]
            values = [row.get(clock) if row else None for row in rows]
            totals[variant] = sum(values) if all(number(v) for v in values) else None
        a, b = totals["baseline"], totals["candidate"]
        ratio = b / a if a is not None and a > 0 and b is not None else None
        result.append({"pair": pair, "baseline_ns": a, "candidate_ns": b, "candidate_over_baseline": ratio})
    return result


rules = []
for case, api, phase, threshold in [("repeated", "root", "warm", 0.85), ("repeated", "commitment", "warm", 0.95)] + [
    (case, api, phase, 1.05) for case in ["unique", "collision"] for api in ["root", "commitment"] for phase in ["cold", "warm"]
]:
    pairs = group(case, api, phase, "cpu_ns")
    ratios = [pair["candidate_over_baseline"] for pair in pairs]
    known = all(ratio is not None for ratio in ratios)
    median = statistics.median(ratios) if known else None
    rules.append({"case": case, "api": api, "phase": phase, "clock": "calling_thread_cpu",
                  "warm_calls_per_process": 8 if phase == "warm" else 1,
                  "threshold": threshold, "paired_ratios": pairs, "median_paired_ratio": median,
                  "pass": known and median <= threshold})

all_phase_costs = []
for case in PLAN["grid"]["case_order"]:
    for api in ["root", "commitment"]:
        for phase in dict.fromkeys(p for p, _, _ in phases(case)):
            for clock in ["cpu_ns", "wall_ns"]:
                pairs = group(case, api, phase, clock)
                ratios = [p["candidate_over_baseline"] for p in pairs]
                all_phase_costs.append({"case": case, "api": api, "phase": phase, "clock": clock,
                    "paired_costs": pairs,
                    "median_paired_ratio": statistics.median(ratios) if all(v is not None for v in ratios) else None,
                    "threshold_applies": clock == "cpu_ns" and any(r["case"] == case and r["api"] == api and r["phase"] == phase for r in rules)})

memory = []
for variant in ["baseline", "candidate"]:
    for case in PLAN["grid"]["case_order"]:
        rows = [value for key, value in samples.items() if key[1:4] == (variant, case, "root")]
        observations = [row["after"] for row in rows if isinstance(row.get("after"), dict)]
        stats = {}
        for field in ["retained_payload_bytes", "retained_string_charge_bytes", "retained_string_entries"]:
            values = [o[field] for o in observations if number(o.get(field))]
            stats[field] = {"min": min(values), "max": max(values)} if values else None
        warm = [row["after"] for row in rows if row["phase"] == "warm"]
        stats["warm_observations"] = sorted({json.dumps(o, sort_keys=True) for o in warm})
        stats["warm_observations"] = [json.loads(o) for o in stats["warm_observations"]]
        memory.append({"variant": variant, "case": case, **stats})

result = {"schema": "value-pool-preregistered-result-v1", "scope": "finite x86_64 M06 component, not ARM/Host/service/TPS acceptance",
          "plan_sha256": sha(BASE / "benchmark-plan.json"), "execution_freeze_sha256": sha(BASE / "benchmark-execution-freeze.json"),
          "execution_sha256": sha(DATA / "execution.json"), "sources": PLAN["sources"], "artifacts": FREEZE["variants"],
          "planned_samples": 700, "observed_unique_samples": len(samples), "planned_processes": 10,
          "processes": processes, "data_quality_issues": ISSUES, "data_quality_pass": not ISSUES,
          "timing_rules": rules, "timing_rules_pass": all(r["pass"] for r in rules),
          "overall_pass": not ISSUES and all(r["pass"] for r in rules),
          "all_phase_costs": all_phase_costs, "direct_root_retained_charge": memory,
          "limitations": ["Five separately launched process pairs determine the median of paired ratios; eight warm calls within each process are correlated. Statistical independence and p95/p99 behavior are not established.",
                          "Whole-process VmHWM is not the bounded retained material charge and includes setup and references.",
                          "FullRootArithmetic private charge/failed-cache observation is not exposed by the public API; it remains null, with semantic unit controls separate.",
                          "Cold is an empty arithmetic owner after common setup, not cold OS/allocator/global hash state.",
                          "No new gate, threshold, profile, workload, provider, budget or Host-check frequency was changed."]}
(BASE / "benchmark-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
lines = ["# Value-pool finite component result", "", f"Overall preregistered result: **{'PASS' if result['overall_pass'] else 'FAIL'}**.", "",
         f"Data: {len(samples)}/700 unique planned samples; {len(processes)}/10 processes. Data quality: {'PASS' if not ISSUES else 'FAIL'}.", "",
         "CPU statistic is the median of five paired candidate/baseline ratios. Each warm process value sums eight correlated complete calls.", "",
         "| Case | API | Phase | Baseline CPU ms/call | Candidate CPU ms/call | Median paired ratio | Limit | Result |",
         "|---|---|---|---:|---:|---:|---:|---|"]
for rule in rules:
    divisor = rule["warm_calls_per_process"] * 1_000_000
    av = [p["baseline_ns"] / divisor for p in rule["paired_ratios"] if p["baseline_ns"] is not None]
    bv = [p["candidate_ns"] / divisor for p in rule["paired_ratios"] if p["candidate_ns"] is not None]
    def fmt(value):
        return "unknown" if value is None else f"{value:.4f}"
    a = statistics.median(av) if len(av) == 5 else None
    b = statistics.median(bv) if len(bv) == 5 else None
    lines.append(f"| {rule['case']} | {rule['api']} | {rule['phase']} | {fmt(a)} | {fmt(b)} | {fmt(rule['median_paired_ratio'])} | {rule['threshold']:.2f} | {'PASS' if rule['pass'] else 'FAIL'} |")
lines += ["", "Separate median CPU columns are descriptive; the acceptance statistic is the median of paired ratios, not the ratio of these medians.", "",
          "## Data quality and retained observations", ""]
lines += [f"- {issue}" for issue in ISSUES] if ISSUES else ["All planned processes, reference roots/errors, complete input hashes, unchanged failed-input observations, clocks, and exposed original 2 MiB bounds passed."]
lines += ["", "| Variant | Case | Retained payload range (bytes) | Retained entries range |", "|---|---|---:|---:|"]
for m in memory:
    p, n = m["retained_payload_bytes"], m["retained_string_entries"]
    lines.append(f"| {m['variant']} | {m['case']} | {p['min']}–{p['max'] if p else 'unknown'} | {n['min']}–{n['max'] if n else 'unknown'} |" if p and n else f"| {m['variant']} | {m['case']} | unknown | unknown |")
lines += ["", "## Limits", ""] + [f"- {limit}" for limit in result["limitations"]]
lines += ["", "All raw samples, pair ratios, setup costs, change/restore/error timing, whole-process VmHWM and binary/source identities are preserved in benchmark-result.json and measurements/.", ""]
(BASE / "benchmark-result.md").write_text("\n".join(lines))
print(json.dumps({"overall_pass": result["overall_pass"], "data_quality_pass": not ISSUES,
                  "data_quality_issue_count": len(ISSUES), "timing_rules": [
                      {key: rule[key] for key in ["case", "api", "phase", "median_paired_ratio", "threshold", "pass"]} for rule in rules]}, indent=2))
