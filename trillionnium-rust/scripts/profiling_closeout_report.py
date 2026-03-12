#!/usr/bin/env python3
import argparse
import glob
import math
import os
import re
import statistics
import sys
from datetime import datetime

sys.dont_write_bytecode = True

KV = re.compile(r"([a-zA-Z0-9_\.]+)=([^\s]+)")


def matching_files(pattern: str) -> list[str]:
    return sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)


def latest(pattern: str):
    files = matching_files(pattern)
    return files[0] if files else None


def first_existing_dir(*paths: str) -> str:
    for path in paths:
        if os.path.isdir(path):
            return path
    return paths[0]


def parse_kv_line(line: str):
    return {k: v for k, v in KV.findall(line)}


def load_kv_rows(path: str | None):
    rows = []
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                parsed = parse_kv_line(raw.strip())
                if parsed:
                    rows.append(parsed)
    return rows


def as_num(v):
    try:
        return int(v)
    except Exception:
        try:
            return float(v)
        except Exception:
            return v


def summarize(vals):
    vals = [as_num(v) for v in vals]
    if not vals:
        return None
    vals = sorted(vals)
    p95 = vals[min(len(vals) - 1, max(0, math.ceil(len(vals) * 0.95) - 1))]
    return vals[0], statistics.median(vals), p95, vals[-1]


def fmt_metric(name: str, vals):
    s = summarize(vals)
    if not s:
        return f"- {name}: n/a"
    mn, p50, p95, mx = s
    return f"- {name}: min={mn} p50={p50} p95={p95} max={mx}"


def recommended_producer(label: str) -> str:
    if label == "node_log":
        return (
            "cargo run -q -p trnm-node -- --config configs/node1.toml --block-ms 5 "
            "--max-blocks 3 --demo-tasks 8 --demo-keys 3 --parallel-workers 4 > run/parallel-sanity.log"
        )
    if label == "bench_dir":
        return "mkdir -p run/bench"
    if label == "classic_bench":
        return "./scripts/run_bench_matrix.sh"
    if label == "mixed_bench":
        return "./scripts/run_bench_mixed_matrix.sh"
    if label == "executor_profile":
        return "cargo run -q -p trnm-bench -- --profile"
    return "unknown"


def benchmark_producer_for(label: str) -> str:
    if label == "classic_bench":
        return recommended_producer(label)
    if label == "mixed_bench":
        return recommended_producer(label)
    if label == "executor_profile":
        return recommended_producer(label)
    return "unknown"


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def build_followup_command_chain(labels: list[str], producer_for) -> str:
    commands = []
    for label in labels:
        producer = producer_for(label)
        if producer and producer != "unknown":
            commands.append(producer)
    commands = dedupe_preserve_order(commands)
    if not commands:
        return "none"
    return " && ".join(commands)


def benchmark_capture_cohesion(paths: list[str | None]) -> tuple[str, int | None]:
    mtimes = [os.path.getmtime(path) for path in paths if path and os.path.exists(path)]
    if len(mtimes) < 2:
        return ("insufficient_artifacts", None)
    spread_seconds = int(max(mtimes) - min(mtimes))
    if spread_seconds <= 15 * 60:
        return ("same_capture_window", spread_seconds)
    if spread_seconds <= 2 * 60 * 60:
        return ("mixed_capture_window", spread_seconds)
    return ("divergent_capture_window", spread_seconds)


def must_run_gate_artifact_posture(bench_dir_exists: bool, classic, mixed, executor_profile) -> str:
    benchmark_artifacts = [classic, mixed, executor_profile]
    persisted_count = sum(1 for path in benchmark_artifacts if path and os.path.exists(path))
    if persisted_count == 0:
        if not bench_dir_exists:
            return "stdout_only_bench_gate_without_artifact_dir"
        return "stdout_only_bench_gate_without_persisted_artifacts"
    if persisted_count < len(benchmark_artifacts):
        return "partial_persisted_bench_artifacts"
    return "persisted_bench_artifacts_present"


def autopilot_severity(missing_inputs, stale_inputs, old_inputs) -> str:
    if not missing_inputs and not stale_inputs and not old_inputs:
        return "GREEN"
    if missing_inputs:
        if len(missing_inputs) >= 3:
            return "RED"
        return "YELLOW"
    if old_inputs:
        return "YELLOW"
    if stale_inputs:
        return "YELLOW"
    return "GREEN"


def closeout_decision(missing_inputs, stale_inputs, old_inputs, capture_status: str) -> tuple[str, str]:
    if missing_inputs:
        return (
            "INCOMPLETE",
            "missing evidence inputs must be produced before closeout is reviewable",
        )
    if old_inputs:
        return (
            "REFRESH_REQUIRED",
            "at least one evidence input is old and should not be treated as current",
        )
    if stale_inputs:
        return (
            "REFRESH_RECOMMENDED",
            "all evidence inputs exist, but at least one is stale",
        )
    if capture_status == "mixed_capture_window":
        return (
            "REFRESH_RECOMMENDED",
            "all evidence inputs are present and individually fresh, but they were not captured tightly enough to treat as a strong single closeout set",
        )
    if capture_status == "divergent_capture_window":
        return (
            "REFRESH_RECOMMENDED",
            "all evidence inputs are present and individually fresh, but they were captured too far apart to treat as one coherent closeout set",
        )
    return ("READY", "all expected closeout inputs are present and fresh enough for review")


def main():
    p = argparse.ArgumentParser(description="Render profiling closeout baseline from node/bench outputs")
    p.add_argument("--node-log", default=None)
    p.add_argument("--classic", default=None)
    p.add_argument("--mixed", default=None)
    p.add_argument("--executor-profile", default=None)
    p.add_argument("--out", default=None)
    args = p.parse_args()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    repo_root = os.path.abspath(os.path.join(root, ".."))
    bench_dir = first_existing_dir(
        os.path.join(root, "run", "bench"),
        os.path.join(repo_root, "run", "bench"),
    )
    node_log_pattern = os.path.join(root, "run", "parallel-sanity.log")
    classic_pattern = os.path.join(bench_dir, "bench-matrix-*.txt")
    mixed_pattern = os.path.join(bench_dir, "bench-mixed-matrix-*.txt")
    executor_profile_pattern = os.path.join(bench_dir, "executor-profile-summary-*.txt")
    node_log_candidates = matching_files(node_log_pattern)
    classic_candidates = matching_files(classic_pattern)
    mixed_candidates = matching_files(mixed_pattern)
    executor_profile_candidates = matching_files(executor_profile_pattern)
    node_log = args.node_log or latest(node_log_pattern)
    classic = args.classic or latest(classic_pattern)
    mixed = args.mixed or latest(mixed_pattern)
    executor_profile = args.executor_profile or latest(executor_profile_pattern)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or os.path.join(root, "docs", "reports", f"profiling-closeout-baseline-{ts}.md")

    bench_dir_exists = os.path.isdir(bench_dir)

    block_rows = []
    consensus_rows = []
    classic_rows = load_kv_rows(classic)
    mixed_rows = load_kv_rows(mixed)
    if node_log and os.path.exists(node_log):
        with open(node_log, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if line.startswith("[block] "):
                    block_rows.append(parse_kv_line(line))
                elif line.startswith("[consensus] "):
                    consensus_rows.append(parse_kv_line(line))

    def input_status(path: str | None) -> str:
        if not path:
            return "missing"
        return "present" if os.path.exists(path) else "missing"

    def file_age_seconds(path: str | None):
        if not path or not os.path.exists(path):
            return None
        return max(0, int((datetime.now() - datetime.fromtimestamp(os.path.getmtime(path))).total_seconds()))

    def freshness_label(age_seconds: int | None) -> str:
        if age_seconds is None:
            return "missing"
        if age_seconds <= 15 * 60:
            return "fresh"
        if age_seconds <= 2 * 60 * 60:
            return "stale"
        return "old"

    def file_mtime_iso(path: str | None) -> str | None:
        if not path or not os.path.exists(path):
            return None
        return datetime.fromtimestamp(os.path.getmtime(path)).isoformat()

    def artifact_lineage(label: str, path: str | None, producer: str) -> str:
        status = input_status(path)
        age_seconds = file_age_seconds(path)
        freshness = freshness_label(age_seconds)
        basename = os.path.basename(path) if path else "None"
        anchor_path = path
        anchor_note = ""
        if label == "bench_dir" and bench_dir_exists and newest_benchmark_artifact:
            anchor_path = newest_benchmark_artifact
            age_seconds = bench_dir_age_seconds()
            freshness = "empty" if age_seconds is None else freshness_label(age_seconds)
            basename = os.path.basename(newest_benchmark_artifact)
            anchor_note = f" anchor={newest_benchmark_artifact}"
        return (
            f"- {label}: status={status} freshness={freshness} "
            f"age_seconds={age_seconds if age_seconds is not None else 'n/a'} "
            f"updated_at={file_mtime_iso(anchor_path) or 'n/a'} basename={basename} "
            f"path={path or 'None'} producer={producer}{anchor_note}"
        )

    def candidate_preview(label: str, selected: str | None, candidates: list[str], max_items: int = 3) -> list[str]:
        preview = [f"- {label}: selected={selected or 'None'} candidate_count={len(candidates)}"]
        if not candidates:
            preview.append(f"  - none: pattern produced no matches")
            return preview
        newest = candidates[0]
        oldest = candidates[-1]
        spread_seconds = int(os.path.getmtime(newest) - os.path.getmtime(oldest)) if len(candidates) >= 2 else 0
        preview.append(
            f"  - candidate_window: newest={os.path.basename(newest)} oldest={os.path.basename(oldest)} "
            f"spread_seconds={spread_seconds} newest_freshness={freshness_label(file_age_seconds(newest))} "
            f"oldest_freshness={freshness_label(file_age_seconds(oldest))}"
        )
        for idx, path in enumerate(candidates[:max_items], start=1):
            preview.append(
                f"  - recent_{idx}: basename={os.path.basename(path)} "
                f"updated_at={file_mtime_iso(path) or 'n/a'} freshness={freshness_label(file_age_seconds(path))} path={path}"
            )
        if len(candidates) > max_items:
            preview.append(f"  - remaining_candidates: {len(candidates) - max_items}")
        return preview

    def latest_benchmark_artifact():
        artifact_candidates = [path for path in [classic, mixed, executor_profile] if path and os.path.exists(path)]
        if not artifact_candidates:
            return None
        return max(artifact_candidates, key=os.path.getmtime)

    def bench_dir_age_seconds() -> int | None:
        newest_artifact = latest_benchmark_artifact()
        if not bench_dir_exists or not newest_artifact:
            return None
        newest_mtime = os.path.getmtime(newest_artifact)
        return max(0, int((datetime.now() - datetime.fromtimestamp(newest_mtime)).total_seconds()))

    newest_benchmark_artifact = latest_benchmark_artifact()

    lines = ["# Profiling Closeout Baseline", f"generated_at={datetime.now().isoformat()}", "", "## Inputs"]
    lines += [
        f"- node_log: {node_log}",
        f"- node_log_status: {input_status(node_log)}",
        f"- bench_dir: {bench_dir}",
        f"- bench_dir_status: {'present' if bench_dir_exists else 'missing'}",
        f"- bench_dir_producer: {recommended_producer('bench_dir')}",
        f"- bench_dir_newest_artifact: {newest_benchmark_artifact or 'none'}",
        f"- classic_bench: {classic}",
        f"- classic_bench_status: {input_status(classic)}",
        f"- mixed_bench: {mixed}",
        f"- mixed_bench_status: {input_status(mixed)}",
        f"- executor_profile: {executor_profile}",
        f"- executor_profile_status: {input_status(executor_profile)}",
        "",
        "## Input Freshness",
    ]

    freshness_rows = [
        ("bench_dir", bench_dir if bench_dir_exists else None),
        ("node_log", node_log),
        ("classic_bench", classic),
        ("mixed_bench", mixed),
        ("executor_profile", executor_profile),
    ]
    stale_inputs = []
    old_inputs = []
    for label, path in freshness_rows:
        age_seconds = bench_dir_age_seconds() if label == "bench_dir" else file_age_seconds(path)
        freshness = "empty" if label == "bench_dir" and bench_dir_exists and age_seconds is None else freshness_label(age_seconds)
        if freshness == "stale":
            stale_inputs.append(label)
        elif freshness == "old":
            old_inputs.append(label)
        anchor = ""
        if label == "bench_dir" and newest_benchmark_artifact:
            anchor = f" anchor={os.path.basename(newest_benchmark_artifact)}"
        lines.append(
            f"- {label}: freshness={freshness} age_seconds={age_seconds if age_seconds is not None else 'n/a'}{anchor}"
        )

    lines += ["", "## Input Readiness"]

    readiness_rows = [
        (
            "bench_dir",
            "present" if bench_dir_exists else "missing",
            recommended_producer("bench_dir"),
        ),
        ("node_log", input_status(node_log), recommended_producer("node_log")),
        ("classic_bench", input_status(classic), recommended_producer("classic_bench")),
        ("mixed_bench", input_status(mixed), recommended_producer("mixed_bench")),
        (
            "executor_profile",
            input_status(executor_profile),
            recommended_producer("executor_profile"),
        ),
    ]
    for label, status, producer in readiness_rows:
        lines.append(f"- {label}: {status} | producer={producer}")

    lines += ["", "## Artifact Lineage"]
    lines.append(artifact_lineage("bench_dir", bench_dir if bench_dir_exists else None, recommended_producer("bench_dir")))
    lines.append(artifact_lineage("node_log", node_log, recommended_producer("node_log")))
    lines.append(artifact_lineage("classic_bench", classic, recommended_producer("classic_bench")))
    lines.append(artifact_lineage("mixed_bench", mixed, recommended_producer("mixed_bench")))
    lines.append(artifact_lineage("executor_profile", executor_profile, recommended_producer("executor_profile")))

    lines += ["", "## Artifact Discovery"]
    lines.extend(candidate_preview("node_log_candidates", node_log, node_log_candidates, max_items=1))
    lines.extend(candidate_preview("classic_bench_candidates", classic, classic_candidates))
    lines.extend(candidate_preview("mixed_bench_candidates", mixed, mixed_candidates))
    lines.extend(candidate_preview("executor_profile_candidates", executor_profile, executor_profile_candidates))

    lines += ["", "## Data Completeness"]
    lines.append(
        f"- must_run_gate_artifact_posture: {must_run_gate_artifact_posture(bench_dir_exists, classic, mixed, executor_profile)}"
    )

    inputs = [
        ("node_log", node_log),
        ("classic_bench", classic),
        ("mixed_bench", mixed),
        ("executor_profile", executor_profile),
    ]
    present_count = sum(1 for _, path in inputs if path and os.path.exists(path))

    if present_count == 0:
        if not bench_dir_exists:
            lines.append("- autopilot_assessment: BENCH_DIR_MISSING (must-run gate may have passed, but the persisted bench artifact directory does not exist yet)")
            lines.append("- note: create `run/bench/` and persist bench outputs before treating closeout evidence as reviewable")
        else:
            lines.append("- autopilot_assessment: BENCH_ONLY_RUN (must-run gate passed, but no persisted closeout artifacts were found)")
            lines.append("- note: `cargo run -q -p trnm-bench -- --profile` prints useful immediate telemetry, but closeout files must be produced separately for curator/autopilot consumption")
    elif present_count < len(inputs):
        lines.append("- autopilot_assessment: PARTIAL_CLOSEOUT (some persisted closeout artifacts are present, but the evidence set is incomplete)")
        lines.append("- note: closeout is usable for directional review, but curator/autopilot decisions should prefer a full 4/4 evidence set")
    else:
        lines.append("- autopilot_assessment: COMPLETE_CLOSEOUT (all persisted closeout artifacts are present)")

    missing_inputs = []
    present_inputs = []
    for label, path in inputs:
        if not path or not os.path.exists(path):
            missing_inputs.append(label)
        else:
            present_inputs.append(label)

    if missing_inputs:
        lines.append(f"- status: PARTIAL ({', '.join(missing_inputs)} missing)")
    else:
        lines.append("- status: COMPLETE")
    lines.append(f"- present_inputs: {', '.join(present_inputs) if present_inputs else 'none'}")
    lines.append(f"- missing_inputs: {', '.join(missing_inputs) if missing_inputs else 'none'}")
    lines.append(f"- stale_inputs: {', '.join(stale_inputs) if stale_inputs else 'none'}")
    lines.append(f"- old_inputs: {', '.join(old_inputs) if old_inputs else 'none'}")
    lines.append(f"- readiness_score: {len(present_inputs)}/{len(inputs)}")
    lines.append(
        f"- autopilot_severity: {autopilot_severity(missing_inputs, stale_inputs, old_inputs)}"
    )
    lines.append(
        f"- total_evidence_coverage: {len(present_inputs)}/{len(inputs)} (node_log + classic_bench + mixed_bench + executor_profile)"
    )
    lines.append(
        "- benchmark_artifact_coverage_note: benchmark_artifact_coverage below excludes node_log by design; use total_evidence_coverage for the full closeout evidence set"
    )

    lines += ["", "## Curator Verdict"]
    verdict = autopilot_severity(missing_inputs, stale_inputs, old_inputs)
    if verdict == "GREEN":
        verdict_reason = "all expected closeout inputs are present and fresh"
    elif missing_inputs:
        verdict_reason = f"missing inputs: {', '.join(missing_inputs)}"
    elif old_inputs:
        verdict_reason = f"old inputs: {', '.join(old_inputs)}"
    else:
        verdict_reason = f"stale inputs: {', '.join(stale_inputs)}"
    lines.append(f"- curator_verdict: {verdict}")
    lines.append(f"- curator_reason: {verdict_reason}")

    closeout_capture_status, closeout_capture_spread_seconds = benchmark_capture_cohesion(
        [node_log, classic, mixed, executor_profile]
    )
    closeout_status, closeout_reason = closeout_decision(
        missing_inputs, stale_inputs, old_inputs, closeout_capture_status
    )
    lines += ["", "## Closeout Action Summary"]
    lines.append(f"- closeout_decision: {closeout_status}")
    lines.append(f"- closeout_decision_reason: {closeout_reason}")
    lines.append(
        "- closeout_action_counts: "
        f"missing={len(missing_inputs)} stale={len(stale_inputs)} old={len(old_inputs)} ready={len(present_inputs) - len(stale_inputs) - len(old_inputs)}"
    )
    lines.append(f"- closeout_capture_cohesion: {closeout_capture_status}")
    lines.append(
        f"- closeout_capture_spread_seconds: {closeout_capture_spread_seconds if closeout_capture_spread_seconds is not None else 'n/a'}"
    )
    closeout_blockers = missing_inputs + stale_inputs + old_inputs
    if closeout_capture_status == "mixed_capture_window":
        closeout_blockers.append("capture_window:mixed")
    elif closeout_capture_status == "divergent_capture_window":
        closeout_blockers.append("capture_window:divergent")
    lines.append(
        f"- closeout_blockers: {', '.join(closeout_blockers) if closeout_blockers else 'none'}"
    )
    lines.append(
        f"- closeout_ready_inputs: {', '.join(sorted(set(present_inputs) - set(stale_inputs) - set(old_inputs))) if present_inputs else 'none'}"
    )
    closeout_followup_labels = missing_inputs + stale_inputs + old_inputs
    if closeout_capture_status in {"mixed_capture_window", "divergent_capture_window"}:
        closeout_followup_labels = ["node_log", "classic_bench", "mixed_bench", "executor_profile"]
    lines.append(
        f"- closeout_followup_command_chain: {build_followup_command_chain(closeout_followup_labels, recommended_producer)}"
    )

    lines += ["", "## Autopilot Recommended Next Steps"]
    if missing_inputs:
        for label, status, producer in readiness_rows:
            if status != "present":
                lines.append(f"- produce {label}: {producer}")
    if stale_inputs:
        for label in stale_inputs:
            lines.append(f"- refresh {label}: existing artifact is stale; regenerate before curator/autopilot review")
    if old_inputs:
        for label in old_inputs:
            lines.append(f"- refresh {label}: existing artifact is old; do not treat as current evidence")
    if closeout_capture_status in {"mixed_capture_window", "divergent_capture_window"}:
        lines.append("- refresh closeout capture set: regenerate node_log and benchmark artifacts in one tighter capture window before curator/autopilot review")
    if not missing_inputs and not stale_inputs and not old_inputs and closeout_capture_status not in {"mixed_capture_window", "divergent_capture_window"}:
        lines.append("- none: all expected closeout inputs are present and fresh")

    lines += ["", "## Benchmark Next Step Matrix"]
    benchmark_inputs = [
        ("classic_bench", classic),
        ("mixed_bench", mixed),
        ("executor_profile", executor_profile),
    ]
    benchmark_actions = []
    for label, path in benchmark_inputs:
        status = input_status(path)
        age_seconds = file_age_seconds(path)
        freshness = freshness_label(age_seconds)
        updated_at = file_mtime_iso(path)
        if status != "present":
            action = "produce"
            reason = "missing benchmark artifact"
        elif freshness == "fresh":
            action = "keep"
            reason = "artifact is fresh enough for curator/autopilot review"
        elif freshness == "stale":
            action = "refresh"
            reason = "artifact is stale and should be regenerated before review"
        else:
            action = "refresh"
            reason = "artifact is old and should not be treated as current evidence"
        benchmark_actions.append((label, action, freshness, reason))
        lines.append(
            f"- {label}: action={action} freshness={freshness} age_seconds={age_seconds if age_seconds is not None else 'n/a'} updated_at={updated_at or 'n/a'} path={path or 'None'} producer={benchmark_producer_for(label)} reason={reason}"
        )

    benchmark_action_counts = {
        "produce": sum(1 for _, action, _, _ in benchmark_actions if action == "produce"),
        "refresh": sum(1 for _, action, _, _ in benchmark_actions if action == "refresh"),
        "keep": sum(1 for _, action, _, _ in benchmark_actions if action == "keep"),
    }
    benchmark_blockers = [
        f"{label}:{action}:{freshness}"
        for label, action, freshness, _ in benchmark_actions
        if action in {"produce", "refresh"}
    ]
    benchmark_ready_inputs = [
        label for label, action, _, _ in benchmark_actions if action == "keep"
    ]
    benchmark_capture_status, benchmark_capture_spread_seconds = benchmark_capture_cohesion(
        [classic, mixed, executor_profile]
    )
    if benchmark_action_counts["produce"]:
        benchmark_decision = "INCOMPLETE"
        benchmark_decision_reason = "missing benchmark artifacts must be produced before benchmark closeout is reviewable"
    elif benchmark_action_counts["refresh"]:
        benchmark_decision = "REFRESH_RECOMMENDED"
        benchmark_decision_reason = "all benchmark artifacts exist, but at least one is stale or old"
    elif benchmark_capture_status == "mixed_capture_window":
        benchmark_decision = "REFRESH_RECOMMENDED"
        benchmark_decision_reason = "benchmark artifacts are fresh enough individually, but they were not captured tightly enough to treat as a strong single closeout set"
    elif benchmark_capture_status == "divergent_capture_window":
        benchmark_decision = "REFRESH_RECOMMENDED"
        benchmark_decision_reason = "benchmark artifacts are fresh enough individually, but they were captured too far apart to treat as one coherent closeout set"
    else:
        benchmark_decision = "READY"
        benchmark_decision_reason = "all benchmark artifacts exist and are fresh enough for curator/autopilot review"

    lines += ["", "## Benchmark Action Summary"]
    lines.append(f"- benchmark_decision: {benchmark_decision}")
    lines.append(f"- benchmark_decision_reason: {benchmark_decision_reason}")
    lines.append(
        "- benchmark_action_counts: "
        f"produce={benchmark_action_counts['produce']} refresh={benchmark_action_counts['refresh']} keep={benchmark_action_counts['keep']}"
    )
    lines.append(
        f"- benchmark_capture_cohesion: {benchmark_capture_status}"
    )
    lines.append(
        f"- benchmark_capture_spread_seconds: {benchmark_capture_spread_seconds if benchmark_capture_spread_seconds is not None else 'n/a'}"
    )
    lines.append(
        f"- benchmark_blockers: {', '.join(benchmark_blockers) if benchmark_blockers else 'none'}"
    )
    lines.append(
        f"- benchmark_ready_inputs: {', '.join(benchmark_ready_inputs) if benchmark_ready_inputs else 'none'}"
    )
    benchmark_followup_labels = [
        label for label, action, _, _ in benchmark_actions if action in {"produce", "refresh"}
    ]
    if benchmark_capture_status in {"mixed_capture_window", "divergent_capture_window"}:
        benchmark_followup_labels = ["classic_bench", "mixed_bench", "executor_profile"]
    lines.append(
        f"- benchmark_followup_command_chain: {build_followup_command_chain(benchmark_followup_labels, benchmark_producer_for)}"
    )

    lines += ["", "## Block Metrics"]
    for key in [
        "scheduler_elapsed_ms",
        "preexec_elapsed_ms",
        "commit_elapsed_ms",
        "state_root_total_ms",
        "critical_wait_blocks",
        "rollback_count",
        "groups",
        "elapsed_ms",
    ]:
        lines.append(fmt_metric(key, [r.get(key) for r in block_rows if key in r]))

    lines += ["", "## Consensus Summary"]
    if consensus_rows:
        c = consensus_rows[-1]
        for key in [
            "finality_p50_ms",
            "finality_p95_ms",
            "scheduler_elapsed_p50_ms",
            "scheduler_elapsed_p95_ms",
            "preexec_elapsed_p50_ms",
            "preexec_elapsed_p95_ms",
            "commit_elapsed_p50_ms",
            "commit_elapsed_p95_ms",
            "state_root_total_p50_ms",
            "state_root_total_p95_ms",
            "critical_wait_blocks_p50",
            "critical_wait_blocks_p95",
            "rollback_total",
            "preexec_reject_total",
            "apply_error_total",
            "bft_round_change_total",
        ]:
            if key in c:
                lines.append(f"- {key}: {c[key]}")
    else:
        lines.append("- consensus summary: missing")

    lines += ["", "## Benchmark Summary"]
    benchmark_artifact_count = len(
        [p for p in [classic, mixed, executor_profile] if p and os.path.exists(p)]
    )
    lines.append(
        f"- benchmark_artifact_coverage: {benchmark_artifact_count}/3 (classic_bench + mixed_bench + executor_profile)"
    )
    bench_metric_labels = [
        ("classic", classic_rows),
        ("mixed", mixed_rows),
    ]
    bench_metric_keys = [
        "elapsed_ms",
        "groups",
        "grouped",
        "estimated_conflict_rate",
        "profile.report.coverage_ratio",
        "profile.report.groups_per_1k_txs",
        "profile.report.grouping_efficiency",
        "profile.conflict_hit_rate",
        "profile.hot_object_share",
        "profile.candidate_groups_scanned",
    ]
    for label, rows in bench_metric_labels:
        if rows:
            lines.append(f"- {label}_bench_rows: {len(rows)}")
            latest_row = rows[-1]
            for key in bench_metric_keys:
                if key in latest_row:
                    lines.append(f"- {label}_bench.{key}: {latest_row[key]}")
        else:
            lines.append(f"- {label}_bench_rows: 0")
    if classic and os.path.exists(classic):
        lines.append(
            f"- classic_bench_freshness: {freshness_label(file_age_seconds(classic))}"
        )
    else:
        lines.append("- classic_bench_freshness: missing")
    if mixed and os.path.exists(mixed):
        lines.append(
            f"- mixed_bench_freshness: {freshness_label(file_age_seconds(mixed))}"
        )
    else:
        lines.append("- mixed_bench_freshness: missing")
    if executor_profile and os.path.exists(executor_profile):
        lines.append(
            f"- executor_profile_freshness: {freshness_label(file_age_seconds(executor_profile))}"
        )
        with open(executor_profile, "r", encoding="utf-8") as f:
            executor_profile_lines = [line.rstrip() for line in f]
        lines.extend(executor_profile_lines)

        executor_profile_metrics = {}
        for line in executor_profile_lines:
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            executor_profile_metrics[key.strip()] = value.strip()

        auto_metric_keys = [
            "profile.auto.use_hot_bucket",
            "profile.auto.reason",
            "profile.auto.sample_len",
            "profile.auto.streak_ratio",
            "profile.auto.streak_threshold",
            "profile.auto.min_margin",
            "profile.auto.hot_key_share",
            "profile.auto.min_hot_key_share",
            "profile.auto.expected_gain_score",
            "profile.auto.min_expected_gain_score",
        ]
        executor_context_keys = [
            "profile.report.workload",
            "profile.report.strategy",
            "profile.report.txs",
            "profile.report.keys",
            "profile.report.read_fanout",
            "profile.report.write_every",
            "profile.report.persist_profile",
            "profile.report.elapsed_ms",
            "profile.report.path",
            "profile.report.persist_error",
            "profile.report.autopilot_hint",
        ]
        executor_context_lines = [
            f"- executor_profile.{key}: {executor_profile_metrics[key]}"
            for key in executor_context_keys
            if key in executor_profile_metrics
        ]
        if executor_context_lines:
            lines.append("")
            lines.append("### Executor Profile Context")
            lines.extend(executor_context_lines)

        auto_metric_lines = [
            f"- executor_profile.{key}: {executor_profile_metrics[key]}"
            for key in auto_metric_keys
            if key in executor_profile_metrics
        ]
        if auto_metric_lines:
            lines.append("")
            lines.append("### Executor Auto-Adaptive Decision Summary")
            lines.extend(auto_metric_lines)
    else:
        lines.append("- executor_profile_freshness: missing")
        lines.append("- executor profile summary: missing")

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[OK] profiling closeout baseline: {out}")


if __name__ == "__main__":
    main()
