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


def format_bytes(num_bytes: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(max(0, num_bytes))
    unit = units[0]
    for candidate in units:
        unit = candidate
        if value < 1024.0 or candidate == units[-1]:
            break
        value /= 1024.0
    if unit == "B":
        return f"{int(value)} {unit}"
    return f"{value:.1f} {unit}"


def recommended_producer(label: str) -> str:
    if label == "node_log":
        return (
            "cargo run -q -p trnm-node --features legacy-harness --bin trnm-sim -- --config configs/node1.toml --block-ms 5 "
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


def archive_review_command_for(label: str) -> str:
    if label == "classic_bench_candidates":
        return "ls -1t run/bench/bench-matrix-*.txt | sed -n '3,$p'"
    if label == "mixed_bench_candidates":
        return "ls -1t run/bench/bench-mixed-matrix-*.txt | sed -n '3,$p'"
    if label == "executor_profile_candidates":
        return "ls -1t run/bench/executor-profile-summary-*.txt | sed -n '3,$p'"
    if label == "baseline_closeout_report_candidates":
        return "ls -1t docs/reports/profiling-closeout-baseline-*.md | sed -n '3,$p'"
    return "unknown"


def build_archive_review_command_chain(labels: list[str]) -> str:
    commands = []
    for label in labels:
        command = archive_review_command_for(label)
        if command != "unknown":
            commands.append(command)
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


def detect_capture_stamp(path: str | None) -> tuple[str, str] | None:
    if not path:
        return None
    basename = os.path.basename(path)
    patterns = [
        (r"bench-(?:mixed-)?matrix-(\d{8}-\d{6})\.txt$", "wall_clock"),
        (r"executor-profile-summary-(\d+)\.txt$", "epoch"),
        (r"executor-profile-summary-(\d{8}-\d{6})\.txt$", "wall_clock"),
        (r"profiling-closeout-baseline-(\d{8}-\d{6})\.md$", "wall_clock"),
    ]
    for pattern, family in patterns:
        m = re.search(pattern, basename)
        if m:
            return family, m.group(1)
    return None


def normalize_capture_stamp(family: str, value: str) -> int | None:
    try:
        if family == "epoch":
            return int(value)
        if family == "wall_clock":
            return int(datetime.strptime(value, "%Y%m%d-%H%M%S").timestamp())
    except Exception:
        return None
    return None


def capture_stamp_metadata(path: str | None) -> dict[str, str]:
    exists = bool(path and os.path.exists(path))
    basename = os.path.basename(path) if path else "None"
    stamp = detect_capture_stamp(path)
    family = "unavailable"
    value = "unavailable"
    normalized = "unavailable"
    if stamp:
        family, value = stamp
        normalized_epoch = normalize_capture_stamp(family, value)
        if normalized_epoch is not None:
            normalized = str(normalized_epoch)
    return {
        "path": path or "None",
        "exists": "true" if exists else "false",
        "basename": basename,
        "capture_stamp_family": family,
        "capture_stamp": value,
        "capture_stamp_epoch": normalized,
    }


def infer_pending_capture_epoch(path: str | None) -> int | None:
    if not path or os.path.exists(path):
        return None
    stamp = detect_capture_stamp(path)
    if not stamp:
        return None
    family, value = stamp
    return normalize_capture_stamp(family, value)



def capture_stamp_line(label: str, path: str | None) -> str:
    metadata = capture_stamp_metadata(path)
    return (
        f"- {label}: exists={metadata['exists']} basename={metadata['basename']} "
        f"capture_stamp_family={metadata['capture_stamp_family']} "
        f"capture_stamp={metadata['capture_stamp']} "
        f"capture_stamp_epoch={metadata['capture_stamp_epoch']} path={metadata['path']}"
    )


def capture_stamp_alignment_status(paths_by_label: list[tuple[str, str | None]]) -> tuple[str, str]:
    detected = []
    missing = []
    raw_values = set()
    normalized_values = set()
    has_normalization_gap = False
    for label, path in paths_by_label:
        stamp = detect_capture_stamp(path)
        if not stamp:
            missing.append(label)
            continue
        family, value = stamp
        normalized_epoch = normalize_capture_stamp(family, value)
        if normalized_epoch is None:
            has_normalization_gap = True
        detected.append((label, family, value, normalized_epoch))
        raw_values.add(f"{family}:{value}")
        if normalized_epoch is not None:
            normalized_values.add(normalized_epoch)
    if not detected:
        return ("unavailable", "no selected artifacts expose a recognizable capture stamp")
    if missing:
        return (
            "partial",
            f"some selected artifacts do not expose a recognizable capture stamp: {', '.join(missing)}",
        )
    if len(raw_values) == 1:
        return ("aligned", "all selected artifacts advertise the same capture stamp")
    if normalized_values and len(normalized_values) == 1 and not has_normalization_gap:
        return (
            "aligned_normalized",
            "selected artifacts use different capture stamp encodings, but they normalize to the same capture second",
        )
    if has_normalization_gap:
        return (
            "mixed_family",
            "selected artifacts expose different capture stamp families, and at least one stamp could not be normalized for cross-family comparison",
        )
    return (
        "misaligned",
        "selected artifacts expose different capture stamps after normalization",
    )


def capture_epoch_span_summary(paths_by_label: list[tuple[str, str | None]]) -> tuple[str, int | None, str]:
    normalized = []
    missing = []
    for label, path in paths_by_label:
        stamp = detect_capture_stamp(path)
        if not stamp:
            missing.append(label)
            continue
        normalized_epoch = normalize_capture_stamp(*stamp)
        if normalized_epoch is None:
            missing.append(label)
            continue
        normalized.append((label, normalized_epoch))
    if not normalized:
        return ("unavailable", None, "no selected artifacts expose a normalizable capture stamp")
    if missing:
        return (
            "partial",
            None,
            f"some selected artifacts do not expose a normalizable capture epoch: {', '.join(missing)}",
        )
    epochs = [epoch for _, epoch in normalized]
    span_seconds = max(epochs) - min(epochs)
    if span_seconds == 0:
        return ("identical", span_seconds, "all selected artifacts normalize to the same capture second")
    if span_seconds <= 15 * 60:
        return (
            "tight",
            span_seconds,
            "selected artifacts normalize to a tight capture window suitable for closeout review",
        )
    if span_seconds <= 2 * 60 * 60:
        return (
            "loose",
            span_seconds,
            "selected artifacts normalize to a loose capture window; refresh recommended before strong closeout claims",
        )
    return (
        "divergent",
        span_seconds,
        "selected artifacts normalize to a divergent capture window and should not be treated as one coherent closeout set",
    )


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
    baseline_report_pattern = os.path.join(root, "docs", "reports", "profiling-closeout-baseline-*.md")
    node_log_candidates = matching_files(node_log_pattern)
    classic_candidates = matching_files(classic_pattern)
    mixed_candidates = matching_files(mixed_pattern)
    executor_profile_candidates = matching_files(executor_profile_pattern)
    baseline_report_candidates = matching_files(baseline_report_pattern)
    node_log = args.node_log or latest(node_log_pattern)
    classic = args.classic or latest(classic_pattern)
    mixed = args.mixed or latest(mixed_pattern)
    executor_profile = args.executor_profile or latest(executor_profile_pattern)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or os.path.join(root, "docs", "reports", f"profiling-closeout-baseline-{ts}.md")
    baseline_report_candidates_with_out = [out] + [path for path in baseline_report_candidates if path != out]

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
        if not path:
            return None
        if os.path.exists(path):
            return max(0, int((datetime.now() - datetime.fromtimestamp(os.path.getmtime(path))).total_seconds()))
        inferred_epoch = infer_pending_capture_epoch(path)
        if inferred_epoch is None:
            return None
        return max(0, int((datetime.now() - datetime.fromtimestamp(inferred_epoch)).total_seconds()))

    def freshness_label(age_seconds: int | None) -> str:
        if age_seconds is None:
            return "missing"
        if age_seconds <= 15 * 60:
            return "fresh"
        if age_seconds <= 2 * 60 * 60:
            return "stale"
        return "old"

    def file_mtime_iso(path: str | None) -> str | None:
        if not path:
            return None
        if os.path.exists(path):
            return datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
        inferred_epoch = infer_pending_capture_epoch(path)
        if inferred_epoch is None:
            return None
        return datetime.fromtimestamp(inferred_epoch).isoformat()

    def file_size_bytes(path: str | None) -> int | None:
        if not path or not os.path.exists(path):
            return None
        try:
            return os.path.getsize(path)
        except OSError:
            return None

    def artifact_lineage(label: str, path: str | None, producer: str) -> str:
        status = input_status(path)
        age_seconds = file_age_seconds(path)
        freshness = freshness_label(age_seconds)
        basename = os.path.basename(path) if path else "None"
        anchor_path = path
        anchor_note = ""
        size_bytes = file_size_bytes(path)
        if label == "bench_dir" and bench_dir_exists and newest_benchmark_artifact:
            anchor_path = newest_benchmark_artifact
            age_seconds = bench_dir_age_seconds()
            freshness = "empty" if age_seconds is None else freshness_label(age_seconds)
            basename = os.path.basename(newest_benchmark_artifact)
            size_bytes = file_size_bytes(newest_benchmark_artifact)
            anchor_note = f" anchor={newest_benchmark_artifact}"
        return (
            f"- {label}: status={status} freshness={freshness} "
            f"age_seconds={age_seconds if age_seconds is not None else 'n/a'} "
            f"updated_at={file_mtime_iso(anchor_path) or 'n/a'} size_bytes={size_bytes if size_bytes is not None else 'n/a'} basename={basename} "
            f"path={path or 'None'} producer={producer}{anchor_note}"
        )

    def candidate_preview(label: str, selected: str | None, candidates: list[str], max_items: int = 3) -> list[str]:
        existing_candidates = [path for path in candidates if os.path.exists(path)]
        pending_selected = bool(selected and selected in candidates and not os.path.exists(selected))
        missing_candidates = sum(
            1 for path in candidates if not os.path.exists(path) and path != selected
        )
        preview = [
            f"- {label}: selected={selected or 'None'} matched_count={len(candidates)} existing_count={len(existing_candidates)} missing_count={missing_candidates} pending_selected={'true' if pending_selected else 'false'}"
        ]
        if not existing_candidates:
            preview.append(f"  - none: pattern produced no matches")
            return preview
        newest = existing_candidates[0]
        oldest = existing_candidates[-1]
        spread_seconds = int(os.path.getmtime(newest) - os.path.getmtime(oldest)) if len(existing_candidates) >= 2 else 0
        freshness_counts = {"fresh": 0, "stale": 0, "old": 0}
        for path in existing_candidates:
            freshness = freshness_label(file_age_seconds(path))
            if freshness in freshness_counts:
                freshness_counts[freshness] += 1
        preview.append(
            f"  - candidate_window: newest={os.path.basename(newest)} oldest={os.path.basename(oldest)} "
            f"spread_seconds={spread_seconds} newest_freshness={freshness_label(file_age_seconds(newest))} "
            f"oldest_freshness={freshness_label(file_age_seconds(oldest))}"
        )
        preview.append(
            "  - candidate_freshness_counts: "
            f"fresh={freshness_counts['fresh']} stale={freshness_counts['stale']} old={freshness_counts['old']}"
        )
        if selected and selected in candidates and os.path.exists(selected):
            selected_rank = existing_candidates.index(selected) + 1 if selected in existing_candidates else "n/a"
            selected_vs_newest_seconds = max(0, int(os.path.getmtime(newest) - os.path.getmtime(selected)))
            preview.append(
                f"  - selected_status: is_newest={'true' if selected_rank == 1 else 'false'} "
                f"rank={selected_rank}/{len(existing_candidates)} freshness={freshness_label(file_age_seconds(selected))} "
                f"updated_at={file_mtime_iso(selected) or 'n/a'} size_bytes={file_size_bytes(selected) if file_size_bytes(selected) is not None else 'n/a'} "
                f"age_seconds={file_age_seconds(selected) if file_age_seconds(selected) is not None else 'n/a'} "
                f"delta_vs_newest_seconds={selected_vs_newest_seconds}"
            )
        elif selected and selected in candidates:
            inferred_age_seconds = file_age_seconds(selected)
            inferred_updated_at = file_mtime_iso(selected) or 'n/a'
            preview.append(
                f"  - selected_status: is_newest={'pending_write_newest' if candidates and candidates[0] == selected else 'pending_write'} "
                f"rank={'1' if candidates and candidates[0] == selected else 'pending_write'}/{len(existing_candidates)} "
                f"freshness={freshness_label(inferred_age_seconds)} "
                f"updated_at={inferred_updated_at} size_bytes={file_size_bytes(selected) if file_size_bytes(selected) is not None else 'n/a'} age_seconds={inferred_age_seconds if inferred_age_seconds is not None else 'n/a'} "
                f"delta_vs_newest_seconds=n/a"
            )
        elif selected:
            preview.append(
                f"  - selected_status: is_newest=false rank=not_in_candidate_set freshness={freshness_label(file_age_seconds(selected))} "
                f"updated_at={file_mtime_iso(selected) or 'n/a'} size_bytes={file_size_bytes(selected) if file_size_bytes(selected) is not None else 'n/a'} age_seconds={file_age_seconds(selected) if file_age_seconds(selected) is not None else 'n/a'} "
                f"delta_vs_newest_seconds=n/a"
            )
        for idx, path in enumerate(existing_candidates[:max_items], start=1):
            preview.append(
                f"  - recent_{idx}: basename={os.path.basename(path)} size_bytes={file_size_bytes(path) if file_size_bytes(path) is not None else 'n/a'} "
                f"updated_at={file_mtime_iso(path) or 'n/a'} freshness={freshness_label(file_age_seconds(path))} path={path}"
            )
        if len(existing_candidates) > max_items:
            preview.append(f"  - remaining_candidates: {len(existing_candidates) - max_items}")
        return preview

    def candidate_pool_health_struct(label: str, selected: str | None, candidates: list[str]) -> dict[str, str | int | bool]:
        existing_candidates = [path for path in candidates if os.path.exists(path)]
        pending_selected = bool(selected and selected in candidates and not os.path.exists(selected))
        pending_count = 1 if pending_selected else 0
        missing_count = sum(
            1 for path in candidates if not os.path.exists(path) and path != selected
        )
        selected_freshness = freshness_label(file_age_seconds(selected)) if selected else "missing"
        selected_age_seconds = file_age_seconds(selected) if selected else None
        selected_updated_at = file_mtime_iso(selected) if selected else None
        if not existing_candidates:
            effective_candidate_count = pending_count
            return {
                "label": label,
                "status": "empty",
                "action": "produce",
                "selected": selected or "None",
                "selected_freshness": selected_freshness,
                "selected_age_seconds": selected_age_seconds if selected_age_seconds is not None else "n/a",
                "selected_updated_at": selected_updated_at or "n/a",
                "pending_selected": pending_selected,
                "pending_count": pending_count,
                "candidate_count": 0,
                "effective_candidate_count": effective_candidate_count,
                "missing_count": missing_count,
                "fresh": 0,
                "effective_fresh": 1 if pending_selected and selected_freshness == "fresh" else 0,
                "stale": 0,
                "old": 0,
                "old_backlog": 0,
                "fresh_ratio": "0.0000",
                "old_backlog_ratio": "0.0000",
            }
        freshness_counts = {"fresh": 0, "stale": 0, "old": 0}
        for path in existing_candidates:
            freshness = freshness_label(file_age_seconds(path))
            if freshness in freshness_counts:
                freshness_counts[freshness] += 1
        effective_fresh_count = freshness_counts["fresh"]
        if pending_selected and selected_freshness == "fresh":
            effective_fresh_count += 1
        old_backlog = freshness_counts["stale"] + freshness_counts["old"]
        candidate_count = len(existing_candidates)
        effective_candidate_count = candidate_count + pending_count
        fresh_ratio = effective_fresh_count / effective_candidate_count if effective_candidate_count else 0.0
        old_backlog_ratio = old_backlog / effective_candidate_count if effective_candidate_count else 0.0
        if candidate_count == 0:
            status = "empty"
            action = "produce"
        elif effective_fresh_count == 0:
            status = "refresh_required"
            action = "refresh"
        elif candidate_count >= 12 or old_backlog >= 8:
            status = "backlog_heavy"
            action = "keep_latest_and_consider_archive"
        elif candidate_count >= 5 or old_backlog >= 3:
            status = "backlog_present"
            action = "keep_latest"
        else:
            status = "tight"
            action = "keep_latest"
        return {
            "label": label,
            "status": status,
            "action": action,
            "selected": os.path.basename(selected) if selected else "None",
            "selected_freshness": selected_freshness,
            "selected_age_seconds": selected_age_seconds if selected_age_seconds is not None else "n/a",
            "selected_updated_at": selected_updated_at or "n/a",
            "pending_selected": pending_selected,
            "pending_count": pending_count,
            "candidate_count": candidate_count,
            "effective_candidate_count": effective_candidate_count,
            "missing_count": missing_count,
            "fresh": freshness_counts["fresh"],
            "effective_fresh": effective_fresh_count,
            "stale": freshness_counts["stale"],
            "old": freshness_counts["old"],
            "old_backlog": old_backlog,
            "fresh_ratio": f"{fresh_ratio:.4f}",
            "old_backlog_ratio": f"{old_backlog_ratio:.4f}",
        }

    def candidate_pool_health_line(pool: dict[str, str | int | bool]) -> str:
        return (
            f"- {pool['label']}: status={pool['status']} action={pool['action']} selected={pool['selected']} "
            f"selected_freshness={pool['selected_freshness']} selected_age_seconds={pool['selected_age_seconds']} "
            f"selected_updated_at={pool['selected_updated_at']} pending_selected={'true' if pool['pending_selected'] else 'false'} "
            f"pending_count={pool['pending_count']} candidate_count={pool['candidate_count']} "
            f"effective_candidate_count={pool['effective_candidate_count']} missing_count={pool['missing_count']} fresh={pool['fresh']} "
            f"effective_fresh={pool['effective_fresh']} stale={pool['stale']} old={pool['old']} old_backlog={pool['old_backlog']} "
            f"fresh_ratio={pool['fresh_ratio']} old_backlog_ratio={pool['old_backlog_ratio']}"
        )

    def archive_candidates_for_pool(candidates: list[str], keep_latest: int = 2) -> list[str]:
        if len(candidates) <= keep_latest:
            return []
        archive_candidates = []
        for path in candidates[keep_latest:]:
            freshness = freshness_label(file_age_seconds(path))
            if freshness in {"stale", "old"}:
                archive_candidates.append(path)
        return archive_candidates

    def archive_candidate_stats(candidates: list[str], keep_latest: int = 2) -> dict[str, int]:
        archive_candidates = archive_candidates_for_pool(candidates, keep_latest=keep_latest)
        total_bytes = 0
        stale_bytes = 0
        old_bytes = 0
        for path in archive_candidates:
            size_bytes = file_size_bytes(path) or 0
            total_bytes += size_bytes
            freshness = freshness_label(file_age_seconds(path))
            if freshness == "stale":
                stale_bytes += size_bytes
            elif freshness == "old":
                old_bytes += size_bytes
        return {
            "count": len(archive_candidates),
            "total_bytes": total_bytes,
            "stale_bytes": stale_bytes,
            "old_bytes": old_bytes,
        }

    def archive_candidate_line(label: str, candidates: list[str], limit: int = 5) -> str:
        archive_candidates = archive_candidates_for_pool(candidates)
        stats = archive_candidate_stats(candidates)
        basenames = [os.path.basename(path) for path in archive_candidates[:limit]]
        remaining = max(0, len(archive_candidates) - limit)
        return (
            f"- {label}: archive_candidate_count={stats['count']} "
            f"archive_candidate_total_bytes={stats['total_bytes']} "
            f"archive_candidate_total_bytes_human={format_bytes(stats['total_bytes'])} "
            f"archive_candidate_stale_bytes={stats['stale_bytes']} "
            f"archive_candidate_stale_bytes_human={format_bytes(stats['stale_bytes'])} "
            f"archive_candidate_old_bytes={stats['old_bytes']} "
            f"archive_candidate_old_bytes_human={format_bytes(stats['old_bytes'])} "
            f"keep_latest=2 preview={', '.join(basenames) if basenames else 'none'} "
            f"remaining={remaining}"
        )

    def selected_candidate_rank(label: str, selected: str | None, candidates: list[str]) -> str:
        existing_candidates = [path for path in candidates if os.path.exists(path)]
        if not selected:
            return f"- {label}: selected=none rank=missing newest=unknown candidate_count={len(existing_candidates)}"
        if selected in existing_candidates:
            rank = existing_candidates.index(selected) + 1
            return (
                f"- {label}: selected={os.path.basename(selected)} rank={rank}/{len(existing_candidates)} "
                f"newest={'true' if rank == 1 else 'false'}"
            )
        if selected in candidates:
            effective_candidate_count = len(existing_candidates) + 1
            return (
                f"- {label}: selected={os.path.basename(selected)} "
                f"rank={'1' if candidates and candidates[0] == selected else 'pending_write'}/{effective_candidate_count} "
                f"newest={'pending_write_newest' if candidates and candidates[0] == selected else 'pending_write'}"
            )
        return (
            f"- {label}: selected={os.path.basename(selected)} rank=not_in_candidate_set/{len(existing_candidates)} "
            "newest=false"
        )

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

    lines += ["", "## Artifact Capture Stamps"]
    selected_capture_paths = [
        ("node_log", node_log),
        ("classic_bench", classic),
        ("mixed_bench", mixed),
        ("executor_profile", executor_profile),
    ]
    selected_capture_metadata = {
        label: capture_stamp_metadata(path) for label, path in selected_capture_paths
    }
    for label, path in selected_capture_paths:
        lines.append(capture_stamp_line(label, path))
    capture_stamp_status, capture_stamp_reason = capture_stamp_alignment_status(selected_capture_paths)
    benchmark_capture_paths = [
        ("classic_bench", classic),
        ("mixed_bench", mixed),
        ("executor_profile", executor_profile),
    ]
    benchmark_capture_stamp_status, benchmark_capture_stamp_reason = capture_stamp_alignment_status(
        benchmark_capture_paths
    )
    benchmark_capture_epoch_status, benchmark_capture_epoch_span_seconds, benchmark_capture_epoch_reason = capture_epoch_span_summary(
        benchmark_capture_paths
    )
    lines.append(f"- selected_capture_stamp_alignment: {capture_stamp_status}")
    lines.append(f"- selected_capture_stamp_alignment_reason: {capture_stamp_reason}")
    lines.append(f"- benchmark_selected_capture_epoch_window: {benchmark_capture_epoch_status}")
    lines.append(
        f"- benchmark_selected_capture_epoch_window_span_seconds: {benchmark_capture_epoch_span_seconds if benchmark_capture_epoch_span_seconds is not None else 'n/a'}"
    )
    lines.append(f"- benchmark_selected_capture_epoch_window_reason: {benchmark_capture_epoch_reason}")

    benchmark_pools = [
        candidate_pool_health_struct("classic_bench_candidates", classic, classic_candidates),
        candidate_pool_health_struct("mixed_bench_candidates", mixed, mixed_candidates),
        candidate_pool_health_struct("executor_profile_candidates", executor_profile, executor_profile_candidates),
    ]

    lines += ["", "## Benchmark Artifact Pool Health"]
    for pool in benchmark_pools:
        lines.append(candidate_pool_health_line(pool))

    pool_status_counts = {
        "empty": sum(1 for pool in benchmark_pools if pool["status"] == "empty"),
        "refresh_required": sum(1 for pool in benchmark_pools if pool["status"] == "refresh_required"),
        "backlog_present": sum(1 for pool in benchmark_pools if pool["status"] == "backlog_present"),
        "backlog_heavy": sum(1 for pool in benchmark_pools if pool["status"] == "backlog_heavy"),
        "tight": sum(1 for pool in benchmark_pools if pool["status"] == "tight"),
    }
    pool_action_counts = {
        "produce": sum(1 for pool in benchmark_pools if pool["action"] == "produce"),
        "refresh": sum(1 for pool in benchmark_pools if pool["action"] == "refresh"),
        "keep_latest": sum(1 for pool in benchmark_pools if pool["action"] == "keep_latest"),
        "keep_latest_and_consider_archive": sum(
            1 for pool in benchmark_pools if pool["action"] == "keep_latest_and_consider_archive"
        ),
    }
    pool_attention = [
        f"{pool['label']}:{pool['status']}:{pool['action']}"
        for pool in benchmark_pools
        if pool["status"] in {"empty", "refresh_required", "backlog_present", "backlog_heavy"}
    ]
    pool_followup_labels = []
    for pool in benchmark_pools:
        if pool["action"] == "produce":
            pool_followup_labels.append(str(pool["label"]).replace("_candidates", ""))
        elif pool["action"] == "refresh":
            pool_followup_labels.append(str(pool["label"]).replace("_candidates", ""))

    lines += ["", "## Benchmark Pool Action Summary"]
    lines.append(selected_candidate_rank("classic_bench_selection", classic, classic_candidates))
    lines.append(selected_candidate_rank("mixed_bench_selection", mixed, mixed_candidates))
    lines.append(selected_candidate_rank("executor_profile_selection", executor_profile, executor_profile_candidates))
    selected_newest_count = sum(
        1
        for pool in benchmark_pools
        if pool["selected"] != "None" and str(pool["selected"]) != "None" and pool["pending_selected"] is False
        and pool["candidate_count"]
        and pool["selected"] == os.path.basename(
            next(
                (
                    path
                    for path in (
                        classic_candidates
                        if pool["label"] == "classic_bench_candidates"
                        else mixed_candidates
                        if pool["label"] == "mixed_bench_candidates"
                        else executor_profile_candidates
                    )
                    if os.path.exists(path)
                ),
                "",
            )
        )
    )
    selected_fresh_count = sum(1 for pool in benchmark_pools if pool["selected_freshness"] == "fresh")
    selected_pending_count = sum(1 for pool in benchmark_pools if pool["pending_selected"])
    selection_mismatches = []
    for pool in benchmark_pools:
        label = str(pool["label"])
        if pool["pending_selected"]:
            selection_mismatches.append(f"{label}:pending_selected")
            continue
        selected = str(pool["selected"])
        if selected == "None" or int(pool["candidate_count"]) == 0:
            selection_mismatches.append(f"{label}:missing_selection")
            continue
        candidate_source = (
            classic_candidates
            if label == "classic_bench_candidates"
            else mixed_candidates
            if label == "mixed_bench_candidates"
            else executor_profile_candidates
        )
        newest_existing = next((path for path in candidate_source if os.path.exists(path)), None)
        if not newest_existing:
            selection_mismatches.append(f"{label}:missing_newest_candidate")
            continue
        newest_basename = os.path.basename(newest_existing)
        if selected != newest_basename:
            selection_mismatches.append(
                f"{label}:selected={selected}:newest={newest_basename}"
            )
    lines.append(
        "- benchmark_pool_selected_artifact_status: "
        f"newest_selected={selected_newest_count}/{len(benchmark_pools)} "
        f"fresh_selected={selected_fresh_count}/{len(benchmark_pools)} "
        f"pending_selected={selected_pending_count}/{len(benchmark_pools)}"
    )
    lines.append(
        f"- benchmark_pool_selection_mismatches: {', '.join(selection_mismatches) if selection_mismatches else 'none'}"
    )
    lines.append(
        "- benchmark_pool_status_counts: "
        f"empty={pool_status_counts['empty']} refresh_required={pool_status_counts['refresh_required']} "
        f"backlog_present={pool_status_counts['backlog_present']} backlog_heavy={pool_status_counts['backlog_heavy']} "
        f"tight={pool_status_counts['tight']}"
    )
    lines.append(
        "- benchmark_pool_action_counts: "
        f"produce={pool_action_counts['produce']} refresh={pool_action_counts['refresh']} "
        f"keep_latest={pool_action_counts['keep_latest']} "
        f"keep_latest_and_consider_archive={pool_action_counts['keep_latest_and_consider_archive']}"
    )
    lines.append(
        f"- benchmark_pool_attention: {', '.join(pool_attention) if pool_attention else 'none'}"
    )
    lines.append(
        "- benchmark_pool_backlog_totals: "
        f"candidate_count={sum(int(pool['candidate_count']) for pool in benchmark_pools)} "
        f"effective_candidate_count={sum(int(pool['effective_candidate_count']) for pool in benchmark_pools)} "
        f"pending_count={sum(int(pool['pending_count']) for pool in benchmark_pools)} "
        f"fresh={sum(int(pool['fresh']) for pool in benchmark_pools)} "
        f"effective_fresh={sum(int(pool['effective_fresh']) for pool in benchmark_pools)} "
        f"stale={sum(int(pool['stale']) for pool in benchmark_pools)} "
        f"old={sum(int(pool['old']) for pool in benchmark_pools)} "
        f"old_backlog={sum(int(pool['old_backlog']) for pool in benchmark_pools)}"
    )
    lines.append(
        f"- benchmark_pool_followup_command_chain: {build_followup_command_chain(pool_followup_labels, recommended_producer)}"
    )

    archive_pools = [
        ("classic_bench_candidates", classic_candidates),
        ("mixed_bench_candidates", mixed_candidates),
        ("executor_profile_candidates", executor_profile_candidates),
    ]
    baseline_report_pool = candidate_pool_health_struct(
        "baseline_closeout_reports",
        out,
        baseline_report_candidates_with_out,
    )
    archive_candidates_by_pool = {
        label: archive_candidates_for_pool(candidates)
        for label, candidates in archive_pools
    }
    archive_candidate_stats_by_pool = {
        label: archive_candidate_stats(candidates)
        for label, candidates in archive_pools
    }
    archive_candidate_counts = {
        label: archive_candidate_stats_by_pool[label]["count"]
        for label, _ in archive_pools
    }
    archive_attention = [
        f"{label}:{archive_candidate_counts[label]}"
        for label, _ in archive_pools
        if archive_candidate_counts[label] > 0
    ]
    archive_freshness_counts = {"stale": 0, "old": 0}
    for archive_candidates in archive_candidates_by_pool.values():
        for path in archive_candidates:
            freshness = freshness_label(file_age_seconds(path))
            if freshness in archive_freshness_counts:
                archive_freshness_counts[freshness] += 1

    lines += ["", "## Benchmark Archive Candidates"]
    for label, candidates in archive_pools:
        lines.append(archive_candidate_line(label, candidates))

    lines += ["", "## Benchmark Archive Summary"]
    lines.append(
        f"- benchmark_archive_candidate_total: {sum(archive_candidate_counts.values())}"
    )
    lines.append(
        "- benchmark_archive_freshness_counts: "
        f"stale={archive_freshness_counts['stale']} old={archive_freshness_counts['old']}"
    )
    benchmark_archive_total_bytes = sum(int(stats['total_bytes']) for stats in archive_candidate_stats_by_pool.values())
    benchmark_archive_stale_bytes = sum(int(stats['stale_bytes']) for stats in archive_candidate_stats_by_pool.values())
    benchmark_archive_old_bytes = sum(int(stats['old_bytes']) for stats in archive_candidate_stats_by_pool.values())
    lines.append(
        "- benchmark_archive_byte_totals: "
        f"total_bytes={benchmark_archive_total_bytes} "
        f"total_bytes_human={format_bytes(benchmark_archive_total_bytes)} "
        f"stale_bytes={benchmark_archive_stale_bytes} "
        f"stale_bytes_human={format_bytes(benchmark_archive_stale_bytes)} "
        f"old_bytes={benchmark_archive_old_bytes} "
        f"old_bytes_human={format_bytes(benchmark_archive_old_bytes)}"
    )
    lines.append(
        f"- benchmark_archive_attention: {', '.join(archive_attention) if archive_attention else 'none'}"
    )
    lines.append(
        "- benchmark_archive_hotspots: "
        + (
            "none"
            if not archive_attention
            else ", ".join(
                sorted(
                    archive_attention,
                    key=lambda item: int(item.rsplit(":", 1)[1]),
                    reverse=True,
                )
            )
        )
    )
    lines.append(
        "- benchmark_archive_recommendation: "
        + (
            "keep_latest_only_no_archive_action"
            if not archive_attention
            else "review_archive_candidates_before_manual_cleanup"
        )
    )
    lines.append(
        "- benchmark_archive_review_command_chain: "
        + build_archive_review_command_chain(
            [label for label, count in archive_candidate_counts.items() if count > 0]
        )
    )

    lines += ["", "## Baseline Report Pool Health"]
    lines.append(candidate_pool_health_line(baseline_report_pool))
    lines.extend(candidate_preview("baseline_closeout_report_candidates", out, baseline_report_candidates_with_out))
    baseline_report_archive_candidates = archive_candidates_for_pool(baseline_report_candidates_with_out)
    baseline_report_archive_line = archive_candidate_line(
        "baseline_closeout_report_candidates", baseline_report_candidates_with_out
    )
    lines.append(baseline_report_archive_line)
    baseline_report_archive_freshness_counts = {"stale": 0, "old": 0}
    for path in baseline_report_archive_candidates:
        freshness = freshness_label(file_age_seconds(path))
        if freshness in baseline_report_archive_freshness_counts:
            baseline_report_archive_freshness_counts[freshness] += 1
    lines += ["", "## Baseline Report Archive Summary"]
    lines.append(
        f"- baseline_closeout_report_archive_candidate_total: {len(baseline_report_archive_candidates)}"
    )
    lines.append(
        "- baseline_closeout_report_archive_freshness_counts: "
        f"stale={baseline_report_archive_freshness_counts['stale']} old={baseline_report_archive_freshness_counts['old']}"
    )
    baseline_report_archive_stats = archive_candidate_stats(baseline_report_candidates_with_out)
    lines.append(
        "- baseline_closeout_report_archive_byte_totals: "
        f"total_bytes={baseline_report_archive_stats['total_bytes']} "
        f"total_bytes_human={format_bytes(baseline_report_archive_stats['total_bytes'])} "
        f"stale_bytes={baseline_report_archive_stats['stale_bytes']} "
        f"stale_bytes_human={format_bytes(baseline_report_archive_stats['stale_bytes'])} "
        f"old_bytes={baseline_report_archive_stats['old_bytes']} "
        f"old_bytes_human={format_bytes(baseline_report_archive_stats['old_bytes'])}"
    )
    lines.append(
        "- baseline_closeout_report_archive_attention: "
        + (
            "none"
            if not baseline_report_archive_candidates
            else f"baseline_closeout_report_candidates:{len(baseline_report_archive_candidates)}"
        )
    )
    lines.append(
        "- baseline_closeout_report_archive_recommendation: "
        + (
            "keep_latest_only_no_archive_action"
            if not baseline_report_archive_candidates
            else "review_archive_candidates_before_manual_cleanup"
        )
    )
    baseline_report_followup = {
        "produce": "produce_new_closeout_report",
        "refresh": "refresh_closeout_report_set",
        "keep_latest": "keep_latest_only_no_archive_action",
        "keep_latest_and_consider_archive": "review_archive_candidates_before_manual_cleanup",
    }.get(str(baseline_report_pool["action"]), "review_archive_candidates_before_manual_cleanup")

    lines += ["", "## Baseline Report Action Summary"]
    lines.append(
        selected_candidate_rank(
            "baseline_closeout_report_selection",
            out,
            baseline_report_candidates_with_out,
        )
    )
    baseline_closeout_report_decision = (
        "INCOMPLETE"
        if baseline_report_pool["action"] == "produce"
        else "REFRESH_RECOMMENDED"
        if baseline_report_pool["action"] == "refresh"
        else "ARCHIVE_RECOMMENDED"
        if baseline_report_pool["action"] == "keep_latest_and_consider_archive"
        else "READY"
    )
    lines.append(f"- baseline_closeout_report_status: {baseline_report_pool['status']}")
    lines.append(f"- baseline_closeout_report_action: {baseline_report_pool['action']}")
    lines.append(f"- baseline_closeout_report_decision: {baseline_closeout_report_decision}")
    lines.append(
        f"- baseline_closeout_report_reason: status={baseline_report_pool['status']} action={baseline_report_pool['action']}"
    )
    lines.append(
        "- baseline_closeout_report_action_counts: "
        f"candidate_count={baseline_report_pool['candidate_count']} "
        f"effective_candidate_count={baseline_report_pool['effective_candidate_count']} "
        f"pending_count={baseline_report_pool['pending_count']} fresh={baseline_report_pool['fresh']} "
        f"effective_fresh={baseline_report_pool['effective_fresh']} "
        f"stale={baseline_report_pool['stale']} old={baseline_report_pool['old']} "
        f"old_backlog={baseline_report_pool['old_backlog']} archive_candidate_count={len(baseline_report_archive_candidates)}"
    )
    lines.append(
        f"- baseline_closeout_report_selected: {baseline_report_pool['selected']}"
    )
    baseline_refresh_labels = [
        str(pool["label"]).replace("_candidates", "")
        for pool in benchmark_pools
        if pool["action"] in {"produce", "refresh"}
    ]
    baseline_refresh_command_chain = build_followup_command_chain(
        baseline_refresh_labels, benchmark_producer_for
    )
    baseline_followup_command_chain = (
        (
            "python3 scripts/profiling_closeout_report.py"
            if baseline_refresh_command_chain == "none"
            else f"{baseline_refresh_command_chain} && python3 scripts/profiling_closeout_report.py"
        )
        if baseline_report_pool["action"] in {"produce", "refresh"}
        else "none"
    )
    lines.append(
        f"- baseline_closeout_report_followup_command_chain: {baseline_followup_command_chain}"
    )
    lines.append(
        "- baseline_closeout_report_archive_review_command_chain: "
        + (
            build_archive_review_command_chain(["baseline_closeout_report_candidates"])
            if baseline_report_archive_candidates
            else "none"
        )
    )
    lines.append(f"- baseline_closeout_report_followup: {baseline_report_followup}")

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
    closeout_present_set = set(present_inputs)
    closeout_stale_inputs = [label for label in stale_inputs if label in closeout_present_set]
    closeout_old_inputs = [label for label in old_inputs if label in closeout_present_set]
    closeout_ready_inputs = sorted(
        set(present_inputs) - set(closeout_stale_inputs) - set(closeout_old_inputs)
    )
    closeout_ready_count = len(closeout_ready_inputs)
    closeout_structural_blockers = []
    if not bench_dir_exists:
        closeout_structural_blockers.append("bench_dir")
    if closeout_capture_status == "mixed_capture_window":
        closeout_structural_blockers.append("capture_window:mixed")
    elif closeout_capture_status == "divergent_capture_window":
        closeout_structural_blockers.append("capture_window:divergent")
    closeout_evidence_blockers = missing_inputs + closeout_stale_inputs + closeout_old_inputs
    closeout_blockers = closeout_evidence_blockers + closeout_structural_blockers
    lines += ["", "## Closeout Action Summary"]
    lines.append(f"- closeout_decision: {closeout_status}")
    lines.append(f"- closeout_decision_reason: {closeout_reason}")
    lines.append(
        "- closeout_action_counts: "
        f"missing={len(missing_inputs)} stale={len(closeout_stale_inputs)} old={len(closeout_old_inputs)} ready={closeout_ready_count} structural={len(closeout_structural_blockers)}"
    )
    lines.append(f"- closeout_capture_cohesion: {closeout_capture_status}")
    lines.append(
        f"- closeout_capture_spread_seconds: {closeout_capture_spread_seconds if closeout_capture_spread_seconds is not None else 'n/a'}"
    )
    lines.append(
        f"- closeout_evidence_blockers: {', '.join(closeout_evidence_blockers) if closeout_evidence_blockers else 'none'}"
    )
    lines.append(
        f"- closeout_structural_blockers: {', '.join(closeout_structural_blockers) if closeout_structural_blockers else 'none'}"
    )
    lines.append(
        f"- closeout_blockers: {', '.join(closeout_blockers) if closeout_blockers else 'none'}"
    )
    lines.append(
        f"- closeout_ready_inputs: {', '.join(closeout_ready_inputs) if closeout_ready_inputs else 'none'}"
    )
    closeout_followup_labels = closeout_evidence_blockers
    if closeout_capture_status in {"mixed_capture_window", "divergent_capture_window"}:
        closeout_followup_labels = ["node_log", "classic_bench", "mixed_bench", "executor_profile"]
    closeout_followup_command_chain = build_followup_command_chain(
        closeout_followup_labels, recommended_producer
    )
    if closeout_followup_command_chain != "none":
        closeout_followup_command_chain = (
            f"{closeout_followup_command_chain} && python3 scripts/profiling_closeout_report.py"
        )
    lines.append(
        f"- closeout_followup_command_chain: {closeout_followup_command_chain}"
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
    benchmark_followup_command_chain = build_followup_command_chain(
        benchmark_followup_labels, benchmark_producer_for
    )
    lines.append(
        f"- benchmark_followup_command_chain: {benchmark_followup_command_chain}"
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
    lines.append(
        f"- benchmark_selected_capture_alignment: {benchmark_capture_stamp_status}"
    )
    lines.append(
        f"- benchmark_selected_capture_alignment_reason: {benchmark_capture_stamp_reason}"
    )
    lines.append(
        "- benchmark_selected_capture_epochs: "
        f"classic={selected_capture_metadata['classic_bench']['capture_stamp_epoch']} "
        f"mixed={selected_capture_metadata['mixed_bench']['capture_stamp_epoch']} "
        f"executor_profile={selected_capture_metadata['executor_profile']['capture_stamp_epoch']}"
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
            "profile.report.effective_read_fanout",
            "profile.report.effective_write_ratio",
            "profile.report.workload_signature",
            "profile.report.persist_profile",
            "profile.report.capture_started_at_epoch",
            "profile.report.capture_started_at_iso",
            "profile.report.capture_stamp_family",
            "profile.report.capture_stamp",
            "profile.report.capture_stamp_epoch",
            "profile.report.elapsed_ms",
            "profile.report.path",
            "profile.report.artifact_basename",
            "profile.report.output_line_count",
            "profile.report.output_bytes",
            "profile.report.ungrouped_count",
            "profile.report.grouping_complete",
            "profile.report.persist_error",
            "profile.report.autopilot_hint",
        ]
        executor_context_lines = [
            f"- executor_profile.{key}: {executor_profile_metrics[key]}"
            for key in executor_context_keys
            if key in executor_profile_metrics
        ]
        embedded_profile_path = executor_profile_metrics.get("profile.report.path")
        embedded_profile_basename = executor_profile_metrics.get("profile.report.artifact_basename")
        embedded_capture_epoch = executor_profile_metrics.get("profile.report.capture_started_at_epoch")
        embedded_capture_stamp_epoch = executor_profile_metrics.get("profile.report.capture_stamp_epoch")
        selected_basename = os.path.basename(executor_profile)
        selected_capture_stamp = detect_capture_stamp(executor_profile)
        selected_capture_epoch = "unavailable"
        if selected_capture_stamp:
            normalized_selected_epoch = normalize_capture_stamp(*selected_capture_stamp)
            if normalized_selected_epoch is not None:
                selected_capture_epoch = str(normalized_selected_epoch)
        basename_match = None
        capture_epoch_match = None
        capture_stamp_epoch_match = None
        embedded_report_path_exists = None
        embedded_report_path_match = None
        executor_context_lines.extend([
            f"- executor_profile.selected_artifact_path: {executor_profile}",
            f"- executor_profile.selected_artifact_exists: {'true' if os.path.exists(executor_profile) else 'false'}",
            f"- executor_profile.selected_artifact_basename: {selected_basename}",
            f"- executor_profile.selected_capture_stamp_epoch: {selected_capture_epoch}",
            f"- executor_profile.raw_line_count: {len(executor_profile_lines)}",
        ])
        if embedded_profile_basename:
            basename_match = embedded_profile_basename == selected_basename
            executor_context_lines.append(
                "- executor_profile.embedded_artifact_basename_matches_selected: "
                f"{'true' if basename_match else 'false'}"
            )
        if embedded_capture_epoch:
            capture_epoch_match = embedded_capture_epoch == selected_capture_epoch
            executor_context_lines.append(
                "- executor_profile.embedded_capture_epoch_matches_selected: "
                f"{'true' if capture_epoch_match else 'false'}"
            )
        if embedded_capture_stamp_epoch:
            capture_stamp_epoch_match = embedded_capture_stamp_epoch == selected_capture_epoch
            executor_context_lines.append(
                "- executor_profile.embedded_capture_stamp_epoch_matches_selected: "
                f"{'true' if capture_stamp_epoch_match else 'false'}"
            )
        if embedded_profile_path:
            embedded_report_path_exists = os.path.exists(embedded_profile_path)
            embedded_report_path_match = bool(
                executor_profile
                and os.path.abspath(embedded_profile_path) == os.path.abspath(executor_profile)
            )
            executor_context_lines.extend([
                f"- executor_profile.embedded_report_path_exists: {'true' if embedded_report_path_exists else 'false'}",
                (
                    "- executor_profile.embedded_report_path_matches_selected: "
                    f"{'true' if embedded_report_path_match else 'false'}"
                ),
            ])
        integrity_checks = []
        if basename_match is not None:
            integrity_checks.append(basename_match)
        if capture_epoch_match is not None:
            integrity_checks.append(capture_epoch_match)
        if capture_stamp_epoch_match is not None:
            integrity_checks.append(capture_stamp_epoch_match)
        if embedded_report_path_match is not None:
            integrity_checks.append(embedded_report_path_match)
        integrity_status = (
            "OK"
            if integrity_checks and all(integrity_checks)
            else "FAIL"
            if integrity_checks and any(check is False for check in integrity_checks)
            else "PARTIAL"
            if integrity_checks
            else "UNVERIFIED"
        )
        integrity_reason_parts = []
        if basename_match is not None:
            integrity_reason_parts.append(
                f"basename_match={'true' if basename_match else 'false'}"
            )
        if capture_epoch_match is not None:
            integrity_reason_parts.append(
                f"capture_epoch_match={'true' if capture_epoch_match else 'false'}"
            )
        if capture_stamp_epoch_match is not None:
            integrity_reason_parts.append(
                f"capture_stamp_epoch_match={'true' if capture_stamp_epoch_match else 'false'}"
            )
        if embedded_report_path_match is not None:
            integrity_reason_parts.append(
                f"report_path_match={'true' if embedded_report_path_match else 'false'}"
            )
        if executor_context_lines:
            lines.append("")
            lines.append("### Executor Profile Context")
            lines.extend(executor_context_lines)
            lines.append(f"- executor_profile.integrity_status: {integrity_status}")
            lines.append(
                "- executor_profile.integrity_reason: "
                + (", ".join(integrity_reason_parts) if integrity_reason_parts else "no embedded integrity keys available")
            )

        auto_metric_lines = [
            f"- executor_profile.{key}: {executor_profile_metrics[key]}"
            for key in auto_metric_keys
            if key in executor_profile_metrics
        ]
        if auto_metric_lines:
            lines.append("")
            lines.append("### Executor Auto-Adaptive Decision Summary")
            lines.extend(auto_metric_lines)

        lines.append("")
        lines.append("### Executor Profile Raw KV")
        lines.extend(executor_profile_lines)
    else:
        lines.append("- executor_profile_freshness: missing")
        lines.append("- executor profile summary: missing")

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[OK] profiling closeout baseline: {out}")


if __name__ == "__main__":
    main()
