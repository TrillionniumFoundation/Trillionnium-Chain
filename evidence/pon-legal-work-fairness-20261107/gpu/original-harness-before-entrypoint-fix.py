#!/usr/bin/env python3
"""Bounded hardware comparison for the existing exact int257 research relation.

Standalone: pass --payload frozen.json or replace PAYLOAD_B64 with its base64
bytes before freezing the submitted script. No download, training, installation,
credential access or external effects. A CUDA failure remains a failed CUDA
attempt; --cpu-check is a separately labelled local correctness check.

FP64 is an implementation of the EXACT integer relation here: all admitted
operands, products and every absolute partial-sum bound are strictly below
2**53. No FP32/TF32/tolerance-based substitute is admitted. This finite hardware
experiment establishes neither a minimum legal cost nor PoW qualification.
"""
from __future__ import annotations

import time

ENTRY_NS = time.perf_counter_ns()
import argparse
import base64
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import traceback

PAYLOAD_B64 = ""
PROFILE = "pon-routed-int257-grouped-research-v0"
DIM, CLASSES, EXPERTS = 257, 3, 3
F64_EXACT_LIMIT = 1 << 53


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, code):
    if not condition:
        raise ValueError(code)


def write_report(report, destination):
    # Each stage remains observable if a later import/device/operation fails.
    data = canonical(report) + b"\n"
    target = Path(destination)
    temporary = target.with_suffix(target.suffix + ".partial")
    with temporary.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, target)


def validate_matrix(matrix, rows, cols, limit):
    require(type(matrix) is list and len(matrix) == rows, "MATRIX_ROWS")
    require(all(type(row) is list and len(row) == cols for row in matrix), "MATRIX_COLUMNS")
    require(all(type(v) is int and abs(v) <= limit for row in matrix for v in row),
            "MATRIX_INTEGER_RANGE")


def validate_case(case):
    model, rows = case["model"], case["rows"]
    require(type(rows) is list and len(rows) == 16, "FIXED_BATCH_16")
    validate_matrix(model["base"], 3, DIM, 32767)
    validate_matrix(model["router"], 3, DIM, 32767)
    require(type(model["deltas"]) is list and len(model["deltas"]) == 3, "EXPERT_COUNT")
    for delta in model["deltas"]:
        validate_matrix(delta, 3, DIM, 32767)
    validate_matrix([row["x"] for row in rows], 16, DIM, 8)
    require(all(row["x"][-1] == 8 for row in rows), "BIAS_8")
    require(len({row["id"] for row in rows}) == 16, "UNIQUE_REQUEST_IDENTITIES")
    merged = [[[model["base"][r][k] + delta[r][k] for k in range(DIM)]
               for r in range(3)] for delta in model["deltas"]]
    maxima = [max(abs(row["x"][k]) for row in rows) for k in range(DIM)]
    bound = lambda matrix: max(sum(abs(w) * x for w, x in zip(row, maxima))
                               for row in matrix)
    bounds = {"router_abs_partial_sum_bound": bound(model["router"]),
              "base_abs_partial_sum_bound": bound(model["base"]),
              "delta_abs_partial_sum_bound": max(bound(d) for d in model["deltas"]),
              "merged_abs_partial_sum_bound": max(bound(d) for d in merged),
              "original_max_coefficient": max(abs(v) for m in [model["base"], model["router"],
                                                                *model["deltas"]] for r in m for v in r),
              "generic_full_logit_bound": DIM * 65534 * 8,
              "f64_exact_integer_limit_exclusive": F64_EXACT_LIMIT}
    if case.get("factors") is not None:
        require(len(case["factors"]) == 3, "FACTORS_COUNT")
        factor_bounds = []
        for expert, factor in enumerate(case["factors"]):
            rank = len(factor["down"])
            require(1 <= rank <= 8, "FACTOR_RANK")
            validate_matrix(factor["up"], 3, rank, 32767)
            validate_matrix(factor["down"], rank, DIM, 32767)
            for r in range(3):
                for k in range(DIM):
                    require(sum(factor["up"][r][j] * factor["down"][j][k]
                                for j in range(rank)) == model["deltas"][expert][r][k],
                            "FACTOR_NOT_IDENTICAL_DELTA")
            hidden_bounds = [sum(abs(w) * x for w, x in zip(row, maxima))
                             for row in factor["down"]]
            factor_bounds += hidden_bounds
            factor_bounds += [sum(abs(w) * h for w, h in zip(row, hidden_bounds))
                              + bounds["base_abs_partial_sum_bound"] for row in factor["up"]]
        bounds["factor_abs_partial_sum_bound"] = max(factor_bounds)
    require(all(v < F64_EXACT_LIMIT for k, v in bounds.items()
                if k != "f64_exact_integer_limit_exclusive"), "FP64_EXACT_BOUND")
    return bounds


def scalar_reference(model, rows):
    """Original base and selected delta are summed independently using Python ints."""
    scores, routes, logits = [], [], []
    for row in rows:
        x = row["x"]
        score = [sum(w * v for w, v in zip(weights, x)) for weights in model["router"]]
        expert = max(range(3), key=lambda i: score[i])  # first index wins ties
        values = [sum(w * v for w, v in zip(model["base"][r], x))
                  + sum(w * v for w, v in zip(model["deltas"][expert][r], x))
                  for r in range(3)]
        scores.append(score)
        routes.append(expert)
        logits.append(values)
    return {"router_outputs": scores, "routes": routes,
            "groups": [[i for i, e in enumerate(routes) if e == expert] for expert in range(3)],
            "logits": logits, "predictions": [max(range(3), key=lambda i: v[i]) for v in logits]}


def controlled_case(rows):
    """Fixed rank-one model, same dimensions; not trained weights or new demand."""
    model = {"base": [[(r * 7 + k * 11) % 13 - 6 for k in range(DIM)] for r in range(3)],
             "router": [[(e * 5 + k * 3) % 11 - 5 for k in range(DIM)] for e in range(3)],
             "deltas": []}
    factors = []
    for expert in range(3):
        up = [[(r + expert) % 5 - 2] for r in range(3)]
        down = [[(k + expert) % 5 - 2 for k in range(DIM)]]
        factors.append({"up": up, "down": down})
        model["deltas"].append([[up[r][0] * down[0][k] for k in range(DIM)] for r in range(3)])
    return {"name": "controlled_rank1_same_shape", "kind": "synthetic_factor_control_not_trained_model",
            "model": model, "rows": rows, "factors": factors}


def make_numpy(case, np, dtype):
    model = case["model"]
    base = np.asarray(model["base"], dtype=dtype)
    deltas = np.asarray(model["deltas"], dtype=dtype)
    value = {"x": np.asarray([r["x"] for r in case["rows"]], dtype=dtype),
             "router": np.asarray(model["router"], dtype=dtype), "base": base, "deltas": deltas}
    begin = time.perf_counter_ns()
    value["merged"] = base[None, :, :] + deltas
    merge_ns = time.perf_counter_ns() - begin
    if case.get("factors"):
        value["up"] = np.asarray([f["up"] for f in case["factors"]], dtype=dtype)
        value["down"] = np.asarray([f["down"] for f in case["factors"]], dtype=dtype)
    return value, merge_ns


def numpy_arm(prepared, np, *, factor=False):
    x = prepared["x"]
    scores = x @ prepared["router"].T
    routes = np.argmax(scores, axis=1)
    logits = np.empty((len(x), 3), dtype=x.dtype)
    for expert in range(3):
        indices = np.flatnonzero(routes == expert)  # ascending, stable gather
        if len(indices):
            selected = x[indices]
            if factor:
                logits[indices] = (selected @ prepared["base"].T
                                   + (selected @ prepared["down"][expert].T) @ prepared["up"][expert].T)
            else:
                logits[indices] = selected @ prepared["merged"][expert].T
    return scores, routes, logits, np.argmax(logits, axis=1)


def cuda_arm(prepared, torch, kind):
    x = prepared["x"]
    scores = x @ prepared["router"].T
    routes = torch.argmax(scores, dim=1)
    if kind == "direct_original":
        logits = x @ prepared["base"].T + torch.bmm(prepared["deltas"][routes], x.unsqueeze(2)).squeeze(2)
    elif kind == "direct_cached_merged":
        logits = torch.bmm(prepared["merged"][routes], x.unsqueeze(2)).squeeze(2)
    else:
        logits = torch.empty((x.shape[0], 3), dtype=torch.float64, device="cuda")
        for expert in range(3):
            indices = torch.nonzero(routes == expert, as_tuple=False).flatten()
            if indices.numel():
                selected = torch.index_select(x, 0, indices)
                if kind == "factor_selected":
                    values = (selected @ prepared["base"].T
                              + (selected @ prepared["down"][expert].T) @ prepared["up"][expert].T)
                else:
                    require(kind == "grouped_cached_merged", "CUDA_ARM")
                    values = selected @ prepared["merged"][expert].T
                logits.index_copy_(0, indices, values)  # complete scatter to original order
    return scores, routes, logits, torch.argmax(logits, dim=1)


def normalized(output, np, torch=None):
    values = []
    for item in output:
        array = item.detach().cpu().numpy() if torch is not None else item
        require(np.isfinite(array).all() and np.equal(array, np.rint(array)).all(), "NONINTEGER_OUTPUT")
        require((np.abs(array) < F64_EXACT_LIMIT).all(), "OUTPUT_INTEGER_BOUND")
        values.append(array.astype(np.int64).tolist())
    scores, routes, logits, predictions = values
    return {"router_outputs": scores, "routes": routes,
            "groups": [[i for i, e in enumerate(routes) if e == expert] for expert in range(3)],
            "logits": logits, "predictions": predictions}


def orders(names):
    # Each arm appears equally often in every position; reverse cycles counter
    # direction. Fixed schedule, no winner-dependent stopping or sample pruning.
    schedule = []
    for shift in range(len(names)):
        row = names[shift:] + names[:shift]
        schedule.extend([row, list(reversed(row))])
    return schedule * 3


def summaries(records):
    answer = {}
    for name in sorted({r["arm"] for r in records}):
        rows = [r for r in records if r["arm"] == name and r["phase"] == "warm"]
        passed = [r for r in rows if r["status"] == "verified"]
        answer[name] = {"planned_or_attempted_warm_samples": len(rows), "verified": len(passed)}
        for field in ("compute_wall_ns", "host_result_transfer_normalize_ns", "verification_ns", "whole_sample_ns"):
            vals = [r[field] for r in passed]
            if vals:
                answer[name][field] = {"median": statistics.median(vals), "minimum": min(vals),
                                       "maximum": max(vals), "sum": sum(vals)}
    return answer


def run_case(case, np, torch, *, cpu_only=False):
    case_start = time.perf_counter_ns()
    validation_start = time.perf_counter_ns()
    bounds = validate_case(case)
    validation_ns = time.perf_counter_ns() - validation_start
    reference_start = time.perf_counter_ns()
    expected = scalar_reference(case["model"], case["rows"])
    reference_ns = time.perf_counter_ns() - reference_start
    if case.get("expected_product") is not None:
        require(expected == case["expected_product"], "PREEXISTING_INDEPENDENT_REFERENCE")
    preparation_start = time.perf_counter_ns()
    cpu_i64, merge_i64_ns = make_numpy(case, np, np.int64)
    cpu_f64, merge_f64_ns = make_numpy(case, np, np.float64)
    cpu_preparation_ns = time.perf_counter_ns() - preparation_start
    funcs = {"cpu_ordinary_cached_merged_i64": lambda: numpy_arm(cpu_i64, np),
             "cpu_ordinary_cached_merged_exact_fp64": lambda: numpy_arm(cpu_f64, np)}
    gpu = None
    h2d_ns = gpu_merge_ns = gpu_bytes = 0
    if torch is not None:
        torch.cuda.synchronize()
        begin = time.perf_counter_ns()
        gpu = {k: torch.as_tensor(v, dtype=torch.float64, device="cuda")
               for k, v in cpu_f64.items() if k != "merged"}
        torch.cuda.synchronize()
        h2d_ns = time.perf_counter_ns() - begin
        gpu_bytes = sum(v.numel() * v.element_size() for v in gpu.values())
        begin = time.perf_counter_ns()
        gpu["merged"] = gpu["base"].unsqueeze(0) + gpu["deltas"]
        torch.cuda.synchronize()
        gpu_merge_ns = time.perf_counter_ns() - begin
        for kind in ("direct_original", "direct_cached_merged", "grouped_cached_merged"):
            funcs["cuda_" + kind + "_exact_fp64"] = lambda k=kind: cuda_arm(gpu, torch, k)
    if case.get("factors"):
        funcs["cpu_factor_selected_i64"] = lambda: numpy_arm(cpu_i64, np, factor=True)
        if torch is not None:
            funcs["cuda_factor_selected_exact_fp64"] = lambda: cuda_arm(gpu, torch, "factor_selected")
    names = list(funcs)
    schedule = orders(names)
    record = {"name": case["name"], "kind": case["kind"], "model_sha256": sha(case["model"]),
              "rows_sha256": sha(case["rows"]), "batch_size": 16, "numeric_bounds": bounds,
              "validation_and_factor_equivalence_ns": validation_ns,
              "independent_scalar_reference_ns": reference_ns, "expected_product": expected,
              "expected_product_sha256": sha(expected), "cpu_preparation_ns": cpu_preparation_ns,
              "cpu_i64_merge_ns": merge_i64_ns, "cpu_fp64_merge_ns": merge_f64_ns,
              "host_to_device_material_ns": h2d_ns, "host_to_device_material_bytes": gpu_bytes,
              "gpu_merge_preparation_ns": gpu_merge_ns, "warm_orders": schedule,
              "warm_schedule_scope": "equal per-arm position frequency; fixed rotations and reversals; shared immutable cache",
              "planned_warm_samples": len(schedule) * len(names), "attempts": [],
              "setup_order": names, "gpu_used": torch is not None,
              "cache_scope": "exact same frozen model and 16 inputs throughout; repetitions are not new work queries or demand"}
    phases = [("first_call", names), ("warmup", list(reversed(names))), ("warmup", names)]
    phases += [("warm", order) for order in schedule]
    for ordinal, (phase, order) in enumerate(phases):
        for position, name in enumerate(order):
            is_gpu = name.startswith("cuda_")
            row = {"arm": name, "phase": phase, "order": ordinal, "position": position,
                   "status": "started", "compute_scope": "prepared fixed model and input; router, selected computation, scatter/prediction; no host-result transfer"}
            start = time.perf_counter_ns()
            try:
                if is_gpu:
                    torch.cuda.synchronize()
                before_cpu = time.process_time_ns()
                begin = time.perf_counter_ns()
                result = funcs[name]()
                if is_gpu:
                    torch.cuda.synchronize()
                row["compute_wall_ns"] = time.perf_counter_ns() - begin
                row["compute_host_cpu_ns"] = time.process_time_ns() - before_cpu
                begin = time.perf_counter_ns()
                public_result = normalized(result, np, torch if is_gpu else None)
                row["host_result_transfer_normalize_ns"] = time.perf_counter_ns() - begin
                begin = time.perf_counter_ns()
                require(public_result == expected, "FULL_PRODUCT_MISMATCH")
                row["verification_ns"] = time.perf_counter_ns() - begin
                row.update(status="verified", product_sha256=sha(public_result))
            except Exception as error:
                row.update(status="error", error_type=type(error).__name__, error=str(error)[:1024])
            row["whole_sample_ns"] = time.perf_counter_ns() - start
            record["attempts"].append(row)
    record["summary"] = summaries(record["attempts"])
    record["all_samples_verified"] = all(r["status"] == "verified" for r in record["attempts"])
    # A fresh input traversal includes allocation, H2D/D2H, and a recomputed
    # scalar verification; model and merged weights remain prepared and charged above.
    fresh = []
    for name in names:
        start = time.perf_counter_ns()
        row = {"arm": name, "status": "started", "model_cache_reused": True,
               "scope": "fresh host input conversion + optional H2D + full computation + D2H + new scalar reference + comparison"}
        try:
            arr = np.asarray([r["x"] for r in case["rows"]], dtype=np.float64 if "fp64" in name else np.int64)
            if name.startswith("cuda_"):
                gpu["x"] = torch.as_tensor(arr, dtype=torch.float64, device="cuda")
                torch.cuda.synchronize()
            elif "fp64" in name:
                cpu_f64["x"] = arr
            else:
                cpu_i64["x"] = arr
            value = normalized(funcs[name](), np, torch if name.startswith("cuda_") else None)
            fresh_reference = scalar_reference(case["model"], case["rows"])
            require(value == fresh_reference, "FRESH_PRODUCT_MISMATCH")
            row.update(status="verified", product_sha256=sha(value))
        except Exception as error:
            row.update(status="error", error_type=type(error).__name__, error=str(error)[:1024])
        row["whole_wall_ns"] = time.perf_counter_ns() - start
        fresh.append(row)
    record["fresh_input_verified_samples"] = fresh
    record["all_samples_verified"] &= all(r["status"] == "verified" for r in fresh)
    record["case_total_wall_ns"] = time.perf_counter_ns() - case_start
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--out", default="result.json")
    parser.add_argument("--cpu-check", action="store_true")
    args = parser.parse_args(argv)
    report = {"schema": "pon-grouped-gpu-legal-v0", "profile": PROFILE, "status": "started",
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "cpu_check_only": args.cpu_check, "cases": [], "errors": [],
              "pow_qualified": False, "production_activation": False, "chainwork_awarded": 0,
              "minimum_legal_cost_proved": False, "full_lottery_cost_measured": False}
    write_report(report, args.out)
    stage = "payload"
    try:
        raw = args.payload.read_bytes() if args.payload else base64.b64decode(PAYLOAD_B64, validate=True)
        payload = json.loads(raw)
        require(payload["schema"] == "pon-grouped-gpu-legal-payload-v0", "PAYLOAD_SCHEMA")
        require(payload["profile"] == PROFILE, "PROFILE")
        report.update(payload_sha256=hashlib.sha256(raw).hexdigest(), provenance=payload["provenance"],
                      source_files=payload["source_files"],
                      numeric_backend="exact integer relation, IEEE binary64 implementation under verified <2^53 absolute partial-sum bounds",
                      no_tf32_or_fp32=True, business_quality_tolerance=None)
        stage = "imports"
        before = time.perf_counter_ns()
        # One CPU thread makes resource scope explicit. Record library details;
        # no package installation or version-changing retry occurs in the workload.
        for variable in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
            os.environ[variable] = "1"
        import numpy as np
        report["numpy_import_ns"] = time.perf_counter_ns() - before
        report["environment"] = {"python": sys.version, "platform": platform.platform(),
                                 "machine": platform.machine(), "numpy": np.__version__,
                                 "cpu_threads_requested": 1, "cpu_count": os.cpu_count()}
        torch = None
        if not args.cpu_check:
            stage = "torch_import_and_cuda"
            before = time.perf_counter_ns()
            import torch
            report["torch_import_ns"] = time.perf_counter_ns() - before
            torch.set_num_threads(1)
            torch.backends.cuda.matmul.allow_tf32 = False
            torch.backends.cudnn.allow_tf32 = False
            torch.set_float32_matmul_precision("highest")
            report["environment"].update(torch=torch.__version__, cuda_build=torch.version.cuda,
                                         cudnn=torch.backends.cudnn.version(), tf32_allowed=False)
            before = time.perf_counter_ns()
            require(torch.cuda.is_available(), "CUDA_REQUIRED_NO_CPU_FALLBACK")
            require(torch.cuda.device_count() == 1, "EXACTLY_ONE_CUDA_DEVICE_REQUIRED")
            torch.cuda.init()
            torch.cuda.synchronize()
            report["cuda_initialization_ns"] = time.perf_counter_ns() - before
            prop = torch.cuda.get_device_properties(0)
            report["device"] = {"name": prop.name, "total_memory_bytes": prop.total_memory,
                                "compute_capability": [prop.major, prop.minor],
                                "multiprocessor_count": prop.multi_processor_count}
            report["device_metadata_sha256"] = sha(report["device"])
            require("T4" in prop.name, "FIXED_T4_HARDWARE")
            try:
                observed = subprocess.run(["nvidia-smi", "--query-gpu=name,driver_version,memory.total",
                                           "--format=csv,noheader,nounits"], capture_output=True,
                                          text=True, timeout=8, check=False)
                report["nvidia_smi"] = {"returncode": observed.returncode,
                                         "stdout": observed.stdout[:2048], "stderr": observed.stderr[:512]}
            except Exception as error:
                report["nvidia_smi"] = {"error_type": type(error).__name__}
        report["entry_to_ready_ns"] = time.perf_counter_ns() - ENTRY_NS
        write_report(report, args.out)
        real = {"name": "retained_consumer16", "kind": "retained_trained_model_and_frozen_source_consumer",
                "model": payload["model"], "rows": payload["rows"],
                "expected_product": payload["expected_product"]}
        for case in (real, controlled_case(payload["rows"])):
            stage = case["name"]
            report["cases"].append(run_case(case, np, torch, cpu_only=args.cpu_check))
            write_report(report, args.out)
        stage = "tie_control"
        zeros = [[0] * DIM for _ in range(3)]
        tie = {"name": "zero_model_tie_control", "kind": "synthetic_tie_control_only",
               "model": {"base": zeros, "router": zeros, "deltas": [zeros, zeros, zeros]},
               "rows": payload["rows"]}
        validate_case(tie)
        expected_tie = scalar_reference(tie["model"], tie["rows"])
        require(expected_tie["routes"] == [0] * 16 and expected_tie["predictions"] == [0] * 16,
                "SCALAR_LOWEST_TIE")
        values, _ = make_numpy(tie, np, np.float64)
        require(normalized(numpy_arm(values, np), np) == expected_tie, "CPU_LOWEST_TIE")
        if torch is not None:
            gpu_tie = {k: torch.as_tensor(v, dtype=torch.float64, device="cuda") for k, v in values.items()}
            for kind in ("direct_original", "direct_cached_merged", "grouped_cached_merged"):
                require(normalized(cuda_arm(gpu_tie, torch, kind), np, torch) == expected_tie,
                        "CUDA_LOWEST_TIE_AND_STABLE_SCATTER")
        report["tie_control"] = {"verified": True, "routes": [0] * 16, "predictions": [0] * 16,
                                  "groups": [list(range(16)), [], []], "gpu": torch is not None}
        require(all(c["all_samples_verified"] for c in report["cases"]), "ATTEMPT_FAILURE_RETAINED")
        report["status"] = "cpu_correctness_only_hold" if args.cpu_check else "gpu_comparison_complete_research_hold"
    except Exception as error:
        report["status"] = "failed_research_hold"
        report["errors"].append({"stage": stage, "error_type": type(error).__name__,
                                  "error": str(error)[:2048], "traceback": traceback.format_exc()[-4096:]})
    report["total_process_wall_ns_before_final_write"] = time.perf_counter_ns() - ENTRY_NS
    usage = resource.getrusage(resource.RUSAGE_SELF)
    report["process_resource"] = {"user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
                                  "max_rss_kib_linux": usage.ru_maxrss}
    report["environment_sha256"] = sha(report.get("environment", {}))
    report["interpretation"] = [
        "Fixed 16-request historical batch repeated for timing; no new authenticated demand or ticket query.",
        "Warm compute excludes transfer and independent verification; both are retained separately and in whole-sample costs.",
        "First calls share a process and caches; setup order is recorded, not represented as independent cold boots.",
        "Setup, preparation, merge, validation, reference, warmup, failed attempts and full process time remain charged observations.",
        "FP64 is exact only inside the proved integer bounds; this is not a floating tolerance or arbitrary reassociation profile.",
        "Synthetic rank-one control is not the trained model and does not establish a full LLM or W1 speedup.",
        "VM allocation, host launcher startup, transport, final artifact I/O and release are captured by external adapter receipts, not this process clock.",
        "Finite measured implementations are upper bounds on attainable cost; no minimum attacker cost, fairness or PoW security is proved."]
    write_report(report, args.out)
    print(json.dumps({"status": report["status"], "source_sha256": report["source_sha256"],
                      "payload_sha256": report.get("payload_sha256"), "errors": report["errors"],
                      "result_sha256": hashlib.sha256(Path(args.out).read_bytes()).hexdigest(),
                      "result_bytes": Path(args.out).stat().st_size,
                      "gpu": report.get("device"), "cases": [c["name"] for c in report["cases"]]},
                     sort_keys=True), flush=True)
    return 1 if report["status"] == "failed_research_hold" else 0


if __name__ == "__main__":
    raise SystemExit(main())
