#!/usr/bin/env python3
"""Execute a preregistered, relation-only task-family/producer selection game.

This is actual two-phase dispatch, not a minimum-cost claim or native task
authorization. Every child starts a fresh real PreparedTask. The controller's
absolute RUSAGE_SELF + RUSAGE_CHILDREN CPU includes Python startup, source checks,
spawn, material/setup, every failed proof trial, native verifier calls and logs.
Completed child batches are delivered conservatively only after exit, bounded
raw retention and basic validation. No ticket from an over-budget batch receives
in-budget credit. Post-hoc strict record validation has a separate CPU interval;
it cannot change selection, and any failure invalidates the entire report.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
WALL_ORIGIN = time.monotonic_ns()
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from bounded_process import ProcessFailure, run_bounded

SCHEMA = "pon-w1-task-family-selection-v1"
FAMILIES = ("full-rank-field", "zero", "continuity-maintenance-v1")
FAMILY_ARMS = {
    "full-rank-field": ("prepared-generic", "paired-product", "integer-paired-general"),
    "zero": ("prepared-generic", "blocked-zero-integer-paired", "integer-paired-general"),
    "continuity-maintenance-v1": ("prepared-generic", "maintenance-prefix", "maintenance-limb"),
}
ARMS = tuple(dict.fromkeys(arm for family in FAMILIES for arm in FAMILY_ARMS[family]))
TRAINING_SEED, EVALUATION_SEED = 7001, 9001
TRAINING_ATTEMPTS, EVALUATION_ATTEMPTS = 4, 64
TARGET = "7f" + "ff" * 31
BUDGETS = (100_000_000, 1_000_000_000, 5_000_000_000)
GRID = tuple((family, arm) for family in FAMILIES for arm in FAMILY_ARMS[family])
OUTPUT_LIMIT = 4 * 1024 * 1024
TIMEOUT = 30
PLAN = {
    "families": FAMILIES, "arms": ARMS, "family_arms": FAMILY_ARMS, "training_seed": TRAINING_SEED,
    "evaluation_seed": EVALUATION_SEED, "training_attempts": TRAINING_ATTEMPTS,
    "evaluation_attempts": EVALUATION_ATTEMPTS, "target": TARGET,
    "registered_cpu_budgets_ns": BUDGETS, "grid_order": GRID,
    "selection": "minimum full measured child-call CPU / completed proofs; fixed grid ordinal tie break",
    "selection_uses_target_hits": False, "requires_complete_training_grid": True,
    "delivery": "all tickets of a complete child batch at its validated/retained return time",
    "material_seed_changed": False, "prepared_objects_shared_across_children": False,
    "qualification_level": "relation-only; no eligible-task or nonce-grinding claim",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def usage():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    own_ns = round((own.ru_utime + own.ru_stime) * 1_000_000_000)
    child_ns = round((children.ru_utime + children.ru_stime) * 1_000_000_000)
    return {"self_cpu_ns": own_ns, "waited_child_cpu_ns": child_ns,
            "total_cpu_ns": own_ns + child_ns,
            "wall_ns_since_module_loaded": time.monotonic_ns() - WALL_ORIGIN}


def native_args(family, arm, seed, attempts):
    return ["--scope", "relation", "--mode", "hot", "--samples", "1",
            "--families", family, "--arms", arm, "--seed", str(seed),
            "--attempts", str(attempts), "--target", TARGET]


def h(tag, *parts):
    encoded = tag.encode()
    out = b"TRNM-PON1\0" + struct.pack("<H", len(encoded)) + encoded
    for part in parts:
        out += struct.pack("<I", len(part)) + part
    return hashlib.sha256(out).digest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def decode(text):
    return json.loads(text, object_pairs_hook=unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("JSON_CONSTANT")))


def basic_review(data, family, arm, seed, attempts):
    """Execution gate; full independent record review runs after selection."""
    require(len(data) <= OUTPUT_LIMIT and data.endswith(b"\n"), "RAW_BOUNDARY")
    lines = data.splitlines()
    require(all(len(line) <= 2 * 1024 * 1024 for line in lines), "RAW_LINE_BOUND")
    rows = [decode(line) for line in lines]
    require(rows and rows[0].get("kind") == "campaign" and rows[-1].get("kind") == "end"
            and rows[-1].get("complete") is True, "INCOMPLETE_CHILD")
    require(all(row.get("schema") == "pon-w1-valid-cost-game-v1" for row in rows), "RAW_SCHEMA")
    options = rows[0]["options"]
    require(options["scope"] == "relation" and options["mode"] == "hot"
            and options["samples"] == 1 and options["families"] == [family]
            and rows[0]["arm_names"] == [arm] and options["seed"] == seed
            and options["attempts"] == attempts and options["cpu_budget_ns"] is None
            and bytes(options["target"]).hex() == TARGET, "CHILD_OPTIONS")
    summaries = [row for row in rows if row["kind"] == "cohort-end"]
    actual = [row for row in rows if row["kind"] == "attempt"]
    require(len(summaries) == 1 and summaries[0]["status"] == "attempt-cap-complete"
            and len(actual) == attempts and summaries[0]["attempts"] == attempts
            and summaries[0]["training_attempts"] == 0, "CHILD_ATTEMPT_CLOSURE")
    tickets = []
    for ordinal, row in enumerate(actual):
        require(row["attempt_index"] == ordinal and row["ordinal"] == ordinal
                and row["nonce"] == ordinal and row["phase"] == "evaluation"
                and row["arm"] == arm and row["relation_valid"] is True
                and row["qualification_level"] == "relation-valid-only"
                and row["production_verifier"]["accepted"] is True
                and row["reference_verifier"]["accepted"] is True
                and row["proof_bytes"] == 49188 and row["parent"] is None
                and row["native_admission"] is None, "INVALID_COMPLETE_RELATION")
        values = {}
        for name in ("task", "challenge", "trace", "ticket", "semantic_id", "proof_sha256"):
            require(type(row[name]) is str and re.fullmatch(r"[0-9a-f]{64}", row[name]), "HASH_FIELD")
            values[name] = bytes.fromhex(row[name])
        challenge = h("w1-cost-game-challenge-v1", values["task"], struct.pack("<Q", seed),
                      struct.pack("<Q", 0), b"evaluation", struct.pack("<Q", ordinal))
        require(values["challenge"] == challenge and values["ticket"] == h("ticket", challenge, values["trace"])
                and values["semantic_id"] == h("w1-cost-game-semantic-ticket-v1", values["task"], challenge, values["ticket"])
                and row["target"] == TARGET and row["target_hit"] == (values["ticket"] <= bytes.fromhex(TARGET)),
                "TICKET_BINDING")
        tickets.append({key: row[key] for key in ("semantic_id", "task", "challenge", "ticket", "target_hit")})
    return {"complete_proofs": len(actual), "tickets": tickets}


def choose(training):
    require(len(training) == len(GRID) and [(r["family"], r["arm"]) for r in training] == list(GRID),
            "INCOMPLETE_TRAINING_GRID")
    require(all(type(row["full_call_cpu_ns"]) is int and row["full_call_cpu_ns"] >= 0
                and row["complete_proofs"] == TRAINING_ATTEMPTS for row in training), "TRAINING_COST")
    return min(range(len(training)), key=lambda index: (
        Fraction(training[index]["full_call_cpu_ns"], training[index]["complete_proofs"]), index))


def execute_strategy(run_job, cpu_now, budget, event):
    """Injectable control logic; tests use clocks/receipts, never fake runtime evidence."""
    records, training, all_tickets = [], [], {}
    selected = None
    status = "budget-before-training"

    def collect(phase, family, arm, seed, attempts):
        before = cpu_now()
        result = run_job(phase, family, arm, seed, attempts)
        after = cpu_now()
        require(after >= before, "CPU_CLOCK_REVERSED")
        require(result["complete_proofs"] == attempts, "CHILD_PROOF_COUNT")
        record = dict(result, phase=phase, family=family, arm=arm, seed=seed,
                      full_call_cpu_ns=after-before, delivery_cpu_ns=after,
                      within_cpu_budget=after <= budget)
        records.append(record)
        for ticket in result["tickets"]:
            all_tickets.setdefault(ticket["semantic_id"], dict(ticket, first_phase=phase,
                first_job=len(records)-1, delivery_cpu_ns=after, within_cpu_budget=after <= budget))
        event({"kind":"child-delivered", "job":len(records)-1, "phase":phase,
               "family":family,"arm":arm,"full_call_cpu_ns":after-before,
               "delivery_cpu_ns":after,"within_cpu_budget":after <= budget})
        return record

    for family, arm in GRID:
        if cpu_now() >= budget:
            status = "budget-during-training" if training else "budget-before-training"
            break
        training.append(collect("training", family, arm, TRAINING_SEED, TRAINING_ATTEMPTS))
    if len(training) == len(GRID):
        if cpu_now() >= budget:
            status = "budget-after-training"
        else:
            index = choose(training)
            selected = {"family":training[index]["family"],"arm":training[index]["arm"],
                        "training_index":index,"policy":"full-call-cpu-per-proof; grid-order-tie-break"}
            event({"kind":"selection", **selected, "before_evaluation":True})
            if cpu_now() >= budget:
                status = "budget-after-selection"
            else:
                collect("evaluation", selected["family"], selected["arm"], EVALUATION_SEED, EVALUATION_ATTEMPTS)
                status = "evaluation-complete" if cpu_now() <= budget else "evaluation-overrun"
    return {"status":status,"selected":selected,"records":records,"distinct_tickets":list(all_tickets.values()),
            "distinct_target_hits":sum(ticket["target_hit"] for ticket in all_tickets.values()),
            "budget_distinct_target_hits":sum(ticket["target_hit"] and ticket["within_cpu_budget"] for ticket in all_tickets.values()),
            "training_grid_complete":len(training) == len(GRID),
            "heldout_executed":any(row["phase"] == "evaluation" for row in records)}


def identity(expected_head, expected_tree):
    guard = load_module("task_family_source_guard", ROOT / "scripts/ci/verify_ci_source.py")
    raw = guard.verify("head", expected_head, root=ROOT)
    observed = {}
    for key, arguments in (("head",["rev-parse","HEAD"]), ("tree",["rev-parse","HEAD^{tree}"]),
                           ("status",["status","--porcelain","--untracked-files=all"])):
        result = run_bounded(["git","-C",str(ROOT),*arguments],b"",timeout=10,stdout_limit=256*1024)
        require(result.returncode == 0,"GIT_IDENTITY_FAILED")
        observed[key] = result.stdout.decode().strip()
    require(observed["head"] == expected_head and observed["tree"] == expected_tree
            and not observed["status"], "CLEAN_EXACT_SOURCE_REQUIRED")
    observed["raw_tracked_source_verification"] = raw
    return observed


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name,path)
    require(spec is not None and spec.loader is not None,"READER_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_reader():
    return load_module("task_family_strict_reader", ROOT / "scripts/read_w1_cost_research.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",type=Path,required=True)
    parser.add_argument("--binary-sha256",required=True)
    parser.add_argument("--expected-head",required=True)
    parser.add_argument("--expected-tree",required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--cpu-budget-ns",type=int,choices=BUDGETS,default=BUDGETS[-1])
    args = parser.parse_args()
    require(sys.platform.startswith("linux"), "LINUX_CPU_ACCOUNTING_REQUIRED")
    runner = load_module("task_family_runner_environment", ROOT / "scripts/run_w1_cost_research.py")
    runner.validate_build_environment(os.environ)
    require(re.fullmatch(r"[0-9a-f]{64}",args.binary_sha256) is not None,"BINARY_PIN")
    require(all(re.fullmatch(r"[0-9a-f]{40}",value) for value in (args.expected_head,args.expected_tree)),"SOURCE_PINS")
    binary, output = args.binary.resolve(), args.out.resolve()
    require(binary.is_file() and os.access(binary,os.X_OK) and binary.stat().st_size <= 256*1024*1024,"BINARY_FILE")
    require(not output.is_relative_to(ROOT),"OUTPUT_OUTSIDE_PINNED_REPOSITORY_REQUIRED")
    before_source = identity(args.expected_head,args.expected_tree)
    require(sha(binary) == args.binary_sha256,"BINARY_HASH")
    output.mkdir(parents=True,exist_ok=False)
    write_new(output/"preregistration.json", {"schema":SCHEMA,"plan":PLAN,
        "source":before_source,"binary":str(binary),"binary_sha256":args.binary_sha256,
        "binary_source_binding":"conditional on trusted owner's jointly supplied source/binary pins; this script does not build or establish reproducible source-to-binary linkage",
        "cpu_budget_ns":args.cpu_budget_ns,"initial_usage":usage(),
        "all_work_is_relation_only":True,"scientific_or_chain_authority":False})
    job_paths=[]
    with (output/"events.jsonl").open("x",encoding="utf-8") as stream:
        def event(value):
            stream.write(json.dumps(value,sort_keys=True,allow_nan=False)+"\n")
            stream.flush()
        def run_job(phase,family,arm,seed,attempts):
            require(sha(binary) == args.binary_sha256,"BINARY_CHANGED")
            index=len(job_paths)
            arguments=native_args(family,arm,seed,attempts)
            raw=output/f"job-{index:02d}.jsonl"
            errors=output/f"job-{index:02d}.stderr"
            job_paths.append((raw,arguments))
            failure=None
            stdout,stderr,returncode=b"",b"",None
            try:
                result=run_bounded([str(binary),*arguments],b"",timeout=TIMEOUT,
                                   stdout_limit=OUTPUT_LIMIT,stderr_limit=256*1024,cwd=ROOT)
                stdout,stderr,returncode=result.stdout,result.stderr,result.returncode
            except ProcessFailure as error:
                stdout,stderr,returncode=error.stdout,error.stderr,error.returncode
                failure=str(error)
            except (ValueError,OSError) as error:
                failure=str(error)
            raw.write_bytes(stdout)
            errors.write_bytes(stderr)
            write_new(output/f"job-{index:02d}.execution.json",{"phase":phase,"command":[str(binary),*arguments],
                "returncode":returncode,"failure":failure,"stdout_sha256":sha(raw),"stderr_sha256":sha(errors),
                "actual_process_usage_after_retention":usage()})
            require(failure is None and returncode == 0,"CHILD_EXECUTION_FAILED")
            reviewed=basic_review(stdout,family,arm,seed,attempts)
            return dict(reviewed,raw_file=raw.name,stdout_sha256=sha(raw))
        try:
            report=execute_strategy(run_job,lambda:usage()["total_cpu_ns"],args.cpu_budget_ns,event)
            strategy_end=usage()
            # Explicitly post hoc: neither these costs nor verdict-dependent
            # retries can alter the already retained training decision.
            posthoc_start=usage()
            reader=load_reader()
            reviews=[]
            for raw,arguments in job_paths:
                reviews.append(reader.validate_raw(raw,replay=False,expected_options=reader.options_from_args(arguments)))
            require(sha(binary) == args.binary_sha256,"BINARY_CHANGED")
            after_source=identity(args.expected_head,args.expected_tree)
            posthoc_end=usage()
            report.update(schema=SCHEMA,record_consistency="PASS",plan=PLAN,source_before=before_source,
                source_after=after_source,binary_sha256=args.binary_sha256,cpu_budget_ns=args.cpu_budget_ns,
                binary_source_binding="conditional on trusted owner's joint external pins; fresh-build manifest association is retained by the owning runner",
                strategy_end_usage=strategy_end,posthoc_end_usage=posthoc_end,
                posthoc_record_validation_cpu_ns=posthoc_end["total_cpu_ns"]-posthoc_start["total_cpu_ns"],
                posthoc_review_feeds_selection=False,independent_transcript_replay=False,
                raw_reviews=reviews,hardness_accepted=False,production_activation=False,
                limits=["Calling process plus waited children CPU, not joules or hardware attestation.",
                    "Budget applies to strategy through child delivery; separately retained post-hoc review cannot create work credit.",
                    "Each child starts from public material and a fresh constructor; no cross-child prepared-object reuse.",
                    "Seed changes are precommitted independent challenge streams, not adaptive seed grinding.",
                    "The full child call includes spawn, public material generation, all misses, native verification and raw retention.",
                    "Relation-only diagnostic family choice grants no parent-state eligibility or chainweight."])
            write_new(output/"report.json",report)
            write_new(output/"closure.json",{"schema":SCHEMA,"report_sha256":sha(output/"report.json"),
                "usage_through_report_retention":usage(),"this_final_receipt_write_excluded":True})
            print(json.dumps({"record_consistency":"PASS","status":report["status"],"output":str(output)},sort_keys=True))
            return 0
        except (ValueError,OSError,KeyError,TypeError) as error:
            event({"kind":"failure","error":str(error),"actual_usage":usage()})
            write_new(output/"failure.json",{"schema":SCHEMA,"record_consistency":"FAIL","error":str(error),
                "actual_usage":usage(),"attempted_child_jobs":len(job_paths),
                "hardness_accepted":False,"production_activation":False})
            print(json.dumps({"record_consistency":"FAIL","error":str(error),"output":str(output)},sort_keys=True))
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
