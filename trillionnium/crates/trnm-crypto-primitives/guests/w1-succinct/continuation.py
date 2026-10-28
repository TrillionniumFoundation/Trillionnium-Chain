#!/usr/bin/env python3
"""Continue an exact failed transparent window; never relabel its failed costs."""
import argparse
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import stat
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import runner as r

HERE = Path(__file__).resolve().parent
TASKS = [task for batch in r.batches() for task in batch]
BY_NAME = {r.name(task): task for task in TASKS}
PRIOR_PHASES = tuple(list(r.PHASE_TIMEOUTS)[:12])


def policy():
    p = r.read_json(HERE / "continuation_policy.json")
    r.policy()
    r.require(p["schema"] == "pon-w1-succinct-continuation-policy-v1"
              and p["origin"]["conclusion"] == "failure"
              and p["retained_successful_stages"] == 112
              and p["new_stages_required"] == 11
              and p["interrupted_stages"] == ["join-32-40", "join-40-48"],
              "explicit frozen failed window required")
    for key in ("additional_pow", "consensus_authority", "original_recursion_budget_changed",
                "complete_from_zero_generation_measured"):
        r.require(p[key] is False, "continuation promotion: " + key)
    r.require(p["all_retained_stages_reverified"] is True
              and p["original_failed_window_retained"] is True, "retained checks required")
    return p


def raw_logs(out, name, row):
    for stream in ("stdout", "stderr"):
        item = row["raw_logs"][stream]
        r.require(item["path"] == name + "." + stream + ".log"
                  and r.digest(out / item["path"], 16 * 1024**2)
                  == {key: item[key] for key in ("bytes", "sha256")}, "raw phase logs changed")


def costs(row):
    for key in ("wall_seconds", "user_cpu_seconds", "system_cpu_seconds"):
        value = row[key]
        r.require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                  "finite actual process cost required")


def completed_names(attempt):
    names = attempt["completed"]
    r.require(isinstance(names, list) and len(names) == 112 and len(set(names)) == 112
              and set(names).issubset(BY_NAME), "exact successful checkpoint stage set required")
    completed_ranges = set()
    for task in TASKS:
        if r.name(task) not in names:
            continue
        a, middle, b = (task[key] for key in ("start", "split", "end"))
        if task["op"] == "join":
            r.require((a, middle) in completed_ranges and (middle, b) in completed_ranges,
                      "checkpoint is not dependency closed")
        completed_ranges.add((a, b))
    return names


def stage_result(row, task):
    r.require(row["schema"] == "pon-w1-succinct-stage-v1"
              and row["operation"] == task["op"]
              and all(row[key] == task[key] for key in ("start", "split", "end"))
              and row["real_recursion_stark_verified"] is True
              and row["complete_w1_proof_verified"] is False
              and all(row[key] is False for key in
                      ("additional_pow", "povw_requested", "dev_mode", "consensus_authority")),
              "stage profile or exact range differs")


def anchor_prior(prior):
    origin = policy()["origin"]
    archive = prior.parent / "prior-window.zip"
    r.require(r.digest(archive, 128 * 1024**2) == {"bytes": origin["artifact_bytes"],
              "sha256": origin["artifact_sha256"]}, "original failure archive anchor differs")
    with zipfile.ZipFile(archive) as z:
        expected_names = set(z.namelist()) - {"original-assembly.zip"}
        actual_names = {str(path.relative_to(prior)) for path in prior.rglob("*") if not path.is_dir()}
        r.require(actual_names == expected_names, "extracted original evidence inventory differs")
        for name in sorted(expected_names):
            raw = z.read(name)
            r.require(r.digest(prior / name, 128 * 1024**2)
                      == {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                      "extracted original evidence changed: " + name)


def inspect_prior(prior):
    p = policy(); origin = p["origin"]
    anchor_prior(prior)
    before = r.read_json(prior / "source-before.json")
    r.require(before == r.read_json(prior / "source-after.json")
              and before["candidate"] == before["tested_commit"] == origin["source_sha"]
              and before["tested_tree"] == origin["source_tree"]
              and before["tracked_worktree_verified"] is True
              and before["tests_executed_by_identity_check"] is False,
              "original failed source identity changed")
    r.require(r.read_json(prior / "policy.json") == r.policy(), "original budgets or relation changed")
    r.check_inputs(prior / "original")
    phases = {name: r.closed_phase(prior, name, origin["source_sha"])
              for name in PRIOR_PHASES if name != "compress"}
    failed = r.read_json(prior / "compress.process.json")
    r.require(failed["schema"] == "pon-w1-actual-process-v2"
              and failed["source_sha"] == origin["source_sha"] and failed["returncode"] == 1
              and failed["timed_out"] is False and failed["child_reaped"] is True
              and failed["owned_process_group_empty"] is True and not failed["cleanup_errors"]
              and failed["timeout_seconds"] == 3600 and 3500 <= failed["wall_seconds"] <= 3600,
              "original failed bounded window must remain a failure")
    costs(failed); raw_logs(prior, "compress", failed); phases["compress"] = failed
    settled = r.read_json(prior / "recursion-after-cleanup.json")
    attempt = r.read_json(prior / "recursion/attempt.json")
    r.require(attempt["schema"] == "pon-w1-succinct-attempt-v1"
              and attempt["source_sha"] == origin["source_sha"] and attempt["outcome"] == "failed"
              and attempt["github_run_id"] == str(origin["run_id"])
              and attempt["github_run_attempt"] == str(origin["run_attempt"])
              and attempt["budgets"] == r.policy()["budgets"]
              and attempt["real_succinct_stark_verified"] is False
              and not attempt["direct_children_missing_terminal"]
              and "independent recursion work-stop reached" in attempt["error"],
              "original stopped attempt differs")
    r.require(attempt["helper"] == r.digest(prior / "native/trnm-w1-succinct-research", 64 * 1024**2),
              "original native helper identity changed")
    r.require(settled["complete"] is False and settled["owned_family_closed"] is True
              and settled["attempt"] == attempt and settled["outer_phase"] == failed
              and not settled["missing_stage_terminals"] and settled["new_work_started"] is False,
              "original family closure missing")
    actual_files = {}
    for directory in (prior / "recursion/steps", prior / "recursion/receipts"):
        for path in sorted(directory.iterdir()):
            actual_files[str(path.relative_to(prior))] = r.digest(path, 16 * 1024**2)
    r.require(actual_files == settled["retained_files"], "retained checkpoint byte inventory differs")
    names = completed_names(attempt)
    terminals = {v["name"]: v for v in settled["known_stage_terminals"]}
    r.require(len(terminals) == len(settled["known_stage_terminals"]) == 115
              and set(terminals) == set(names) | {"prepare"} | set(p["interrupted_stages"]),
              "original terminal set differs")
    records = {}
    for name in ["prepare"] + names + p["interrupted_stages"]:
        term = r.read_json(prior / f"recursion/steps/{name}.terminal.json")
        r.require(term == terminals[name], "settled terminal changed")
        if name in p["interrupted_stages"]:
            r.require(term["returncode"] == -15 and term["child_reaped"] is True
                      and term["source_sha"] == origin["source_sha"] and term["timeout_seconds"] == 300,
                      "interrupted stage became a success")
            costs(term)
            continue
        r.terminal(term, origin["source_sha"])
        if name == "prepare":
            continue
        task = BY_NAME[name]
        row = r.read_single_result(prior / f"recursion/steps/{name}.stdout.log", "pon-w1-succinct-stage-v1")
        stage_result(row, task)
        expected = {"bytes": row["receipt_bytes"], "sha256": row["receipt_sha256"]}
        r.require(r.digest(prior / f'recursion/receipts/range-{task["start"]}-{task["end"]}.bin', 2 * 1024**2)
                  == expected, "retained verified stage bytes differ")
        records[name] = {"process": term, "native": row}
    return {"source": before, "attempt": attempt, "stages": records, "exclusive_outer_phases": phases}


def unpack(archive, out):
    p = policy(); origin = p["origin"]
    r.require(r.digest(archive, 128 * 1024**2) == {"bytes": origin["artifact_bytes"],
              "sha256": origin["artifact_sha256"]}, "frozen failed artifact bytes differ")
    prior = out / "prior"; prior.mkdir()
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        r.require(len(infos) == origin["archive_members"]
                  and len({info.filename for info in infos}) == len(infos)
                  and sum(info.file_size for info in infos) == origin["archive_uncompressed_bytes"],
                  "original archive inventory differs")
        for info in infos:
            relative = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            r.require(not relative.is_absolute() and ".." not in relative.parts
                      and str(relative) == info.filename and not info.is_dir()
                      and (stat.S_IFMT(mode) in (0, stat.S_IFREG))
                      and info.file_size <= 128 * 1024**2, "nonregular or unsafe archived member")
            # The complete nested Composite archive remains in the hashed ZIP;
            # avoid a second 80 MB extracted copy, without discarding any bytes.
            if info.filename == "original-assembly.zip":
                continue
            destination = prior.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(z.read(info))
    record = inspect_prior(prior)
    original = out / "original"; original.mkdir()
    for name in r.policy()["input_files"]:
        shutil.copyfile(prior / "original" / name, original / name)
    r.check_inputs(original)
    return record


def fetch(out):
    p = policy(); origin = p["origin"]
    run = r.api_json("actions/runs/" + str(origin["run_id"]))
    artifact = r.api_json("actions/artifacts/" + str(origin["artifact_id"]))
    r.require(run["id"] == origin["run_id"] and run["run_attempt"] == origin["run_attempt"]
              and run["head_sha"] == origin["source_sha"] and run["status"] == "completed"
              and run["conclusion"] == "failure", "exact failed run required")
    r.require(artifact["id"] == origin["artifact_id"] and artifact["name"] == origin["artifact_name"]
              and artifact["workflow_run"]["id"] == origin["run_id"]
              and artifact["workflow_run"]["head_sha"] == origin["source_sha"]
              and artifact["expired"] is False and artifact["size_in_bytes"] == origin["artifact_bytes"]
              and artifact["digest"] == "sha256:" + origin["artifact_sha256"], "failed artifact identity differs")
    r.write(out / "prior-run.json", run); r.write(out / "prior-artifact.json", artifact)
    url = "https://api.github.com/repos/" + origin["repository"] + "/actions/artifacts/" + str(origin["artifact_id"]) + "/zip"
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                                                   "User-Agent": "w1-succinct-continuation"})
    try:
        urllib.request.build_opener(r.NoRedirect).open(request, timeout=30)
        raise ValueError("artifact redirect required")
    except urllib.error.HTTPError as error:
        r.require(error.code in (302, 303, 307), "artifact redirect status")
        location = error.headers.get("Location", "")
    parsed = urllib.parse.urlsplit(location)
    r.require(parsed.scheme == "https" and parsed.hostname is not None
              and (parsed.hostname.endswith(".blob.core.windows.net")
                   or parsed.hostname.endswith(".githubusercontent.com")), "unreviewed object host")
    archive = out / "prior-window.zip"; size = 0; digest = hashlib.sha256()
    with urllib.request.urlopen(location, timeout=120) as response, archive.open("xb") as stream:
        while chunk := response.read(1024**2):
            size += len(chunk); r.require(size <= origin["artifact_bytes"], "frozen ZIP cap")
            digest.update(chunk); stream.write(chunk)
        stream.flush(); os.fsync(stream.fileno())
    r.require(size == origin["artifact_bytes"] and digest.hexdigest() == origin["artifact_sha256"],
              "frozen failed ZIP hash differs")
    record = unpack(archive, out)
    result = {"schema": "pon-w1-succinct-resume-fetch-v1", "accepted": True, "origin": origin,
              "retained_successful_stages": len(record["stages"]), "original_outcome": "failed",
              "prior_archive": r.digest(archive, 128 * 1024**2), "consensus_authority": False}
    r.write(out / "fetch-result.json", result); print(r.json.dumps(result))


def retained_result(row, task, previous):
    r.require(row["schema"] == "pon-w1-succinct-retained-range-v1"
              and all(row[key] == task[key] for key in ("start", "end"))
              and all(row[key] == previous[key] for key in ("receipt_bytes", "receipt_sha256", "claim_digest"))
              and row["real_recursion_stark_verified"] is True
              and all(row[key] is False for key in ("complete_w1_proof_verified", "new_proof_generated",
                                                   "additional_pow", "povw_requested", "dev_mode", "consensus_authority")),
              "fresh retained-range cryptographic verification differs")
    r.nanosecond_costs(row, "verify_wall_ns", "verify_process_cpu_ns")


def prove(args):
    r.require(os.getpid() == os.getpgrp(), "owned process-group wrapper required")
    r.require(os.environ.get("RAYON_NUM_THREADS") == "2" and "RISC0_DEV_MODE" not in os.environ,
              "fixed threads/no development mode")
    ids = r.identity(); p = policy(); r.check_inputs(args.out / "original")
    prior = inspect_prior(args.out / "prior")
    d = args.out / "recursion"; d.mkdir(); steps = d / "steps"; steps.mkdir()
    receipts = d / "receipts"; receipts.mkdir()
    signal.signal(signal.SIGTERM, r.scheduler.stopping); signal.signal(signal.SIGINT, r.scheduler.stopping)
    stages = []; started = time.monotonic()
    outcome = {"schema": "pon-w1-succinct-resume-attempt-v1", **ids, "outcome": "failed",
               "completed": [], "reverified": [], "reused": sorted(prior["stages"]),
               "origin": p["origin"], "real_succinct_stark_verified": False,
               "additional_pow": False, "povw_requested": False, "consensus_authority": False,
               "budgets": r.policy()["budgets"], "helper": r.digest(args.helper, 64 * 1024**2)}
    def remaining():
        r.require(not r.scheduler.STOP and time.monotonic() - started < 3500, "continuation work-stop reached")
    def wait(stage):
        while stage.check() is None:
            remaining(); time.sleep(.025)
        r.terminal(stage.record, ids["source_sha"]); remaining()
    try:
        r.require_runner(d / "resources.json")
        stage = r.scheduler.Stage(steps, "prepare", [str(args.helper), "prepare", str(args.out / "original"),
                                                    str(d / "prepared.json")], 300)
        stages.append(stage); wait(stage)
        prepared = r.read_single_result(steps / "prepare.stdout.log", "pon-w1-succinct-prepare-v1")
        r.require(prepared["original_composite_verified"] is True and prepared["native_full_w1_matches"] is True,
                  "new full original verification missing")
        for task in TASKS:
            name = r.name(task)
            if name not in prior["stages"]:
                continue
            filename = f'range-{task["start"]}-{task["end"]}.bin'
            shutil.copyfile(args.out / "prior/recursion/receipts" / filename, receipts / filename)
            stage = r.scheduler.Stage(steps, "recheck-" + name,
                [str(args.helper), "verify-range", str(args.out / "original/receipt.bin"),
                 str(task["start"]), str(task["end"]), str(receipts / filename)], 300)
            stages.append(stage); wait(stage)
            row = r.read_single_result(steps / ("recheck-" + name + ".stdout.log"), "pon-w1-succinct-retained-range-v1")
            retained_result(row, task, prior["stages"][name]["native"])
            outcome["reverified"].append(name)
        for batch in r.batches():
            pending = [task for task in batch if r.name(task) not in prior["stages"]]; active = {}
            while pending or active:
                remaining()
                while pending and len(active) < 2:
                    task = pending.pop(0); name = r.name(task)
                    a, middle, b = (task[key] for key in ("start", "split", "end"))
                    left = str(receipts / f"range-{a}-{middle}.bin") if task["op"] == "join" else "-"
                    right = str(receipts / f"range-{middle}-{b}.bin") if task["op"] == "join" else "-"
                    command = [str(args.helper), "stage", str(args.r0vm), str(args.out / "original/receipt.bin"),
                               str(a), str(middle), str(b), left, right, str(receipts / f"range-{a}-{b}.bin")]
                    stage = r.scheduler.Stage(steps, name, command, 300, logs=True)
                    stages.append(stage); active[name] = (task, stage)
                for name, (task, stage) in list(active.items()):
                    if stage.check() is None:
                        continue
                    r.terminal(stage.record, ids["source_sha"]); remaining()
                    row = r.read_single_result(steps / (name + ".stdout.log"), "pon-w1-succinct-stage-v1")
                    stage_result(row, task)
                    r.require(r.digest(receipts / f'range-{task["start"]}-{task["end"]}.bin', 2 * 1024**2)
                              == {"bytes": row["receipt_bytes"], "sha256": row["receipt_sha256"]}, "new stage bytes changed")
                    outcome["completed"].append(name); del active[name]
                    print(r.json.dumps({"new_completed_stage": name, "wall_seconds": stage.record["wall_seconds"]}),
                          file=sys.stderr, flush=True)
                time.sleep(.025)
        r.require(len(outcome["completed"]) == 11 and sorted(outcome["reverified"]) == outcome["reused"]
                  and set(outcome["completed"]).isdisjoint(outcome["reused"])
                  and set(outcome["completed"] + outcome["reused"]) == set(BY_NAME), "incomplete resumed graph")
        remaining()
        stage = r.scheduler.Stage(steps, "finish", [str(args.helper), "finish", str(args.out / "original"),
            str(receipts / "range-0-62.bin"), str(args.out / "succinct.bin"), str(args.out / "certificate.bin")], 300)
        stages.append(stage); wait(stage)
        finished = r.read_single_result(steps / "finish.stdout.log", "pon-w1-succinct-finish-v1")
        r.require(finished["real_succinct_stark_verified"] is True and finished["claim_digest"] == r.policy()["claim_digest"],
                  "complete original relation proof missing")
        outcome.update(outcome="complete", real_succinct_stark_verified=True, finish=finished,
                       work_finished_wall_seconds=time.monotonic() - started)
    except BaseException as error:
        outcome["error"] = repr(error); raise
    finally:
        try:
            outcome["direct_children_missing_terminal"] = r.scheduler.cleanup(stages)
        except BaseException as error:
            outcome["cleanup_error"] = repr(error); raise
        finally:
            outcome["wall_seconds"] = time.monotonic() - started; r.write(d / "attempt.json", outcome)
    r.require(not outcome["direct_children_missing_terminal"], "unobserved native child terminal")
    print(r.json.dumps(outcome))


def report(out):
    ids = r.identity(); p = policy(); original_policy = r.check_inputs(out / "original")
    source = r.read_json(out / "source-before.json")
    r.require(source == r.read_json(out / "source-after.json")
              and source["candidate"] == source["tested_commit"] == ids["source_sha"]
              and source["tracked_worktree_verified"] is True, "current complete source guard missing")
    r.require(r.digest(out / "prior-window.zip", 128 * 1024**2)
              == {"bytes": p["origin"]["artifact_bytes"], "sha256": p["origin"]["artifact_sha256"]},
              "complete original failed artifact changed")
    prior = inspect_prior(out / "prior")
    phases = {name: r.closed_phase(out, name, ids["source_sha"]) for name in r.PHASE_TIMEOUTS}
    attempt = r.read_json(out / "recursion/attempt.json")
    r.require(attempt["schema"] == "pon-w1-succinct-resume-attempt-v1"
              and attempt["source_sha"] == ids["source_sha"] and attempt["outcome"] == "complete"
              and attempt["real_succinct_stark_verified"] is True and not attempt["direct_children_missing_terminal"]
              and attempt["origin"] == p["origin"] and attempt["budgets"] == original_policy["budgets"]
              and attempt["reused"] == sorted(prior["stages"])
              and sorted(attempt["reverified"]) == attempt["reused"]
              and len(attempt["completed"]) == len(set(attempt["completed"])) == 11
              and set(attempt["completed"]).isdisjoint(attempt["reused"])
              and set(attempt["completed"] + attempt["reused"]) == set(BY_NAME)
              and type(attempt["work_finished_wall_seconds"]) in (int, float)
              and 0 <= attempt["work_finished_wall_seconds"] < 3500,
              "complete independent continuation missing")
    r.require(attempt["helper"] == r.digest(out / "native/trnm-w1-succinct-research", 64 * 1024**2),
              "current native helper changed")
    settled = r.read_json(out / "recursion-after-cleanup.json")
    r.require(settled["complete"] is True and settled["owned_family_closed"] is True
              and settled["attempt"] == attempt and settled["outer_phase"] == phases["compress"]
              and not settled["missing_stage_terminals"] and settled["new_work_started"] is False,
              "continuation family not settled")
    step_names = ["prepare", "finish"] + ["recheck-" + name for name in attempt["reused"]] + attempt["completed"]
    files = {f"recursion/steps/{name}.{suffix}" for name in step_names
             for suffix in ("started.json", "terminal.json", "stdout.log", "stderr.log")}
    files |= {f'recursion/receipts/range-{t["start"]}-{t["end"]}.bin' for t in TASKS}
    r.require(set(settled["retained_files"]) == files and len(settled["known_stage_terminals"]) == 125,
              "current checkpoint coverage differs")
    for relative, expected in settled["retained_files"].items():
        r.require(r.digest(out / relative, 16 * 1024**2) == expected, "current settled bytes changed")
    current_stages = {}
    for name in step_names:
        process = r.read_json(out / f"recursion/steps/{name}.terminal.json")
        r.terminal(process, ids["source_sha"])
        current_stages[name] = {"process": process}
        if name in ("prepare", "finish"):
            continue
        reused = name.startswith("recheck-"); task_name = name[8:] if reused else name; task = BY_NAME[task_name]
        schema = "pon-w1-succinct-retained-range-v1" if reused else "pon-w1-succinct-stage-v1"
        row = r.read_single_result(out / f"recursion/steps/{name}.stdout.log", schema)
        if reused:
            retained_result(row, task, prior["stages"][task_name]["native"])
        else:
            stage_result(row, task)
        r.require(r.digest(out / f'recursion/receipts/range-{task["start"]}-{task["end"]}.bin', 2 * 1024**2)
                  == {"bytes": row["receipt_bytes"], "sha256": row["receipt_sha256"]}, "current receipt changed")
        current_stages[name]["native"] = row
    terminal_map = {row["name"]: row for row in settled["known_stage_terminals"]}
    r.require(len(terminal_map) == len(step_names) and set(terminal_map) == set(step_names)
              and all(terminal_map[name] == row["process"] for name, row in current_stages.items()),
              "settled current terminal records differ")
    prepared = r.read_single_result(out / "recursion/steps/prepare.stdout.log", "pon-w1-succinct-prepare-v1")
    r.require(prepared == r.read_json(out / "recursion/prepared.json")
              and prepared["original_composite_verified"] is True and prepared["native_full_w1_matches"] is True
              and prepared["image_id"] == original_policy["image_id"]
              and prepared["claim_digest"] == original_policy["claim_digest"]
              and prepared["input_sha256"] == original_policy["input_files"]["input.bin"]["sha256"]
              and prepared["original_sha256"] == original_policy["input_files"]["receipt.bin"]["sha256"]
              and prepared["new_proof_generated"] is False and prepared["additional_pow"] is False
              and prepared["povw_requested"] is False and prepared["consensus_authority"] is False,
              "actual full original native preparation changed")
    finished = r.read_single_result(out / "recursion/steps/finish.stdout.log", "pon-w1-succinct-finish-v1")
    expected = {"bytes": finished["receipt_bytes"], "sha256": finished["receipt_sha256"]}
    r.require(finished == attempt["finish"] and finished["real_succinct_stark_verified"] is True
              and r.digest(out / "succinct.bin", 2 * 1024**2) == expected
              and r.digest(out / "certificate.bin", 3 * 1024**2)
              == {"bytes": finished["certificate_wire_bytes"], "sha256": finished["certificate_wire_sha256"]},
              "complete proof/certificate changed")
    receipt = r.frozen.checked_bytes(out / "succinct.bin", 2 * 1024**2)
    input_bytes = r.frozen.checked_bytes(out / "original/input.bin", 49640)
    r.require(r.frozen.checked_bytes(out / "certificate.bin", 3 * 1024**2)
              == b"PWSR0001" + len(input_bytes).to_bytes(4, "little") + len(receipt).to_bytes(4, "little")
              + input_bytes + receipt, "certificate input and proof binding changed")
    verified = r.read_single_result(out / "verify.stdout.log", "pon-w1-succinct-verify-v1")
    benchmark = r.read_single_result(out / "benchmark.stdout.log", "pon-w1-succinct-benchmark-v1")
    r.require(all(v["real_succinct_stark_verified"] is True and v["receipt_bytes"] == expected["bytes"]
                  and v["receipt_sha256"] == expected["sha256"] for v in (verified, benchmark)), "native complete verifier missing")
    samples = benchmark["samples"]; r.require(len(samples) == 31, "original verification sample count")
    for sample in samples:
        r.require(set(sample) == {"verify_wall_ns", "verify_process_cpu_ns"}, "verifier cost columns differ")
        r.nanosecond_costs(sample, "verify_wall_ns", "verify_process_cpu_ns")
    audit = r.read_single_result(out / "audit.stdout.log", "pon-w1-succinct-audit-v1")
    cases = r.checked_audit(audit)
    material = r.check_loopback_anchor(out, phases["loopback"])
    loop_settled = r.read_json(out / "loopback-after-cleanup.json")
    r.require(loop_settled["complete"] is True and loop_settled["new_work_started"] is False
              and loop_settled["outer_phase"] == phases["loopback"]
              and loop_settled["known_files"] == material["files"]
              and loop_settled["output_material"] == r.digest(out / "loopback-output-material.json"),
              "full transport material not settled")
    loop = r.check_loopback(out)
    baseline = r.read_single_result(out / "original-verify.stdout.log", "pon-w1-risc0-research-v1", "verify")
    r.require(baseline["real_composite_stark_verified"] is True and baseline["receipt_bytes"] == 15862780,
              "same-host original verification missing")
    exclusive = list(phases.values()) + list(prior["exclusive_outer_phases"].values())
    median = statistics.median(s["verify_wall_ns"] for s in samples)
    value = {"schema": "pon-w1-succinct-continuation-costs-v1", **ids, "source": source, "complete": True,
        "origin": p["origin"], "original_failure_retained": True, "retained_stage_count": 112, "new_stage_count": 11,
        "complete_recursion_stages": 123, "retained_stages_reverified": 112, "original_window": prior,
        "current_stage_costs": current_stages, "exclusive_current_outer_phases": phases,
        "both_window_phase_cpu_seconds": sum(v["user_cpu_seconds"] + v["system_cpu_seconds"] for v in exclusive),
        "both_window_phase_wall_seconds_sum": sum(v["wall_seconds"] for v in exclusive),
        "cpu_accounting": "exclusive outer phase totals only, including the original failed window; never add included stage costs",
        "phase_cost_exclusions": ["original Composite generation; retained separately in the original artifact",
            "GitHub checkout and runner provisioning", "source/preflight/finalization readers, report writing and artifact upload"],
        "from_zero_generation_measured": False, "finish": finished, "verification": verified, "benchmark": benchmark,
        "verify_median_wall_ns": median, "same_host_original_verification": baseline,
        "original_verify_over_succinct_median": baseline["verify_wall_ns"] / median if median else None,
        "maximum_tested_rejection": max(cases, key=lambda v: v["wall_ns"]), "global_worst_invalid_proven": False,
        "audit": audit, "loopback": loop, "existing_packet_codec_accepts_succinct": False,
        "additional_pow": False, "povw_requested": False, "groth16_used": False, "pq128_qualified": False,
        "consensus_authority": False}
    r.write(out / "costs.json", value)
    print(r.json.dumps({"schema": value["schema"], "complete": True, "receipt": expected,
                       "verify_median_wall_ns": median, "original_failed_window_retained": True,
                       "consensus_authority": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "prove", "report"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--helper", type=Path); parser.add_argument("--r0vm", type=Path)
    args = parser.parse_args(); policy()
    if args.command == "fetch":
        fetch(args.out)
    elif args.command == "prove":
        prove(args)
    else:
        report(args.out)


if __name__ == "__main__":
    main()
