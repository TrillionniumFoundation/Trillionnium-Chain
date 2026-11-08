#!/usr/bin/env python3
"""Check original research records and replay the unchanged Chain reader.

This verifier does not execute a model, authenticate an independent operator,
or turn the original reader's denied production qualifications into grants.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "scripts"))
import capture_cell_learning_completion as capture
import cell_learning_completion_join as completion
import cell_learning_iteration_join as iteration

MANIFEST_SHA256 = "28523b53429d8094760ff67206e95139ae4b868dee1ed9ae80b923882027f351"
SOURCE = "27849cbdcfc0d4afc69764d6c1742af22c41c293"
TREE = "af50e58bf382891fb41861810cbf5425ca0da5a9"


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(name):
    return json.loads((ROOT / name).read_bytes())


def checkpoint(run, count):
    owner = read(f"{run}/evidence/native-checkpoint-{count}-owner.json")
    encoded = owner["snapshot"]
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    snapshot, replay = iteration.decode_native_learning_checkpoint(raw)
    require(owner["binding"] == replay["initial_head"], "original owner binding")
    return raw, snapshot, replay


def tensor_output(row, originals):
    record = row["artifact"]
    path = originals[record["path"]]
    raw = path.read_bytes()
    require(sha(raw) == row["output_sha256"] == record["sha256"], "output identity")
    size = struct.unpack("<Q", raw[:8])[0]
    header, data = json.loads(raw[8:8 + size]), raw[8 + size:]
    item = header["next_token_logits"]
    require(item["dtype"] == "F32" and item["shape"] == [1, 49152], "full vocabulary")
    left, right = item["data_offsets"]
    require(sha(data[left:right]) == row["logits_sha256"], "full logit bytes")
    left, right = header["scores_q32"]["data_offsets"]
    scores = list(struct.unpack("<2q", data[left:right]))
    require(scores == row["scores_q32"], "original Q32 scores")
    left, right = header["raw_action_logits"]["data_offsets"]
    require([round(x * (1 << 32)) for x in struct.unpack("<2f", data[left:right])] == scores,
            "Q32 scores are not derived from original action logits")
    require(row["predicted_output"] == ["yes", "no"][int(scores[1] > scores[0])],
            "answer does not follow original logits")


def join(run):
    initial, frozen_snapshot, frozen_replay = checkpoint(run, 0)
    selection, _, _ = checkpoint(run, 5)
    terminal, _, _ = checkpoint(run, 6)
    require(not frozen_snapshot["receipts"], "freeze must be actual initial checkpoint")
    frozen = dict(schema=iteration.FREEZE_SCHEMA, initial_head=frozen_replay["initial_head"],
                  request=frozen_snapshot["request"], owners=frozen_snapshot["owners"])
    raw = (ROOT / run / "evidence/next-use-acked.json").read_bytes()
    expected = capture.fixture_expectations(raw)
    review = completion.review_native_learning_completion(
        selection, terminal, raw, expected_selection_sha256=sha(selection),
        expected_completed_sha256=sha(terminal), expected_readback_sha256=sha(raw),
        frozen=frozen, expected=expected)
    require(review["native_receipt_chain_complete"] and review["original_receipt_prefix_preserved"]
            and review["acknowledged_use_observed"] and review["model_stop_observed"]
            and review["no_update"] and review["receipt_count"] == 6, "incomplete original join")
    require(not review["native_origin_authenticated"] and not review["real_model_training_verified"]
            and not review["full_learning_iteration_completed"]
            and review["qualification"] == "HOLD_NO_GO", "reader authority changed")
    return review, frozen, dict(initial=initial, selection=selection, completed=terminal,
                               readback=raw, expected=capture.json_bytes(expected))


def main():
    require(sha((ROOT / "export-manifest.json").read_bytes()) == MANIFEST_SHA256,
            "original export manifest changed")
    manifest = read("export-manifest.json")
    originals = {}
    for item in manifest["files"]:
        relative = Path(item["path"])
        require(not relative.is_absolute() and ".." not in relative.parts, "path escape")
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), "missing original")
        raw = path.read_bytes()
        require(len(raw) == item["bytes"] and sha(raw) == item["sha256"], "changed original " + str(relative))
        originals[item["original"]] = path
    require(len(originals) == 517 and manifest["private_source_exported"] is False, "export scope")

    failures = {
        "v4": "InvalidGrant", "v5": "expected Starting generation 5",
        "v6": "generation service predecessor is not retired",
        "v7": "prompt pipeline durable owners failed to open: RegistryOpen",
    }
    for run in ("v3", "v4", "v5", "v6", "v7"):
        result = read(run + "/execution-result.json")
        require(result["result"] == "FAIL", "original failure was hidden")
        if run == "v3":
            require(not result["model_test_started"], "packaging failure was promoted")
            continue
        require(result["exit_code"] == 100 and result["model_test_started"], "native refusal missing")
        log = (ROOT / run / "test.log").read_text()
        require(failures[run] in log, "wrong original native refusal " + run)
        current = read(run + "/owner-originals/current.json")
        claims = (ROOT / run / "owner-originals/final-use/authority.claims").stat().st_size
        require((current["prepared"] is not None) == (run == "v4"), "preparation boundary")
        require((current["published"] is not None) == (run != "v4"), "publication boundary")
        require(claims == (0 if run == "v4" else 40), "nonce claim boundary")

    result = read("v8/execution-result.json")
    require(result["result"] == "PASS_ACTUAL_NATIVE_MODEL_ITERATION" and result["exit_code"] == 0,
            "original native test did not pass")
    require(result["source"] == SOURCE and result["tree"] == TREE
            and result["tracked_before"] == result["tracked_after"] == 11207, "exact source identity")
    junit = ROOT / "v8/original-junit.xml"
    require(sha(junit.read_bytes()) == result["junit_sha256"], "JUnit pin")
    cases = ET.parse(junit).findall(".//testcase")
    require(len(cases) == 1 and all(cases[0].find(k) is None for k in ("failure", "error", "skipped")),
            "original JUnit refusal")
    admission = read("v8/test-admission.json")
    require(admission["original_watchdog_seconds"] == 60 and admission["automatic_retries"] == 0,
            "watchdog or retries changed")
    runtime = read("v8/compiled-runtime.json")
    require(runtime["archive"]["source"] == SOURCE and runtime["archive"]["tree"] == TREE,
            "archive source identity")
    require(runtime["archive"]["files"]["agentd-nextest.tar.zst"]["sha256"]
            == admission["archive_sha256"], "archive pin")
    require(len(runtime["binaries"]) == 1 and runtime["binaries"][0]["ldd_exit"] == 0
            and "not found" not in runtime["binaries"][0]["ldd_stdout"], "runtime dynamic dependency")

    frozen = read("v8/model/frozen.json")
    before = read("v8/evidence/native-before-training.json")
    train = read("v8/model/train-result.json")
    receipt = read("v8/model/training/worker/actual-receipt.json")
    evaluation = read("v8/model/evaluate-result.json")
    native_admission = read("v8/model/native-training-admission.json")
    require(frozen["created_unix_ns"] < before["created_unix_seconds"] * 1_000_000_000,
            "profile was not frozen before native coordinator")
    require(before["frozen_plan_sha256"] == evaluation["frozen_sha256"]
            == native_admission["frozen_sha256"] == sha((ROOT / "v8/model/frozen.json").read_bytes()),
            "freeze identity drift")
    require(before["initial_learning_head"] == native_admission["initial_learning_head"],
            "training did not bind initial native coordinator")
    require(before["absolute_deadline_unix_seconds"] == frozen["deadline_unix_seconds"]
            == native_admission["deadline_unix_seconds"], "absolute deadline drift")
    require(frozen["prior_tasks_and_outcomes_exposed"] and frozen["independent_evaluation"] is False,
            "public fixture was relabeled independent")
    require(receipt["operation_id"] == frozen["operation"] + "-train"
            and receipt["outcome"] == "success" and receipt["parameter_change"] is True,
            "actual fresh training identity")
    require(receipt["training"]["steps"] == train["steps"] == frozen["steps"] == 10
            and train["milliseconds"] <= frozen["maximum_training_seconds"] * 1000,
            "actual training resource bound")
    require(receipt["actual_loaded_parent"] == frozen["parent"]["adapter"] == train["actual_loaded_parent"],
            "training loaded another parent")
    require(receipt["artifact"] == train["candidate"]["adapter"] == evaluation["candidate"]["adapter"],
            "candidate training/evaluation identity")
    require(sha((ROOT / "v8/model/training/worker/artifact.safetensors").read_bytes())
            == train["candidate"]["file_sha256"] == evaluation["candidate"]["file_sha256"],
            "actual candidate checkpoint bytes")
    require(all(v is False for v in receipt["authority"].values()), "trainer authority expanded")
    correct = []
    for item in evaluation["evaluations"]:
        require(len(item["rows"]) == len(frozen["evaluation"]) == 4, "evaluation roster")
        score = 0
        for row, task in zip(item["rows"], frozen["evaluation"]):
            require(row["expected_output"] == task["expected_output"]
                    and row["request_id"] == task["request_id"]
                    and row["prompt_sha256"] == sha(task["prompt"].encode()), "frozen evaluation drift")
            score += row["predicted_output"] == row["expected_output"]
            tensor_output(row, originals)
        require(score == item["correct"], "evaluation score drift")
        correct.append(score)
    require(correct == [3, 1] and evaluation["disposition"] == "NoUpdate"
            and evaluation["selected_adapter"] == frozen["parent"]["adapter"], "regression was adopted")

    hot = read("v8/model/probe-18cbfb249570f999d2b8-result.json")
    cold = read("v8/model/probe_recover-18cbfb249570f999d2b8-result.json")
    require(hot["worker_pid"] == cold["previous_worker_pid"] != cold["worker_pid"], "same worker process")
    require(hot["observation"] == cold["observation"]
            and hot["original_response_sha256"] == cold["original_response_sha256"], "cold replay drift")
    for phase, expected in (("hot", (0, 1, 1)), ("cold", (1, 1, 0))):
        count = read(f"v8/model/probe-18cbfb249570f999d2b8-{phase}-counters.json")
        require((count["before"]["forward_examples"], count["after"]["forward_examples"], count["delta"])
                == expected, "fresh worker ledger counter")
        for side in ("before", "after"):
            require(count[side]["forward_examples"]
                    == count[side]["original_response"]["result"]["cost"]["forward_examples_total"],
                    "counter not derived from original worker reply")
    controls = read("v8/model/probe-18cbfb249570f999d2b8-recovery-controls.json")
    require(controls["conflict"]["error"]["code"] == "IDEMPOTENCY_CONFLICT"
            and controls["exhausted"]["error"]["code"] == "FORWARD_BUDGET"
            and controls["final_counter"]["forward_examples"] == 1, "original recovery controls")
    tensor_output(hot["observation"], originals)
    require(hot["selected_adapter"] == evaluation["selected_adapter"]
            and hot["selected_file_sha256"] == frozen["parent"]["file_sha256"], "retained next-task material")
    native = read("v8/evidence/native-result.json")
    owner = read("v8/evidence/next-use-cold-owner.json")
    require(native["generation_owner_reopened"] and native["learning_owner_reopened"]
            and native["native_fleet_lifecycle_recreated"] and native["worker_process_restarted"]
            and not native["native_daemon_os_restart"] and not native["reexecuted_after_recovery"],
            "cold owner scope")
    require(owner["native_nonce_count"] == 1 and owner["readback"] == read("v8/evidence/next-use-acked.json"),
            "native cold readback/nonce drift")
    reviews = {run: join(run)[0] for run in ("v7", "v8")}
    require(reviews["v8"]["completed_checkpoint_sha256"] == native["checkpoint_sha256"],
            "original native completion and reader differ")
    for name in ("independent_operator_custody", "production_activation", "production_final_use",
                 "production_root_capability"):
        require(native[name] is False, "research qualification expanded")
    output = dict(schema="hepta-real-native-original-record-review-v1",
                  result="PASS_ORIGINAL_RESEARCH_RECORDS", original_files=len(originals),
                  successful_native_source=SOURCE, successful_native_tree=TREE,
                  native_test_seconds=float(cases[0].get("time")), actual_optimizer_steps=10,
                  parent_correct=3, candidate_correct=1, disposition="NoUpdate",
                  real_new_candidate_adoption=False, cold_worker_pids=[hot["worker_pid"], cold["worker_pid"]],
                  forward_count_kind="source-bound-live-worker-ledger-delta-inference",
                  original_watchdog_seconds=60, automatic_retries=0,
                  unchanged_chain_reader_join_pass=["v7-hot-completion", "v8-complete-recovery"],
                  original_failed_operations_retained=["v3", "v4", "v5", "v6", "v7"],
                  native_daemon_os_restart=False, production_activation=False,
                  independent_operator_custody=False, qualification="HOLD_NO_GO")
    print(json.dumps(output, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
