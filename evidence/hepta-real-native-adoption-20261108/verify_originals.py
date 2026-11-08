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

MANIFEST_SHA256 = "09c7a6079af9497835062815b2a421b385969ad665139f1454cad25bb35be628"
SOURCE = "edf03ecb8a814a0f5e86b1d6a752aeac80b1a978"
TREE = "c7588a07d20310059d4016559fa550d397b7eb09"


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


def join(run, adopted):
    count = 7 if adopted else 6
    initial, frozen_snapshot, frozen_replay = checkpoint(run, 0)
    selection, _, _ = checkpoint(run, count - 1)
    terminal, _, _ = checkpoint(run, count)
    require(not frozen_snapshot["receipts"], "initial checkpoint is not empty")
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
            and review["no_update"] is (not adopted) and review["receipt_count"] == count,
            "original checkpoint continuation failed")
    for name in ("native_origin_authenticated", "real_model_training_verified",
                 "full_learning_iteration_completed", "production_activation",
                 "learning_signatures_verified", "pre_dispatch_freeze_authenticated",
                 "settlement_verified", "independent_control_accepted"):
        require(review[name] is False, "reader authority expanded: " + name)
    require(review["qualification"] == "HOLD_NO_GO", "reader qualification changed")
    require(review == read(f"chain-reader/{run}/stdout.json"), "original CLI result differs")
    for name, content in dict(initial=initial, selection=selection, completed=terminal).items():
        require((ROOT / "chain-reader" / run / (name + ".bin")).read_bytes() == content,
                "original CAS bytes differ: " + name)
    require((ROOT / "chain-reader" / run / "readback.json").read_bytes() == raw,
            "original acknowledged readback differs")
    return review


def verify_run(run, adopted, originals):
    result = read(run + "/execution-result.json")
    require(result["result"] == "PASS_ACTUAL_NATIVE_MODEL_ITERATION" and result["exit_code"] == 0,
            "original model execution failed")
    require(result["source"] == SOURCE and result["tree"] == TREE
            and result["tracked_before"] == result["tracked_after"] == 11212, "tested source drift")
    junit = ROOT / run / "original-junit.xml"
    require(sha(junit.read_bytes()) == result["junit_sha256"], "JUnit hash")
    cases = ET.parse(junit).findall(".//testcase")
    require(len(cases) == 1 and all(cases[0].find(k) is None for k in ("failure", "error", "skipped")),
            "original test did not pass")
    admission = read(run + "/test-admission.json")
    require(admission["original_watchdog_seconds"] == 60 and admission["automatic_retries"] == 0
            and float(cases[0].get("time")) < 60, "original execution budget changed")
    runtime = read(run + "/compiled-runtime.json")
    require(runtime["archive"]["source"] == SOURCE and runtime["archive"]["tree"] == TREE
            and runtime["archive"]["files"]["agentd-nextest.tar.zst"]["sha256"]
            == admission["archive_sha256"]
            == "e3c169dac89c0330efe52ca8b2581b9d7bff64f368e9749051977370b2591b56", "archive identity")
    require(len(runtime["binaries"]) == 1 and runtime["binaries"][0]["ldd_exit"] == 0
            and "not found" not in runtime["binaries"][0]["ldd_stdout"], "dynamic dependency")
    frozen = read(run + "/model/frozen.json")
    before = read(run + "/evidence/native-before-training.json")
    train = read(run + "/model/train-result.json")
    start = read(run + "/model/training-start.json")
    command = read(run + "/model/training-command.json")
    receipt = read(run + "/model/training/worker/actual-receipt.json")
    evaluation = read(run + "/model/evaluate-result.json")
    native_admission = read(run + "/model/native-training-admission.json")
    frozen_hash = sha((ROOT / run / "model/frozen.json").read_bytes())
    require(before["frozen_plan_sha256"] == evaluation["frozen_sha256"]
            == native_admission["frozen_sha256"] == start["frozen_sha256"] == frozen_hash,
            "frozen profile identity")
    require(before["initial_learning_head"] == native_admission["initial_learning_head"],
            "training admission did not bind native coordinator")
    require(frozen["created_unix_ns"] <= before["created_unix_ns"] <= start["started_unix_ns"]
            == command["started_unix_ns"] < command["completed_unix_ns"]
            < frozen["deadline_unix_seconds"] * 1_000_000_000, "real freeze/training time order")
    require(frozen["prior_tasks_and_outcomes_exposed"] and frozen["independent_evaluation"] is False,
            "exposed research fixture became independent")
    require(command["returncode"] == 0 and receipt["outcome"] == "success"
            and receipt["operation_id"] == frozen["operation"] + "-train"
            and receipt["parameter_change"] is True, "actual fresh training")
    require(receipt["training"]["steps"] == train["steps"] == frozen["steps"] == 10
            and train["milliseconds"] <= frozen["maximum_training_seconds"] * 1000,
            "training budget")
    require(receipt["actual_loaded_parent"] == frozen["parent"]["adapter"] == train["actual_loaded_parent"]
            and receipt["artifact"] == train["candidate"]["adapter"] == evaluation["candidate"]["adapter"],
            "training/evaluation lineage")
    candidate = train["candidate"]
    require(sha((ROOT / run / "model/training/worker/artifact.safetensors").read_bytes())
            == candidate["file_sha256"] != frozen["parent"]["file_sha256"], "candidate bytes")
    require(all(v is False for v in receipt["authority"].values()), "trainer authority expanded")
    scores = []
    answers = []
    for item in evaluation["evaluations"]:
        require(len(item["rows"]) == len(frozen["evaluation"]) == 4, "evaluation roster")
        score = 0
        for row, task in zip(item["rows"], frozen["evaluation"]):
            require(row["expected_output"] == task["expected_output"]
                    and row["request_id"] == task["request_id"]
                    and row["prompt_sha256"] == sha(task["prompt"].encode()), "frozen task drift")
            score += row["predicted_output"] == row["expected_output"]
            tensor_output(row, originals)
        require(score == item["correct"], "evaluation score drift")
        scores.append(score)
        answers.append([row["predicted_output"] for row in item["rows"]])
    require(scores == ([1, 2] if adopted else [3, 1]), "actual local scores changed")
    require(evaluation["disposition"] == ("Qualified" if adopted else "NoUpdate"), "decision rule")
    selected = candidate if adopted else frozen["parent"]
    require(evaluation["selected_adapter"] == selected["adapter"], "selected adapter")
    cold_files = list((ROOT / run / "model").glob("probe_recover-*-result.json"))
    require(len(cold_files) == 1, "cold result roster")
    cold_path = cold_files[0]
    hot_path = cold_path.with_name(cold_path.name.replace("probe_recover-", "probe-"))
    cold, hot = json.loads(cold_path.read_bytes()), json.loads(hot_path.read_bytes())
    require(hot["worker_pid"] == cold["previous_worker_pid"] != cold["worker_pid"], "distinct worker PIDs")
    require(hot["observation"] == cold["observation"]
            and hot["original_response_sha256"] == cold["original_response_sha256"], "cold output drift")
    for phase, expected in (("hot", (0, 1, 1)), ("cold", (1, 1, 0))):
        count = json.loads(hot_path.with_name(hot_path.name.replace("-result.json", f"-{phase}-counters.json")).read_bytes())
        require((count["before"]["forward_examples"], count["after"]["forward_examples"], count["delta"])
                == expected, "fresh original worker ledger counter")
        for side in ("before", "after"):
            require(count[side]["forward_examples"]
                    == count[side]["original_response"]["result"]["cost"]["forward_examples_total"],
                    "counter must come from original reply")
    controls = json.loads(hot_path.with_name(hot_path.name.replace("-result.json", "-recovery-controls.json")).read_bytes())
    require(controls["conflict"]["error"]["code"] == "IDEMPOTENCY_CONFLICT"
            and controls["exhausted"]["error"]["code"] == "FORWARD_BUDGET"
            and controls["final_counter"]["forward_examples"] == 1, "replay controls")
    tensor_output(hot["observation"], originals)
    require(hot["selected_adapter"] == cold["selected_adapter"] == selected["adapter"]
            and hot["selected_file_sha256"] == cold["selected_file_sha256"] == selected["file_sha256"],
            "actual hot/cold selected checkpoint")
    native = read(run + "/evidence/native-result.json")
    require(native["real_new_candidate_adoption"] is adopted
            and native["native_proposal_update_candidates"] is adopted, "actual branch qualification")
    require(native["generation_owner_reopened"] and native["learning_owner_reopened"]
            and native["native_fleet_lifecycle_recreated"] and native["worker_process_restarted"]
            and not native["native_daemon_os_restart"] and not native["reexecuted_after_recovery"], "cold scope")
    owner = read(run + "/evidence/next-use-cold-owner.json")
    require(owner["native_nonce_count"] == 1 and owner["readback"] == read(run + "/evidence/next-use-acked.json"),
            "native cold readback or nonce")
    current = read(run + "/owner-originals/current.json")
    require(current["prepared"] is None and current["published"] is not None
            and (ROOT / run / "owner-originals/final-use/authority.claims").stat().st_size == 40,
            "original isolated CURRENT/nonce")
    review = join(run, adopted)
    require(review["completed_checkpoint_sha256"] == native["checkpoint_sha256"], "native terminal mismatch")
    for name in ("original_parameter_v3_qualified", "product_ope_qualified", "independent_operator_custody",
                 "production_activation", "production_final_use", "production_root_capability"):
        require(native[name] is False, "research qualification expanded")
    if adopted:
        bootstrap = read(run + "/evidence/external-artifact-owner/bootstrap.json")
        require(frozen["created_unix_ns"] <= bootstrap["created_unix_ns"] <= before["created_unix_ns"],
                "research owner was created after training")
        proposal = read(run + "/evidence/external-artifact-owner/receipt.json")
        anchor = read(run + "/evidence/external-artifact-owner-anchor/receipt.json")
        require(anchor["receipt_sha256"] == sha((ROOT / run / "evidence/external-artifact-owner/receipt.json").read_bytes())
                and anchor["reservation_sha256"] == sha((ROOT / run / "evidence/external-artifact-owner/reservation.json").read_bytes())
                and proposal["material"]["candidate_file_sha256"] == selected["file_sha256"], "proposal anchor/material")
        require(proposal["parameter_v3_qualified"] is False and proposal["product_ope_qualified"] is False
                and proposal["production_qualified"] is False, "new owner namespace changed")
        for rel, count in (("external-material-rejections.json", 2),
                           ("external-proposal-context-rejections.json", 7),
                           ("external-owner-cold-rejections.json", 8)):
            rejection = read(run + "/evidence/" + rel)
            require(len(rejection["results"]) == count and all(row["rejected"] for row in rejection["results"]),
                    "original negative controls missing")
        faults = read(run + "/evidence/external-material-rejections.json")
        require(faults["selection_current_checkpoint_nonce_and_proposal_store_unchanged"]
                and faults["snapshot_and_prepared_payload_unchanged"]
                and all(row["original_bytes_restored"] and row["fresh_prepare_after_restore_succeeded"]
                        for row in faults["results"]), "real material rejection advanced owner")
        require(answers[1] == ["no"] * 4 and hot["observation"]["predicted_output"] == "no"
                and frozen["next_prompt"] == "Answer with only yes or no. Is 8517 greater than 8516?",
                "record the limited candidate and incorrect next answer honestly")
    return dict(operation=frozen["operation"], native_test_seconds=float(cases[0].get("time")),
                scores=scores, predicted_answers=answers, real_new_candidate_adoption=adopted,
                original_checkpoint_counts=[0, 6, 7] if adopted else [0, 5, 6],
                selected_file_sha256=selected["file_sha256"],
                next_task_answer=hot["observation"]["predicted_output"],
                next_task_answer_correct=hot["observation"]["predicted_output"] == "yes",
                worker_pids=[hot["worker_pid"], cold["worker_pid"]],
                unchanged_chain_reader_join="PASS", checkpoint_sha256=native["checkpoint_sha256"])


def main():
    require(sha((ROOT / "export-manifest.json").read_bytes()) == MANIFEST_SHA256, "original manifest changed")
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
    require(len(originals) == 417 and manifest["private_source_exported"] is False
            and manifest["full_base_weights_exported"] is False, "public export scope")
    runs = [verify_run("no-update-v9", False, originals), verify_run("adopt-v1", True, originals)]
    print(json.dumps(dict(schema="hepta-real-native-adoption-record-review-v1",
                          result="PASS_ORIGINAL_RESEARCH_RECORDS", original_files=len(originals),
                          successful_native_source=SOURCE, successful_native_tree=TREE, runs=runs,
                          original_watchdog_seconds=60, automatic_retries=0,
                          forward_count_kind="source-bound-live-worker-ledger-delta-inference",
                          native_daemon_os_restart=False, original_parameter_v3_qualified=False,
                          product_ope_qualified=False, general_model_quality_qualified=False,
                          production_activation=False, independent_operator_custody=False,
                          qualification="HOLD_NO_GO"), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
