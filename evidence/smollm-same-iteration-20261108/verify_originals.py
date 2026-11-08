#!/usr/bin/env python3
"""Replay byte and identity checks over original, bounded research observations.

This does not rerun a model, authenticate a remote operator or grant adoption.
The four-row quality regression and all production denials remain visible.
"""
import hashlib
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parent
MANIFESTS = {
    "initial": "95c98b2cb99ee35c14ad92423dfd42d8d775528a71663a3727257389df4f2ea7",
    "no-update": "8dd662be666bc29d59933d47a44b83eb220900c9a65c2ca5548acca3d75d9240",
    "cell-transfer": "bf5dadd599c036f847c5d7027b7571a30c6c723cc0b7323a0b8d157580978514",
}
RUNNERS = {
    "run_model_iteration.py": "f77d6af6f677e53019499bf141b6b7389ee375e9d6857d32133ca96ac9cee155",
    "run_model_readback.py": "185e747bb90e4c793ea9c2bc0ce8606f88780d7154873e153a902f4da4e2ee4e",
    "run_model_no_update.py": "d972f6a6e55dc4de725d8258aa6fb2555111897e237ebca83015a266b0448f4b",
    "run_cell_model_transfer.py": "e32051d4112b9ea4adb95268ac4f174de18123b48c0ba87dc2c1a63d462277b4",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(name):
    return json.loads((ROOT / name).read_bytes())


def transcript(name, request_id):
    return [row["message"] for line in (ROOT / name).read_text().splitlines()
            if (row := json.loads(line))["direction"] == "receive"
            and row["message"]["id"] == request_id]


def tensor_bytes(path):
    raw = path.read_bytes()
    require(len(raw) >= 8, "short tensor file")
    length = struct.unpack("<Q", raw[:8])[0]
    require(0 < length < len(raw) - 8, "tensor header bound")
    header = json.loads(raw[8:8 + length])
    payload = raw[8 + length:]
    for name, entry in header.items():
        if name == "__metadata__":
            continue
        left, right = entry["data_offsets"]
        require(0 <= left <= right <= len(payload), "tensor offsets")
    return header, payload


def verify_output(name, observed):
    path = ROOT / name
    require(sha(path) == observed["output_sha256"], "original output file pin")
    header, payload = tensor_bytes(path)
    logits = header["next_token_logits"]
    require(logits["dtype"] == "F32" and logits["shape"] == [1, 49152],
            "full original vocabulary output")
    left, right = logits["data_offsets"]
    require(hashlib.sha256(payload[left:right]).hexdigest() == observed["logits_sha256"],
            "full vocabulary logit pin")
    left, right = header["scores_q32"]["data_offsets"]
    scores = list(struct.unpack("<2q", payload[left:right]))
    require(scores == observed["scores_q32"], "original Q32 score bytes")
    left, right = header["raw_action_logits"]["data_offsets"]
    actual = struct.unpack("<2f", payload[left:right])
    require([round(value * (1 << 32)) for value in actual] == scores,
            "raw action logits do not reproduce Q32 scores")
    require(observed["predicted_output"] == ["yes", "no"][int(scores[1] > scores[0])],
            "prediction does not follow original score order")


def main():
    originals = {}
    counts = {}
    for scope, expected in MANIFESTS.items():
        manifest = ROOT / scope / "artifact-manifest.json"
        require(sha(manifest) == expected, "changed original export manifest: " + scope)
        files = json.loads(manifest.read_bytes())["files"]
        for name, record in files.items():
            rel = Path(name)
            require(not rel.is_absolute() and ".." not in rel.parts, "export path escape")
            path = ROOT / scope / rel
            require(path.is_file() and not path.is_symlink(), "missing original file: " + str(path))
            require(path.stat().st_size == record["bytes"] and sha(path) == record["sha256"],
                    "changed original file: " + str(path))
            originals.setdefault(record["source_path"], []).append(path)
        counts[scope] = len(files)
    for name, expected in RUNNERS.items():
        require(sha(ROOT / name) == expected, "changed actual execution runner: " + name)

    def reference(record):
        paths = originals.get(record["path"], [])
        require(paths and all(sha(path) == record["sha256"] for path in paths),
                "unbound original reference: " + record["path"])

    training = read("initial/training/training-result.json")
    plan = read("initial/training/frozen-plan.json")
    require(plan["production_adoption_rule"] == "none-research-load-only", "first run authority changed")
    reference(training["frozen_plan"])
    require(training["optimizer_steps"] == 20 and len(training["stages"]) == 2, "two actual training rounds")
    receipts = []
    parents = []
    for i, stage in enumerate(training["stages"], start=1):
        reference(stage["actual_receipt"])
        reference(stage["parent_material"])
        receipt = read(f"initial/training/generation-{i}/worker/actual-receipt.json")
        parent = read(f"initial/training/generation-{i}/worker/parent-material.json")
        artifact = ROOT / f"initial/training/generation-{i}/worker/artifact.safetensors"
        require(receipt["outcome"] == "success" and receipt["parameter_change"] is True,
                "training did not complete with changed parameters")
        require(receipt["training"]["steps"] == 10 and receipt["artifact"] == parent["adapter"],
                "training and artifact identity differ")
        require(parent["file_sha256"] == sha(artifact), "checkpoint bytes changed")
        require(stage["actual_adapter"] == parent["adapter"], "stage artifact identity")
        require(all(value is False for value in receipt["authority"].values()), "research authority expanded")
        receipts.append(receipt)
        parents.append(parent)
    require(receipts[1]["actual_loaded_parent"] == parents[0]["adapter"], "gen2 did not load gen1")
    require(parents[0]["file_sha256"] != parents[1]["file_sha256"], "two checkpoints are identical")

    readback = read("initial/readback/readback-result.json")
    require(readback["training_result_sha256"] == sha(ROOT / "initial/training/training-result.json"),
            "first readback does not bind original training")
    for observed in readback["evaluations"]:
        require(len(observed["rows"]) == observed["count"] == 4, "incomplete evaluation")
        correct = sum(row["predicted_output"] == row["expected_output"] for row in observed["rows"])
        require(correct == observed["correct"], "changed exact answer count")
    require([row["correct"] for row in readback["evaluations"]] == [3, 1], "regression was hidden")
    verify_output("initial/readback/next-task-output.safetensors", readback["next_use"])
    require(readback["next_use"]["predicted_output"] == "no", "incorrect candidate answer was hidden")
    require(readback["first_worker_pid"] != readback["recovered_worker_pid"], "same first-run PID")

    replay = read("no-update/result.json")
    frozen = read("no-update/frozen-decision-plan.json")
    command = read("no-update/training-command.json")
    decision = read("no-update/decision.json")
    receipt = read("no-update/training/worker/actual-receipt.json")
    for key in ["frozen_plan", "training_receipt", "evaluation", "decision"]:
        reference(replay[key])
    require(frozen["start_unix_ns"] < command["start_unix_ns"] < command["end_unix_ns"]
            <= decision["decided_unix_ns"] < replay["end_unix_ns"], "freeze/training/decision order")
    require(receipt["operation_id"] == replay["operation"] + "-train" and receipt["training"]["steps"] == 10,
            "fresh controlled replay training identity")
    require(receipt["actual_loaded_parent"] == parents[0]["adapter"], "replay parent differs")
    require(receipt["artifact"] == parents[1]["adapter"], "deterministic replay candidate differs")
    require(decision["rule"] == frozen["decision_rule"], "decision rule changed after freeze")
    require(replay["candidate_correct"] == 1 < replay["parent_correct"] == 3,
            "controlled replay regression was hidden")
    require(replay["disposition"] == decision["disposition"] == "NoUpdate", "regression was adopted")
    require(replay["selected_adapter"] == decision["selected_adapter"] == parents[0]["adapter"],
            "NoUpdate did not retain the complete parent")
    require(frozen["prior_outcomes_exposed"] and not frozen["prospective_evaluation"], "replay scope changed")
    verify_output("no-update/retained-next-task-output.safetensors", replay["next_task"])
    hot = transcript("no-update/retained-next-task.jsonl", "next-task")[0]
    cold = transcript("no-update/retained-cold-recovery.jsonl", "next-task")
    require(hot == cold[0] and cold[1]["error"]["code"] == "IDEMPOTENCY_CONFLICT", "cold replay identity")
    controls = read("no-update/recovery-controls.json")
    require(controls["exhausted"]["error"]["code"] == "FORWARD_BUDGET", "cold budget control")
    require(controls["close"]["result"]["forward_examples"] == 1, "persisted forward budget changed")
    require(replay["first_worker_pid"] != replay["recovery_worker_pid"], "same replay PID")

    cell = read("cell-transfer/result.json")
    reference(cell["frozen_plan"])
    require(cell["cell_source"] == "0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a", "Cell source changed")
    require(cell["binary_sha256"] == "f4110b8a9126133303fdee34ed586018ab266433f0ee20d5650c8d6968a54427",
            "Cell executable identity changed")
    require(len(cell["transfers"]) == 3, "incomplete Cell material closure")
    for transfer in cell["transfers"]:
        packed, fetched = transfer["packed"], transfer["fetched"]
        actual = ROOT / "cell-transfer/replica" / transfer["name"]
        require(sha(actual) == packed["payload_sha256"] == fetched["payload_sha256"] == transfer["actual_sha256"],
                "Cell payload changed")
        require(packed["manifest"] == fetched["manifest"], "Cell manifest changed")
        require(packed["bytes"] == fetched["downloaded_bytes"] == actual.stat().st_size, "Cell byte accounting")
        require(fetched["cached_chunks"] == fetched["rejected_responses"] == 0, "Cell transfer controls")
    require(sum(x["fetched"]["downloaded_bytes"] for x in cell["transfers"]) == 1011315, "Cell total bytes")
    require(sum(x["fetched"]["downloaded_chunks"] for x in cell["transfers"]) == 17, "Cell total chunks")
    opened = read("cell-transfer/actual-open.json")["result"]["model"]["identity"]
    require(opened["parent"]["file_sha256"] == parents[0]["file_sha256"], "loaded another transferred model")
    verify_output("cell-transfer/actual-next-task-output.safetensors", cell["actual_model_output"])
    require(read("cell-transfer/actual-response.json") ==
            transcript("cell-transfer/transferred-model-cold-readback.jsonl", "probe")[0], "Cell cold replay differs")
    require(cell["first_worker"]["pid"] != cell["cold_worker"]["pid"], "same Cell cold PID")
    for key in ["full_base_weights_transferred", "independent_operators", "long_term_custody",
                "native_current_binding", "production_activation", "production_final_use", "public_discovery"]:
        require(cell[key] is False, "Cell qualification expanded: " + key)
    for observed in [training, readback, replay, cell]:
        require(observed["production_activation"] is False and observed["qualification"] == "HOLD_NO_GO",
                "research result promoted to production")
    print(json.dumps(dict(schema="trnm-smollm-original-evidence-replay-v1", result="PASS",
                         original_files_verified=counts, actual_runtime_rerun=False,
                         quality_observation="parent-3-of-4-candidate-1-of-4",
                         decision="NoUpdate", new_optimizer_steps_recorded=30,
                         cell_payload_bytes=1011315, cell_chunks=17,
                         independently_authenticated=False, production_activation=False,
                         qualification="HOLD_NO_GO"), sort_keys=True))


if __name__ == "__main__":
    main()
