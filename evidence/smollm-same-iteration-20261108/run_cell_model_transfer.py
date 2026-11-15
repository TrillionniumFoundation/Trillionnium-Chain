#!/usr/bin/env python3
"""Fixed native Cell transport, then actual loading of the retained LoRA.

Finite loopback peers under one operator. This proves transferred bytes can be
loaded by the original model worker; it confers no CURRENT or FinalUse authority.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

BINARY_SHA = "f4110b8a9126133303fdee34ed586018ab266433f0ee20d5650c8d6968a54427"
SOURCE = "0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a"
HELPER_SHA = "185e747bb90e4c793ea9c2bc0ce8606f88780d7154873e153a902f4da4e2ee4e"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "research-root", "training-root", "decision-root", "helper", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--operation", required=True)
    args = p.parse_args()
    os.umask(0o077)
    assert sha(args.binary) == BINARY_SHA and sha(args.helper) == HELPER_SHA
    spec = importlib.util.spec_from_file_location("original_worker_helper", args.helper)
    helper = importlib.util.module_from_spec(spec)
    exec(compile(args.helper.read_bytes(), str(args.helper), "exec"), helper.__dict__)
    save = helper.save
    args.output.mkdir(mode=0o700, exist_ok=False)
    result = dict(schema="trnm-cell-real-model-material-transfer-v1", result="FAIL", operation=args.operation,
                  cell_source=SOURCE, binary_sha256=BINARY_SHA, provider_transport="persistent-v2",
                  independent_operators=False, public_discovery=False, long_term_custody=False,
                  full_base_weights_transferred=False, native_current_binding=False,
                  production_final_use=False, production_activation=False, qualification="HOLD_NO_GO")
    server = None
    owners = []
    try:
        decision = json.loads((args.decision_root / "decision.json").read_bytes())
        assert decision["disposition"] == "NoUpdate"
        config = json.loads((args.training_root / "model-generation-1.json").read_bytes())
        parent = Path(config["parent_dir"])
        assert config["parent_adapter"] == decision["selected_adapter"] == decision["parent_adapter"]
        assert sha(parent / "artifact.safetensors") == config["parent_file_sha256"]
        names = ["artifact.safetensors", "target-contract.json", "wrapped-adapter.json"]
        originals = {name: dict(bytes=(parent / name).stat().st_size, sha256=sha(parent / name)) for name in names}
        frozen = save(args.output / "frozen-transfer.json", dict(operation=args.operation, source=SOURCE,
                      binary_sha256=BINARY_SHA, retained_adapter=config["parent_adapter"], files=originals,
                      decision_sha256=sha(args.decision_root / "decision.json"),
                      expected_material_manifest_sha256=config["material_manifest_sha256"],
                      start_unix_ns=time.time_ns(), purpose="bounded-single-operator-research-load"))
        cache = ["--cache-max-bytes", "16777216", "--cache-max-chunks", "128",
                 "--cache-max-manifests", "16", "--cache-max-db-bytes", "16777216"]
        context = ["--family", "smollm2-135m-research-v1", "--base", config["material_manifest_sha256"],
                   "--parent", config["parent_adapter"], "--tokenizer", config["material_manifest_sha256"],
                   "--layout", config["parent_contract"], "--runtime", helper.PACKAGE]
        commands = []
        def run(label, tail):
            command = [str(args.binary), *tail]
            started = time.monotonic()
            r = subprocess.run(command, capture_output=True, text=True, timeout=30)
            record = dict(command=command, exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr,
                          elapsed_seconds=time.monotonic() - started)
            save(args.output / (label + ".json"), record)
            commands.append(record)
            assert r.returncode == 0, record
            return json.loads(r.stdout)
        packed = {}
        for index, name in enumerate(names):
            packed[name] = run(f"pack-{index}", ["pack", "--store", str(args.output / "provider.db"),
                                  "--input", str(parent / name), "--chunk-bytes", "65536", *context, *cache])
            assert packed[name]["payload_sha256"] == originals[name]["sha256"]
        command = [str(args.binary), "serve", "--store", str(args.output / "provider.db"),
                   "--bind", "127.0.0.1:0", "--seconds", "12", "--bounded-workers", "2",
                   "--max-served-bytes", "16777216", "--max-connections", "16", "--request-ms", "2000",
                   "--transport", "persistent-v2", "--max-requests", "128", "--max-requests-per-connection", "64",
                   "--announce-ready", "true"]
        server_stderr = (args.output / "provider.stderr").open("xb")
        server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=server_stderr, bufsize=0)
        ready_lines = []
        with selectors.DefaultSelector() as selector:
            selector.register(server.stdout, selectors.EVENT_READ)
            for _ in range(2):
                assert selector.select(5), "original provider readiness timeout"
                line = server.stdout.readline()
                assert line, "provider exited before readiness"
                ready_lines.append(json.loads(line))
        address = ready_lines[0]["address"]
        assert ready_lines[1]["schema"] == "trnm.cell.ready.v1", ready_lines
        save(args.output / "provider-start.json", dict(command=command, pid=server.pid, readiness=ready_lines))
        replica = args.output / "replica"
        replica.mkdir()
        transfers = []
        for index, name in enumerate(names):
            record = run(f"fetch-{index}", ["fetch", "--store", str(args.output / "consumer.db"),
                         "--manifest", packed[name]["manifest"], "--peers", address,
                         "--output", str(replica / name), "--max-bytes", str(originals[name]["bytes"]),
                         "--overall-ms", "3000", "--request-ms", "2000", "--parallelism", "1",
                         "--max-connections", "2", "--max-response-bytes", "4194304",
                         "--transport", "persistent-v2", "--max-requests", "64", "--max-requests-per-connection", "64", *cache])
            assert sha(replica / name) == originals[name]["sha256"]
            run(f"verify-{index}", ["verify", "--store", str(args.output / "consumer.db"), "--manifest", packed[name]["manifest"], *cache])
            transfers.append(dict(name=name, packed=packed[name], fetched=record, actual_sha256=sha(replica / name)))
        remaining = server.communicate(timeout=20)[0]
        server_stderr.close()
        assert server.returncode == 0
        save(args.output / "provider-terminal.json", dict(exit_code=server.returncode,
             stdout=remaining.decode(), readiness=ready_lines))
        model = dict(config, parent_dir=str(replica))
        worker = args.research_root / "worktree/workers/weight/worker.py"
        params = dict(provider="smollm2_cell", model=model, cpu_threads=4,
                      input_roots=[model["source_dir"], model["materials_dir"], str(Path(model["plan_path"]).parent), str(replica)],
                      output_root=str(args.output / "worker-store"), limits=dict(max_forward_examples=1, max_patch_candidates=1))
        owner = helper.Worker(worker, args.operation, args.output, "transferred-model-load")
        owners.append(owner)
        opened = owner.call("open", "open", params)
        assert opened["ok"] and opened["result"]["model"]["parent_adapter"] == decision["parent_adapter"]
        assert opened["result"]["model"]["identity"]["parent"]["file_sha256"] == originals["artifact.safetensors"]["sha256"]
        next_task = json.loads((args.decision_root / "frozen-decision-plan.json").read_bytes())["next_task"]
        inputs = dict(next_task, request_id=args.operation + "-actual-next-task")
        response = owner.call("probe", "probe", dict(inputs=inputs))
        observation = helper.output_record(response, inputs, 1)
        save(args.output / "actual-open.json", opened)
        save(args.output / "actual-response.json", response)
        first = owner.finish();owners.remove(owner)
        recovery = helper.Worker(worker, args.operation, args.output, "transferred-model-cold-readback")
        owners.append(recovery)
        assert recovery.call("open", "open", params) == opened
        assert recovery.call("probe", "probe", dict(inputs=inputs)) == response
        close = recovery.call("close", "close", {})
        assert close["ok"] and close["result"]["forward_examples"] == 1
        cold = recovery.finish();owners.remove(recovery)
        assert all(sha(parent / n) == originals[n]["sha256"] == sha(replica / n) for n in names)
        result.update(result="PASS_NATIVE_CELL_TRANSFER_AND_ACTUAL_RETAINED_MODEL_LOAD", frozen_plan=frozen,
                      transfers=transfers, actual_model_output=observation,
                      actual_retained_model_loaded=True, actual_new_forward_calls=1,
                      cold_response_exact=True, reexecuted_after_recovery=False,
                      first_worker=first, cold_worker=cold, all_originals_unchanged=True, end_unix_ns=time.time_ns())
    except BaseException as error:
        result["error"] = repr(error)
        raise
    finally:
        for owner in owners:
            try: owner.finish()
            except Exception as error: result.setdefault("cleanup_errors", []).append(repr(error))
        if server is not None and server.poll() is None:
            # The finite original server exits by its unchanged twelve-second
            # lifetime; preserve its actual status without restarting it.
            server.communicate(timeout=20)
        save(args.output / "result.json", result)
        print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
