#!/usr/bin/env python3
"""Actual model bytes through an offline-publisher Cell replica, then forwards.

This one-host research command uses the existing native TCL4/TCR1 transport and
existing SmolLM loaders. It does not install a Hepta artifact, issue FinalUse,
change a selector, qualify an operator, add chainwork or decide a release.
All model and adapter inputs must already match the original pinned contracts.
The new public comparison fixture is frozen after both adapters are fixed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import random
import secrets
import selectors
import socket
import subprocess
import sys
import time

import llm_inherited_runtime as inherited
import llm_runtime_pilot as runtime
from run_llm_cell_native_handoff import sha, write_json

CHAIN = Path(__file__).resolve().parents[1]
NO_AUTHORITY = dict(inherited.NO_AUTHORITY)
CACHE_LIMITS = ["--cache-max-bytes", str(512 * 1024**2), "--cache-max-chunks", "1024",
                "--cache-max-manifests", "32", "--cache-max-db-bytes", str(512 * 1024**2)]
TRANSFER_SECONDS = 180


def run_logged(argv, directory, name, *, timeout, expected_success=True):
    start = time.monotonic()
    completed = subprocess.run([str(v) for v in argv], capture_output=True, text=True, timeout=timeout)
    (directory / (name + ".log")).write_text(completed.stdout + completed.stderr)
    write_json(directory / (name + "-command.json"), dict(argv=[str(v) for v in argv],
        returncode=completed.returncode, elapsed_seconds=time.monotonic() - start))
    if expected_success:
        completed.check_returncode()
    elif completed.returncode == 0:
        raise ValueError("negative control unexpectedly succeeded: " + name)
    return completed


@contextmanager
def peer(binary, store, directory, name, connections, response_bytes):
    error = (directory / (name + "-stderr.log")).open("w")
    process = subprocess.Popen([str(binary), "serve", "--store", str(store), "--bind", "127.0.0.1:0",
        "--seconds", str(TRANSFER_SECONDS + 30), "--bounded-workers", "2", "--request-ms", "5000",
        "--max-connections", str(connections), "--max-served-bytes", str(response_bytes)],
        stdout=subprocess.PIPE, stderr=error, text=True)
    record = dict(pid=process.pid, store=str(store), stopped=False)
    line = ""
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            if not ready.select(10):
                raise TimeoutError("Cell peer did not announce a listener")
            line = process.stdout.readline()
        record["address"] = json.loads(line)["address"]
        yield record
    finally:
        # Deliberately stop the actual producer/replica process before returning.
        if process.poll() is None:
            process.terminate()
        try:
            tail, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            tail, _ = process.communicate(timeout=5)
        record.update(returncode=process.returncode, stopped=True)
        (directory / (name + "-stdout.log")).write_text(line + tail)
        error.close()
        write_json(directory / (name + "-process.json"), record)


def fetch_release(binary, store, release_file, release, address, directory, name,
                  connection_budget, response_budget, *, seconds=TRANSFER_SECONDS,
                  expected_success=True):
    if store.exists():
        raise ValueError("acquisition store must initially be absent")
    command = [binary, "fetch-release", *CACHE_LIMITS, "--store", store,
        "--release-file", release_file, "--release", release["release"], "--peers", address,
        "--output", directory / (name + ".tcr1"), "--max-bytes", str(release["payload_bytes"]),
        "--max-chunks", str(release["chunks"]), "--overall-ms", str(seconds * 1000),
        "--request-ms", str(min(seconds * 1000, 5000)), "--max-connections", str(connection_budget),
        "--max-response-bytes", str(response_budget), "--parallelism", "2"]
    result = run_logged(command, directory, name, timeout=seconds + 5, expected_success=expected_success)
    if not expected_success:
        return dict(returncode=result.returncode, no_completion_file=not (directory / (name + ".tcr1")).exists())
    observed = json.loads(result.stdout)
    for key in ("release", "cells", "payload_bytes", "chunks"):
        if observed[key] != release[key]:
            raise ValueError("release does not match complete pinned set: " + key)
    if (observed["downloaded_chunks"] == 0 or observed["received_response_bytes"] <= 0
            or observed["cached_chunks"] + observed["downloaded_chunks"] != release["chunks"]
            or observed["connection_attempts"] > connection_budget
            or observed["received_response_bytes"] > response_budget
            or sha(directory / (name + ".tcr1")) != sha(release_file)):
        raise ValueError("fresh-store download or pinned completion check failed")
    return observed


def transport(args, candidate, directory):
    directory.mkdir(mode=0o700)
    family = runtime.verify_family(runtime.read_json(runtime.FAMILY_PATH))
    runtime.verify_materials(args.materials)
    contract, _, _ = inherited.read_parent(candidate)
    parent_dir = Path(candidate["directory"])
    consumer_parent = directory / "consumer-parent"
    consumer_materials = directory / "consumer-materials"
    consumer_parent.mkdir(mode=0o700)
    consumer_materials.mkdir(mode=0o700)
    members = [("base/" + name, args.materials / name, consumer_materials / name)
               for name in sorted(family["material_pins"]["files"])]
    members.append(("base/material-manifest.json", args.materials / "material-manifest.json",
                    consumer_materials / "material-manifest.json"))
    members += [("adapter/" + name, parent_dir / name, consumer_parent / name)
                for name in ("target-contract.json", "wrapped-adapter.json", "artifact.safetensors")]
    context = ["--family", family["id"], "--base", contract["backbone"]["index_root"],
        "--parent", candidate["file_sha256"], "--tokenizer", contract["tokenizer"]["files_root"],
        "--layout", candidate["contract"], "--runtime", sha(CHAIN / "scripts/llm_neural_read_worker.py")]
    publisher = directory / "publisher.sqlite"
    report = dict(scope="one-host-controlled-native-TCL4-complete-model-and-LoRA-replica", members=[],
                  original_hepta_installed=False, hepta_final_use=False, independent_operators=False,
                  pq_authenticated_transport=False, authority=NO_AUTHORITY)
    for index, (name, source, target) in enumerate(members):
        completed = run_logged([args.cell_bin, "pack", *CACHE_LIMITS, "--store", publisher,
            "--input", source, *context], directory, f"pack-{index}", timeout=120)
        packed = json.loads(completed.stdout)
        if packed["payload_sha256"] != sha(source) or packed["bytes"] != source.stat().st_size:
            raise ValueError("packed source mismatch")
        report["members"].append(dict(name=name, source=str(source), destination=str(target), pack=packed))
    total = sum(m["pack"]["bytes"] for m in report["members"])
    chunks = sum(m["pack"]["chunks"] for m in report["members"])
    release_file = directory / "source-release.tcr1"
    prepared = run_logged([args.cell_bin, "prepare-release", *CACHE_LIMITS, "--store", publisher,
        "--manifests", ",".join(m["pack"]["manifest"] for m in report["members"]),
        "--output", release_file, "--max-bytes", str(total), "--max-chunks", str(chunks),
        "--overall-ms", "120000"], directory, "prepare-release", timeout=125)
    release = json.loads(prepared.stdout)
    if release["cells"] != len(members) or release["payload_bytes"] != total or release["chunks"] != chunks:
        raise ValueError("release omitted a declared dependency")
    connections = 2 * (chunks + len(members))
    response_bytes = 2 * total + len(members) * 1_048_576 + 9 * connections
    report.update(release=release, release_sha256=sha(release_file),
                  connection_budget=connections, response_byte_budget=response_bytes)
    replica = directory / "replica.sqlite"
    with peer(args.cell_bin, publisher, directory, "publisher", connections, response_bytes) as producer:
        report["replica_acquisition"] = fetch_release(args.cell_bin, replica, release_file, release,
            producer["address"], directory, "publisher-to-replica", connections, response_bytes)
    report["publisher"] = producer
    if not producer["stopped"]:
        raise ValueError("publisher must be stopped before fresh consumer acquisition")
    # This command uses the actual dead peer and original client. It must fail,
    # retain its failure evidence, and cannot mint a completion file.
    report["offline_publisher_negative"] = fetch_release(args.cell_bin,
        directory / "offline-negative.sqlite", release_file, release, producer["address"],
        directory, "offline-publisher-negative", connections, response_bytes,
        seconds=2, expected_success=False)
    if not report["offline_publisher_negative"]["no_completion_file"]:
        raise ValueError("offline publisher minted completion")
    consumer = directory / "consumer.sqlite"
    with peer(args.cell_bin, replica, directory, "replica", connections, response_bytes) as replica_peer:
        report["consumer_acquisition"] = fetch_release(args.cell_bin, consumer, release_file, release,
            replica_peer["address"], directory, "replica-to-consumer", connections, response_bytes)
    report["replica"] = replica_peer
    # Both network peers are now stopped. Only the verified consumer cache may
    # materialize the exact complete release. This is data acquisition, not install.
    deadline = time.monotonic() + TRANSFER_SECONDS
    for index, member in enumerate(report["members"]):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("aggregate cache materialization deadline exhausted")
        packed = member["pack"]
        fetched = run_logged([args.cell_bin, "fetch", *CACHE_LIMITS, "--store", consumer,
            "--manifest", packed["manifest"], "--peers", "", "--output", member["destination"],
            "--max-bytes", str(packed["bytes"]), "--overall-ms", str(max(1, int(remaining * 1000))),
            "--request-ms", "1000", "--parallelism", "1", "--max-connections", "1",
            "--max-response-bytes", "0"], directory, f"materialize-{index}", timeout=remaining + 2)
        observed = json.loads(fetched.stdout)
        if (observed["downloaded_chunks"] != 0 or observed["connection_attempts"] != 0
                or observed["received_response_bytes"] != 0 or observed["cached_chunks"] != packed["chunks"]
                or sha(Path(member["destination"])) != packed["payload_sha256"]):
            raise ValueError("cache-only materialization differs from authenticated content pins")
        member["materialization"] = observed
    if time.monotonic() >= deadline:
        raise TimeoutError("late final materialization is not accepted")
    relocated = dict(candidate, directory=str(consumer_parent))
    inherited.read_parent(relocated)
    runtime.verify_materials(consumer_materials)
    descriptor = consumer_parent / "parent-material.json"
    write_json(descriptor, relocated)
    report.update(all_model_dependencies_rehashed=True, parent_sha256=sha(descriptor),
                  consumer_parent=str(descriptor), consumer_materials=str(consumer_materials))
    write_json(directory / "transport-report.json", report)
    return report, descriptor, consumer_materials


def freeze_comparison(output, baseline, candidate):
    # Sample once after the artifacts exist. No search over tasks or seeds based
    # on model outputs; these are public synthetic inputs, not user observations.
    seed = secrets.token_hex(32)
    generator = random.Random(int(seed, 16))
    rows, prompts = [], set()
    for index in range(32):
        while True:
            a, b = generator.sample(range(100, 10000), 2)
            if (a > b) != (index % 2 == 0):
                a, b = b, a
            prompt = f"Answer with only yes or no. Is {a} greater than {b}?"
            if prompt not in prompts:
                prompts.add(prompt)
                break
        rows.append(dict(request_id=f"public-next-task-{index}", prompt=prompt,
                         expected_output="yes" if a > b else "no"))
    value = dict(schema="trnm-smollm-public-post-artifact-comparison-v1", seed=seed,
        scope="operator-controlled-public-fixtures", baseline=baseline, candidate=candidate,
        profile="hepta-smollm-single-token-action-score-v1", tasks=rows,
        independently_custodied=False, prospective_accepted=False, authority=NO_AUTHORITY)
    write_json(output / "frozen-comparison.json", value)
    return value


def socket_request(directory, value, deadline):
    raw = runtime.canonical(value)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("original comparison deadline exhausted")
    # Use an owned directory FD to keep the Unix socket path below sun_path.
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(min(remaining, 30))
            stream.connect(f"/proc/self/fd/{fd}/model.sock")
            stream.sendall(raw + b"\n")
            reply = bytearray()
            while len(reply) <= 131072:
                stream.settimeout(min(deadline - time.monotonic(), 30))
                part = stream.recv(8192)
                if not part:
                    break
                reply.extend(part)
                if b"\n" in part:
                    break
            if value.get("stop") is True:
                return None
            if len(reply) > 131072 or not reply.endswith(b"\n") or reply.count(b"\n") != 1:
                raise ValueError("bounded neural response frame required")
            return json.loads(reply, object_pairs_hook=runtime.unique)
    finally:
        os.close(fd)


def actual_forwards(args, parent_path, materials, fixture, directory, actions):
    parent = inherited.validate_parent(runtime.read_json(parent_path))
    deadline = time.monotonic() + 600
    command = [str(args.python), str(CHAIN / "scripts/llm_neural_read_worker.py"), "serve",
        "--materials", str(materials), "--parent", str(parent_path), "--parent-sha256", sha(parent_path),
        "--actions", str(actions), "--actions-sha256", sha(actions), "--output", str(directory),
        "--threads", str(args.threads)]
    stdout = (directory.parent / (directory.name + "-stdout.log")).open("w")
    stderr = (directory.parent / (directory.name + "-stderr.log")).open("w")
    process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    observations = []
    ready_path = directory / "worker/ready.json"
    try:
        ready_deadline = min(deadline, time.monotonic() + 120)
        while not ready_path.exists():
            if process.poll() is not None or time.monotonic() >= ready_deadline:
                raise RuntimeError("original model worker did not become ready")
            time.sleep(0.05)
        ready = runtime.read_json(ready_path)
        if (ready["actual_loaded_parent"] != parent["adapter"] or ready["file_sha256"] != parent["file_sha256"]
                or ready["contract"] != parent["contract"] or ready["authority"] != NO_AUTHORITY):
            raise ValueError("original loaded model identity mismatch")
        for row in fixture["tasks"]:
            request = dict(schema="hepta-smollm-inference-input-v1", request_id=row["request_id"], prompt=row["prompt"])
            observed = socket_request(directory / "worker", request, deadline)
            if (observed["request_id"] != row["request_id"] or observed["input_sha256"] != runtime.identity(request)
                    or observed["artifact"] != parent["adapter"] or observed["file_sha256"] != parent["file_sha256"]
                    or observed["contract"] != parent["contract"] or observed["authority"] != NO_AUTHORITY
                    or observed["profile"] != fixture["profile"] or observed["action_ids"] != ["no", "yes"]
                    or len(observed["scores_q32"]) != 2 or not all(type(v) is int for v in observed["scores_q32"])):
                raise ValueError("unbound original forward observation")
            # Ties choose the lexically first frozen action, matching the profile.
            predicted = observed["action_ids"][max(range(2), key=lambda i: observed["scores_q32"][i])]
            observations.append(dict(request=row, observation=observed, predicted=predicted,
                                     correct=predicted == row["expected_output"]))
        socket_request(directory / "worker", {"schema": "hepta-smollm-neural-read-worker-v1", "stop": True}, deadline)
        process.wait(timeout=min(30, max(1, deadline - time.monotonic())))
        if process.returncode != 0 or (directory / "worker/model.sock").exists():
            raise RuntimeError("original worker did not cleanly stop and unload")
        return observations
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        stdout.close()
        stderr.close()
        write_json(directory.parent / (directory.name + "-observations.json"), observations)
        write_json(directory.parent / (directory.name + "-process.json"), dict(argv=command,
            pid=process.pid, returncode=process.returncode, observations=len(observations),
            original_hepta_owner_used=False, authority=NO_AUTHORITY))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("materials", "baseline-parent", "candidate-parent", "python", "cell-bin", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--threads", type=int, default=2)
    args = parser.parse_args()
    if any(not v.is_absolute() for v in vars(args).values() if isinstance(v, Path)) or not 1 <= args.threads <= 4:
        parser.error("explicit absolute paths and 1..4 CPU threads required")
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    result = dict(schema="trnm-smollm-cell-replica-research-v1", status="failed", decision="no-update",
        scope="one-host-public-fixtures-real-model-bytes-and-forwards", authority=NO_AUTHORITY,
        product_artifact_installed=False, original_hepta_final_use=False,
        public_wan_accepted=False, independent_operators=False, pq_authenticated_transport=False,
        source_pins=inherited.source_pins(), worker_sha256=sha(CHAIN / "scripts/llm_neural_read_worker.py"),
        runner_sha256=sha(Path(__file__)), cell_binary_sha256=sha(args.cell_bin))
    start = time.monotonic()
    try:
        baseline = inherited.validate_parent(runtime.read_json(args.baseline_parent))
        candidate = inherited.validate_parent(runtime.read_json(args.candidate_parent))
        inherited.read_parent(baseline)
        inherited.read_parent(candidate)
        if candidate["generation"] != baseline["generation"] + 1 or candidate["contract"] != baseline["contract"]:
            raise ValueError("compatible consecutive research generations required")
        fixture = freeze_comparison(args.output, baseline, candidate)
        result["frozen_comparison_sha256"] = sha(args.output / "frozen-comparison.json")
        transport_report, consumer_parent, consumer_materials = transport(args, candidate, args.output / "transport")
        result["transport"] = transport_report
        actions = args.output / "actions.json"
        write_json(actions, [dict(action_id="no", completion="no"), dict(action_id="yes", completion="yes")])
        base_observations = actual_forwards(args, args.baseline_parent, args.materials, fixture,
                                            args.output / "baseline-read", actions)
        candidate_observations = actual_forwards(args, consumer_parent, consumer_materials, fixture,
                                                 args.output / "candidate-read", actions)
        base_correct = sum(row["correct"] for row in base_observations)
        candidate_correct = sum(row["correct"] for row in candidate_observations)
        result.update(status="research-completed-no-update", baseline_correct=base_correct,
            candidate_correct=candidate_correct, tasks_per_model=len(fixture["tasks"]),
            observed_accuracy_difference=(candidate_correct - base_correct) / len(fixture["tasks"]),
            raw_forward_observations=base_observations + candidate_observations,
            no_update_reasons=["public synthetic tasks are not an authorized independent user cohort",
                "complete required model-family comparison controls were not executed",
                "original Hepta product bootstrap, installation and FinalUse were not admitted"],
            python_packages={name: importlib.metadata.version(name) for name in
                ("torch", "transformers", "peft", "safetensors", "tokenizers", "numpy", "accelerate")})
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error))
        raise
    finally:
        result["elapsed_seconds"] = time.monotonic() - start
        write_json(args.output / "research-result.json", result)
        print(json.dumps(dict(status=result["status"], decision=result["decision"],
                              report=str(args.output / "research-result.json"))))


if __name__ == "__main__":
    main()
