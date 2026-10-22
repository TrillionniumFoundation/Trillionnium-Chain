#!/usr/bin/env python3
"""Controlled TCP dependency download followed by original Hepta inference owners.

This creates evidence, not independent evaluation, product qualification or a
release decision. All source and destination directories must be explicit. The
producer's finite server exits before the consumer loads the downloaded model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("chain", "hepta", "source-parent", "source-materials", "output",
                 "python", "cell-bin", "just", "hepta-target"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    for value in vars(args).values():
        if not value.is_absolute():
            parser.error("all paths must be absolute")
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    started = time.monotonic()
    evidence = {
        "schema": "pon-smollm-cell-native-handoff-v1", "status": "running",
        "scope": "one-host-controlled-tcp-full-model-dependencies-original-hepta-owners",
        "independent_operators": False, "independent_evaluation": False,
        "product_qualification": False, "production_activation": False,
        "cell_binary_sha256": sha(args.cell_bin), "members": [],
    }
    server = None
    try:
        family_path = args.chain / "config/pon/model-family-smollm2-135m-v1.json"
        family = json.loads(family_path.read_text())
        parent = json.loads(args.source_parent.read_text())
        source_parent = Path(parent["directory"])
        if not source_parent.is_absolute() or parent["generation"] < 1:
            raise ValueError("explicit real parent descriptor required")
        contract = json.loads((source_parent / "target-contract.json").read_text())
        stage = args.output / "consumer-parent"
        material_stage = args.output / "consumer-materials"
        stage.mkdir(mode=0o700)
        material_stage.mkdir(mode=0o700)
        members = []
        for name, pin in sorted(family["material_pins"]["files"].items()):
            if Path(name).name != name:
                raise ValueError("material pin is not a single filename")
            source = args.source_materials / name
            if source.stat().st_size != pin["size"] or sha(source) != pin["sha256"]:
                raise ValueError(f"source material differs from frozen pin: {name}")
            members.append(("base/" + name, source, material_stage / name))
        # This retained manifest is also a runtime dependency. The consumer's
        # original verify_materials checks its entries against code-pinned public
        # hashes; downloading just the seven upstream files is insufficient.
        manifest_path = args.source_materials / "material-manifest.json"
        material_manifest = json.loads(manifest_path.read_text())
        if (material_manifest["model"] != family["reference"]["model"]
                or material_manifest["revision"] != family["reference"]["revision"]
                or material_manifest["files"] != family["material_pins"]["files"]):
            raise ValueError("retained material manifest differs from frozen family pins")
        members.append(("base/material-manifest.json", manifest_path,
                        material_stage / "material-manifest.json"))
        for name in ("target-contract.json", "wrapped-adapter.json", "artifact.safetensors"):
            members.append(("adapter/" + name, source_parent / name, stage / name))
        if sha(source_parent / "artifact.safetensors") != parent["file_sha256"]:
            raise ValueError("actual parent weight mismatch")
        context = ["--family", family["id"], "--base", contract["backbone"]["index_root"],
                   "--parent", parent["file_sha256"], "--tokenizer", contract["tokenizer"]["files_root"],
                   "--layout", parent["contract"], "--runtime", sha(args.chain / "scripts/llm_neural_read_worker.py")]
        producer = args.output / "producer.sqlite"
        consumer = args.output / "consumer.sqlite"
        for index, (name, source, destination) in enumerate(members):
            command = [str(args.cell_bin), "pack", "--store", str(producer),
                       "--input", str(source), *context]
            packed = subprocess.run(command, capture_output=True, text=True, timeout=120)
            (args.output / f"pack-{index}.log").write_text(packed.stdout + packed.stderr)
            packed.check_returncode()
            observation = json.loads(packed.stdout)
            if observation["payload_sha256"] != sha(source):
                raise ValueError("pack payload observation mismatch")
            evidence["members"].append({"name": name, "source": str(source),
                "destination": str(destination), "pack": observation})
        # One finite producer, one initially empty consumer. These are controlled
        # loopback processes and never count as independent custody or a WAN test.
        with (args.output / "server-stderr.log").open("w") as server_error:
            server = subprocess.Popen([str(args.cell_bin), "serve", "--store", str(producer),
                "--bind", "127.0.0.1:0", "--seconds", "45"], stdout=subprocess.PIPE,
                stderr=server_error, text=True)
            with selectors.DefaultSelector() as poll:
                poll.register(server.stdout, selectors.EVENT_READ)
                if not poll.select(5):
                    raise TimeoutError("finite producer did not announce its listener")
                listen_line = server.stdout.readline()
            address = json.loads(listen_line)["address"]
            transfer_deadline = time.monotonic() + 35
            for index, member in enumerate(evidence["members"]):
                remaining = int(transfer_deadline - time.monotonic())
                if remaining < 1:
                    raise TimeoutError("original aggregate transfer deadline exhausted")
                command = [str(args.cell_bin), "fetch", "--store", str(consumer),
                    "--manifest", member["pack"]["manifest"], "--peers", address,
                    "--output", member["destination"], "--max-bytes", str(member["pack"]["bytes"]),
                    "--seconds", str(remaining), "--parallelism", "2"]
                fetched = subprocess.run(command, capture_output=True, text=True,
                    timeout=remaining + 2)
                (args.output / f"fetch-{index}.log").write_text(fetched.stdout + fetched.stderr)
                fetched.check_returncode()
                result = json.loads(fetched.stdout)
                if result["downloaded_chunks"] != member["pack"]["chunks"] or result["cached_chunks"] != 0:
                    raise ValueError("member was not fully fetched from this producer")
                if sha(Path(member["destination"])) != member["pack"]["payload_sha256"]:
                    raise ValueError("consumer readback differs from pinned bytes")
                member["fetch"] = result
                member["consumer_sha256"] = sha(Path(member["destination"]))
            tail, _ = server.communicate(timeout=50)
            (args.output / "server-stdout.log").write_text(listen_line + tail)
            if server.returncode != 0:
                raise RuntimeError("finite producer did not stop successfully")
            evidence["producer_exit_code_before_consumer_load"] = server.returncode
        parent["directory"] = str(stage)
        consumer_parent = stage / "parent-material.json"
        write_json(consumer_parent, parent)
        config = {"schema": "hepta-smollm-neural-native-check-v1", "python": str(args.python),
            "chain": str(args.chain), "materials": str(material_stage), "parent": str(consumer_parent),
            "parent_sha256": sha(consumer_parent), "output": str(args.output / "original-hepta-consumer")}
        config_path = args.output / "native-config.json"
        write_json(config_path, config)
        env = {**os.environ, "PATH": str(args.just.parent) + os.pathsep + os.environ.get("PATH", ""),
            "CARGO_TARGET_DIR": str(args.hepta_target), "CARGO_BUILD_JOBS": "6",
            "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
            "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "CUDA_VISIBLE_DEVICES": "",
            "OMP_NUM_THREADS": "4", "MKL_NUM_THREADS": "4", "HEPTA_PN3_NEURAL_NATIVE_CONFIG": str(config_path)}
        command = [str(args.just), "test", "--offline", "--locked", "--retries", "0", "-p", "codex-hepta-infer-worker-host",
            "--run-ignored", "only", "real_smollm_parent_query_original_control_final_use_and_terminal_unload"]
        with (args.output / "hepta-native.log").open("w") as log:
            native = subprocess.run(command, cwd=args.hepta / "codex-rs", env=env,
                stdout=log, stderr=subprocess.STDOUT, timeout=600)
        evidence["hepta_exit_code"] = native.returncode
        if native.returncode:
            raise RuntimeError("original Hepta consumer check failed; see retained native log")
        result_path = Path(config["output"]) / "native-owner-bridge-result.json"
        evidence["native_result"] = json.loads(result_path.read_text())
        evidence["native_result_sha256"] = sha(result_path)
        evidence["source_parent_sha256"] = sha(args.source_parent)
        evidence["consumer_parent_sha256"] = sha(consumer_parent)
        evidence["status"] = "passed"
    except BaseException as error:
        evidence["status"] = "failed"
        evidence["error"] = str(error)
        raise
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            evidence["producer_cleanup_after_failure"] = True
        evidence["elapsed_seconds"] = time.monotonic() - started
        write_json(args.output / "handoff.json", evidence)
        print(json.dumps({"status": evidence["status"], "report": str(args.output / "handoff.json")}))


if __name__ == "__main__":
    main()
