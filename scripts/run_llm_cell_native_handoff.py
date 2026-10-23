#!/usr/bin/env python3
"""Controlled TCP dependency download; the native Hepta consumer is unavailable.

This creates evidence, not independent evaluation, product qualification or a
release decision. All source and destination directories must be explicit. The
finite producer exits before the unavailable consumer boundary. Transport
completion cannot establish I10; this command deliberately fails closed there.
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


def remaining_fetch_budget(deadline: float) -> tuple[float, int, int]:
    remaining = deadline - time.monotonic()
    # Floor the original remaining window. No child receives rounded-up time.
    overall_ms = int(remaining * 1000)
    if overall_ms < 10:
        raise TimeoutError("original aggregate transfer window is below the 10ms minimum request deadline")
    return remaining, overall_ms, min(2000, overall_ms)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    # Retain the original absolute-path invocation arguments. Hepta, Python,
    # just and target paths do not enable an unshipped native consumer.
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
        "scope": "one-host-controlled-tcp-full-model-dependencies-native-consumer-unavailable",
        "independent_operators": False, "independent_evaluation": False,
        "product_qualification": False, "production_activation": False,
        "native_consumer_status": "UNAVAILABLE", "native_receipt_status": "UNVERIFIED",
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
        # Declare the complete compatibility set before acquisition. The native
        # CLI verifies every local member and publishes canonical TCR1 bytes;
        # this root carries transport completeness, never model-use authority.
        total_bytes = sum(member["pack"]["bytes"] for member in evidence["members"])
        total_chunks = sum(member["pack"]["chunks"] for member in evidence["members"])
        release_file = args.output / "source-release.tcr1"
        command = [str(args.cell_bin), "prepare-release", "--store", str(producer),
            "--manifests", ",".join(member["pack"]["manifest"] for member in evidence["members"]),
            "--output", str(release_file), "--max-bytes", str(total_bytes),
            "--max-chunks", str(total_chunks), "--overall-ms", "120000"]
        prepared = subprocess.run(command, capture_output=True, text=True, timeout=122)
        (args.output / "prepare-release.log").write_text(prepared.stdout + prepared.stderr)
        prepared.check_returncode()
        release = json.loads(prepared.stdout)
        if (release["schema"] != "trnm.cell.release.prepare.v1"
                or release["cells"] != len(members)
                or release["payload_bytes"] != total_bytes
                or release["chunks"] != total_chunks):
            raise ValueError("prepared release differs from the declared complete set")
        # A bounded retry allowance covers response headers and all manifests.
        # These limits are shared across the release, not reset for each cell.
        connection_budget = 2 * (total_chunks + len(members))
        response_budget = 2 * total_bytes + len(members) * 1_048_576 + 9 * connection_budget
        evidence["release"] = {"prepare": release, "source_file": str(release_file),
            "source_sha256": sha(release_file), "max_response_bytes": response_budget,
            "max_connections": connection_budget, "selection_authority": False}
        if consumer.exists():
            raise ValueError("controlled consumer store must initially be absent")
        evidence["release"]["consumer_initially_absent"] = True
        # One finite producer, one initially empty consumer. These are controlled
        # loopback processes and never count as independent custody or a WAN test.
        with (args.output / "server-stderr.log").open("w") as server_error:
            server = subprocess.Popen([str(args.cell_bin), "serve", "--store", str(producer),
                "--bind", "127.0.0.1:0", "--seconds", "45", "--bounded-workers", "2",
                "--max-connections", str(connection_budget),
                "--max-served-bytes", str(response_budget)], stdout=subprocess.PIPE,
                stderr=server_error, text=True)
            with selectors.DefaultSelector() as poll:
                poll.register(server.stdout, selectors.EVENT_READ)
                if not poll.select(5):
                    raise TimeoutError("finite producer did not announce its listener")
                listen_line = server.stdout.readline()
            address = json.loads(listen_line)["address"]
            transfer_started = time.monotonic()
            transfer_deadline = transfer_started + 35
            transfer = {"schema": "cell-native-aggregate-transfer-v2", "clock": "monotonic",
                "limit_seconds": 35, "all_members_verified": False,
                "scope": "listener announced through aggregate TCR1 fetch, cache-only materialization and final consumer readback; excludes packing, release preparation, provider drain and Hepta load"}
            evidence["transfer"] = transfer
            try:
                remaining, overall_ms, request_ms = remaining_fetch_budget(transfer_deadline)
                complete_release = args.output / "consumer-release.tcr1"
                command = [str(args.cell_bin), "fetch-release", "--store", str(consumer),
                    "--release-file", str(release_file), "--release", release["release"],
                    "--peers", address, "--output", str(complete_release),
                    "--max-bytes", str(total_bytes), "--max-chunks", str(total_chunks),
                    "--overall-ms", str(overall_ms), "--request-ms", str(request_ms),
                    "--max-response-bytes", str(response_budget),
                    "--max-connections", str(connection_budget), "--parallelism", "2"]
                fetched = subprocess.run(command, capture_output=True, text=True,
                    timeout=remaining + 2)
                (args.output / "fetch-release.log").write_text(fetched.stdout + fetched.stderr)
                fetched.check_returncode()
                result = json.loads(fetched.stdout)
                if (result["schema"] != "trnm.cell.release.fetch.v1"
                        or result["release"] != release["release"]
                        or result["cells"] != len(members)
                        or result["payload_bytes"] != total_bytes
                        or result["chunks"] != total_chunks
                        or result["cached_chunks"] + result["downloaded_chunks"] != total_chunks
                        or result["received_response_bytes"] > response_budget
                        or result["connection_attempts"] > connection_budget
                        or sha(complete_release) != evidence["release"]["source_sha256"]):
                    raise ValueError("aggregate release completion differs from pinned set or budget")
                evidence["release"]["fetch"] = result
                evidence["release"]["completion_file"] = str(complete_release)
                # Any cache hits in the aggregate acquisition arise within this
                # fresh release transfer. Materialization must now use only the
                # verified local store and spend no further network budget.
                for index, member in enumerate(evidence["members"]):
                    member_started = time.monotonic()
                    timing = {"started_seconds": member_started - transfer_started,
                        "completed": False}
                    member["transfer_timing"] = timing
                    try:
                        remaining, overall_ms, request_ms = remaining_fetch_budget(transfer_deadline)
                        timing["overall_timeout_ms"] = overall_ms
                        timing["request_timeout_ms"] = request_ms
                        command = [str(args.cell_bin), "fetch", "--store", str(consumer),
                            "--manifest", member["pack"]["manifest"], "--peers", "",
                            "--output", member["destination"], "--max-bytes", str(member["pack"]["bytes"]),
                            "--overall-ms", str(overall_ms), "--request-ms", str(request_ms),
                            "--parallelism", "1", "--max-connections", "1",
                            "--max-response-bytes", "0"]
                        fetch_started = time.monotonic()
                        try:
                            fetched = subprocess.run(command, capture_output=True, text=True,
                                timeout=remaining + 2)
                        finally:
                            timing["fetch_elapsed_seconds"] = time.monotonic() - fetch_started
                        (args.output / f"fetch-{index}.log").write_text(fetched.stdout + fetched.stderr)
                        fetched.check_returncode()
                        result = json.loads(fetched.stdout)
                        if (result["downloaded_chunks"] != 0
                                or result["cached_chunks"] != member["pack"]["chunks"]
                                or result["received_response_bytes"] != 0
                                or result["connection_attempts"] != 0):
                            raise ValueError("member materialization escaped the verified release store")
                        readback_started = time.monotonic()
                        try:
                            if sha(Path(member["destination"])) != member["pack"]["payload_sha256"]:
                                raise ValueError("consumer readback differs from pinned bytes")
                            member["fetch"] = result
                            member["consumer_sha256"] = sha(Path(member["destination"]))
                        finally:
                            timing["readback_elapsed_seconds"] = time.monotonic() - readback_started
                        timing["completed"] = True
                    finally:
                        member_ended = time.monotonic()
                        timing["ended_seconds"] = member_ended - transfer_started
                        timing["elapsed_seconds"] = member_ended - member_started
                transfer["all_members_verified"] = True
            finally:
                transfer_ended = time.monotonic()
                transfer["elapsed_seconds"] = transfer_ended - transfer_started
                transfer["within_original_deadline"] = transfer_ended < transfer_deadline
            # The subprocess timeout includes cleanup slack. It is not authority
            # to accept a late final file or readback as an in-window transfer.
            if not transfer["within_original_deadline"]:
                raise TimeoutError("original aggregate transfer deadline exhausted after consumer readback")
            tail, _ = server.communicate(timeout=50)
            (args.output / "server-stdout.log").write_text(listen_line + tail)
            if server.returncode != 0:
                raise RuntimeError("finite producer did not stop successfully")
            evidence["producer_exit_code_before_consumer_load"] = server.returncode
        parent["directory"] = str(stage)
        consumer_parent = stage / "parent-material.json"
        write_json(consumer_parent, parent)
        evidence["source_parent_sha256"] = sha(args.source_parent)
        evidence["consumer_parent_sha256"] = sha(consumer_parent)
        # No supported native consumer or owner-receipt contract is shipped.
        # Do not invoke an unknown selector, parse arbitrary JSON as authority,
        # or invent success fields for a future I10 implementation.
        raise RuntimeError("native Hepta consumer UNAVAILABLE; owner receipt UNVERIFIED: "
                           "no supported consumer or receipt contract is shipped")
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
