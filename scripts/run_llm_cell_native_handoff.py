#!/usr/bin/env python3
"""Controlled TCP dependency download; the native Hepta consumer is unavailable.

This creates evidence, not independent evaluation, product qualification or a
release decision. All source and destination directories must be explicit. The
finite producer exits before the unavailable consumer boundary. Transport
completion cannot establish I10; this command deliberately fails closed there.
All six writer CLI entries use fresh TCL4/schema4 caches and the same immutable
caps. The main-image cap also derives supported WAL/SHM file-length allowances;
a pinned cache reader can refuse before mutation. Old TCL3 caches are not migrated.
No allocated-block, output, whole-model use or global-disk authority is supplied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
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


def wait_for_provider_listener(server: subprocess.Popen, stdout_path: Path,
                               timeout: float = 5.0) -> str:
    """Read the first complete line from the already durable raw stdout stream.

    The provider writes directly to a file, never a pipe that can be lost on an
    exception or fill while the consumer runs. This is an announcement wait,
    not a connection retry or additional transfer window.
    """
    deadline = time.monotonic() + timeout
    line = bytearray()
    with stdout_path.open("rb") as stream:
        while True:
            piece = stream.readline(65_537 - len(line))
            line.extend(piece)
            if len(line) > 65_536:
                raise ValueError("finite producer listener announcement exceeds 65536 bytes")
            if line.endswith(b"\n"):
                announcement = json.loads(line)
                if (not isinstance(announcement, dict)
                        or announcement.get("schema") != "trnm.cell.listen.v1"
                        or not isinstance(announcement.get("address"), str)):
                    raise ValueError("finite producer listener announcement has an unknown shape")
                return announcement["address"]
            if server.poll() is not None:
                raise RuntimeError("finite producer exited before a complete listener announcement")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("finite producer did not announce its listener")
            time.sleep(min(0.01, remaining))


def retain_provider_terminal(server: subprocess.Popen | None, output: Path,
                             command: list[str] | None,
                             cleanup_timeout: float = 5.0) -> dict:
    """Reap the exact provider, then preserve actual logs and observed reports.

    A terminated provider may never emit a final serve report. Record that
    absence explicitly; do not fabricate counters or infer a network cause.
    """
    terminal = {"schema": "cell-native-provider-terminal-v1", "started": server is not None,
        "argv": command, "pid": None, "returncode": None, "cleanup_actions": [],
        "cleanup_errors": [], "reaped": server is None}
    if server is not None:
        terminal["pid"] = server.pid
        for action in ("terminate", "kill"):
            if server.poll() is not None:
                break
            terminal["cleanup_actions"].append(action)
            try:
                getattr(server, action)()
            except ProcessLookupError:
                pass
            except OSError as error:
                terminal["cleanup_errors"].append(f"{action}: {error}")
            try:
                server.wait(timeout=cleanup_timeout)
            except subprocess.TimeoutExpired:
                terminal["cleanup_errors"].append(f"{action}: wait timed out")
            except OSError as error:
                terminal["cleanup_errors"].append(f"{action}: wait: {error}")
        terminal["returncode"] = server.poll()
        terminal["reaped"] = terminal["returncode"] is not None
    for name in ("server-stdout.log", "server-stderr.log"):
        path = output / name
        if not path.exists():
            path.touch(exist_ok=False)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
        terminal[name] = {"bytes": path.stat().st_size, "sha256": sha(path)}
    write_json(output / "server-terminal.json", terminal)
    reports, malformed = [], []
    with (output / "server-stdout.log").open("rb") as stream:
        for number, line in enumerate(stream, 1):
            try:
                item = json.loads(line)
            except (ValueError, UnicodeError):
                malformed.append(number)
                continue
            if isinstance(item, dict) and item.get("schema") == "trnm.cell.serve.bounded.v1":
                reports.append({"stdout_line": number, "report": item})
    write_json(output / "server-serve-report.json", {
        "schema": "cell-native-provider-serve-observation-v1",
        "observation": "observed" if reports else "not_emitted",
        "source": "server-stdout.log", "reports": reports,
        "malformed_stdout_lines": malformed,
        "network_failure_cause_inferred": False})
    return terminal


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controlled-consumer-profile", choices=("smollm-signed-read-v1",))
    # Retain the original absolute-path invocation arguments. Hepta, Python,
    # just and target paths do not enable an unshipped native consumer.
    for name in ("chain", "hepta", "source-parent", "source-materials", "output",
                 "python", "cell-bin", "just", "hepta-target"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("cache-max-bytes", "cache-max-chunks", "cache-max-manifests", "cache-max-db-bytes"):
        parser.add_argument(f"--{name}", type=int, required=True)
    args = parser.parse_args()
    if min(args.cache_max_bytes, args.cache_max_chunks, args.cache_max_manifests, args.cache_max_db_bytes) <= 0:
        parser.error("cache limits must be positive and finite")
    if not 262_144 <= args.cache_max_db_bytes <= 2_199_023_255_552 or args.cache_max_db_bytes % 4096:
        parser.error("cache database image cap must be 4096-aligned and between 262144 and 2199023255552")
    cache_limits = ["--cache-max-bytes", str(args.cache_max_bytes),
                    "--cache-max-chunks", str(args.cache_max_chunks),
                    "--cache-max-manifests", str(args.cache_max_manifests),
                    "--cache-max-db-bytes", str(args.cache_max_db_bytes)]
    for value in (value for value in vars(args).values() if isinstance(value, Path)):
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
        "members": [],
    }
    if args.controlled_consumer_profile:
        evidence.update(schema="pon-smollm-cell-controlled-handoff-v2",
            scope="controlled-eleven-object-byte-closure-and-original-signed-read-not-I10")
    server = None
    server_command = None
    try:
        for name in ("server-stdout.log", "server-stderr.log"):
            (args.output / name).touch(exist_ok=False)
        evidence["cell_binary_sha256"] = sha(args.cell_bin)
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
            command = [str(args.cell_bin), "pack", *cache_limits, "--store", str(producer),
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
        command = [str(args.cell_bin), "prepare-release", *cache_limits, "--store", str(producer),
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
        if args.controlled_consumer_profile:
            import llm_cell_release
            evidence["controlled_byte_closure"] = llm_cell_release.prepare_sidecar(
                args, family, parent, contract, evidence["members"], release_file, release["release"], producer)
        if consumer.exists():
            raise ValueError("controlled consumer store must initially be absent")
        evidence["release"]["consumer_initially_absent"] = True
        # One finite producer, one initially empty consumer. These are controlled
        # loopback processes and never count as independent custody or a WAN test.
        with (args.output / "server-stdout.log").open("ab", buffering=0) as server_output, \
                (args.output / "server-stderr.log").open("ab", buffering=0) as server_error:
            server_command = [str(args.cell_bin), "serve", "--store", str(producer),
                "--bind", "127.0.0.1:0", "--seconds", "45", "--bounded-workers", "2",
                "--max-connections", str(connection_budget),
                "--max-served-bytes", str(response_budget)]
            server = subprocess.Popen(server_command, stdout=server_output, stderr=server_error)
            address = wait_for_provider_listener(server, args.output / "server-stdout.log")
            transfer_started = time.monotonic()
            transfer_deadline = transfer_started + 35
            transfer = {"schema": "cell-native-aggregate-transfer-v2", "clock": "monotonic",
                "limit_seconds": 35, "all_members_verified": False,
                "scope": "listener announced through aggregate TCR1 fetch, cache-only materialization and final consumer readback; excludes packing, release preparation, provider drain and Hepta load"}
            evidence["transfer"] = transfer
            try:
                remaining, overall_ms, request_ms = remaining_fetch_budget(transfer_deadline)
                complete_release = args.output / "consumer-release.tcr1"
                command = [str(args.cell_bin), "fetch-release", *cache_limits, "--store", str(consumer),
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
                        command = [str(args.cell_bin), "fetch", *cache_limits, "--store", str(consumer),
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
            server.wait(timeout=50)
            if server.returncode != 0:
                raise RuntimeError("finite producer did not stop successfully")
            evidence["producer_exit_code_before_consumer_load"] = server.returncode
        parent["directory"] = str(stage)
        consumer_parent = stage / "parent-material.json"
        write_json(consumer_parent, parent)
        evidence["source_parent_sha256"] = sha(args.source_parent)
        evidence["consumer_parent_sha256"] = sha(consumer_parent)
        if args.controlled_consumer_profile:
            evidence["controlled_native"] = llm_cell_release.consume_controlled(
                args, consumer_parent, evidence["controlled_byte_closure"])
            evidence["native_consumer_status"] = "CONTROLLED_LOAD_OBSERVED"
            raise RuntimeError("I10 selected installation UNAVAILABLE; controlled byte-closure load is not installation authority")
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
        try:
            terminal = retain_provider_terminal(server, args.output, server_command)
            evidence["provider_terminal_file"] = "server-terminal.json"
            evidence["provider_serve_report_file"] = "server-serve-report.json"
            if terminal["cleanup_actions"]:
                evidence["producer_cleanup_after_failure"] = True
            if not terminal["reaped"]:
                raise RuntimeError("finite producer cleanup did not reap the child")
        except BaseException as cleanup_error:
            evidence["provider_evidence_error"] = {
                "type": type(cleanup_error).__name__, "message": str(cleanup_error)}
            raise
        finally:
            evidence["elapsed_seconds"] = time.monotonic() - started
            write_json(args.output / "handoff.json", evidence)
            print(json.dumps({"status": evidence["status"], "report": str(args.output / "handoff.json")}))


if __name__ == "__main__":
    main()
