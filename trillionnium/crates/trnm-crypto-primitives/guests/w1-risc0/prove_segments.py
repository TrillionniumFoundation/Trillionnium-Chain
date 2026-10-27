#!/usr/bin/env python3
"""One complete unchanged W1 proof, using exactly two bounded segment workers.

Run only inside measure_step.py's fresh owned process group. Every host and
r0vm inherits that group; no worker starts a detached session. A failure retains
partial receipts but never assembles or qualifies an incomplete W1 proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from proof_resources import require_runner
from observations import read_single_result

STOP = False


def stopping(*_):
    global STOP
    STOP = True


def write_new(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def read(path, cap=1024 * 1024):
    if path.stat().st_size > cap:
        raise ValueError(f"JSON byte budget: {path.name}")
    return json.loads(path.read_text())


class Stage:
    def __init__(self, directory, name, command, timeout, *, logs=False):
        self.directory, self.name = directory, name
        self.started = time.monotonic()
        self.timeout = timeout
        self.finished = None
        self.stdout = (directory / f"{name}.stdout.log").open("xb")
        self.stderr = (directory / f"{name}.stderr.log").open("xb")
        environment = os.environ.copy()
        environment["RAYON_NUM_THREADS"] = "2"
        if logs:
            environment["RUST_LOG"] = ("risc0_zkvm::host::server::prove=debug,"
                "risc0_circuit_rv32im::prove=debug,risc0_zkp=info")
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                stdout=self.stdout, stderr=self.stderr, env=environment,
                start_new_session=False)
        except BaseException as error:
            self.stdout.close()
            self.stderr.close()
            write_new(directory / f"{name}.spawn-failure.json",
                {"name": name, "command": command, "error": repr(error),
                 "child_started": False, "complete_w1_proof_verified": False})
            raise
        self.record = {"schema": "pon-w1-segment-worker-process-v1",
            "command": command, "name": name, "pid": self.process.pid,
            "process_group": os.getpgrp(), "timeout_seconds": timeout,
            "source_sha": os.environ.get("TRNM_EXPECTED_SOURCE_SHA"),
            "started_monotonic": self.started, "child_reaped": False,
            "returncode": None, "complete_w1_proof_verified": False,
            "consensus_authority": False}
        write_new(directory / f"{name}.started.json", self.record)

    def poll(self):
        if self.finished is not None:
            return self.finished
        pid, status, usage = os.wait4(self.process.pid, os.WNOHANG)
        if not pid:
            return None
        code = os.waitstatus_to_exitcode(status)
        self.process.returncode = code
        self.finished = code
        self.stdout.close()
        self.stderr.close()
        self.record.update(returncode=code, child_reaped=True,
            wall_seconds=time.monotonic() - self.started,
            user_cpu_seconds=usage.ru_utime, system_cpu_seconds=usage.ru_stime,
            max_waited_descendant_rss_kib=usage.ru_maxrss,
            cpu_rss_scope="this independently waited host and descendants it waited for; orphan cleanup belongs to the outer phase record",
            raw_logs_hashed_after_phase_cleanup=False)
        write_new(self.directory / f"{self.name}.terminal.json", self.record)
        return code

    def check(self):
        code = self.poll()
        if code is not None and code != 0:
            raise RuntimeError(f"actual {self.name} failed with {code}")
        if code is None and time.monotonic() - self.started > self.timeout:
            raise TimeoutError(f"actual {self.name} exceeded {self.timeout}s")
        return code


def wait_stage(stage):
    while stage.check() is None:
        if STOP:
            raise InterruptedError("owned proving group cancelled")
        time.sleep(0.025)


def cleanup(stages):
    running = [stage for stage in stages if stage.poll() is None]
    if running:
        # This controller is its group's leader, created by the outer wrapper.
        # Its signal handler stays alive to retain direct-child terminations.
        os.killpg(os.getpgrp(), signal.SIGTERM)
        deadline = time.monotonic() + 5
        while running and time.monotonic() < deadline:
            running = [stage for stage in running if stage.poll() is None]
            time.sleep(0.025)
        for stage in running:
            try:
                stage.process.kill()
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 2
        while running and time.monotonic() < deadline:
            running = [stage for stage in running if stage.poll() is None]
            time.sleep(0.025)
    # If r0vm outlives a killed host, measure_step's subreaper collects it and
    # empties the original group before its final CPU/RSS/log observation.
    return [stage.name for stage in stages if stage.finished is None]


def run(args):
    if os.getpid() != os.getpgrp():
        raise RuntimeError("run requires measure_step.py's fresh owned process group")
    if os.environ.get("RAYON_NUM_THREADS") != "2":
        raise RuntimeError("the reviewed worker profile requires RAYON_NUM_THREADS=2")
    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    directory = args.out / "segmented"
    directory.mkdir()
    receipts = directory / "receipts"
    receipts.mkdir()
    steps = directory / "steps"
    steps.mkdir()
    session_dir = directory / "session"
    stages = []
    started = time.monotonic()
    result = None
    outcome = {"schema": "pon-w1-segmented-attempt-v1", "workers": 2,
        "rayon_threads_per_worker": 2, "segment_timeout_seconds": 300,
        "outer_complete_attempt_timeout_seconds": 3600,
        "source_sha": os.environ.get("TRNM_EXPECTED_SOURCE_SHA"),
        "completed_segment_indexes": [], "real_composite_stark_verified": False,
        "partial_receipts_are_complete_proofs": False, "consensus_authority": False}
    try:
        resources = require_runner(directory / "resources.json")
        export = Stage(steps, "export", [args.host, "export-segments", args.r0vm,
            args.elf, args.input, "18", str(session_dir)], 300)
        stages.append(export)
        wait_stage(export)
        session = read(session_dir / "session.json")
        items = session["segments"]
        if not (0 < len(items) <= 2048 and session["full_w1_guest_executed"] is True
                and session["segment_po2_limit"] == 18):
            raise RuntimeError("no complete exported original-profile session")
        pending = list(range(len(items)))
        active = {}
        while pending or active:
            if STOP or time.monotonic() - started >= 3500:
                raise TimeoutError("complete proof work stopped within the outer 3600s cap")
            while pending and len(active) < 2:
                index = pending.pop(0)
                stage = Stage(steps, f"segment-{index}", [args.host, "prove-segment",
                    args.r0vm, str(session_dir), str(index),
                    str(receipts / f"segment-{index}.bin"),
                    str(receipts / f"segment-{index}.json")], 300, logs=True)
                stages.append(stage)
                active[index] = stage
            for index, stage in list(active.items()):
                if stage.check() is None:
                    continue
                report = read(receipts / f"segment-{index}.json")
                if not (report["index"] == index and report["real_segment_stark_verified"] is True
                        and report["complete_w1_proof_verified"] is False
                        and report["segment_sha256"] == items[index]["sha256"]):
                    raise RuntimeError("unverified or foreign segment result")
                outcome["completed_segment_indexes"].append(index)
                print(json.dumps({"completed_segment": index, "total_segments": len(items),
                    "wall_seconds": stage.record["wall_seconds"],
                    "user_cpu_seconds": stage.record["user_cpu_seconds"],
                    "system_cpu_seconds": stage.record["system_cpu_seconds"],
                    "receipt_bytes": report["receipt_bytes"]}), file=sys.stderr, flush=True)
                del active[index]
            time.sleep(0.025)
        if sorted(outcome["completed_segment_indexes"]) != list(range(len(items))):
            raise RuntimeError("incomplete segment set; no assembly is permitted")
        assembly = Stage(steps, "assembly", [args.host, "assemble-segments",
            args.elf, args.input, str(session_dir), str(receipts),
            str(args.out / "receipt.bin")], 300)
        stages.append(assembly)
        wait_stage(assembly)
        result = read_single_result(steps / "assembly.stdout.log",
                                  "pon-w1-segmented-assembly-v1")
        if result["real_composite_stark_verified"] is not True:
            raise RuntimeError("final strict complete proof verification failed")
        outcome.update(real_composite_stark_verified=True,
            wall_seconds=time.monotonic() - started, resources=resources)
        result.update(schema="pon-w1-risc0-research-v1", operation="prove",
            proving_schedule="two-independent-workers-two-rayon-threads-each",
            prove_including_execution_and_integrity_verify_wall_ns=int(outcome["wall_seconds"] * 1_000_000_000),
            independent_hashcash=False)
    except BaseException as error:
        outcome.update(error=repr(error), wall_seconds=time.monotonic() - started)
        raise
    finally:
        try:
            outcome["direct_children_missing_terminal"] = cleanup(stages)
        except BaseException as error:
            outcome["cleanup_error"] = repr(error)
            raise
        finally:
            outcome["live_process_sampling"] = {"owner": "measure_step.py",
                "record": "prove.process.json", "samples": "prove.proc-group.jsonl",
                "interval_seconds": 15, "unavailable_samples_are_zero": False}
            write_new(directory / "attempt.json", outcome)
    if outcome["direct_children_missing_terminal"]:
        raise RuntimeError("direct worker termination was not fully observed")
    print(json.dumps(result), flush=True)


def finalize(out):
    directory = out / "segmented"
    if not directory.is_dir():
        return
    phase = read(out / "prove.process.json")
    if phase.get("owned_process_group_empty") is not True or phase.get("child_reaped") is not True:
        raise RuntimeError("raw segment logs cannot be finalized before owned group cleanup")
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("unexpected symlink in retained proof assets")
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            files[str(path.relative_to(directory))] = {"bytes": path.stat().st_size,
                                                       "sha256": digest.hexdigest()}
    write_new(out / "segmented-evidence-index.json",
        {"schema": "pon-w1-segmented-final-evidence-index-v1",
         "phase": phase, "files": files, "source_sha": phase.get("source_sha"),
         "partial_receipts_are_complete_proofs": False, "consensus_authority": False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--finalize", action="store_true")
    for name in ["host", "r0vm", "elf", "input"]:
        parser.add_argument("--" + name)
    args = parser.parse_args()
    if args.finalize:
        finalize(args.out)
    else:
        if not all([args.host, args.r0vm, args.elf, args.input]):
            parser.error("host, r0vm, elf and full W1 input are required")
        run(args)


if __name__ == "__main__":
    main()
