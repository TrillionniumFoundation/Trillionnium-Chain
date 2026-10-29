#!/usr/bin/env python3
"""Bounded local Composite receipt transport research, never a live PoN codec.

The public entry first runs the real, explicitly trusted host verifier. Only
then may retained receipt bytes enter a fixed IPv4 loopback transport campaign.
Synthetic wire tests call helpers directly and cannot qualify a proof cost.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

MAGIC = b"PWCO0001"
INPUT_BYTES = 49640
RECEIPT_CAP = 128 * 1024 * 1024
PROGRAM_CAP = 16 * 1024 * 1024
HOST_CAP = 256 * 1024 * 1024
CHUNK = 65536
FRAME_CAP = 16 + INPUT_BYTES + RECEIPT_CAP
CAMPAIGN_SECONDS = 2400
VERIFY_SECONDS = 900
NETWORK_SECONDS = 30
ADDRESS_SPACE = 2 * 1024 * 1024 * 1024
LOG_CAP = 128 * 1024
BACKEND = Path("trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0")
E_OBSERVER_SHA256 = "fb3fd8a033ac0781052b5da55577bbeb59e6f4c714d2b4b3ff8e2c6c866e62bd"
ASSET_CAPS = {"host": HOST_CAP, "program": PROGRAM_CAP, "input": INPUT_BYTES, "receipt": RECEIPT_CAP}
CASES = ("positive-0", "positive-1", "positive-2", "wrong-magic", "wrong-input-length",
         "over-receipt-cap", "truncated-receipt", "trailing-byte")


class Refusal(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def remaining(deadline):
    value = deadline - time.monotonic()
    require(value > 0, "deadline")
    return value


def stable_identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def regular(path, cap, exact=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= cap, "regular-input-cap")
        require(exact is None or info.st_size == exact, "exact-input-length")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def fingerprint(descriptor, deadline, cap):
    before = os.fstat(descriptor)
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, "fingerprint-input-cap")
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        remaining(deadline)
        piece = os.pread(descriptor, min(CHUNK, before.st_size - offset), offset)
        require(piece, "input-short-read")
        digest.update(piece)
        offset += len(piece)
    require(stable_identity(before) == stable_identity(os.fstat(descriptor)), "input-changed")
    return {"bytes": offset, "sha256": digest.hexdigest(), "identity": list(stable_identity(before))}


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result

    def constant(_):
        raise Refusal("nonfinite-json")

    def floating(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite-json")
        return number

    return json.loads(raw, object_pairs_hook=unique, parse_constant=constant, parse_float=floating)


def read_json(path, deadline, cap=LOG_CAP):
    descriptor = regular(path, cap)
    try:
        before = fingerprint(descriptor, deadline, cap)
        raw = os.pread(descriptor, before["bytes"], 0)
        require(before == fingerprint(descriptor, deadline, cap), "json-changed")
        value = decode(raw)
        require(type(value) is dict, "json-object-required")
        return value
    finally:
        os.close(descriptor)


def durable_json(path, value):
    raw = (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()
    require(len(raw) <= LOG_CAP, "record-cap")
    with Path(path).open("xb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def header(input_bytes, receipt_bytes, magic=MAGIC):
    return struct.pack("<8sII", magic, input_bytes, receipt_bytes)


def parse_header(raw):
    require(len(raw) == 16, "short-header")
    magic, input_bytes, receipt_bytes = struct.unpack("<8sII", raw)
    require(magic == MAGIC, "wrong-magic")
    require(input_bytes == INPUT_BYTES, "wrong-input-length")
    require(0 < receipt_bytes <= RECEIPT_CAP and 16 + input_bytes + receipt_bytes <= FRAME_CAP,
            "receipt-cap")
    return input_bytes, receipt_bytes


def receive_exact(connection, count, deadline, counters):
    output = bytearray()
    require(0 <= count <= CHUNK, "read-chunk-cap")
    while len(output) < count:
        connection.settimeout(remaining(deadline))
        piece = connection.recv(count - len(output))
        require(piece, "truncated-frame")
        output.extend(piece)
        counters["received_bytes"] += len(piece)
    return bytes(output)


def send_piece(connection, piece, deadline, counters):
    require(len(piece) <= CHUNK, "send-chunk-cap")
    view = memoryview(piece)
    while view:
        connection.settimeout(remaining(deadline))
        sent = connection.send(view)
        require(sent > 0, "send-stalled")
        counters["sent_bytes"] += sent
        require(counters["sent_bytes"] <= FRAME_CAP + 1, "sent-frame-cap")
        view = view[sent:]


def transfer(case, input_fd, receipt_fd, expected, output, deadline):
    """One real TCP loopback transfer; does not claim cryptographic validity."""
    require(case in CASES, "unknown-network-case")
    output = Path(output)
    output.mkdir(mode=0o700)
    deadline = min(deadline, time.monotonic() + NETWORK_SECONDS)
    effective_deadline_seconds = remaining(deadline)
    counters = {"sent_bytes": 0, "received_bytes": 0}
    received = {"accepted": False, "refusal": None, "error": None}
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connections = []
    sender_error = None
    started = time.monotonic_ns()
    worker_cpu_before = time.process_time_ns()

    def receiver():
        thread_cpu_before = time.thread_time_ns()
        receiver_started = time.monotonic_ns()
        try:
            listener.settimeout(remaining(deadline))
            connection, peer = listener.accept()
            connections.append(connection)
            require(peer[0] == "127.0.0.1", "non-loopback-peer")
            lengths = parse_header(receive_exact(connection, 16, deadline, counters))
            identities = {}
            for label, length in zip(("input", "receipt"), lengths):
                digest = hashlib.sha256()
                with (output / (label + ".bin")).open("xb") as target:
                    left = length
                    while left:
                        piece = receive_exact(connection, min(CHUNK, left), deadline, counters)
                        target.write(piece)
                        digest.update(piece)
                        left -= len(piece)
                    target.flush()
                    os.fsync(target.fileno())
                identities[label] = {"bytes": length, "sha256": digest.hexdigest()}
            connection.settimeout(remaining(deadline))
            tail = connection.recv(1)
            counters["received_bytes"] += len(tail)
            require(not tail, "trailing-byte")
            for label, actual in identities.items():
                require(actual == {key: expected[label][key] for key in ("bytes", "sha256")},
                        "received-asset-digest")
            received.update(accepted=True, assets=identities)
        except Refusal as error:
            received["refusal"] = str(error)
        except (OSError, ValueError) as error:
            received["error"] = {"type": type(error).__name__, "errno": getattr(error, "errno", None)}
        finally:
            received["wall_ns"] = time.monotonic_ns() - receiver_started
            received["thread_cpu_ns"] = time.thread_time_ns() - thread_cpu_before
            for connection in connections:
                connection.close()

    receiver_thread = None
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        address = listener.getsockname()
        receiver_thread = threading.Thread(target=receiver, daemon=True)
        receiver_thread.start()
        sender_cpu_before = time.thread_time_ns()
        sender_started = time.monotonic_ns()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sender:
            sender.settimeout(remaining(deadline))
            sender.connect(address)
            raw_header = header(INPUT_BYTES, expected["receipt"]["bytes"])
            if case == "wrong-magic":
                raw_header = header(INPUT_BYTES, expected["receipt"]["bytes"], b"PWAI0001")
            elif case == "wrong-input-length":
                raw_header = header(INPUT_BYTES - 1, expected["receipt"]["bytes"])
            elif case == "over-receipt-cap":
                raw_header = header(INPUT_BYTES, RECEIPT_CAP + 1)
            send_piece(sender, raw_header, deadline, counters)
            if case not in ("wrong-magic", "wrong-input-length", "over-receipt-cap"):
                for label, descriptor in (("input", input_fd), ("receipt", receipt_fd)):
                    count = expected[label]["bytes"]
                    if case == "truncated-receipt" and label == "receipt":
                        count = min(4096, count - 1)
                    offset = 0
                    while offset < count:
                        piece = os.pread(descriptor, min(CHUNK, count - offset), offset)
                        require(piece, "sender-short-read")
                        send_piece(sender, piece, deadline, counters)
                        offset += len(piece)
                if case == "trailing-byte":
                    send_piece(sender, b"\0", deadline, counters)
            sender.shutdown(socket.SHUT_WR)
        sender = {"wall_ns": time.monotonic_ns() - sender_started,
                  "thread_cpu_ns": time.thread_time_ns() - sender_cpu_before}
    except (OSError, ValueError) as error:
        sender_error = {"type": type(error).__name__, "errno": getattr(error, "errno", None),
                        "reason": str(error)[:256]}
        sender = {}
    finally:
        if receiver_thread is not None:
            receiver_thread.join(max(0, deadline - time.monotonic()))
        listener.close()
        for connection in connections:
            connection.close()
    require(receiver_thread is not None and not receiver_thread.is_alive(), "receiver-cleanup-deadline")
    expected_refusal = {"wrong-magic": "wrong-magic", "wrong-input-length": "wrong-input-length",
                        "over-receipt-cap": "receipt-cap", "truncated-receipt": "truncated-frame",
                        "trailing-byte": "trailing-byte"}.get(case)
    passed = (sender_error is None and received["error"] is None and
              (received["accepted"] if expected_refusal is None
               else not received["accepted"] and received["refusal"] == expected_refusal))
    return {"schema": "pon-w1-receipt-loopback-case-v1", "case": case,
            "transport": "IPv4 TCP 127.0.0.1 only", "wire_namespace": MAGIC.decode(),
            "network_deadline_seconds": NETWORK_SECONDS, "passed": passed,
            "effective_deadline_seconds": effective_deadline_seconds,
            "expected_refusal": expected_refusal, "sender": sender, "sender_error": sender_error,
            "receiver": received, "counters": counters,
            "local_transfer_wall_ns": time.monotonic_ns() - started,
            "worker_self_cpu_ns": time.process_time_ns() - worker_cpu_before,
            "cpu_scope": "thread CPU overlaps worker self CPU; do not add them",
            "io_scope": "sender pread/send; receiver recv/write/hash/fsync/EOF, includes local file I/O",
            "physical_network_bytes_measured": False, "wan_measurement": False,
            "cryptographic_verification_performed_here": False}


def verify_child(host_fd, program_fd, input_fd, receipt_fd):
    # One child execs the held ELF in the same process group as the campaign.
    # The outer reserved-leader owner can therefore contain a timeout at any phase.
    resource.setrlimit(resource.RLIMIT_FSIZE, (LOG_CAP, LOG_CAP))
    resource.setrlimit(resource.RLIMIT_CPU, (2 * VERIFY_SECONDS, 2 * VERIFY_SECONDS + 1))
    for descriptor in (program_fd, input_fd, receipt_fd):
        os.set_inheritable(descriptor, True)
    require(os.pread(host_fd, 4, 0) == b"\x7fELF", "host-not-elf")
    os.execve(host_fd, ["trnm-w1-risc0-host", "verify", *[
        "/proc/self/fd/" + str(value) for value in (program_fd, input_fd, receipt_fd)]], os.environ)


def verify_once(host_fd, program_fd, input_fd, receipt_fd, output, expected, deadline):
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "sigchld-disposition")
    output = Path(output)
    output.mkdir(mode=0o700)
    before = {name: fingerprint(fd, deadline, ASSET_CAPS[name]) for name, fd in
              (("host", host_fd), ("program", program_fd), ("input", input_fd), ("receipt", receipt_fd))}
    require(all(before[name][key] == expected[name][key] for name in before for key in ("bytes", "sha256")),
            "verifier-input-digests")
    allotted = min(VERIFY_SECONDS, remaining(deadline))
    end = time.monotonic() + allotted
    started = time.monotonic_ns()
    child = None
    timed_out = False
    waited = None
    record = {"schema": "pon-w1-receipt-independent-verify-cost-v1", "timeout_seconds": allotted,
              "before": before, "timed_out": False, "passed": False, "runner_error": None}
    try:
        with (output / "stdout.log").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
            child = subprocess.Popen([str(Path(sys.executable).resolve()), "-B", str(Path(__file__).resolve()),
                                      "_verify", *map(str, (host_fd, program_fd, input_fd, receipt_fd))],
                                     stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     pass_fds=(host_fd, program_fd, input_fd, receipt_fd), start_new_session=False)
            while True:
                event = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if event is not None:
                    require(event.si_pid == child.pid, "wait-identity")
                    break
                if time.monotonic() >= end:
                    timed_out = True
                    break
                time.sleep(min(0.02, max(0, end - time.monotonic())))
    except (OSError, ValueError) as error:
        record["runner_error"] = {"type": type(error).__name__, "errno": getattr(error, "errno", None)}
    finally:
        if child is not None:
            # SIGCHLD remains default and no wait/poll/reap precedes this signal.
            # Reserve the child PID even when waitid observed its exit.
            try:
                os.kill(child.pid, signal.SIGKILL)
                cleanup_end = min(deadline, time.monotonic() + 2)
                while time.monotonic() < cleanup_end:
                    event = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if event is not None:
                        pid, status, usage = os.wait4(child.pid, 0)
                        require(pid == child.pid, "reap-identity")
                        child.returncode = os.waitstatus_to_exitcode(status)
                        waited = {"returncode": child.returncode, "user_cpu_seconds": usage.ru_utime,
                                  "system_cpu_seconds": usage.ru_stime, "max_rss_kib": usage.ru_maxrss}
                        break
                    time.sleep(0.01)
            except (OSError, ValueError) as error:
                record["cleanup_error"] = {"type": type(error).__name__, "errno": getattr(error, "errno", None)}
        record.update(wall_ns=time.monotonic_ns() - started, timed_out=timed_out, direct_wait4=waited)
    try:
        require(waited is not None and "cleanup_error" not in record, "verify-cleanup-incomplete")
        record["after"] = {name: fingerprint(fd, deadline, ASSET_CAPS[name]) for name, fd in
                           (("host", host_fd), ("program", program_fd), ("input", input_fd), ("receipt", receipt_fd))}
        if record["runner_error"] is None and not timed_out and waited["returncode"] == 0:
            result = read_json(output / "stdout.log", deadline)
            record["actual_host_output"] = result
            record["passed"] = (before == record["after"] and result.get("schema") == "pon-w1-risc0-research-v1"
                and result.get("operation") == "verify" and result.get("real_composite_stark_verified") is True
                and result.get("native_w1_recomputed") is False and result.get("consensus_authority") is False
                and result.get("receipt_bytes") == expected["receipt"]["bytes"]
                and result.get("image_id") == expected["image_id"]
                and result.get("statement_id") == expected["statement_id"])
    except (OSError, ValueError, KeyError) as error:
        record["readback_error"] = {"type": type(error).__name__, "reason": str(error)[:256]}
    finally:
        record["cpu_scope"] = "direct verifier child wait4; keep separate from outer owner family observations"
        durable_json(output / "result.json", record)
    require(record["passed"], "actual-verifier-did-not-pass")
    return record


def campaign(args):
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE, ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (RECEIPT_CAP, RECEIPT_CAP))
    require("RISC0_DEV_MODE" not in os.environ, "ambient-development-mode")
    require(os.environ.get("RAYON_NUM_THREADS") == "2", "explicit-two-thread-setting-required")
    deadline = time.monotonic() + CAMPAIGN_SECONDS
    out = args.out / "campaign"
    out.mkdir(mode=0o700)
    descriptors = {}
    result = {"schema": "pon-w1-real-receipt-loopback-observation-v1", "passed": False,
              "real_receipt_verified_before_network": False, "received_receipt_verified": False,
              "qualified_cost": None, "cases": [], "failure": None, "wan_measurement": False,
              "production_admission": False, "global_worst_invalid_proof_established": False,
              "runtime_environment": {key: os.environ.get(key) for key in ("RAYON_NUM_THREADS", "RISC0_DEV_MODE", "RUST_LOG")}}
    try:
        source = read_json(args.artifact / "source-before.json", deadline)
        after = read_json(args.artifact / "source-after.json", deadline)
        require(canonical(source) == canonical(after) and source.get("tested_commit") == args.expected_proof_source
                and source.get("tracked_worktree_verified") is True, "proof-source-binding")
        manifest = read_json(args.artifact / "backend-manifest.json", deadline)
        pinned = read_json(args.repository_root / BACKEND / "backend-manifest.json", deadline)
        require(canonical(manifest) == canonical(pinned), "pinned-manifest")
        proof = read_json(args.artifact / "prove.stdout.log", deadline)
        observed = read_json(args.artifact / "prove.observer.json", deadline, 256 * 1024)
        process = read_json(args.artifact / "prove.process.json", deadline)
        require(type(process.get("returncode")) is int and process["returncode"] == 0 and process.get("timed_out") is False
                and process.get("source_sha") == args.expected_proof_source, "original-proof-process")
        require(observed.get("source_sha") == args.expected_proof_source
                and canonical(observed.get("host_before")) == canonical(observed.get("host_after"))
                and observed.get("finite_cleanup_observed") is True and observed.get("failure") is None,
                "original-prover-observer")
        require(proof.get("operation") == "prove" and proof.get("real_composite_stark_verified") is True
                and proof.get("independent_hashcash") is False, "actual-composite-proof-record")
        for name, path, cap, exact in (
            ("host", args.host, HOST_CAP, None),
            ("program", args.artifact / "guest.bin", PROGRAM_CAP, None),
            ("input", args.artifact / "input.bin", INPUT_BYTES, INPUT_BYTES),
            ("receipt", args.artifact / "receipt.bin", RECEIPT_CAP, None)):
            descriptors[name] = regular(path, cap, exact)
        assets = {name: fingerprint(fd, deadline, ASSET_CAPS[name]) for name, fd in descriptors.items()}
        require(assets["host"]["sha256"] == args.expected_host_sha256, "trusted-host-identity")
        require(type(observed.get("host_before")) is dict
                and type(observed["host_before"].get("sha256")) is str, "original-host-identity")
        require(assets["program"]["sha256"] == manifest["guest_program_sha256"]
                and proof.get("image_id") == manifest["guest_image_id"]
                and proof.get("receipt_bytes") == assets["receipt"]["bytes"], "proof-assets")
        expected = dict(assets, image_id=manifest["guest_image_id"], statement_id=proof["statement_id"])
        result.update(proof_source=source, assets=assets, frame_bytes=16 + INPUT_BYTES + assets["receipt"]["bytes"],
                      original_prover_host_sha256=observed["host_before"]["sha256"],
                      same_host_binary_as_prover=assets["host"]["sha256"] == observed["host_before"]["sha256"],
                      verifier_binary_provenance="caller-supplied trusted expected SHA-256; harness does not compile or attest source",
                      original_pwai_supported=False,
                      pwai_receipt_byte_budget=1048576 - 16 - INPUT_BYTES,
                      pwai_reason="PWAI0001 requires Succinct and 1MiB total; this is a Composite research transport")
        result["verify_before"] = verify_once(descriptors["host"], descriptors["program"],
            descriptors["input"], descriptors["receipt"], out / "verify-before", expected, deadline)
        result["real_receipt_verified_before_network"] = True
        for case in CASES:
            remaining(deadline)
            directory = out / case
            try:
                observation = transfer(case, descriptors["input"], descriptors["receipt"], expected, directory, deadline)
            except (OSError, ValueError) as error:
                observation = {"schema": "pon-w1-receipt-loopback-case-v1", "case": case,
                               "passed": False, "incomplete_measurement": True,
                               "error": {"type": type(error).__name__, "reason": str(error)[:256],
                                         "errno": getattr(error, "errno", None)}}
            durable_json(out / (case + ".json"), observation)
            result["cases"].append(observation)
            require(observation["passed"], "network-case-failed:" + case)
            if case != "positive-2":
                for name in ("input.bin", "receipt.bin"):
                    path = directory / name
                    if path.exists():
                        path.unlink()  # Only files created in this invocation's exclusive directory.
        received = out / "positive-2"
        descriptors["received_input"] = regular(received / "input.bin", INPUT_BYTES, INPUT_BYTES)
        descriptors["received_receipt"] = regular(received / "receipt.bin", RECEIPT_CAP)
        result["verify_received"] = verify_once(descriptors["host"], descriptors["program"],
            descriptors["received_input"], descriptors["received_receipt"], out / "verify-received", expected, deadline)
        result["received_receipt_verified"] = True
        result["assets_after"] = {name: fingerprint(descriptors[name], deadline, ASSET_CAPS[name]) for name in assets}
        require(result["assets_after"] == assets, "source-assets-changed")
        result.update(passed=True, qualified_cost="finite actual-receipt local transport and verifier observations only")
    except (OSError, ValueError, KeyError) as error:
        result["failure"] = {"type": type(error).__name__, "reason": str(error)[:512],
                             "errno": getattr(error, "errno", None)}
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        durable_json(out / "result.json", result)
    return 0 if result["passed"] else 1


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--expected-proof-source", required=True)
    parser.add_argument("--expected-host-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    require(len(args.expected_proof_source) == 40 and all(c in "0123456789abcdef" for c in args.expected_proof_source),
            "proof-source-shape")
    require(len(args.expected_host_sha256) == 64 and all(c in "0123456789abcdef" for c in args.expected_host_sha256),
            "host-digest-shape")
    for name in ("repository_root", "artifact", "host", "out"):
        setattr(args, name, getattr(args, name).absolute())
    return args


def owned_campaign(observer, command, out):
    """Poll cancellation only at the owner's existing explicit deadline points.

The signal handler never raises across Popen: its child may exist before the
caller has received/assigned the PID. The scoped adapter is part of this
harness's source identity, separate from the unchanged E owner source bytes.
"""
    interrupted = None
    work_deadline = None
    original_deadline_check = observer.deadline_check

    def interrupt(number, _frame):
        nonlocal interrupted
        if interrupted is None:
            interrupted = number

    def safe_point(deadline):
        nonlocal work_deadline
        if work_deadline is None:
            work_deadline = deadline
        # Sampling can catch an OSError as a missing /proc observation. Keep
        # refusing subsequent work points until the owner reaches its outer
        # handler. Its separate cleanup deadline must remain operational.
        if interrupted is not None and deadline == work_deadline:
            raise InterruptedError(errno.EINTR, "receipt campaign cancelled")
        original_deadline_check(deadline)

    previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        observer.deadline_check = safe_point
        for number in previous:
            signal.signal(number, interrupt)
        result = observer.run_observed(command, out, CAMPAIGN_SECONDS)
    finally:
        observer.deadline_check = original_deadline_check
        for number, disposition in previous.items():
            signal.signal(number, disposition)
    return result, interrupted


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["_verify"]:
        require(len(argv) == 5, "verify-exec-arity")
        verify_child(*map(int, argv[1:]))
    worker = argv[:1] == ["_campaign"]
    args = arguments(argv[1:] if worker else argv)
    if worker:
        return campaign(args)
    require(sys.platform == "linux", "linux-only-owner")
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "sigchld-disposition")
    require(os.environ.get("RAYON_NUM_THREADS") == "2", "explicit-two-thread-setting-required")
    sys.dont_write_bytecode = True
    descriptor = regular(args.repository_root / BACKEND / "proof_observer_v1.py", 256 * 1024)
    try:
        observed_source = os.pread(descriptor, 256 * 1024, 0)
    finally:
        os.close(descriptor)
    require(hashlib.sha256(observed_source).hexdigest() == E_OBSERVER_SHA256, "fixed-E-owner-source")
    descriptor = regular(Path(__file__), 256 * 1024)
    try:
        harness_source = os.pread(descriptor, 256 * 1024, 0)
    finally:
        os.close(descriptor)
    args.out.mkdir(mode=0o700)
    observer_file = args.out / "fixed-proof-owner.py"
    harness_file = args.out / "fixed-receipt-campaign.py"
    for path, raw in ((observer_file, observed_source), (harness_file, harness_source)):
        with path.open("xb") as output:
            output.write(raw)
        path.chmod(0o400)
    spec = importlib.util.spec_from_file_location("receipt_transport_fixed_owner", observer_file)
    observer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observer)
    command = [str(Path(sys.executable).resolve()), "-B", str(harness_file), "_campaign", *argv]
    observed, interrupted = owned_campaign(observer, command, args.out / "owner")
    final = {
        "schema": "pon-w1-receipt-loopback-owner-v1", "fixed_observer_sha256": E_OBSERVER_SHA256,
        "harness_sha256": hashlib.sha256(harness_source).hexdigest(), "passed": False,
        "interrupted_signal": interrupted,
        "cancellation_adapter": "harness flag-only signal handler; every original work-deadline safe point refuses after cancellation; separate cleanup deadline unchanged",
        "outer_returncode": observed["returncode"], "finite_cleanup_observed": observed["finite_cleanup_observed"],
        "outer_observation": "owner/prove.observer.json", "whole_family_peak_memory_qualified": False,
        "wire_frame_cap": FRAME_CAP, "network_case_count": len(CASES), "positive_transfers": 3,
        "maximum_network_application_bytes": 5 * (FRAME_CAP + 1),
        "per_process_address_space_limit": ADDRESS_SPACE,
        "maximum_owned_verifier_children_at_once": 1, "maximum_network_receiver_threads": 1,
        "wall_seconds": observed["wall_seconds"], "global_worst_invalid_proof_established": False,
        "wan_measurement": False, "production_admission": False}
    try:
        completed = read_json(args.out / "campaign/result.json", time.monotonic() + 2)
        final["passed"] = (interrupted is None and observed["returncode"] == 0 and observed["finite_cleanup_observed"] is True
            and completed.get("passed") is True and completed.get("real_receipt_verified_before_network") is True
            and completed.get("received_receipt_verified") is True and len(completed.get("cases", [])) == len(CASES)
            and all(case.get("passed") is True for case in completed["cases"]))
        final["qualified_cost"] = completed.get("qualified_cost") if final["passed"] else None
    except (OSError, ValueError, KeyError) as error:
        final["readback_error"] = {"type": type(error).__name__, "reason": str(error)[:256]}
        final["qualified_cost"] = None
    durable_json(args.out / "campaign-owner.json", final)
    return 0 if final["passed"] else observed["returncode"] or 125


if __name__ == "__main__":
    raise SystemExit(main())
