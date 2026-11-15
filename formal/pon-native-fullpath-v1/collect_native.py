#!/usr/bin/env python3
"""Prospective, same-host native observations. This never grants qualification.

The fixed development binary performs all Node work. The parent timestamps
flushed events on ONE monotonic clock and retains failed processes and inputs.
Build time and this driver's source audit precede the recorded experiment.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import threading
import time

MAX_OUTPUT = 4 * 1024 * 1024
MAX_PACKET = 1024 * 1024
CLEANUP_TIMEOUT = 2
SCHEMA = "trnm-native-fullpath-process-observations-v1"
SOURCE_AUDIT_SCHEMA = "trnm-native-fullpath-raw-source-audit-v1"
SOURCE_BINDING_SCHEMA = "trnm-native-fullpath-raw-source-binding-v1"
# Reuse the exact-head guard used by CI. Git porcelain alone can hide changed
# bytes through clean filters or index flags, and does not bind executed source.
_verifier_spec = importlib.util.spec_from_file_location(
    "fullpath_ci_source", Path(__file__).resolve().parents[2] / "scripts/ci/verify_ci_source.py")
_verifier = importlib.util.module_from_spec(_verifier_spec)
_verifier_spec.loader.exec_module(_verifier)
verify_source = _verifier.verify


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n").encode()


def declares_error(value):
    return isinstance(value, dict) and (value.get("event") == "error" or value.get("status") == "error")


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    return {"path": path.name, "sha256": digest(data)}



def audit_source(repo, expected_source, root, stage):
    """Retain strict raw-byte snapshots, including unsuccessful preparations.

    The audit is outside the timed experiment and is not execution attestation,
    build provenance, resource enforcement, or a new public-service gate.
    Existing process/context v1 formats keep their original fields and meaning.
    """
    if stage not in ("before", "after"):
        raise ValueError("source audit stage must be before or after")
    receipt = {"schema": SOURCE_AUDIT_SCHEMA, "stage": stage,
        "expected_source_commit": expected_source, "snapshot": None, "error": None,
        "scope": "tracked-raw-source-snapshot-only",
        "execution_attested": False, "original_host_contract_qualified": False}
    try:
        receipt["snapshot"] = verify_source("head", expected_source, root=repo)
    except Exception as error:
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
        save(root / f"source-{stage}.json", canonical(receipt))
        raise
    reference = save(root / f"source-{stage}.json", canonical(receipt))
    return receipt["snapshot"], reference


def usage():
    own = resource.getrusage(resource.RUSAGE_SELF)
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "cpu_ns": round((own.ru_utime + own.ru_stime + child.ru_utime + child.ru_stime) * 1e9),
        # Roles are sequential. Sum of the separately observed parent and child
        # maxima bounds their concurrent RSS; it is not an instantaneous sample.
        "peak_rss_upper_bound_bytes": (own.ru_maxrss + child.ru_maxrss) * 1024,
    }


class Collector:
    def __init__(self, binary, root, epoch_ns, process_timeout):
        self.binary = binary
        self.root = root
        self.epoch_ns = epoch_ns
        self.process_timeout = process_timeout
        self.rows = []
        self.unresolved_owner = None

    def now(self):
        return time.monotonic_ns() - self.epoch_ns

    def settle(self, proc, threads, errors, notes):
        """Bounded cleanup; a leader exit is not proof that its group/pipes ended."""
        def poll():
            try:
                proc.poll()
            except OSError as error:
                errors.append(f"POLL:{type(error).__name__}:{error}")

        def group_gone():
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                return True
            except OSError as error:
                errors.append(f"GROUP_PROBE:{type(error).__name__}:{error}")
            return False

        def join():
            for thread in threads:
                thread.join(timeout=CLEANUP_TIMEOUT)

        poll()
        if proc.returncode is not None:
            join()
        attempted = False
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if proc.returncode is not None and not any(t.is_alive() for t in threads) and group_gone():
                break
            attempted = True
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                # The process can exit between wait's timeout and this signal.
                # Still wait/reap it; ESRCH alone is not a successful wait.
                notes.append(f"SIGNAL_{sig}:ProcessLookupError")
            except OSError as error:
                errors.append(f"SIGNAL_{sig}:{type(error).__name__}:{error}")
            try:
                proc.wait(timeout=CLEANUP_TIMEOUT)
            except subprocess.TimeoutExpired:
                notes.append(f"WAIT_AFTER_SIGNAL_{sig}:TimeoutExpired")
            except OSError as error:
                errors.append(f"WAIT_AFTER_SIGNAL_{sig}:{type(error).__name__}:{error}")
            join()
            poll()
        return (proc.returncode is not None,
                not any(t.is_alive() for t in threads), group_gone(), attempted)

    def run(self, label, args, packet=None):
        before = usage()
        start = self.now()
        out_path = self.root / (label + ".stdout.ndjson")
        err_path = self.root / (label + ".stderr.txt")
        events, reader_errors, feeder_errors = [], [], []
        process_errors, cleanup_errors, cleanup_notes, output_errors = [], [], [], []
        sent = [0]
        argv = [str(self.binary), *map(str, args)]
        blocked_by = self.unresolved_owner
        proc, stdout, stderr, read_thread = None, None, None, None
        threads = []
        timed_out = cleanup_attempted = owner_unresolved = False
        process_reaped, pipes_resolved, group_resolved = False, True, True

        def reader():
            total = 0
            try:
                while True:
                    line = proc.stdout.readline(MAX_OUTPUT + 1)
                    if not line:
                        break
                    at = self.now()
                    total += len(line)
                    if total > MAX_OUTPUT or not line.endswith(b"\n"):
                        reader_errors.append("OUTPUT_LIMIT_OR_INCOMPLETE_LINE")
                        break
                    stdout.write(line)
                    stdout.flush()
                    try:
                        value = json.loads(line)
                        if not isinstance(value, dict):
                            raise ValueError("event must be an object")
                        canonical(value)  # Reject NaN/Infinity before retaining an event.
                        events.append({"at_ns": at, "value": value})
                    except (ValueError, UnicodeDecodeError):
                        reader_errors.append("INVALID_EVENT_JSON")
            except Exception as error:
                reader_errors.append(f"READER:{type(error).__name__}:{error}")
            finally:
                try:
                    proc.stdout.close()
                except OSError as error:
                    reader_errors.append(f"CLOSE:{type(error).__name__}:{error}")

        def feeder():
            try:
                view = memoryview(packet)
                while sent[0] < len(view):
                    n = os.write(proc.stdin.fileno(), view[sent[0]:sent[0] + 4096])
                    sent[0] += n
            except (BrokenPipeError, OSError) as error:
                feeder_errors.append(type(error).__name__)
            finally:
                try:
                    proc.stdin.close()
                except OSError as error:
                    feeder_errors.append(f"CLOSE:{type(error).__name__}:{error}")

        try:
            stdout, stderr = out_path.open("xb"), err_path.open("xb")
            if not blocked_by:
                proc = subprocess.Popen(argv, stdin=subprocess.PIPE if packet is not None
                                        else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=stderr, start_new_session=True)
                read_thread = threading.Thread(target=reader, daemon=True)
                read_thread.start()
                threads.append(read_thread)
                if packet is not None:
                    send_thread = threading.Thread(target=feeder, daemon=True)
                    send_thread.start()
                    threads.append(send_thread)
                try:
                    proc.wait(timeout=self.process_timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
        except Exception as error:
            process_errors.append(f"PROCESS:{type(error).__name__}:{error}")
        finally:
            if proc is not None:
                try:
                    process_reaped, pipes_resolved, group_resolved, cleanup_attempted = self.settle(
                        proc, threads, cleanup_errors, cleanup_notes)
                except Exception as error:
                    cleanup_errors.append(f"CLEANUP:{type(error).__name__}:{error}")
                    process_reaped = proc.returncode is not None
                    pipes_resolved = not any(t.is_alive() for t in threads)
                    group_resolved = False
                owner_unresolved = not (process_reaped and pipes_resolved and group_resolved)
                if owner_unresolved:
                    self.unresolved_owner = label
            for stream in (stdout, stderr):
                if stream is None or (stream is stdout and read_thread is not None and read_thread.is_alive()):
                    continue  # Never block on/close a stream still owned by a worker.
                try:
                    stream.flush()
                    if not owner_unresolved:
                        os.fsync(stream.fileno())
                except OSError as error:
                    output_errors.append(f"FLUSH:{type(error).__name__}:{error}")
                finally:
                    try:
                        stream.close()
                    except OSError as error:
                        output_errors.append(f"CLOSE:{type(error).__name__}:{error}")

        stderr_error_event, stderr_bounded = False, True
        if stderr is not None and stderr.closed and not owner_unresolved:
            try:
                with err_path.open("rb") as raw_stderr:
                    diagnostic = raw_stderr.read(MAX_OUTPUT + 1)
                if len(diagnostic) > MAX_OUTPUT:
                    stderr_bounded = False
                    output_errors.append("STDERR_LIMIT")
                else:
                    for line in diagnostic.splitlines():
                        try:
                            stderr_error_event |= declares_error(json.loads(line))
                        except (ValueError, UnicodeDecodeError):
                            pass  # Plain diagnostics do not assert a structured error.
            except Exception as error:
                stderr_bounded = False
                output_errors.append(f"STDERR:{type(error).__name__}:{error}")

        def artifact(path, stream, bounded=True):
            complete = stream is not None and stream.closed and not owner_unresolved and bounded
            result = {"path": path.name, "sha256": None, "complete": False}
            if complete:
                try:
                    result.update(sha256=digest(path.read_bytes()), complete=True)
                except OSError as error:
                    output_errors.append(f"HASH:{type(error).__name__}:{error}")
            return result

        end = self.now()
        after = usage()
        row = {
            "id": label, "argv": argv, "pid": proc.pid if proc is not None else None,
            "start_ns": start, "end_ns": end,
            "exit_code": proc.returncode if proc is not None else None,
            "timed_out": timed_out, "process_started": proc is not None,
            "process_reaped": process_reaped, "pipes_resolved": pipes_resolved,
            "process_group_resolved": group_resolved, "owner_unresolved": owner_unresolved,
            "dispatch_blocked_by": blocked_by, "cleanup_attempted": cleanup_attempted,
            "process_errors": process_errors, "cleanup_errors": cleanup_errors,
            "cleanup_notes": cleanup_notes, "output_errors": output_errors,
            "stderr_error_event": stderr_error_event,
            "events": events[:], "reader_errors": reader_errors[:],
            "feeder_errors": feeder_errors[:], "stdin_bytes_written": sent[0],
            "cpu_ns": after["cpu_ns"] - before["cpu_ns"],
            "resource_accounting_complete": not owner_unresolved and not blocked_by,
            "peak_rss_upper_bound_bytes": after["peak_rss_upper_bound_bytes"],
            "stdout": artifact(out_path, stdout), "stderr": artifact(err_path, stderr, stderr_bounded),
        }
        # Preserve the row for the aggregate even if its separate file cannot be saved.
        self.rows.append(row)
        save(self.root / (label + ".process.json"), canonical(row))
        return row


def final_event(row, name):
    matches = [event for event in row["events"] if event["value"].get("event") == name]
    if (row["exit_code"] != 0 or row["timed_out"] or not row["process_reaped"]
            or not row["pipes_resolved"] or not row["process_group_resolved"]
            or row["owner_unresolved"] or row["dispatch_blocked_by"] or row["cleanup_attempted"]
            or row["stderr_error_event"] or any(declares_error(e["value"]) for e in row["events"])
            or any(row[key] for key in ("reader_errors", "feeder_errors", "process_errors",
                                        "cleanup_errors", "output_errors"))
            or len(matches) != 1):
        return None
    return matches[0]


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def collect(args):
    root = args.output.resolve()
    repo = args.repo.resolve(strict=True)
    if sys.platform != "linux":
        raise ValueError("Linux rusage units required")
    if root.is_relative_to(repo):
        raise ValueError("evidence output must be outside the source checkout")
    root.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("executable required")
    source_before, source_before_ref = audit_source(repo, args.expected_source, root, "before")
    source = source_before["tested_commit"]
    binary_hash = digest(binary.read_bytes())
    # Fixed context is obtained before freezing starts. It does no Node I/O.
    try:
        context_call = subprocess.run([str(binary), "context", "--development"],
                                      check=True, capture_output=True, timeout=30)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # Preflight failures retain their actual captured prefixes, but do not
        # invent a frozen schedule or four dispatched experiment attempts.
        save(root / "context.stdout.json", error.stdout or b"")
        save(root / "context.stderr.txt", error.stderr or b"")
        raise
    save(root / "context.stdout.json", context_call.stdout)
    save(root / "context.stderr.txt", context_call.stderr)
    native_context = json.loads(context_call.stdout)
    if native_context.get("packet_limit") != MAX_PACKET:
        raise ValueError("fixed native packet limit mismatch")
    context = {
        "schema": "trnm-native-fullpath-process-context-v1",
        "scope": "same-host-development-component-observation",
        "source_commit": source, "source_tree": source_before["tested_tree"],
        "binary_sha256": binary_hash, "collector_sha256": digest(Path(__file__).read_bytes()),
        "native_context": native_context,
        "clock": "one parent Python time.monotonic_ns origin, shared by its reader threads",
        "transport": "actual complete PNP2 bytes over same-host child stdin pipe",
        "hardware": {"machine": os.uname().machine, "kernel": os.uname().release,
                     "logical_cpus": os.cpu_count()},
        "resource_measurement": "sequential parent+children rusage CPU; parent plus historical child RSS peak upper bound",
        "resource_enforcement": "unqualified shared development host; no original Host budget claim",
        "process_timeout_seconds": args.process_timeout,
        "original_business_contract": {"deadline_ns": 4_000_000_000,
            "required_depth": 6, "cpu_cores": "0.25", "memory_bytes": 2147483648,
            "swap_bytes": 0, "pids": 256, "hostile_workers": 16},
        "workload": "one signed development transfer, one exact resubmission, one late product error, one terminal cancellation",
        "production_activation": False,
    }
    context_ref = save(root / "context.json", canonical(context))
    schedule = [
        {"id": "valid", "cohort": "honest", "mode": "native", "requires_new_search": True},
        {"id": "duplicate", "cohort": "honest", "mode": "native", "requires_new_search": False},
        {"id": "late_product", "cohort": "hostile", "mode": "native", "requires_new_search": False},
        {"id": "cancelled", "cohort": "honest", "mode": "native", "requires_new_search": False},
    ]
    for row in schedule:
        row.update(scheduled_ns=0, deadline_ns=4_000_000_000,
                   parent_hex=native_context["parent_hex"],
                   task_hex=native_context["task_hex"])
    manifest = {"schema": "trnm-native-fullpath-process-preregistration-v1",
        "context_sha256": context_ref["sha256"], "schedule": schedule,
        "required_depth": 6, "observation_end_ns": 4_000_000_000,
        "all_scheduled_starts_retained": True, "production_activation": False}
    manifest_ref = save(root / "preregistration.json", canonical(manifest))
    # The completed/fsynced manifest predates this common clock's origin.
    epoch = time.monotonic_ns()
    collector = Collector(binary, root, epoch, args.process_timeout)
    beginning_usage = usage()
    packet_path = root / "candidate.pnp2"
    process_plan = {
        "valid": ["produce", "receive", "observe"],
        "duplicate": ["duplicate", "duplicate-observe"],
        "late_product": ["late-product", "late-product-observe"],
        "cancelled": ["cancelled", "cancelled-observe"],
    }
    collection_errors, incomplete_reason = [], "INCOMPLETE_PROCESS_PATH"
    try:
        produced = collector.run("produce", ["produce", "--development", root / "producer",
                                             packet_path, 4096])
        produce_event = final_event(produced, "produce_complete")
        if produce_event is None or not packet_path.is_file():
            incomplete_reason = "NO_COMPLETE_SOURCE_PACKET"
        else:
            with packet_path.open("rb") as source_packet:
                packet = source_packet.read(MAX_PACKET + 1)
            if len(packet) > MAX_PACKET:
                raise ValueError("packet bound")
            collector.run("receive", ["receive", "--development", root / "receiver"], packet)
            collector.run("observe", ["observe", "--development", root / "receiver", packet_path])
            collector.run("duplicate", ["resubmit", "--development", root / "receiver"], packet)
            collector.run("duplicate-observe", ["observe", "--development", root / "receiver", packet_path])
            # PNW1 is the fixed-size final field of canonical PNP2. Mutate its last
            # C element, leaving trace/challenge/claimed ticket unchanged.
            altered = bytearray(packet)
            if altered[-49188:-49184] != b"PNW1":
                raise ValueError("native work framing")
            old = int.from_bytes(altered[-36:-32], "little")
            altered[-36:-32] = ((old + 1) % 4294967291).to_bytes(4, "little")
            bad_path = root / "late-product.pnp2"
            save(bad_path, bytes(altered))
            collector.run("late-product", ["receive", "--development", root / "late-product-store"], bytes(altered))
            collector.run("late-product-observe", ["observe", "--development", root / "late-product-store", bad_path])
            collector.run("cancelled", ["receive-cancel", "--development", root / "cancelled-store"], packet)
            collector.run("cancelled-observe", ["observe", "--development", root / "cancelled-store", packet_path])
    except Exception as error:
        incomplete_reason = "COLLECTOR_ERROR"
        collection_errors.append(f"COLLECTION:{type(error).__name__}:{error}")

    # Frozen schedule IDs survive startup, transport, cleanup and packet failures.
    # Expected negative Node exits are observations; absent/unowned runs are errors.
    recorded = {row["id"]: row for row in collector.rows}
    attempts = []
    for scheduled in schedule:
        planned = process_plan[scheduled["id"]]
        present = [name for name in planned if name in recorded]
        failed = any(recorded[name]["process_errors"] or recorded[name]["output_errors"]
                     or recorded[name]["owner_unresolved"] or recorded[name]["dispatch_blocked_by"]
                     for name in present)
        attempt = {"id": scheduled["id"], "processes": present, "planned_processes": planned,
                   "status": "error" if failed or len(present) != len(planned) else "observed"}
        if attempt["status"] == "error":
            attempt["reason"] = ("OWNER_UNRESOLVED" if collector.unresolved_owner
                                 else "PROCESS_CONTROL_ERROR" if failed else incomplete_reason)
        attempts.append(attempt)
    end = collector.now()
    ending_usage = usage()
    unchanged = False
    source_after_ref = None
    if collector.unresolved_owner:
        # Do not start even an audit subprocess after losing process ownership.
        collection_errors.append("FINAL_SOURCE_AUDIT_SKIPPED_UNRESOLVED_OWNER")
    else:
        try:
            source_after, source_after_ref = audit_source(repo, source, root, "after")
            unchanged = (source_after == source_before
                         and digest(binary.read_bytes()) == binary_hash)
        except Exception as error:
            collection_errors.append(f"SOURCE_AUDIT:{type(error).__name__}:{error}")
    report = {"schema": SCHEMA, "manifest_sha256": manifest_ref["sha256"],
        "context_sha256": context_ref["sha256"], "observed_through_ns": end,
        "attempts": attempts, "processes": collector.rows,
        "cpu_ns": ending_usage["cpu_ns"] - beginning_usage["cpu_ns"],
        "peak_rss_upper_bound_bytes": ending_usage["peak_rss_upper_bound_bytes"],
        "stdin_bytes_written": sum(row["stdin_bytes_written"] for row in collector.rows),
        "owner_unresolved": collector.unresolved_owner is not None,
        "unresolved_owner": collector.unresolved_owner,
        "resource_accounting_complete": collector.unresolved_owner is None,
        "collection_errors": collection_errors,
        "source_and_binary_unchanged": unchanged,
        "qualification": "HOLD", "security_gate": "HOLD",
        "original_host_contract_qualified": False, "compressed_path_executed": False,
        "quantum_lower_bound_proved": False, "production_activation": False}
    report_ref = save(root / "process-observations.json", canonical(report))
    # Separate namespace: historical context/process schemas are not rewritten.
    # Hash-bind the successful snapshots to this exact original report. A failed
    # after-audit is retained on disk and deliberately cannot close the binding.
    save(root / "source-binding.json", canonical({
        "schema": SOURCE_BINDING_SCHEMA, "context": context_ref,
        "preregistration": manifest_ref, "observations": report_ref,
        "source_before": source_before_ref, "source_after": source_after_ref,
        "source_and_binary_unchanged": unchanged,
        "execution_attested": False, "binary_build_provenance_qualified": False,
        "original_host_contract_qualified": False, "qualification": "HOLD"}))
    print(json.dumps({"output": str(root), "manifest_sha256": manifest_ref["sha256"],
        "observations_sha256": digest(canonical(report)), "processes": len(collector.rows),
        "observed_through_ns": end, "source_and_binary_unchanged": unchanged,
        "qualification": "HOLD"}, sort_keys=True))
    infrastructure_errors = any(row["process_errors"] or row["cleanup_errors"] or row["output_errors"]
                                for row in collector.rows)
    return 0 if unchanged and not collection_errors and not infrastructure_errors else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--process-timeout", type=int, default=60)
    args = parser.parse_args()
    if not 1 <= args.process_timeout <= 120:
        parser.error("process timeout must be 1..120 seconds")
    return collect(args)


if __name__ == "__main__":
    raise SystemExit(main())
