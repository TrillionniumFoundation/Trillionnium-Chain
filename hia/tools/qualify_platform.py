"""Qualify the finite HIA Linux fixture; keep full-node I/O requirements OPEN."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "platform"))
from build import (Build, CLEANUP_SECONDS, new_output, run_native, sealed_executable,
                   sha256, write_json)

READINESS_SECONDS = 2
CASE_SECONDS = 10
PAYLOAD = b"HIAprobe"
FILE_NAME = "hia-platform-probe.bin"


class Owned:
    """One exact native child, pidfd ownership, observable readiness, bounded cleanup."""
    def __init__(self, directory, executable, *, stdin=subprocess.PIPE,
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=0o077):
        self.directory = directory
        self.executable = executable
        self.events = []
        self.sent = b""
        self.closed = False
        self.pidfd = None
        self.identity = None
        self.cleanup_record = None
        fd = sealed_executable(executable, directory.name)
        self.child_image_fd = fd
        self.argv = ["/proc/self/fd/" + str(fd)]
        self.start = time.monotonic_ns()
        try:
            self.process = subprocess.Popen(self.argv, stdin=stdin, stdout=stdout,
                stderr=stderr, cwd=directory, env={"PATH": ""}, pass_fds=(fd,),
                start_new_session=True, umask=umask)
        finally:
            os.close(fd)
        try:
            self.pidfd = os.pidfd_open(self.process.pid)
        except BaseException:
            self.process.kill()
            self.process.communicate(timeout=CLEANUP_SECONDS)
            raise
        self.launch = {"argv": self.argv, "cwd": str(directory),
            "environment": {"PATH": ""}, "launcher_umask": oct(umask),
            "native_umask": "0o77", "pid": self.process.pid,
            "sealed_image_inherited_fd": fd, "executable_sha256": sha256(executable),
            "start_monotonic_ns": self.start, "case_limit_seconds": CASE_SECONDS,
            "readiness_limit_seconds": READINESS_SECONDS,
            "cleanup_limit_seconds": CLEANUP_SECONDS,
            "process_ownership": "pidfd of direct child; fixed fixture has no fork/clone"}
        write_json(directory / "launch.json", self.launch)

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if not self.closed:
            self.cleanup()
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None

    def signal(self, number):
        signal.pidfd_send_signal(self.pidfd, number)
        self.events.append({"action": "pidfd_send_signal", "signal": number,
                            "monotonic_ns": time.monotonic_ns()})

    def snapshot(self):
        if self.process.poll() is not None:
            raise RuntimeError("Native child exited before required readiness observation")
        root = Path("/proc") / str(self.process.pid)
        # Access failures are real control failures. There is no sleep fallback.
        fields = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines()
                      if ":" in line)
        ticks = int((root / "stat").read_text().rsplit(")", 1)[1].split()[19])
        if self.identity is None:
            self.identity = ticks
        if ticks != self.identity:
            raise RuntimeError("Owned process identity changed")
        raw = (root / "syscall").read_text().strip()
        words = raw.split()
        syscall = None
        args = []
        if words and words[0] != "running":
            syscall = int(words[0], 0)
            if syscall >= 0:
                args = [int(word, 0) for word in words[1:7]]
        return {"monotonic_ns": time.monotonic_ns(), "start_ticks": ticks,
                "syscall_text": raw, "syscall": syscall, "arguments": args,
                "state": fields["State"].strip(),
                "sig_caught": int(fields["SigCgt"].strip(), 16),
                "sig_pending": int(fields["SigPnd"].strip(), 16),
                "shared_sig_pending": int(fields["ShdPnd"].strip(), 16),
                "voluntary_context_switches": int(fields["voluntary_ctxt_switches"])}

    def observe(self, predicate, label, timeout=READINESS_SECONDS):
        limit = time.monotonic() + timeout
        while time.monotonic() < limit:
            row = self.snapshot()
            if predicate(row):
                row["observation"] = label
                self.events.append(row)
                return row
            # Polling cadence only; readiness is established by the predicate.
            time.sleep(0.002)
        raise TimeoutError("Actual kernel readiness not observed: " + label)

    def blocked_read(self, remaining=8, *, after_context_switches=None):
        bit = 1 << (signal.SIGUSR1 - 1)
        def ready(row):
            return (row["syscall"] == 0 and len(row["arguments"]) == 6
                and row["arguments"][0] == 0 and row["arguments"][2] == remaining
                and row["state"].startswith("S") and row["sig_caught"] & bit
                and not (row["sig_pending"] | row["shared_sig_pending"]) & bit
                and (after_context_switches is None
                     or row["voluntary_context_switches"] > after_context_switches))
        return self.observe(ready, "blocked stdin read with remaining=" + str(remaining))

    def send(self, raw):
        self.process.stdin.write(raw)
        self.process.stdin.flush()
        self.sent += raw
        self.events.append({"action": "stdin_write", "bytes_hex": raw.hex(),
                            "monotonic_ns": time.monotonic_ns()})

    def wait_without_wakeup(self, seconds):
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN)
        limit = time.monotonic() + seconds
        while time.monotonic() < limit:
            if poller.poll(max(1, int((limit - time.monotonic()) * 1000))):
                raise RuntimeError("Native child exited during the required idle interval")

    def cleanup(self):
        start = time.monotonic_ns()
        actions = []
        already_exited = []
        if self.process.poll() is None:
            try:
                self.signal(signal.SIGTERM)
                actions.append("SIGTERM")
            except ProcessLookupError:
                already_exited.append("SIGTERM")
        try:
            stdout, stderr = self.process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                self.signal(signal.SIGKILL)
                actions.append("SIGKILL")
            except ProcessLookupError:
                already_exited.append("SIGKILL")
            stdout, stderr = self.process.communicate(timeout=2)
        self.cleanup_record = {"signals": actions, "exit_code": self.process.returncode,
            "already_exited_before_signal": already_exited,
            "elapsed_ns": time.monotonic_ns() - start,
            "complete": self.process.returncode is not None,
            "wall_limit_seconds": CLEANUP_SECONDS}
        self.closed = True
        (self.directory / "stdin.raw").write_bytes(self.sent)
        (self.directory / "stdout.raw").write_bytes(stdout or b"")
        (self.directory / "stderr.raw").write_bytes(stderr or b"")
        write_json(self.directory / "readiness.json", {"events": self.events})
        write_json(self.directory / "cleanup.json", self.cleanup_record)
        return stdout or b"", stderr or b""

    def finish(self, *, data=None, expected=0, error=None, success=False,
               partial=None, interrupted=None, stdout_override=None):
        if data is not None:
            self.sent += data
        try:
            stdout, stderr = self.process.communicate(data, timeout=CASE_SECONDS)
        except subprocess.TimeoutExpired:
            self.cleanup()
            raise TimeoutError("Native case exceeded the external bound")
        self.closed = True
        end = time.monotonic_ns()
        stdout = (stdout or b"") if stdout_override is None else stdout_override
        stderr = stderr or b""
        (self.directory / "stdin.raw").write_bytes(self.sent)
        (self.directory / "stdout.raw").write_bytes(stdout)
        (self.directory / "stderr.raw").write_bytes(stderr)
        write_json(self.directory / "readiness.json", {"events": self.events})
        row = {**self.launch, "exit_code": self.process.returncode, "expected_exit": expected,
            "end_monotonic_ns": end, "elapsed_ns": end - self.start,
            "stdin_hex": self.sent.hex(), "stdin_sha256": sha256(self.sent),
            "stdout_bytes": len(stdout), "stdout_sha256": sha256(stdout),
            "stdout_hex": stdout.hex(), "stderr_bytes": len(stderr),
            "stderr_sha256": sha256(stderr), "stderr_hex": stderr.hex(),
            "readiness_observations": self.events,
            "passed": self.process.returncode == expected}
        if len(stderr) == 32:
            values = struct.unpack("<4Q", stderr)
            row["error_event"] = {"kernel_result_unsigned": values[0],
                "kernel_result_signed": values[0] if values[0] < (1 << 63) else values[0] - (1 << 64),
                "phase": values[1], "monotonic_seconds": values[2], "monotonic_nanoseconds": values[3]}
        if error is not None:
            row["passed"] &= len(stderr) == 32 and row["error_event"]["kernel_result_signed"] == error
        file = self.directory / FILE_NAME
        row["file_entry_exists"] = file.exists() or file.is_symlink()
        row["file_is_symlink"] = file.is_symlink()
        if file.is_file() and not file.is_symlink():
            row["file_hex"] = file.read_bytes().hex()
            row["file_mode"] = stat.S_IMODE(file.stat().st_mode)
        if success:
            row["passed"] &= (len(stdout) == 96 and not stderr
                and row.get("file_hex") == PAYLOAD.hex() and row.get("file_mode") == 0o600)
            if len(stdout) == 96:
                before_s, before_ns, after_s, after_ns = struct.unpack_from("<4Q", stdout, 8)
                short_count, interrupt_count, calls = struct.unpack_from("<3Q", stdout, 64)
                row.update(magic=stdout[:8].decode("ascii", errors="replace"),
                    socket_payload_hex=stdout[40:48].hex(), random_bytes_hex=stdout[48:64].hex(),
                    partial_kernel_result_count=short_count, eintr_kernel_result_count=interrupt_count,
                    policy_calls_before_stdout=calls,
                    monotonic_bracket=(self.start <= before_s * 10**9 + before_ns
                        <= after_s * 10**9 + after_ns <= end),
                    file_readback_matches=(stdout[88:96].hex() == row.get("file_hex")))
                row["passed"] &= (stdout[:8] == b"HIAOS002" and stdout[40:48] == PAYLOAD
                    and before_ns < 10**9 and after_ns < 10**9
                    and row["monotonic_bracket"] and row["file_readback_matches"])
                if partial is not None:
                    row["passed"] &= short_count == partial
                if interrupted is not None:
                    row["passed"] &= interrupt_count == interrupted
        else:
            row["passed"] &= not stdout
        return row


def guard_source(words):
    """Author a negative HIA command policy, never runtime machine bytes."""
    lines = ["hia-asm.v1 hepta.hia.program.v8 platform_negative_command",
        "fn f0(e:readbuf,c:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(b0)",
        "block b0(e:readbuf,c:mutbuf,w:mutbuf)"]
    for i, byte in enumerate(b"".join(struct.pack("<Q", word) for word in words)):
        lines.extend((f'  p{i}:usize = const() {{"value":{i}}}',
                      f'  v{i}:u8 = const() {{"value":{byte}}}',
                      f"  _ = buffer.store(c,p{i},v{i})"))
    lines.extend(('  result:u32 = const() {"value":0}', "  ret(result)", "end"))
    return ("\n".join(lines) + "\n").encode()


class Qualification:
    def __init__(self, output):
        self.output = output
        self.cases_dir = output / "cases"
        self.cases_dir.mkdir()
        self.rows = []
        self.build = Build(output / "build")
        self.build_receipt = self.build.build()

    def owned(self, directory, **options):
        return Owned(directory, self.build.executable, **options)

    def control(self, name, function, group="finite-os"):
        directory = self.cases_dir / name
        directory.mkdir(mode=0o700)
        try:
            row = function(directory)
        except Exception as exc:
            row = {"passed": False, "exception": type(exc).__name__ + ": " + str(exc)}
        row.update(case=name, group=group)
        write_json(directory / "result.json", row)
        self.rows.append(row)
        write_json(self.output / "controls.partial.json", {"controls": self.rows})
        print(json.dumps({"control": name, "passed": row["passed"],
                          "exception": row.get("exception")}), flush=True)

    def ordinary(self, directory, umask=0o077):
        with self.owned(directory, umask=umask) as owner:
            return owner.finish(data=PAYLOAD, success=True, partial=0, interrupted=0)

    def short_reads(self, directory):
        with self.owned(directory) as owner:
            for remaining, chunk in ((8, b"H"), (7, b"IA"), (5, b"probe")):
                owner.blocked_read(remaining)
                owner.send(chunk)
            return owner.finish(success=True, partial=2, interrupted=0)

    def eintr(self, directory):
        with self.owned(directory) as owner:
            before = owner.blocked_read()
            for _ in range(2):
                owner.signal(signal.SIGUSR1)
                before = owner.blocked_read(after_context_switches=before["voluntary_context_switches"])
            return owner.finish(data=PAYLOAD, success=True, partial=0, interrupted=2)

    def refuse(self, directory, *, data=b"", error=0):
        with self.owned(directory) as owner:
            row = owner.finish(data=data, expected=70, error=error)
            row["passed"] &= not row["file_entry_exists"]
            return row

    def eagain(self, directory):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            os.set_blocking(read_fd, False)
            with self.owned(directory, stdin=read_fd) as owner:
                row = owner.finish(expected=70, error=-11)
                row["passed"] &= not row["file_entry_exists"]
                row["input_setup"] = "empty O_NONBLOCK pipe; parent writer kept open"
                row["eagain_policy"] = "refuse; no readiness retry is implemented"
                return row
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def existing(self, directory, symlink=False):
        path = directory / FILE_NAME
        if symlink:
            (directory / "canary").write_bytes(b"UNCHANGED")
            path.symlink_to("canary")
        else:
            path.write_bytes(b"EXISTING")
        with self.owned(directory) as owner:
            row = owner.finish(data=PAYLOAD, expected=70, error=-17)
            if symlink:
                row["canary_unchanged"] = (directory / "canary").read_bytes() == b"UNCHANGED"
                row["passed"] &= row["canary_unchanged"] and path.is_symlink()
            else:
                row["passed"] &= row.get("file_hex") == b"EXISTING".hex()
            return row

    def closed_pipe(self, directory, stream):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        os.close(read_fd)
        try:
            with self.owned(directory, **{stream: write_fd}) as owner:
                if stream == "stdout":
                    row = owner.finish(data=PAYLOAD, expected=70, error=-32)
                    row["passed"] &= row.get("file_hex") == PAYLOAD.hex()
                else:
                    row = owner.finish(data=b"", expected=70)
                    row["passed"] &= not row["file_entry_exists"] and row["stderr_bytes"] == 0
                row["input_setup"] = stream + " pipe has no reader; actual EPIPE"
                return row
        finally:
            os.close(write_fd)

    def terminate(self, directory):
        with self.owned(directory) as owner:
            owner.blocked_read()
            owner.signal(signal.SIGTERM)
            row = owner.finish(expected=-signal.SIGTERM)
            row["passed"] &= not row["file_entry_exists"]
            return row

    def externally_woken_elapsed(self, directory):
        with self.owned(directory) as owner:
            owner.blocked_read()
            owner.wait_without_wakeup(5.1)
            owner.blocked_read()
            owner.signal(signal.SIGUSR1)
            # Leave the input pipe open until exit: closing it could create EOF.
            owner.process.wait(timeout=READINESS_SECONDS)
            row = owner.finish(expected=70, error=-4)
            row["passed"] &= row["elapsed_ns"] >= 5_000_000_000 and not row["file_entry_exists"]
            row["deadline_scope"] = "elapsed checked only after an external signal returns the blocking syscall"
            row["native_hard_deadline_qualified"] = False
            return row

    def descriptor_closure(self, directory):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        filled = 0
        try:
            while True:
                try:
                    filled += os.write(write_fd, b"Z" * 4096)
                except BlockingIOError:
                    break
            os.set_blocking(write_fd, True)
            with self.owned(directory, stdout=write_fd) as owner:
                owner.send(PAYLOAD)
                owner.observe(lambda r: r["syscall"] == 1 and len(r["arguments"]) == 6
                    and r["arguments"][0] == 1 and r["arguments"][2] == 96
                    and r["state"].startswith("S"), "blocked final stdout write after all explicit closes")
                fd_root = Path("/proc") / str(owner.process.pid) / "fd"
                descriptors = {int(path.name): os.readlink(path) for path in fd_root.iterdir()}
                only_harness_fds = set(descriptors) == {0, 1, 2, owner.child_image_fd}
                drained = b""
                while len(drained) < filled:
                    chunk = os.read(read_fd, filled - len(drained))
                    if not chunk:
                        raise RuntimeError("Full-pipe synchronization prefix truncated")
                    drained += chunk
                os.close(write_fd)
                write_fd = None
                owner.process.wait(timeout=READINESS_SECONDS)
                stdout = b""
                while True:
                    chunk = os.read(read_fd, 4096)
                    if not chunk:
                        break
                    stdout += chunk
                row = owner.finish(success=True, stdout_override=stdout, partial=0, interrupted=0)
                row["descriptors_before_final_report"] = descriptors
                row["all_file_socket_epoll_descriptors_explicitly_closed"] = only_harness_fds
                row["pipe_prefill_bytes"] = filled
                row["passed"] &= only_harness_fds and drained == b"Z" * filled
                return row
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)

    def guard(self, directory, words):
        source = guard_source(words)
        (directory / "policy.hepta").write_bytes(source)
        policy = self.build.stage(self.build.compiler, source, "compile-" + directory.name)
        executable = self.build.stage(self.build.emitter, policy, "pack-" + directory.name)
        with Owned(directory, executable) as owner:
            row = owner.finish(data=b"", expected=78)
            row["source_sha256"] = sha256(source)
            row["command_words"] = words
            row["same_emitter_sha256"] = sha256(self.build.emitter)
            row["passed"] &= not row["file_entry_exists"] and not row["stderr_bytes"]
            return row

    def pack_refusal(self, directory, payload):
        result, row = run_native(self.build.emitter, payload, directory, "native-pack")
        row["passed"] = (not row["timed_out"] and row["exit_code"] == 3
                         and not result and not row["stderr_hex"])
        return row

    def repack(self, directory):
        result, row = run_native(self.build.emitter, self.build.policy, directory, "native-repack")
        row["passed"] = (not row["timed_out"] and row["exit_code"] == 0
                         and not row["stderr_hex"] and result == self.build.executable)
        return row

    def idle_limitation(self):
        directory = self.output / "idle-without-wakeup"
        directory.mkdir()
        row = {"requirement": "native completion or cancellation within the five-second deadline",
               "full_node_io_gate": "OPEN", "counted_as_finite_control_pass": False}
        try:
            with self.owned(directory) as owner:
                before = owner.blocked_read()
                owner.wait_without_wakeup(6)
                after = owner.blocked_read()
                row.update(native_hard_deadline_result="FAIL", observation="STILL_BLOCKED_WITHOUT_WAKEUP",
                    executable_sha256=sha256(self.build.executable), before=before, after=after,
                    idle_observed_ns=after["monotonic_ns"] - before["monotonic_ns"],
                    reason="Blocking read is not independently interrupted by the policy elapsed check")
                stdout, stderr = owner.cleanup()
                row.update(cleanup=owner.cleanup_record, stdout_hex=stdout.hex(), stderr_hex=stderr.hex(),
                    file_entry_exists=(directory / FILE_NAME).exists())
                row["known_limitation_observed"] = (row["idle_observed_ns"] >= 6_000_000_000
                    and not stdout and not stderr and not row["file_entry_exists"]
                    and row["cleanup"]["complete"]
                    and row["cleanup"]["elapsed_ns"] <= CLEANUP_SECONDS * 10**9)
        except Exception as exc:
            row.update(native_hard_deadline_result="UNKNOWN", known_limitation_observed=False,
                       exception=type(exc).__name__ + ": " + str(exc))
        write_json(directory / "result.json", row)
        return row

    def trace(self):
        directory = self.output / "syscall-trace"
        directory.mkdir()
        tracer = shutil.which("strace")
        row = {"executable_sha256": sha256(self.build.executable),
               "counted_as_finite_control_pass": False, "instrumentation": "strace ptrace"}
        if not tracer:
            row.update(status="UNKNOWN", reason="STRACE_NOT_AVAILABLE")
            write_json(directory / "result.json", row)
            return row
        fd = sealed_executable(self.build.executable, "platform-trace")
        argv = [tracer, "-f", "-qq", "-o", str(directory / "trace.raw"),
                "/proc/self/fd/" + str(fd)]
        start = time.monotonic_ns()
        cleanup = None
        try:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, pass_fds=(fd,), cwd=directory, env={"PATH": ""},
                start_new_session=True, umask=0o077)
        finally:
            os.close(fd)
        try:
            stdout, stderr = process.communicate(PAYLOAD, timeout=CASE_SECONDS)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            cleanup_start = time.monotonic_ns()
            try:
                os.killpg(process.pid, signal.SIGKILL)
                signal_outcome = "sent"
            except ProcessLookupError:
                signal_outcome = "already_exited"
            stdout, stderr = process.communicate(timeout=CLEANUP_SECONDS)
            cleanup = {"signal": "SIGKILL", "signal_outcome": signal_outcome,
                "complete": process.returncode is not None,
                "elapsed_ns": time.monotonic_ns() - cleanup_start}
        (directory / "stdin.raw").write_bytes(PAYLOAD)
        (directory / "stdout.raw").write_bytes(stdout)
        (directory / "stderr.raw").write_bytes(stderr)
        trace = (directory / "trace.raw").read_bytes() if (directory / "trace.raw").exists() else b""
        row.update(argv=argv, cwd=str(directory), environment={"PATH": ""},
            tracer_sha256=sha256(Path(tracer).read_bytes()), exit_code=process.returncode,
            timed_out=timed_out, cleanup=cleanup, elapsed_ns=time.monotonic_ns() - start,
            wall_limit_seconds=CASE_SECONDS, cleanup_limit_seconds=CLEANUP_SECONDS,
            stdout_hex=stdout.hex(), stderr=stderr.decode(errors="replace"),
            trace_bytes=len(trace), trace_sha256=sha256(trace))
        if b"Operation not permitted" in stderr and (b"ptrace" in stderr.lower()):
            row.update(status="UNKNOWN", reason="PTRACE_EPERM", instrumentation_attempt="FAILED")
        elif process.returncode == 0 and len(stdout) == 96 and stdout[:8] == b"HIAOS002" and trace:
            # This is retained raw instrumentation, not a generalized syscall-safety proof.
            row.update(status="CAPTURED", reason="raw trace retained; semantic policy audit separate")
        else:
            row.update(status="UNKNOWN", reason="TRACE_ATTEMPT_FAILED", instrumentation_attempt="FAILED")
        write_json(directory / "result.json", row)
        return row

    def run(self):
        self.control("ordinary", self.ordinary)
        self.control("native-private-umask", lambda d: self.ordinary(d, umask=0o777))
        self.control("actual-short-reads", self.short_reads)
        self.control("actual-eintr", self.eintr)
        self.control("eof", self.refuse)
        self.control("wrong-input", lambda d: self.refuse(d, data=b"XIAprobe", error=8))
        self.control("actual-eagain-refusal", self.eagain)
        self.control("existing-file", self.existing)
        self.control("symlink", lambda d: self.existing(d, symlink=True))
        self.control("closed-stdout-epipe", lambda d: self.closed_pipe(d, "stdout"))
        self.control("closed-stderr-epipe", lambda d: self.closed_pipe(d, "stderr"))
        self.control("sigterm-before-effects", self.terminate)
        self.control("descriptors-closed-before-report", self.descriptor_closure)
        self.control("externally-woken-elapsed-check", self.externally_woken_elapsed)
        guards = {
            "unknown-syscall": [9999, 0, 0, 0, 0, 0, 0, 0, 1],
            "pointer-before-data": [1, 1, 127, 1, 0, 0, 0, 2, 1],
            "pointer-end-overflow": [1, 1, 4095, 8, 0, 0, 0, 2, 1],
            "wrong-pointer-mask": [1, 1, 128, 8, 0, 0, 0, 0, 1],
            "epoll-multiple-events": [232, 0, 128, 2, 100, 0, 0, 2, 1],
            "accept4-raw-address": [288, 0, 1, 0, 524288, 0, 0, 0, 1],
            "accept4-raw-length": [288, 0, 0, 1, 524288, 0, 0, 0, 1],
            "accept4-flags": [288, 0, 0, 0, 0, 0, 0, 0, 1],
        }
        for name, words in guards.items():
            self.control(name, lambda d, words=words: self.guard(d, words), "command-guard")
        self.control("empty-policy", lambda d: self.pack_refusal(d, b""), "packer-guard")
        self.control("oversize-policy", lambda d: self.pack_refusal(d, b"\0" * 524289), "packer-guard")
        self.control("exact-native-repack", self.repack, "packer-guard")
        idle = self.idle_limitation()
        trace = self.trace()
        self.build.check_pin()
        passed = all(row["passed"] for row in self.rows)
        fixture_pass = passed and idle["known_limitation_observed"]
        report = {"schema": "trnm.hia.platform-fixture-qualification.v1",
            "status": "FINITE_FIXTURE_PASS" if fixture_pass else "FINITE_FIXTURE_FAIL",
            "source_inputs": self.build.manifest, "build": self.build_receipt,
            "controls": self.rows, "passed_control_count": sum(row["passed"] for row in self.rows),
            "required_control_count": len(self.rows), "source_inputs_stable": True,
            "native_hard_deadline": idle, "syscall_trace": trace,
            "full_node_io_gate": "OPEN", "durable_owner_gate": "OPEN",
            "generic_fd_capability_gate": "OPEN", "short_write_fault_qualification": "NOT_RUN",
            "partial_getrandom_fault_qualification": "NOT_RUN",
            "runtime_host_language_or_dynamic_loader": False,
            "hosted_build_test_and_observation_driver": True,
            "qualification_scope": "fixed trusted policy, finite OS controls, command/packer guards",
            "unqualified_requirements": ["independent hard deadlines for blocking syscalls",
                "EAGAIN readiness resumption", "FD generation/rights capabilities",
                "directory and peer authority", "durable commit and crash recovery",
                "authenticated transport", "general policy object validation and static linking"]}
        write_json(self.output / "report.json", report)
        print(json.dumps({"status": report["status"], "passed": report["passed_control_count"],
            "required": report["required_control_count"], "full_node_io_gate": "OPEN",
            "native_hard_deadline": idle["native_hard_deadline_result"],
            "trace": trace["status"], "report": str(self.output / "report.json")}), flush=True)
        return 0 if fixture_pass else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = new_output(args.output)
    try:
        return Qualification(output).run()
    except Exception as exc:
        write_json(output / "failure.json", {"status": "FAIL", "exception":
            type(exc).__name__ + ": " + str(exc), "full_node_io_gate": "OPEN"})
        raise


if __name__ == "__main__":
    raise SystemExit(main())
