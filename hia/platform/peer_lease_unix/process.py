"""Retain complete bounded child observations for the peer Unix qualification."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

from .build import ROOT, identity, need
from scripts import w1_owned_process_collector_v1 as owned

WALL_SECONDS = 240
CLEANUP_SECONDS = 3
# This bounds cumulative identities and the collector's traversal/reap loops.
# A complete client group sequentially starts over 1,000 children. This qualifier
# does not enforce or qualify the separate original W1 live-PID/cgroup budget.
MAX_PROCESS_OBSERVATIONS = 4096


class Processes:
    def __init__(self, output, cwd, environment, check):
        self.output = Path(output)
        self.output.mkdir(mode=0o700)
        self.cwd = Path(cwd)
        self.environment = dict(environment)
        self.check = check
        self.rows = []

    def run(self, name, arguments, *, timeout=WALL_SECONDS):
        need(type(timeout) is int and 0 < timeout <= WALL_SECONDS,
             "The original child wall limit cannot increase")
        need(name and Path(name).name == name, "Stage label escapes")
        directory = self.output / name
        directory.mkdir(mode=0o700)
        argv = [os.fspath(value) for value in arguments]
        row = {"name": name, "argv": argv, "cwd": str(self.cwd),
               "wall_limit_seconds": timeout, "cleanup_limit_seconds": CLEANUP_SECONDS,
               "max_process_observations": MAX_PROCESS_OBSERVATIONS,
               "started": False, "exit_code": None, "timed_out": False,
               "failure": None, "cleanup_errors": []}
        started = time.monotonic_ns()
        child = None
        cleanup_deadline = None
        try:
            self.check()
            executable = shutil.which(argv[0], path=self.environment.get("PATH"))
            need(executable, "Actual executable unavailable")
            executable = Path(executable).resolve(strict=True)
            python = Path(sys.executable).resolve(strict=True)
            spec = {"argv": argv, "cwd": str(self.cwd), "environment": self.environment,
                    "executable": str(executable), "executable_identity": identity(executable.read_bytes())}
            data = (json.dumps(spec, sort_keys=True, indent=2) + "\n").encode()
            specification = directory / "command.json"
            specification.write_bytes(data)
            boot = owned.boot_id()
            deadline = started + timeout * 1_000_000_000
            collector = directory / "owned"
            command = [str(python), "-B", str(ROOT / "scripts/w1_owned_process_collector_v1.py"),
                       "--out", str(collector), "--cwd", str(ROOT),
                       "--deadline-monotonic-ns", str(deadline), "--deadline-boot-id", boot,
                       "--cleanup-grace-seconds", str(CLEANUP_SECONDS),
                       "--executable-sha256", identity(python.read_bytes())["sha256"],
                       "--max-processes", str(MAX_PROCESS_OBSERVATIONS), "--max-log-bytes", str(16 * 1024 * 1024),
                       "--", str(python), "-B", "-m", "hia.platform.peer_lease_unix.process",
                       "--execute", str(specification), "--sha256", identity(data)["sha256"]]
            row.update(command=identity(data), collector_argv=command, original_boot_id=boot,
                       original_deadline_monotonic_ns=deadline)
            with (directory / "collector.stdout.raw").open("xb") as stdout, \
                    (directory / "collector.stderr.raw").open("xb") as stderr:
                child = subprocess.Popen(command, cwd=self.cwd,
                                         env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                                         stdin=subprocess.DEVNULL, stdout=stdout,
                                         stderr=stderr, start_new_session=True)
                row["started"] = True
                cleanup_deadline = deadline + CLEANUP_SECONDS * 1_000_000_000
                row["collector_exit_code"] = child.wait(
                    timeout=max(0, (cleanup_deadline - time.monotonic_ns()) / 1_000_000_000))
                row["observed_completed_monotonic_ns"] = time.monotonic_ns()
            row["intent"] = identity((collector / "intent.json").read_bytes())
            intent = owned.read_json(collector / "intent.json")
            need(intent["command"] == command[command.index("--") + 1:]
                 and intent["original_boot_id"] == boot
                 and intent["original_deadline_monotonic_ns"] == deadline
                 and intent["cleanup_grace_seconds"] == 3
                 and intent["max_process_records"] == MAX_PROCESS_OBSERVATIONS,
                 "Actual collector intent differs")
            result = owned.read_result(collector, row["collector_exit_code"], observed_boot_id=boot,
                observed_completed_monotonic_ns=row["observed_completed_monotonic_ns"],
                expected_intent_sha256=row["intent"]["sha256"])
            row["collector_readback"] = result
            need(result["collector_wait_domain_reaped"] is True,
                 "The actual owned command family was not fully reaped")
            need(result["deadline_qualified"] is True,
                 "The actual owned command family exceeded its original deadline")
            need(result["command_success"] is True,
                 "Actual owned command failed: " + name + " (exit "
                 + str(result["result"]["root_returncode"]) + ")")
            row["exit_code"] = result["result"]["root_returncode"]
            need(all(stream["eof"] and not stream["truncated"]
                     for stream in result["result"]["streams"].values()), "Incomplete actual child streams")
            self.check()
        except BaseException as error:
            row["failure"] = repr(error)
            raise
        finally:
            if child is not None and child.poll() is None:
                # There is exactly one cleanup deadline. No second wait(3)
                # renews it, and only the known collector direct child is
                # signalled; its existing pidfd/subreaper logic owns descendants.
                if cleanup_deadline is None:
                    cleanup_deadline = time.monotonic_ns() + CLEANUP_SECONDS * 1_000_000_000
                try:
                    child.send_signal(signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    row["cleanup_errors"].append(repr(error))
                try:
                    row["collector_exit_code"] = child.wait(
                        timeout=max(0, (cleanup_deadline - time.monotonic_ns()) / 1_000_000_000))
                except BaseException as error:
                    row["cleanup_errors"].append(repr(error))
                    try:
                        child.kill()
                    except ProcessLookupError:
                        pass
                    row["collector_exit_code"] = child.poll()
                    row["cleanup_errors"].append("Collector terminal/reaping state is UNKNOWN")
            collector = directory / "owned"
            try:
                if (collector / "result.json").is_file():
                    result = owned.read_json(collector / "result.json")
                    row["exit_code"] = result.get("root_returncode")
                    row["timed_out"] = result.get("cause") == "original-deadline"
            except BaseException as error:
                row["cleanup_errors"].append("Retained collector diagnostic: " + repr(error))
            for stream in ("stdout", "stderr"):
                try:
                    source = collector / (stream + ".log")
                    if source.is_file():
                        (directory / (stream + ".raw")).write_bytes(source.read_bytes())
                except BaseException as error:
                    row["cleanup_errors"].append("Retained " + stream + ": " + repr(error))
            row["elapsed_ns"] = time.monotonic_ns() - started
            for name in ("stdout", "stderr"):
                try:
                    path = directory / (name + ".raw")
                    if path.exists():
                        row[name] = identity(path.read_bytes())
                except BaseException as error:
                    row["cleanup_errors"].append("Retained stream identity: " + repr(error))
            (directory / "receipt.json").write_text(json.dumps(row, sort_keys=True, indent=2) + "\n")
            self.rows.append(row)
            (self.output / "stages.json").write_text(json.dumps(self.rows, sort_keys=True, indent=2) + "\n")
        need(row["started"] and row["exit_code"] == 0 and not row["timed_out"]
             and row["failure"] is None and row["cleanup_errors"] == [],
             "Actual child failed; complete raw retained: " + row["name"])
        return (directory / "stdout.raw").read_bytes()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "Optimized Python is not admitted")
    need(args.execute.is_file() and not args.execute.is_symlink(), "Missing or linked exact command")
    raw = args.execute.read_bytes()
    need(identity(raw)["sha256"] == args.sha256, "Exact command changed before dispatch")
    value = json.loads(raw)
    path = Path(value["executable"])
    need(path.is_absolute() and not path.is_symlink(), "Actual command needs its pinned ELF")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        need(os.pread(descriptor, 4, 0) == b"\x7fELF"
             and owned.fd_digest(descriptor) == value["executable_identity"]["sha256"],
             "Actual command executable changed")
        os.chdir(value["cwd"])
        os.execve(descriptor, value["argv"], value["environment"])
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    main()
