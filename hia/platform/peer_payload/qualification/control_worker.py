"""Actual ownership controls; injections affect observers, never product logic."""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback

from hia.platform.peer_payload.contract import HERE, capture, identity, need

parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=("normal", "descendant", "deadline", "native-blocked", "public-close", "ptrace-cleanup"), required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--native", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(mode=0o700)
started = time.monotonic_ns()
report = {"status": "FAIL", "mode": args.mode, "native": str(args.native),
          "native_identity": identity(capture(args.native)), "parent_pid": os.getpid(),
          "product_failure_claimed": False, "observer_injection": None}


def save():
    report["elapsed_ns"] = time.monotonic_ns() - started
    (args.output / "control.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


try:
    if args.mode == "normal":
        print("actual-normal", flush=True)
        report["status"] = "PASS_ACTUAL_NORMAL"
    elif args.mode in {"descendant", "deadline"}:
        child = os.fork()
        if child == 0:
            os.setsid()
            time.sleep(0.2 if args.mode == "descendant" else 30)
            (args.output / "descendant-finished.json").write_text(json.dumps({"pid": os.getpid(), "finished": True}) + "\n")
            os.write(1, b"actual-descendant-finished\n")
            os._exit(0)
        report.update(child_pid=child, status="PASS_PARENT_EXIT_BEFORE_DESCENDANT" if args.mode == "descendant" else "EXPECTED_TIMEOUT_PENDING")
    elif args.mode == "native-blocked":
        with (args.output / "native.stdout.raw").open("xb") as stdout, (args.output / "native.stderr.raw").open("xb") as stderr:
            child = subprocess.Popen([str(args.native)], stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                     start_new_session=True, env={"PATH": ""}, cwd=args.output)
            report.update(child_pid=child.pid, status="EXPECTED_TIMEOUT_PENDING",
                          observer_injection="hold-open-input-without-a-request")
            save()
            time.sleep(30)
            raise AssertionError("The actual native blocking control escaped its one-second outer deadline")
    elif args.mode == "public-close":
        # Load the exact public observer class without executing its cases.
        path = HERE / "qualification/public.py"
        tree = ast.parse(capture(path))
        selected = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
                    or isinstance(node, ast.FunctionDef) and node.name in {"identity", "u64", "word", "request"}
                    or isinstance(node, ast.ClassDef) and node.name == "Process"]
        namespace = {"DEADLINE": time.monotonic() + 240}
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
        directory = args.output / "actual-public-child"
        directory.mkdir(mode=0o700)
        process = namespace["Process"](args.native, directory)
        stdin = process.process.stdin
        class HoldOpen:
            def close(self):
                pass
        # Deliberately suppress EOF, so the native owner stays blocked and the
        # observer's normal wait exhausts the only cleanup deadline. This is a
        # failed observer control, not a successful three-second cleanup claim.
        process.finished = True
        process.process.stdin = HoldOpen()
        report.update(child_pid=process.pid, observer_injection="suppress-stdin-EOF-before-public-close")
        save()
        try:
            process.close()
        except subprocess.TimeoutExpired as error:
            report.update(status="PASS_ACTUAL_OBSERVER_FAILURE_RETAINED", expected_failure=repr(error),
                          receipt=process.receipt, complete_failure_cleanup_claimed=False)
        else:
            raise AssertionError("The held-open native owner did not exercise failure cleanup")
        finally:
            stdin.close()
    else:
        from hia.platform.peer_payload.qualification import owned_trace
        real = owned_trace.ptrace
        def injected(request, *arguments):
            if request == 0x4200:
                raise RuntimeError("deliberate-control-before-PTRACE_SETOPTIONS")
            return real(request, *arguments)
        owned_trace.ptrace = injected
        report["observer_injection"] = "after-actual-TRACEME-stop-before-PTRACE_SETOPTIONS"
        storage = args.output / "storage"
        storage.mkdir(mode=0o700)
        try:
            owned_trace.run(args.native, b"", args.output / "trace", storage=storage, target="open-journal-write")
        except RuntimeError as error:
            need(str(error) == "deliberate-control-before-PTRACE_SETOPTIONS", "Unexpected trace error")
            trace = json.loads((args.output / "trace/trace.json").read_bytes())
            need(trace["status"] == "FAIL" and trace["supervisor_cleanup"]["complete"] is True,
                 "Failed stopped child was not actually reaped")
            try:
                os.waitpid(trace["pid"], os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                raise AssertionError("Stopped control child remains waitable")
            report.update(status="PASS_ACTUAL_STOPPED_CHILD_CLEANUP", child_pid=trace["pid"],
                          expected_failure=repr(error), trace_identity=identity(capture(args.output / "trace/trace.json")))
        else:
            raise AssertionError("The deliberately failed trace succeeded")
finally:
    save()
    print(json.dumps(report, sort_keys=True), flush=True)
