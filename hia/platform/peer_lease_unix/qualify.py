"""Execute and independently read back the complete finite peer Unix contract."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
import traceback

from .build import Build, ROOT, HERE, identity, need
from .original_build import Original
from .process import Processes
from .readback import CONTENTS, GROUPS, inventory, readback, integrity_readback


def run(output):
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "Optimized Python is not admitted")
    need(os.geteuid() != 0, "Owned permission-fault observations require a non-root account")
    output = Path(output).absolute()
    need(not output.exists() and not output.is_symlink() and ROOT not in output.resolve().parents,
         "Qualification needs a fresh directory outside the repository")
    output.mkdir(parents=True, mode=0o700)
    started = time.monotonic_ns()
    report = {"schema": "trnm.hia.peer-unix-qualification.v1", "status": "RUNNING",
              "source_inputs": {}, "groups": {}, "runtime_host_proxy": False,
              "rust_or_interpreter_fallback": False, "whole_peer_package_retired": False,
              "whole_chain_native": False, "production_activation": False,
              "original_service_budget_qualified": False,
              "foreign_pointer_ownership_or_concurrent_arena_qualified": False}
    processes = None
    try:
        build = Build(output / "native")
        native = build.build()
        report["source_inputs"] = native["source_inputs"]
        report["native_build"] = identity((output / "native/build.json").read_bytes())
        original = Original(output / "original", build.check).build()
        report["original_build"] = identity((output / "original/build.json").read_bytes())
        environment = {name: os.environ[name] for name in
                       ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR") if name in os.environ}
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        processes = Processes(output / "observations", ROOT, environment, build.check)
        processes.environment["TRNM_PEER_UNIX_CONTROL_ROOT"] = str(output / "integrity-controls")
        processes.run("integrity-controls", [sys.executable, "-B", "-m", "unittest", "-v",
            "hia.platform.peer_lease_unix.test_qualification"], timeout=30)
        report["integrity_controls"] = integrity_readback(output, processes.rows[-1])
        processes.environment = dict(environment)
        (output / "cases").mkdir(mode=0o700)
        for group, spec in GROUPS.items():
            executable = output / "native" / spec["native"]
            reference = output / "original" / original["observers"][spec["original"]]["path"]
            case_output = output / "cases" / spec["directory"]
            flag = "--reference" if group == "codec" else "--original"
            argv = [sys.executable, "-B", HERE / spec["script"], "--native", executable,
                    flag, reference, "--output", case_output]
            processes.run(group, argv)
            data = (case_output / "report.json").read_bytes()
            value = json.loads(data)
            need(value.get("status") == "PASS", "Actual group failed: " + group)
            report["groups"][group] = {"report": identity(data), "directory": str(case_output.relative_to(output)),
                "native": identity(executable.read_bytes()), "original": identity(reference.read_bytes())}
        build.check()
        report.update(status="PASS", source_inputs_stable=True,
                      retained_original_tests=original["retained_tests"],
                      native_runtime_count=4, original_test_targets=len(original["test_rosters"]))
    except BaseException as error:
        report.update(status="FAIL", failure=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        if processes is not None:
            report["stages"] = processes.rows
        report["elapsed_ns"] = time.monotonic_ns() - started
        contents = inventory(output)
        raw = (json.dumps(contents, sort_keys=True, indent=2) + "\n").encode()
        (output / CONTENTS).write_bytes(raw)
        report["contents"] = identity(raw)
        report["retained_entries"] = len(contents)
        (output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    execute = commands.add_parser("run")
    execute.add_argument("--output", type=Path, required=True)
    reader = commands.add_parser("readback")
    reader.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    value = run(args.output) if args.command == "run" else readback(args.input)
    print(json.dumps({key: value[key] for key in ("schema", "status")}
                     | {key: value[key] for key in ("elapsed_ns", "retained_entries", "groups")
                        if key in value}, sort_keys=True))


if __name__ == "__main__":
    main()
