"""Complete source-bound Linux checkpoint-store qualification and readback."""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import time
import traceback

from . import build, original, readback
from . import cases_api, cases_recovery, cases_files, cases_cli, cases_unix, cases_crash
from .qualification_support import Suite, save


def binaries(native, original_report):
    return {"native_api": {k: native["artifacts"]["checkpoint-store-api"][k] for k in ("bytes", "sha256")},
            "native_cli": {k: native["artifacts"]["trnm-external-node-checkpoint-v2"][k] for k in ("bytes", "sha256")},
            "original_api": original_report["api"], "original_cli": original_report["cli"]}


def qualify(output):
    output = Path(output).absolute()
    build.need(not output.exists() and not output.is_symlink()
               and output.parent.resolve(strict=True) == output.parent
               and build.ROOT != output and build.ROOT not in output.parents,
               "Qualification requires a fresh canonical directory outside the source tree")
    output.mkdir(mode=0o700)
    started = time.monotonic_ns()
    native = oracle = suite = None
    initial, failure, cleanup_failures = {}, None, []
    stages = []
    try:
        native = build.build(output / "native")
        stages.append("native-build")
        initial = {name: build.read(build.ROOT, name) for name in native["source_inputs"]}
        build.need(build.exact({name: build.identity(raw) for name, raw in initial.items()}, native["source_inputs"]),
                   "Source changed immediately after native build")
        oracle = original.Original(output / "original")
        original.validate(output / "original")
        stages.append("original-77-tests-clippy-format")
        suite = Suite(output / "native", oracle.cli, oracle.api, output / "runtime")
        for group, module in (("api", cases_api), ("recovery", cases_recovery), ("files", cases_files),
                              ("cli", cases_cli), ("unix", cases_unix), ("crash", cases_crash)):
            suite.group = group
            before = len(suite.rows)
            module.run(suite)
            build.need(len(suite.rows) - before == readback.GROUPS[group], "Complete runtime group count differs: " + group)
            stages.append("runtime-" + group)
        suite.close()
        build.check_inputs(initial)
    except BaseException as error:
        failure = {"error": repr(error), "traceback": traceback.format_exc()}
    finally:
        if suite is not None:
            try:
                suite.close(require_success=failure is None)
            except BaseException as error:
                cleanup_failures.append(repr(error))
            runtime = {
                "schema": "trnm.hia.checkpoint-store-runtime.v1",
                "status": "PASS" if failure is None and not cleanup_failures else "FAIL",
                "failure": failure, "cleanup_failures": cleanup_failures,
                "binaries": binaries(native, oracle.report),
                "paths": {"output": str(suite.output), "native_api": str(suite.native / "checkpoint-store-api"),
                          "native_cli": str(suite.native / "trnm-external-node-checkpoint-v2"),
                          "original_api": str(suite.original_api), "original_cli": str(suite.original_cli)},
                "observations": build.identity(build.read(suite.output, "observations.json")),
                "files": readback.evidence_manifest(suite.output),
                "power_failure_claimed": False, "whole_node_replacement": False,
            }
            save(suite.output / "runtime.json", runtime)
        if initial:
            try:
                build.check_inputs(initial)
            except BaseException as error:
                cleanup_failures.append(repr(error))
    if failure is None and not cleanup_failures:
        try:
            build.validate(output / "native")
            original.validate(output / "original")
            readback.validate_runtime(output / "runtime", binaries(native, oracle.report))
            stages.append("independent-readback")
            from . import test_integrity
            test_integrity.run(output)
            stages.append("integrity-negatives")
            build.check_inputs(initial)
        except BaseException as error:
            failure = {"error": repr(error), "traceback": traceback.format_exc()}
    report = {
        "schema": "trnm.hia.checkpoint-store-qualification.v1",
        "status": "PASS" if failure is None and not cleanup_failures else "FAIL",
        "failure": failure, "cleanup_failures": cleanup_failures, "stages": stages,
        "source_set_sha256": None if native is None else native["source_set_sha256"],
        "reports": {name: build.identity((output / path).read_bytes()) for name, path in
                    (("native", "native/build.json"), ("original", "original/original.json"),
                     ("runtime", "runtime/runtime.json"), ("integrity", "integrity.json"))
                    if (output / path).is_file()},
        "elapsed_ns": time.monotonic_ns() - started,
        "whole_node_replacement": False, "production_activation": False, "power_failure_claimed": False,
    }
    save(output / "qualification.json", report)
    build.need(report["status"] == "PASS", "Qualification failed; complete actual observations were retained")
    validate(output)
    return report


def validate(output):
    output = Path(output).absolute()
    build.need(output.resolve(strict=True) == output and not output.is_symlink(), "Canonical qualification directory required")
    report = build.decode(build.read(output, "qualification.json"))
    expected_stages = ["native-build", "original-77-tests-clippy-format"]
    expected_stages += ["runtime-" + group for group in readback.GROUPS]
    expected_stages += ["independent-readback", "integrity-negatives"]
    build.need(report["schema"] == "trnm.hia.checkpoint-store-qualification.v1"
               and report["status"] == "PASS" and report["failure"] is None
               and report["cleanup_failures"] == [] and report["stages"] == expected_stages
               and report["whole_node_replacement"] is False and report["production_activation"] is False
               and report["power_failure_claimed"] is False, "Incomplete checkpoint-store qualification")
    for name, path in (("native", "native/build.json"), ("original", "original/original.json"),
                       ("runtime", "runtime/runtime.json"), ("integrity", "integrity.json")):
        build.need(build.exact(report["reports"][name], build.identity(build.read(output, path))),
                   "Qualification child report differs")
    native = build.validate(output / "native")
    original_report = original.validate(output / "original")
    readback.validate_runtime(output / "runtime", binaries(native, original_report))
    from . import test_integrity
    test_integrity.validate(build.decode(build.read(output, "integrity.json")), native["source_set_sha256"])
    build.need(report["source_set_sha256"] == native["source_set_sha256"], "Qualification source binding differs")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--verify", type=Path)
    args = parser.parse_args()
    result = qualify(args.output) if args.output is not None else validate(args.verify)
    print(json.dumps({key: result[key] for key in ("status", "source_set_sha256", "reports")}, sort_keys=True))


if __name__ == "__main__":
    main()
