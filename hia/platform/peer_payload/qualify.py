"""Fresh complete original/native metadata owner qualification and independent readback."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
import traceback

from hia.platform.peer_lease_unix.process import Processes
from .build import Build
from . import original
from .contract import (ROOT, HERE, SCHEMA, LIMITS, FALSE, capture, canonical, check_environment,
                       corpus, document, identity, need, repository_identity, priority_cases, wal_scope_history)

GROUPS = ("primitives", "runtime", "allocations", "views", "public", "syscalls", "crash", "boundaries",
          "wal-small", "wal-large", "wal-maximum-replay", "wal-maximum-index")


class Qualification:
    def __init__(self, output):
        self.output = Path(output).absolute()
        need(not self.output.exists() and not self.output.is_symlink()
             and ROOT not in self.output.resolve().parents, "Fresh output outside repository required")
        need(os.geteuid() != 0, "Real permission refusal histories require a non-root account")
        guard = check_environment(os.environ)
        self.output.mkdir(parents=True, mode=0o700)
        self.started = time.monotonic_ns()
        self.report = {"schema": SCHEMA, "status": "RUNNING", "limits": LIMITS,
            "repository": str(ROOT), "output": str(self.output), "lineage": repository_identity(),
            "environment_guard": guard, "wal_scope_history": wal_scope_history(),
            "compiler_environment": {name: os.environ[name] for name in
                ("HIA_TOOLCHAIN_ROOT", "HIA_NATIVE_COMPILER", "HIA_NATIVE_COMPILER_SHA256")},
            "groups": {}, **dict.fromkeys(FALSE, False)}
        self.build = None
        self.processes = None

    def save(self):
        self.report["elapsed_ns"] = time.monotonic_ns() - self.started
        if self.processes is not None:
            self.report["stages"] = list(self.processes.rows)
        (self.output / "report.json").write_text(json.dumps(self.report, sort_keys=True, indent=2) + "\n")

    def path(self, name):
        path = self.output / name
        return {"path": str(path), "identity": identity(capture(path))}

    def observe(self):
        self.build = Build(self.output / "native")
        native = self.build.build()
        self.report.update(source_inputs=native["source_inputs"],
            source_set_sha256=identity(canonical(native["source_inputs"]))["sha256"],
            native_build=identity(capture(self.output / "native/build.json")))
        self.save()
        old = original.run(self.output / "original", self.build.check)
        self.report["original_build"] = identity(capture(self.output / "original/report.json"))
        self.report["retained_tests"] = old["retained_tests"]
        environment = {name: os.environ[name] for name in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR")
                       if name in os.environ}
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        self.report["observation_environment"] = dict(environment)
        self.processes = Processes(self.output / "observations", ROOT, environment, self.build.check)
        (self.output / "cases").mkdir(mode=0o700)
        (self.output / "requests").mkdir(mode=0o700)
        (self.output / "fixtures").mkdir(mode=0o700)
        for kind in ("codec", "replay"):
            raw, _ = corpus(kind)
            (self.output / "fixtures" / (kind + "-cases.json")).write_bytes(raw)
        (self.output / "fixtures/priority-cases.json").write_bytes(canonical(priority_cases()))
        for group in GROUPS:
            directory = self.output / "cases" / group
            if group in ("public", "syscalls", "crash", "boundaries"):
                argv = [sys.executable, "-B", HERE / "qualification" / (group + ".py"),
                    "--native", self.output / "native/payload-owner.elf", "--original",
                    self.output / "original/public-reference.elf", "--fixtures",
                    self.output / "fixtures/codec-cases.json", "--output", directory]
            elif group == "views":
                argv = [sys.executable, "-B", "-m", "hia.platform.peer_payload.qualification.views",
                    "--image", self.output / "native/view-fixture.elf", "--output", directory]
            else:
                request = {"output": str(directory)}
                if group in ("primitives", "runtime"):
                    request.update(codec=self.path("native/metadata_codec.so"), replay=self.path("native/metadata_log.so"),
                        codec_cases=self.path("fixtures/codec-cases.json"), replay_cases=self.path("fixtures/replay-cases.json"),
                        priority_cases=self.path("fixtures/priority-cases.json"))
                    request["original" if group == "primitives" else "runtime"] = self.path(
                        "original/metadata-reference.elf" if group == "primitives" else "native/metadata_runtime.so")
                    script = group + ".py"
                elif group == "allocations":
                    request.update(production=self.path("native/metadata_log.so"), observed=self.path("native/metadata-observed.so"),
                                   cases=self.path("fixtures/replay-cases.json"))
                    script = "allocations.py"
                else:
                    need(group in ("wal-small", "wal-large", "wal-maximum-replay", "wal-maximum-index"), "Unknown native group")
                    request.update(replay=self.path("native/metadata_log.so"), index=self.path("native/metadata-index.so"),
                        original=self.path("original/metadata-reference.elf"), partition=group.removeprefix("wal-"),
                        worker={"path": str(HERE / "qualification/wal_worker.py"),
                                "identity": identity(capture(HERE / "qualification/wal_worker.py"))})
                    if group == "wal-maximum-index":
                        base = "cases/wal-maximum-replay/"
                        request["maximum_replay"] = {name: self.path(base + suffix) for name, suffix in (
                            ("report", "report.json"), ("input", "fixtures/maximal-aligned-sorted.input.raw"),
                            ("output", "results/maximal-aligned-sorted-replay/output.raw"),
                            ("original_output", "processes/original-parser/stdout.raw"))}
                    script = "wal.py"
                request_path = self.output / "requests" / (group + ".json")
                request_path.write_text(json.dumps(request, sort_keys=True, indent=2) + "\n")
                argv = [sys.executable, "-B", HERE / "qualification" / script, request_path]
            self.processes.run(group, argv, timeout=240)
            raw = capture(directory / "report.json")
            value = document(directory / "report.json")
            need(value.get("status", "").startswith("PASS"), "Actual native group failed: " + group)
            self.report["groups"][group] = {"directory": directory.relative_to(self.output).as_posix(),
                                            "report": identity(raw)}
            self.save()
            print(json.dumps({"group": group, "status": value["status"],
                              "elapsed_ns": self.processes.rows[-1]["elapsed_ns"]}), flush=True)
        self.build.check()
        self.report.update(source_inputs_stable=True, metadata_owner_public_methods_qualified=12,
            original_tests_rerun_in_this_qualification=True, public_observer_links_unchanged_original=True,
            private_observer_append_only_test_hook=True)
        self.save()

    def run(self):
        try:
            self.observe()
            from .readback import production_readback, controls_readback, inventory
            self.report["production_readback"] = production_readback(self.output, self.report)
            self.save()
            (self.output / "pre-controls.json").write_bytes(capture(self.output / "report.json"))
            self.processes.environment["TRNM_PEER_UNIX_CONTROL_ROOT"] = str(self.output / "integrity-controls")
            self.processes.run("integrity-controls", [sys.executable, "-B", "-m", "unittest", "-v",
                "hia.platform.peer_payload.test_qualification"], timeout=30)
            self.report["integrity_controls"] = controls_readback(self.output, self.processes.rows[-1])
            self.build.check()
            self.report.update(status="PASS", complete_original_tests_preserved=True,
                               source_inputs_stable=True)
            self.save()
            need(self.report["elapsed_ns"] <= 1_200_000_000_000, "Qualification exceeded unchanged 20 minute job budget")
            entries = inventory(self.output)
            raw = canonical(entries)
            (self.output / "contents.json").write_bytes(raw)
            self.report.update(contents=identity(raw), retained_entries=len(entries))
            self.save()
            return self.report
        except BaseException as error:
            self.report.update(status="FAIL", failure=repr(error), traceback=traceback.format_exc())
            self.save()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--output", type=Path, required=True)
    reader = commands.add_parser("readback")
    reader.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "run":
        result = Qualification(args.output).run()
    else:
        from .readback import readback
        result = readback(args.input)
    print(json.dumps({key: result[key] for key in ("schema", "status", "elapsed_ns", "retained_entries") if key in result}, sort_keys=True))


if __name__ == "__main__":
    main()
