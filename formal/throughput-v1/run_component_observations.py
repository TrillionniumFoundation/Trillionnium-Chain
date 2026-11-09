#!/usr/bin/env python3
"""Run the fixed native component observations without building or qualifying service.

Supply already-built Linux libtest executables. The caller retains their build
and source receipts; this runner observes executable-file hashes, not a compiler
attestation. Every native process runs once, with its original selector and
limits. A zero runner exit means the planned component observations completed;
the original four-second Host and thirty-second campaign remain NOT_RUN/HOLD.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import execution_report  # noqa: E402
import whole_block_cost_metrics as whole_block  # noqa: E402

BLOCK_SUFFIX = "repeated_sender_tests::repeated_sender_complete_block_cost_observation"
ROOT_SUFFIX = "streaming_root_tests::complete_root_encoding_cost"
ROOT_ARMS = ("original", "streamed", "streamed", "original")
UNIT_SUFFIXES = (
    "cancellation_keeps_first_flag_transition_and_separates_worker_from_resource_close",
    "cancellation_does_not_reconstruct_an_earlier_unobserved_signal",
    "cancellation_and_worker_clocks_do_not_wait_for_diagnostic_row_locks",
    "cancellation_duplicate_worker_entry_preserves_first_owner_and_marks_capture_failed",
    "cancellation_live_snapshots_keep_signal_census_and_worker_creation_consistent",
)
TCP_SUFFIX = "write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work"
SNAPSHOT_MARKER = "TRNM_PUBLIC_CANCELLATION_SNAPSHOT "
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def read_output(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_OUTPUT_BYTES + 1)
    require(len(raw) <= MAX_OUTPUT_BYTES, "native output exceeds readback bound; original retained")
    return raw.decode("utf-8", errors="strict")


def disk():
    value = shutil.disk_usage(ROOT)
    return dict(total_bytes=value.total, used_bytes=value.used, free_bytes=value.free)


def binary_identity(path):
    return dict(path=str(path), bytes=path.stat().st_size, sha256=sha256(path))


def source_metadata():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    paths = (Path(__file__), Path(whole_block.__file__), Path(execution_report.__file__),
             ROOT / "scripts/pon_public_v3_phase_read.py")
    return dict(checkout_head=git("rev-parse", "HEAD"), checkout_tree=git("rev-parse", "HEAD^{tree}"),
        reader_sha256={str(path.relative_to(ROOT)): sha256(path) for path in paths},
        scope="checkout metadata and reader bytes only; not complete-source or binary-build attestation")


class Recorder:
    def __init__(self, output, binaries):
        self.output = output
        self.initial = {str(path): binary_identity(path) for path in binaries}
        self.commands = []

    def execute(self, name, argv, extra_env=None):
        """Retain the exact legacy wait4 receipt and a separate binary binding."""
        argv = [str(value) for value in argv]
        overrides = dict(extra_env or {})
        before_disk = disk()
        invocation_started = time.monotonic_ns()
        process_started = process_wall_ns = None
        before = after = None
        code = waited_pid = usage = None
        problem = None
        interrupted = False
        stdout = self.output / (name + ".stdout")
        stderr = self.output / (name + ".stderr")
        print(json.dumps(dict(event="start", name=name, argv=argv)), flush=True)
        with stdout.open("xb") as out, stderr.open("xb") as err:
            child = None
            try:
                before = binary_identity(Path(argv[0]))
                require(before == self.initial[argv[0]], "binary differs from initial file identity")
                environment = os.environ.copy()
                environment.update(overrides)
                process_started = time.monotonic_ns()
                child = subprocess.Popen(argv, cwd=ROOT, env=environment, stdout=out, stderr=err,
                                         start_new_session=True)
                try:
                    waited_pid, status, actual_usage = os.wait4(child.pid, 0)
                except BaseException:
                    interrupted = True
                    # An interrupted measurement is retained, never retried.
                    # Kill only this runner-created process group, then reap it.
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    waited_pid, status, actual_usage = os.wait4(child.pid, 0)
                code = os.waitstatus_to_exitcode(status)
                child.returncode = code
                process_wall_ns = time.monotonic_ns() - process_started
                usage = {key: getattr(actual_usage, key) for key in sorted(whole_block.RUSAGE_FIELDS)}
            except (OSError, ValueError) as error:
                problem = f"{type(error).__name__}: {error}"
            finally:
                try:
                    after = binary_identity(Path(argv[0]))
                except OSError as error:
                    problem = problem or f"binary readback {type(error).__name__}: {error}"
        receipt = dict(name=name, argv=argv, cwd=str(ROOT), exit_code=code, waited_pid=waited_pid,
            wall_ns=process_wall_ns, disk_before=before_disk, disk_after=disk(),
            extra_env=overrides, rusage=usage, rusage_maxrss_unit="KiB (Linux)",
            stdout_sha256=sha256(stdout), stderr_sha256=sha256(stderr))
        # Do not add binary/provenance fields to this exact historical schema.
        require(set(receipt) == whole_block.PROCESS_FIELDS, "process receipt fields changed")
        write_json(self.output / (name + ".record.json"), receipt)
        stable = before is not None and before == after == self.initial[argv[0]]
        binding = dict(schema="trnm-component-process-binary-binding-v1", name=name,
            binary_before=before, binary_after=after, binary_endpoints_match=stable,
            process_receipt_sha256=sha256(self.output / (name + ".record.json")),
            launch_or_observation_error=problem, interrupted=interrupted,
            invocation_wall_ns=time.monotonic_ns() - invocation_started,
            scope="file hashes before/after; not executed-image or compiled-source attestation",
            process_wall_scope="Popen through wait4 return; excludes binary hashing and report preparation",
            rusage_scope="whole child process including fixture preparation, all threads, assertions and output; not per-arm CPU",
            unobserved_descendant_or_device_costs_are_zero=False)
        write_json(self.output / (name + ".binary-binding.json"), binding)
        self.commands.append(dict(name=name, receipt=name + ".record.json",
            binding=name + ".binary-binding.json", exit_code=code,
            binary_endpoints_match=stable, interrupted=interrupted, error=problem))
        print(json.dumps(dict(event="finish", name=name, exit_code=code,
                              binary_endpoints_match=stable, error=problem)), flush=True)
        if interrupted:
            write_json(self.output / "commands.json", self.commands)
            write_json(self.output / "summary.json", dict(
                schema="trnm-fixed-native-component-run-summary-v1", status="interrupted",
                component_observations_complete=False, interrupted_command=name,
                retained_commands=self.commands, remaining_plan="NOT_RUN",
                original_host_4s="NOT_RUN", original_campaign_30s="NOT_RUN",
                confirmed_business_tps=None, production_activation=False, qualification="HOLD_NO_GO"))
            raise InterruptedError("component measurement interrupted; process reaped and remaining plan not run")
        return receipt, binding


def successful_process(receipt, binding):
    require(receipt["exit_code"] == 0 and not binding["interrupted"]
            and binding["launch_or_observation_error"] is None and binding["binary_endpoints_match"],
            "native process did not complete with unchanged binary endpoints")


def selectors(output, list_name, suffixes):
    names = [line[:-6] for line in read_output(output / (list_name + ".stdout")).splitlines()
             if line.endswith(": test")]
    require(len(names) == len(set(names)), "duplicate native test inventory names")
    write_json(output / (list_name + ".inventory.json"), names)
    chosen = {}
    for suffix in suffixes:
        matches = [name for name in names if name == suffix or name.endswith("::" + suffix)]
        require(len(matches) == 1, f"native test inventory requires exactly one {suffix}")
        chosen[suffix] = matches[0]
    return chosen


def successful_test(output, name, selector, expected_tests=None):
    text = read_output(output / (name + ".stdout"))
    lines = [line for line in text.splitlines() if line.strip()]
    expected = [selector] if expected_tests is None else expected_tests
    count = len(expected)
    require(count > 0 and len(lines) >= 3
            and lines[0] == f"running {count} test{'s' if count != 1 else ''}",
            "complete nonempty native test census required")
    require(re.fullmatch(rf"test result: ok\. {count} passed; 0 failed; 0 ignored; 0 measured; "
            r"[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s", lines[-1]) is not None,
            "complete nonempty native libtest success footer required")
    seen = [line[5:].split(" ... ", 1)[0] for line in lines
            if line.startswith("test ") and " ... " in line]
    require(len(seen) == count and len(set(seen)) == count and set(seen) == set(expected),
            "actual native test names differ from the original inventory")
    if count == 1:
        require(lines[-2] == "ok" or lines[-2] == f"test {selector} ... ok",
                "actual selected test terminal result required")
    return text


def extract_single_json(text, marker):
    candidates = [line[line.index(marker) + len(marker):] for line in text.splitlines() if marker in line]
    require(len(candidates) == 1, "exactly one native observation marker required")
    value = json.loads(candidates[0], object_pairs_hook=whole_block.unique_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite native JSON")))
    require(type(value) is dict, "native observation object required")
    return value


def run(args):
    require(sys.platform.startswith("linux") and hasattr(os, "wait4"), "Linux wait4 is required")
    output = args.output.resolve()
    require(not output.exists(), "output must be a new directory")
    require(not output.is_relative_to(ROOT), "output must be outside the source repository")
    require(not any((parent / ".git").exists() for parent in (output, *output.parents)),
            "output must be outside a Git worktree")
    binaries = [args.mvcc_binary.resolve(strict=True), args.node_binary.resolve(strict=True)]
    require(all(path.is_file() and os.access(path, os.X_OK) for path in binaries),
            "both explicit native binaries must be executable regular files")
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(output, binaries)
    before = source_metadata()
    write_json(output / "source-before.json", before)
    write_json(output / "profile.json", dict(schema="trnm-fixed-component-observation-plan-v1",
        cpu_count=os.cpu_count(), platform=platform.platform(), binaries=list(recorder.initial.values()),
        build_profile=None, build_toolchain=None, caller_must_retain_build_receipts=True,
        whole_block=dict(expected_records=84, senders=[2, 64, 256], workers=4,
            warmup_pairs_per_group=2, measured_pairs_per_group=12, order="alternating AB/BA"),
        complete_root_arms=list(ROOT_ARMS), required_new_cancellation_unit_suffixes=list(UNIT_SUFFIXES),
        new_controls_are_subset_of_one_complete_observation_module=True,
        tcp_test_suffix=TCP_SUFFIX, native_test_processes_planned=7,
        original_host_4s="NOT_RUN", original_campaign_30s="NOT_RUN",
        original_resource_profile_qualified=False, confirmed_business_tps=None,
        independently_accepted_useful_tasks_per_second=None, production_activation=False,
        qualification="HOLD_NO_GO"))
    results, inventories, root_rows = [], {}, []

    def observe(name, binary, selector, *, ignored=False, extra_env=None, inspect=None, expected_tests=None):
        argv = [str(binary), selector, *(["--ignored"] if ignored else []),
                *(["--exact"] if expected_tests is None else []), "--nocapture", "--test-threads=1"]
        receipt, binding = recorder.execute(name, argv, extra_env)
        result = dict(name=name, status="retained_failure", error=None)
        try:
            successful_process(receipt, binding)
            text = successful_test(output, name, selector, expected_tests)
            if inspect is not None:
                inspect(text, receipt)
            result["status"] = "observed_complete"
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
            result["error"] = f"{type(error).__name__}: {error}"
        write_json(output / (name + ".readback.json"), result)
        results.append(result)

    for name, binary, suffixes in (("mvcc-test-list", binaries[0], (BLOCK_SUFFIX, ROOT_SUFFIX)),
                                   ("node-test-list", binaries[1], (*UNIT_SUFFIXES, TCP_SUFFIX))):
        receipt, binding = recorder.execute(name, [str(binary), "--list"])
        try:
            successful_process(receipt, binding)
            inventories[name] = selectors(output, name, suffixes)
        except (OSError, ValueError, UnicodeError) as error:
            results.append(dict(name=name, status="inventory_failed", error=str(error)))
    write_json(output / "selectors.json", inventories)

    def block_readback(_text, _receipt):
        report = whole_block.read(output / "complete-block.stdout", sha256(output / "complete-block.stdout"),
            receipt_path=output / "complete-block.record.json",
            expected_receipt_sha256=sha256(output / "complete-block.record.json"),
            stderr_path=output / "complete-block.stderr")
        write_json(output / "complete-block-metrics.json", report)

    def root_readback(arm, name):
        def inspect(text, receipt):
            marker = f"test {inventories['mvcc-test-list'][ROOT_SUFFIX]} ... "
            row = extract_single_json(text, marker)
            expected = dict(schema="pon-complete-root-encoding-cost-v1", implementation=arm,
                state_keys=16_384, value_encoding_bytes=4096, native_ledger_admission=False,
                end_to_end_throughput=False, production_activation=False)
            require(set(row) == set(expected) | {"root", "root_wall_ns"}
                    and all(type(row[key]) is type(value) and row[key] == value
                            for key, value in expected.items()), "original complete-root fields required")
            require(type(row["root"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["root"])
                    and type(row["root_wall_ns"]) is int and 0 < row["root_wall_ns"] <= receipt["wall_ns"],
                    "complete-root digest and enclosed positive wall interval required")
            root_rows.append(dict(name=name, observation=row, process_receipt=name + ".record.json"))
        return inspect

    if "mvcc-test-list" in inventories:
        selected = inventories["mvcc-test-list"]
        observe("complete-block", binaries[0], selected[BLOCK_SUFFIX], ignored=True, inspect=block_readback)
        for index, arm in enumerate(ROOT_ARMS):
            name = f"complete-root-{index}-{arm}"
            observe(name, binaries[0], selected[ROOT_SUFFIX], ignored=True,
                    extra_env={"TRNM_ROOT_ENCODING_IMPLEMENTATION": arm}, inspect=root_readback(arm, name))
    else:
        results.append(dict(name="mvcc-plan", status="not_run", planned_processes=5,
                            error="native selector inventory unavailable"))

    def snapshot_readback(text, _receipt):
        snapshot = extract_single_json(text, SNAPSHOT_MARKER)
        metrics = execution_report.request_metrics(snapshot)
        require("request_flag_observation" in (metrics.get("cancellation") or {}),
                "actual new cancellation snapshot required")
        write_json(output / "cancellation-request-snapshot.json", snapshot)
        write_json(output / "cancellation-component-profile.json", dict(
            schema="trnm-cancellation-native-component-readback-v1", metrics=metrics,
            native_test="cancellation-native-tcp", qualification="HOLD_NO_GO",
            original_host_4s_executed=False, original_campaign_30s_executed=False,
            public_confirmation=False, production_activation=False))

    if "node-test-list" in inventories:
        selected = inventories["node-test-list"]
        try:
            prefixes = {selected[suffix].rsplit("::", 1)[0] + "::" for suffix in UNIT_SUFFIXES}
            require(len(prefixes) == 1, "new cancellation tests must belong to one original module")
            prefix = prefixes.pop()
            require(prefix.endswith("::request_observation::tests::"),
                    "original request-observation test module required")
            all_names = json.loads((output / "node-test-list.inventory.json").read_text())
            module = [name for name in all_names if prefix in name]
            require(len(module) >= len(UNIT_SUFFIXES) and all(name.startswith(prefix) for name in module),
                    "module filter has ambiguous native inventory membership")
            write_json(output / "node-module-plan.json", dict(prefix=prefix,
                tests=module, test_count=len(module), required_new_controls=[selected[suffix] for suffix in UNIT_SUFFIXES],
                new_controls_are_counted_once_inside_module=True))
            observe("request-observation-module", binaries[1], prefix, expected_tests=module)
        except InterruptedError:
            raise
        except (OSError, ValueError) as error:
            results.append(dict(name="request-observation-module", status="not_run", error=str(error)))
        observe("cancellation-native-tcp", binaries[1], selected[TCP_SUFFIX], inspect=snapshot_readback)
    else:
        results.append(dict(name="node-plan", status="not_run", planned_processes=2,
                            error="native selector inventory unavailable"))
    write_json(output / "complete-root-observations.json", root_rows)
    after = source_metadata()
    write_json(output / "source-after.json", after)
    write_json(output / "commands.json", recorder.commands)
    roots_equal = len(root_rows) == 4 and len({row["observation"]["root"] for row in root_rows}) == 1
    complete = (len(results) == 7 and all(row["status"] == "observed_complete" for row in results)
                and roots_equal and before == after)
    summary = dict(schema="trnm-fixed-native-component-run-summary-v1", results=results,
        component_observations_complete=complete, all_four_complete_roots_equal=roots_equal,
        checkout_metadata_and_reader_bytes_unchanged=before == after,
        source_execution_authenticated=False, whole_process_rusage_is_per_arm_cpu=False,
        original_resource_profile_qualified=False, original_host_4s="NOT_RUN",
        original_campaign_30s="NOT_RUN", confirmed_business_tps=None,
        independently_accepted_useful_tasks_per_second=None, production_activation=False,
        qualification="HOLD_NO_GO")
    write_json(output / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if complete else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mvcc-binary", type=Path, required=True)
    parser.add_argument("--node-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="new output directory outside every Git worktree")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status="runner_refused_or_interrupted", error=str(error),
                              qualification="HOLD_NO_GO")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
