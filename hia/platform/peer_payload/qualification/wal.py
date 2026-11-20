"""Run bounded complete AVL observations and a fresh original parser comparison."""
from pathlib import Path
import hashlib
import json
import os
import signal
import struct
import subprocess
import sys
import time
import traceback

from wal_fixtures import blocks, inspect_tree, names, specification, word

request = json.loads(Path(sys.argv[1]).read_bytes())
out = Path(request["output"])
out.mkdir(mode=0o700)
started = time.monotonic_ns()
deadline = time.monotonic() + 240
partition = request["partition"]
assert partition in ("small", "large", "maximum-replay", "maximum-index")
large = partition != "small"
maximum = partition.startswith("maximum-")
roster = (["maximal-aligned-sorted"] if maximum else
          [name for name in names(large) if name != "maximal-aligned-sorted"])
report = {"status": "FAIL", "cases": [], "processes": [],
          "partition": partition,
          "original_service_budget_qualified": False, "whole_payload_owner_qualified": False}


def identity(path):
    path = Path(path)
    assert path.is_file() and not path.is_symlink()
    with path.open("rb") as stream:
        return {"bytes": path.stat().st_size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def save():
    report["elapsed_ns"] = time.monotonic_ns() - started
    (out / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


def run(name, argv, stdin=None):
    directory = out / "processes" / name
    directory.mkdir(mode=0o700)
    row = {"name": name, "argv": list(map(str, argv)), "cwd": str(out), "exit_code": None,
           "timed_out": False, "cleanup": None, "deadline_monotonic": deadline,
           "stdin_path": str(stdin) if stdin is not None else "/dev/null",
           "stdin": identity(stdin) if stdin is not None else {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}}
    child = None
    before = time.monotonic_ns()
    try:
        with (Path(stdin).open("rb") if stdin is not None else open(os.devnull, "rb")) as source, \
                (directory / "stdout.raw").open("xb") as stdout, \
                (directory / "stderr.raw").open("xb") as stderr:
            child = subprocess.Popen(row["argv"], stdin=source, stdout=stdout, stderr=stderr,
                cwd=out, env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"},
                start_new_session=True, umask=0o077)
            row["pid"] = child.pid
            child.wait(timeout=max(0, deadline - time.monotonic()))
            row["exit_code"] = child.returncode
            assert child.returncode == 0, (name, child.returncode)
    except subprocess.TimeoutExpired:
        row["timed_out"] = True
        raise
    finally:
        if child is not None and child.poll() is None:
            tick = time.monotonic_ns()
            end = tick + 3_000_000_000
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=max(0, (end - time.monotonic_ns()) / 1e9))
            finally:
                row["cleanup"] = {"windows": 1, "limit_seconds": 3,
                    "elapsed_ns": time.monotonic_ns() - tick, "complete": child.poll() is not None}
        row["reaped"] = child is not None and child.poll() is not None
        row["elapsed_ns"] = time.monotonic_ns() - before
        for stream in ("stdout", "stderr"):
            if (directory / (stream + ".raw")).is_file():
                row[stream] = identity(directory / (stream + ".raw"))
        (directory / "process.json").write_text(json.dumps(row, sort_keys=True, indent=2) + "\n")
        report["processes"].append(row)
        save()
    return directory / "stdout.raw"


try:
    for key in ("replay", "index", "original", "worker"):
        assert identity(request[key]["path"]) == request[key]["identity"]
    for name in ("fixtures", "requests", "results", "processes"):
        (out / name).mkdir(mode=0o700)
    maximum_replay = None
    if partition == "maximum-index":
        maximum_replay = request["maximum_replay"]
        assert set(maximum_replay) == {"report", "input", "output", "original_output"}
        for row in maximum_replay.values():
            assert identity(row["path"]) == row["identity"]
        previous = json.loads(Path(maximum_replay["report"]["path"]).read_bytes())
        assert previous["status"] == "PASS" and previous["partition"] == "maximum-replay"
        assert previous["native_calls"] == previous["original_cases"] == 1
        assert previous["original_comparison_mode"] == "actual-fresh-original-invocation"
    for name in roster:
        path = out / "fixtures" / (name + ".input.raw")
        with path.open("xb") as stream:
            for block in blocks(name, large):
                stream.write(block)
        case = specification(name, large)
        case.update(input=str(path), input_identity=identity(path), observations=[], status="RUNNING")
        report["cases"].append(case)
        save()
        modes = ((partition.removeprefix("maximum-"),) if maximum else
                 ("replay", "index") if case["observe_index"] else ("replay",))
        if maximum_replay is not None:
            assert case["input_identity"] == maximum_replay["input"]["identity"]
        for mode in modes:
            label = name + "-" + mode
            item = {key: case[key] for key in ("input", "input_identity", "output_size")}
            item.update(mode=mode, output=str(out / "results" / label),
                library=request[mode]["path"], library_identity=request[mode]["identity"])
            file = out / "requests" / (label + ".json")
            file.write_text(json.dumps(item, sort_keys=True, indent=2) + "\n")
            run(label, [sys.executable, "-I", "-S", "-B", request["worker"]["path"], file])
            observed_path = out / "results" / label / "report.json"
            observed = json.loads(observed_path.read_bytes())
            assert observed["status"] == "ACTUAL_NATIVE_RETURNED"
            assert observed["input"] == case["input_identity"]
            value = {"mode": mode, "report": identity(observed_path), "value": observed["value"],
                     "native_elapsed_ns": observed["native_elapsed_ns"], "output": observed["output"]}
            if mode == "index":
                assert observed["value"] == 0
                tree = inspect_tree(out / "results" / label / "work.raw", path)
                replay = (Path(maximum_replay["output"]["path"]) if maximum_replay else
                          out / "results" / (name + "-replay") / "output.raw").read_bytes()
                assert replay[8:80].hex() == tree["summary_hex"]
                value["index"] = tree
            case["observations"].append(value)
            save()
        case["status"] = "PASS_NATIVE_AND_INDEX"
        save()
    original_cases = ([] if maximum_replay else
                      [row for row in report["cases"] if row["output_size"] == 256])
    input_path = out / "original-input.raw"
    native_path = out / "native-output.raw"
    if maximum_replay is None:
        with input_path.open("xb") as original, native_path.open("xb") as native:
          original.write(word(len(original_cases)))
          native.write(word(len(original_cases)))
          for case in original_cases:
              original.write(word(8, case["input_identity"]["bytes"] - 8))
              with Path(case["input"]).open("rb") as source:
                  assert source.read(8) == word(1)
                  while chunk := source.read(1 << 20):
                      original.write(chunk)
              observed = case["observations"][0]
              raw = (out / "results" / (case["name"] + "-replay") / "output.raw").read_bytes()
              value = raw[8:80] if observed["value"] == 0 else b""
              native.write(word(observed["value"], len(value)) + value)
        assert input_path.stat().st_size <= 512 << 20
        answer = run("original-parser", [request["original"]["path"], out / "original-private-store"], input_path)
        assert answer.read_bytes() == native_path.read_bytes(), "Actual original parser differs"
        report.update(original_comparison_mode="actual-fresh-original-invocation",
                      original_input=identity(input_path), native_output=identity(native_path),
                      original_output=identity(answer))
    else:
        raw = Path(maximum_replay["output"]["path"]).read_bytes()
        assert Path(maximum_replay["original_output"]["path"]).read_bytes() == word(1, 0, 72) + raw[8:80]
        report.update(original_comparison_mode="same-round-maximum-replay",
                      maximum_replay=maximum_replay)
        for row in maximum_replay.values():
            assert identity(row["path"]) == row["identity"]
    for key in ("replay", "index", "original", "worker"):
        assert identity(request[key]["path"]) == request[key]["identity"]
    report.update(status="PASS", source_inputs_stable=True, fresh_original_comparison_complete=True,
        original_cases=len(original_cases), native_calls=sum(len(row["observations"]) for row in report["cases"]),
        full_four_tree_invariants=True, maximum_record_count=(176602 if large else 1281))
except BaseException as error:
    report.update(failure=repr(error), traceback=traceback.format_exc())
    raise
finally:
    save()
    print(json.dumps({key: value for key, value in report.items() if key not in {"cases", "processes", "traceback"}}, sort_keys=True))
