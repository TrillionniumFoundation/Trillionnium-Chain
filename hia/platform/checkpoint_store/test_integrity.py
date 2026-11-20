"""Negative readback controls using copies of actual qualification evidence.

No production source or original observation is mutated. Hard-linked fixture
files are replaced atomically before modification; their source links remain
unchanged. Core capture is cached only inside these controls, and the ordinary
readback's final byte/roster recheck still reads every canonical input.
"""
from pathlib import Path
import contextlib
import json
import os
import shutil
import tempfile
from unittest.mock import patch

from . import build, original, readback
from .qualification_support import save


CONTROLS = (
    "missing-compiler-stage", "mutated-compiler-input", "coherent-compiler-output-forgery",
    "boolean-compiler-exit", "wrong-compiler-working-directory", "missing-compiler-receipt",
    "symlinked-compiler-input", "duplicate-build-json-field", "omitted-source-input",
    "changed-canonical-dependency", "added-owned-source", "relative-path-traversal",
    "missing-original-test", "unlocked-original-cargo", "filtered-original-test",
    "relaxed-original-clippy", "wrong-original-target", "wrong-original-working-directory",
    "changed-original-budget", "original-library-traversal", "missing-runtime-observation",
    "duplicate-runtime-call", "mutated-runtime-output", "mutated-runtime-input",
    "forged-runtime-pass", "symlinked-runtime-output", "mutated-cli-result",
    "missing-durability-action", "wrong-durability-syscall", "incomplete-durability-child",
    "unearned-whole-node-claim",
)


class Mutation:
    def __init__(self):
        self.saved = {}

    def remember(self, path):
        path = Path(path)
        if path not in self.saved:
            self.saved[path] = (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
        return path

    def write(self, path, raw):
        path = self.remember(path)
        fd, name = tempfile.mkstemp(prefix="mutation-", dir=path.parent)
        with os.fdopen(fd, "wb") as file:
            file.write(raw)
        os.replace(name, path)

    def json(self, path, value):
        self.write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())

    def remove(self, path):
        self.remember(path).unlink()

    def symlink(self, path, target):
        self.remember(path).unlink()
        path.symlink_to(target)

    def restore(self):
        for path, saved in reversed(list(self.saved.items())):
            if path.exists() or path.is_symlink():
                path.unlink()
            if saved is not None:
                path.write_bytes(saved[0])
                path.chmod(saved[1])


def run(output):
    output = Path(output)
    fixture = output / "integrity-fixture"
    fixture.mkdir(mode=0o700)
    for name in ("native", "original", "runtime"):
        shutil.copytree(output / name, fixture / name, copy_function=os.link,
                        ignore=(lambda path, names: ["files"] if Path(path) == output / "runtime" else []))
    captured = build.capture()
    canonical_root = fixture / "source"
    for name, raw in captured[0].items():
        path = canonical_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    native = build.decode(build.read(output / "native", "build.json"))
    oracle = build.decode(build.read(output / "original", "original.json"))
    expected = {"native_api": {k: native["artifacts"]["checkpoint-store-api"][k] for k in ("bytes", "sha256")},
                "native_cli": {k: native["artifacts"]["trnm-external-node-checkpoint-v2"][k] for k in ("bytes", "sha256")},
                "original_api": oracle["api"], "original_cli": oracle["cli"]}
    results = []
    report = {"schema": "trnm.hia.checkpoint-store-integrity.v1", "status": "FAIL",
              "source_set_sha256": native["source_set_sha256"], "controls": results}
    source_root, source_here = build.ROOT, build.HERE

    def check(kind):
        if kind == "native":
            build.validate(fixture / "native")
        elif kind == "original":
            original.validate(fixture / "original")
        else:
            readback.validate_runtime(fixture / "runtime", expected)

    def load(kind, filename):
        return build.decode(build.read(fixture / kind, filename))

    def stage(mutation, kind, label, change):
        name = "build.json" if kind == "native" else "original.json"
        value = load(kind, name)
        field = "stage" if kind == "native" else "label"
        row = next(row for row in value["stages"] if row[field] == label)
        change(row)
        prefix = "compiler/" if kind == "native" else ""
        mutation.json(fixture / kind / prefix / label / "receipt.json", row)
        mutation.json(fixture / kind / name, value)

    def refresh_runtime(mutation):
        report = load("runtime", "runtime.json")
        report["observations"] = build.identity(build.read(fixture / "runtime", "observations.json"))
        report["files"] = readback.evidence_manifest(fixture / "runtime")
        mutation.json(fixture / "runtime/runtime.json", report)

    def rows(mutation, change):
        values = load("runtime", "observations.json")
        change(values)
        mutation.json(fixture / "runtime/observations.json", values)
        refresh_runtime(mutation)

    def compiler_output(m):
        folder = fixture / "native"
        raw = bytearray(build.read(folder, "compiler/compile-main/stdout.raw"))
        raw[0] ^= 1
        raw = bytes(raw)
        m.write(folder / "compiler/compile-main/stdout.raw", raw)
        m.write(folder / "main.flat", raw)
        stage(m, "native", "compile-main", lambda row: row.update(output_sha256=build.sha256(raw)))
        report = load("native", "build.json")
        report["images"]["main"] = build.identity(raw)
        for name in build.PROFILES:
            executable = bytearray(build.read(folder, name))
            executable[5120:5120 + len(raw)] = raw
            m.write(folder / name, bytes(executable))
            report["artifacts"][name]["sha256"] = build.sha256(executable)
        m.json(folder / "build.json", report)

    def compiler_input(m):
        path = fixture / "native/compiler/compile-main/stdin.raw"
        raw = path.read_bytes() + b"\n"
        m.write(path, raw)
        stage(m, "native", "compile-main", lambda row: row.update(input_sha256=build.sha256(raw), input_bytes=len(raw)))

    def build_field(m, change):
        value = load("native", "build.json")
        change(value)
        m.json(fixture / "native/build.json", value)

    def original_field(m, change):
        value = load("original", "original.json")
        change(value)
        m.json(fixture / "original/original.json", value)

    def original_host(m):
        path = fixture / "original/rust-version/stdout.raw"
        raw = path.read_bytes().replace(b"x86_64-unknown-linux-gnu", b"aarch64-unknown-linux-gnu")
        m.write(path, raw)
        stage(m, "original", "rust-version", lambda row: row.update(stdout=build.identity(raw)))
        original_field(m, lambda value: value.update(rustc_version=raw.decode()))

    def raw_api(m, stream):
        values = load("runtime", "observations.json")
        first = next(row for row in values if row["kind"] == "api-pair")
        folder = first["native_process"]
        path = fixture / "runtime" / folder / (stream + ".raw")
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        m.write(path, bytes(raw))
        receipt = load("runtime", folder + "/receipt.json")
        receipt[stream] = build.identity(raw)
        m.json(path.parent / "receipt.json", receipt)
        refresh_runtime(m)

    def cli_raw(m):
        first = next(row for row in load("runtime", "observations.json") if row["kind"] == "cli-pair")
        folder = first["native_process"]
        path = fixture / "runtime" / folder / "stderr.raw"
        raw = path.read_bytes() + b"changed\n"
        m.write(path, raw)
        receipt = load("runtime", folder + "/receipt.json")
        receipt["result"]["stderr"] = raw.hex()
        m.json(path.parent / "receipt.json", receipt)
        refresh_runtime(m)

    def trace_mutation(m, action):
        first = next(row for row in load("runtime", "observations.json") if row["kind"] == "durability-boundary")
        path = fixture / "runtime" / (first["case"] + "-native") / "trace.json"
        trace = build.decode(path.read_bytes())
        if action == "missing":
            trace["actions"] = []
        elif action == "syscall":
            entry = trace["actions"][0]["entry"]
            trace["events"][entry - 1]["nr"] = 999
            next(row for row in trace["events"] if row["kind"] == "exit" and row["entry"] == entry)["nr"] = 999
        else:
            trace["supervisor_cleanup"] = "SIGKILL"
        m.json(path, trace)
        refresh_runtime(m)

    def omitted_source(m):
        def change(report):
            del report["source_inputs"]["hia/src/crypto/sha256_stream.hepta"]
            report["source_set_sha256"] = build.sha256(build.canonical(report["source_inputs"]))
        build_field(m, change)

    def duplicate_call(values):
        index = next(i for i, row in enumerate(values[1:], 1) if row["kind"] == "api-pair")
        values[index] = {**values[0], "ordinal": index}

    test_label = "test-" + sorted(oracle["tests"], key=lambda row: row["name"])[1]["name"]
    actions = [
        ("native", lambda m: build_field(m, lambda v: v["stages"].pop()), "compiler execution roster"),
        ("native", compiler_input, "Actual compiler input"),
        ("native", compiler_output, "Frozen compiler output"),
        ("native", lambda m: stage(m, "native", "compile-main", lambda v: v.update(exit_code=False)), "Failed native stage"),
        ("native", lambda m: stage(m, "native", "compile-main", lambda v: v.update(cwd="/tmp")), "execution boundary"),
        ("native", lambda m: m.remove(fixture / "native/compiler/compile-main/receipt.json"), "Missing regular input"),
        ("native", lambda m: m.symlink(fixture / "native/compiler/compile-main/stdin.raw", fixture / "native/main.compiler_input.hepta"), "Symlinked input"),
        ("native", lambda m: m.write(fixture / "native/build.json", (fixture / "native/build.json").read_bytes().rstrip()[:-1] + b',"status":"PASS"}'), "Duplicate JSON field"),
        ("native", omitted_source, "Captured source closure"),
        ("source", lambda m: m.write(canonical_root / "hia/src/crypto/sha256_stream.hepta", captured[0]["hia/src/crypto/sha256_stream.hepta"] + b"\n"), "Source changed"),
        ("source", lambda m: m.write(canonical_root / "hia/platform/checkpoint_store/unexpected.py", b"# unbound source\n"), "Owned input roster"),
        ("path", lambda m: None, "Noncanonical relative input"),
        ("original", lambda m: original_field(m, lambda v: v["tests"].pop()), "test executable roster"),
        ("original", lambda m: stage(m, "original", "cargo-test-build", lambda v: v["argv"].remove("--locked")), "invocation"),
        ("original", lambda m: stage(m, "original", test_label, lambda v: v["argv"].append("nonexistent-filter")), "invocation"),
        ("original", lambda m: stage(m, "original", "original-clippy", lambda v: v["argv"].remove("-D")), "invocation"),
        ("original", original_host, "qualification boundary"),
        ("original", lambda m: stage(m, "original", "cargo-test-build", lambda v: v.update(cwd="/tmp")), "invocation"),
        ("original", lambda m: stage(m, "original", test_label, lambda v: v.update(wall_limit_seconds=999)), "invocation"),
        ("original", lambda m: original_field(m, lambda v: v["rlibs"][0].update(relative_path="../outside.rlib")), "Noncanonical relative input"),
        ("runtime", lambda m: rows(m, lambda v: v.pop()), "observation roster"),
        ("runtime", lambda m: rows(m, duplicate_call), "Duplicate or missing"),
        ("runtime", lambda m: raw_api(m, "stdout"), "actual process bytes"),
        ("runtime", lambda m: raw_api(m, "stdin"), "Invalid saved API request"),
        ("runtime", lambda m: rows(m, lambda v: v[0]["native"]["header"].__setitem__(0, 1)), "actual process bytes"),
        ("runtime", lambda m: m.symlink(fixture / "runtime/process-0/stdout.raw", fixture / "runtime/process-1/stdout.raw"), "Symlinked"),
        ("runtime", cli_raw, "CLI process identity or result"),
        ("runtime", lambda m: trace_mutation(m, "missing"), "Durability action"),
        ("runtime", lambda m: trace_mutation(m, "syscall"), "wrong kernel operation"),
        ("runtime", lambda m: trace_mutation(m, "incomplete"), "terminal observation"),
        ("runtime", lambda m: m.json(fixture / "runtime/runtime.json", {**load("runtime", "runtime.json"), "whole_node_replacement": True}), "Incomplete runtime"),
    ]
    build.need(len(actions) == len(CONTROLS), "Integrity control roster differs")
    try:
        with patch.object(build, "capture", return_value=captured):
            for kind in ("native", "original", "runtime"):
                check(kind)
            for name, (kind, mutate, expected_error) in zip(CONTROLS, actions, strict=True):
                mutation = Mutation()
                try:
                    mutate(mutation)
                    with contextlib.ExitStack() as context:
                        if kind == "source":
                            context.enter_context(patch.object(build, "ROOT", canonical_root))
                            context.enter_context(patch.object(build, "HERE", canonical_root / "hia/platform/checkpoint_store"))
                            check("native")
                        elif kind == "path":
                            build.read(fixture, "../outside")
                        else:
                            check(kind)
                except (ValueError, AssertionError, KeyError, FileNotFoundError) as error:
                    build.need(expected_error.lower() in str(error).lower(),
                               "Negative control failed at an unrelated boundary: " + name + ": " + repr(error))
                    results.append({"name": name, "status": "REFUSED", "error": repr(error)})
                    save(output / "integrity.json", report)
                else:
                    raise AssertionError("Altered evidence was accepted: " + name)
                finally:
                    mutation.restore()
            for kind in ("native", "original", "runtime"):
                check(kind)
        build.need(build.ROOT == source_root and build.HERE == source_here, "Canonical source context was not restored")
        build.check_inputs(captured[0])
        report["status"] = "PASS"
    finally:
        save(output / "integrity.json", report)
    validate(report, native["source_set_sha256"])
    return report


def validate(report, source_set):
    build.need(report["schema"] == "trnm.hia.checkpoint-store-integrity.v1" and report["status"] == "PASS"
               and report["source_set_sha256"] == source_set
               and [row["name"] for row in report["controls"]] == list(CONTROLS)
               and all(row["status"] == "REFUSED" and isinstance(row["error"], str) and row["error"]
                       for row in report["controls"]), "Incomplete independent integrity controls")
