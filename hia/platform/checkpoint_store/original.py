"""Build the exact original Cargo graph, all retained tests and method oracle."""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import time

from .build import ROOT, read, decode, exact
from .qualification_support import identity, need, save, terminal


class Original:
    def __init__(self, output):
        self.output = Path(output).absolute()
        self.output.mkdir(mode=0o700)
        self.stages = []
        rust = shutil.which("rustc")
        need(rust is not None, "Exact original Rust 1.95.0 is required")
        self.bin = Path(rust).resolve().parent
        self.env = dict(os.environ)
        for key in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_ENCODED_RUSTFLAGS",
                    "RUSTFLAGS", "CARGO_TARGET_DIR"):
            self.env.pop(key, None)
        self.env.update(PATH=str(self.bin) + ":/usr/bin:/bin", RUSTC=str(self.bin / "rustc"),
                        CARGO_INCREMENTAL="0", CARGO_NET_OFFLINE="true")
        version = self.command("rust-version", [str(self.bin / "rustc"), "-Vv"], timeout=10).decode()
        need("release: 1.95.0\n" in version and "host: x86_64-unknown-linux-gnu\n" in version,
             "The original Rust release or target differs")
        self.version = version
        self.compiler = identity((self.bin / "rustc").read_bytes())
        self.tools = {name: identity((self.bin / name).read_bytes())
                      for name in ("rustc", "cargo", "rustfmt", "cargo-clippy", "clippy-driver")}
        self.expected = decode(read(ROOT, "hia/platform/checkpoint_store/original_tests.json"))
        need(self.expected["total"] == 77 and self.expected["rust_release"] == "1.95.0",
             "Original complete test boundary differs")
        self.target = self.output / "cargo-target"
        base = [str(self.bin / "cargo"), "test", "--locked", "--offline", "--all-features", "--all-targets",
                "--manifest-path", str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-checkpoint-store",
                "--target-dir", str(self.target)]
        raw = self.command("cargo-test-build", base + ["--no-run", "--message-format=json"], timeout=600)
        events = [json.loads(line) for line in raw.splitlines() if line.startswith(b"{")]
        need(events and events[-1].get("reason") == "build-finished" and events[-1].get("success") is True,
             "Original Cargo graph did not complete")
        self.graph = [row for row in events if row.get("reason") == "compiler-artifact"]
        targets = {row["target"]["name"]: row for row in self.graph
                   if row.get("executable") and row["profile"]["test"]}
        need(set(targets) == set(self.expected["targets"]), "Original executable test roster differs")
        self.tests = []
        for name in sorted(targets):
            executable = Path(targets[name]["executable"])
            listed = self.command("list-" + name, [str(executable), "--list"], timeout=15)
            names = [line.removesuffix(": test") for line in listed.decode().splitlines() if line.endswith(": test")]
            need(exact(names, self.expected["targets"][name]), "Original named test roster changed: " + name)
            output = self.command("test-" + name, [str(executable), "--nocapture", "--test-threads=1"], timeout=90)
            validate_test_output(output, names)
            self.tests.append({"name": name, "tests": names, "executable": identity(executable.read_bytes()),
                               "relative_executable": executable.relative_to(self.output).as_posix()})
        bins = [row for row in self.graph if row["target"]["name"] == "trnm-external-node-checkpoint-v2"
                and row.get("executable") and row["profile"]["test"] is False]
        need(len(bins) == 1, "Original production CLI is not unique")
        self.cli = Path(bins[0]["executable"])
        self.rlibs = []
        for name in ("trnm_checkpoint_store", "trnm_checkpoint_types", "fs2", "libc", "sha2"):
            rows = [row for row in self.graph if row["target"]["name"] == name
                    and row["profile"]["test"] is False and "lib" in row["target"]["kind"]]
            need(len(rows) == 1, "Original dependency artifact is not unique: " + name)
            paths = [Path(p) for p in rows[0]["filenames"] if p.endswith(".rlib")]
            need(len(paths) == 1, "Original exact Cargo rlib is missing: " + name)
            path = paths[0]
            self.rlibs.append({"name": name, "path": str(path), "identity": identity(path.read_bytes()),
                               "relative_path": path.relative_to(self.output).as_posix(),
                               "cargo_artifact": rows[0]})
        adapter = ROOT / "hia/tests/rust_checkpoint_api_reference.rs"
        self.command("adapter-rustfmt", [str(self.bin / "rustfmt"), "--edition", "2021", "--check",
                                         "--config", "skip_children=true", str(adapter)], timeout=15)
        self.api = self.output / "original-method-api"
        argv = [str(self.bin / "rustc"), "--edition", "2021", str(adapter),
                "-L", "dependency=" + str(self.target / "debug/deps"), "-o", str(self.api)]
        for row in self.rlibs:
            argv += ["--extern", row["name"] + "=" + row["path"]]
        self.command("compile-method-api", argv, timeout=60)
        self.command("original-clippy", [str(self.bin / "cargo"), "clippy", "--locked", "--offline",
                                         "--all-features", "--all-targets", "--manifest-path",
                                         str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-checkpoint-store",
                                         "--target-dir", str(self.target), "--", "-D", "warnings"], timeout=600)
        self.command("original-rustfmt", [str(self.bin / "cargo"), "fmt", "--manifest-path",
                                          str(ROOT / "trillionnium/Cargo.toml"), "-p", "trnm-checkpoint-store",
                                          "-p", "trnm-checkpoint-types", "--", "--check"], timeout=20)
        self.report = {"schema": "trnm.hia.checkpoint-store-original.v1", "status": "PASS",
                       "source_root": str(ROOT), "output_root": str(self.output),
                       "tool_bin": str(self.bin), "tools": self.tools,
                       "rustc_version": self.version, "compiler": self.compiler, "graph": self.graph,
                       "tests": self.tests, "total_tests": sum(len(row["tests"]) for row in self.tests),
                       "rlibs": self.rlibs, "stages": self.stages, "cli": identity(self.cli.read_bytes()),
                       "api": identity(self.api.read_bytes()),
                       "relative_cli": self.cli.relative_to(self.output).as_posix(),
                       "adapter": identity(adapter.read_bytes()), "original_implementation_unchanged": True}
        save(self.output / "original.json", self.report)

    def command(self, label, argv, *, timeout):
        directory = self.output / label
        directory.mkdir(mode=0o700)
        started = time.monotonic_ns()
        executable = identity(Path(argv[0]).read_bytes())
        with (directory / "stdout.raw").open("xb") as out, (directory / "stderr.raw").open("xb") as err:
            process = subprocess.Popen(argv, cwd=ROOT, env=self.env, stdout=out, stderr=err,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            cleanup = terminal(process, timeout)
        stdout, stderr = (directory / "stdout.raw").read_bytes(), (directory / "stderr.raw").read_bytes()
        row = {"label": label, "argv": argv, "cwd": str(ROOT), "executable": executable,
               "stdout": identity(stdout), "stderr": identity(stderr), "exit_code": process.returncode,
               "cleanup": cleanup, "elapsed_ns": time.monotonic_ns() - started,
               "wall_limit_seconds": timeout, "rustc": self.env["RUSTC"],
               "cargo_incremental": self.env["CARGO_INCREMENTAL"], "offline": True}
        save(directory / "receipt.json", row)
        self.stages.append(row)
        need(process.returncode == 0 and cleanup is None and identity(Path(argv[0]).read_bytes()) == executable,
             "Original command failed; complete actual receipt retained: " + label)
        return stdout


def validate_test_output(output, names):
    text = output.decode()
    passed = [line[5:-7] for line in text.splitlines() if line.startswith("test ") and line.endswith(" ... ok")]
    need(passed == names, ("Original per-test execution roster differs", passed, names))
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text)
    need(summaries == [(str(len(names)), "0", "0", "0", "0")], "Incomplete original test execution")


def validate(directory):
    directory = Path(directory).absolute()
    need(directory.resolve(strict=True) == directory and not directory.is_symlink(),
         "Canonical original observation directory required")
    report = decode(read(directory, "original.json"))
    expected = decode(read(ROOT, "hia/platform/checkpoint_store/original_tests.json"))
    need(report["schema"] == "trnm.hia.checkpoint-store-original.v1" and report["status"] == "PASS"
         and report["original_implementation_unchanged"] is True and type(report["total_tests"]) is int
         and report["total_tests"] == expected["total"] == 77
         and "release: 1.95.0\n" in report["rustc_version"]
         and "host: x86_64-unknown-linux-gnu\n" in report["rustc_version"],
         "Original qualification boundary differs")
    for key in ("source_root", "output_root", "tool_bin"):
        path = Path(report[key])
        need(path.is_absolute() and path.as_posix() == report[key] and ".." not in path.parts,
             "Noncanonical original execution root")
    need(set(report["tools"]) == {"rustc", "cargo", "rustfmt", "cargo-clippy", "clippy-driver"}
         and exact(report["compiler"], report["tools"]["rustc"]), "Original compiler identity differs")
    labels = ["rust-version", "cargo-test-build"]
    for name in sorted(expected["targets"]):
        labels += ["list-" + name, "test-" + name]
    labels += ["adapter-rustfmt", "compile-method-api", "original-clippy", "original-rustfmt"]
    need([row["label"] for row in report["stages"]] == labels, "Original command roster differs")
    for row in report["stages"]:
        prefix = row["label"] + "/"
        need(exact(decode(read(directory, prefix + "receipt.json")), row), "Original receipt differs")
        need(type(row["exit_code"]) is int and row["exit_code"] == 0 and row["cleanup"] is None,
             "Original stage did not complete")
        for stream in ("stdout", "stderr"):
            need(exact(identity(read(directory, prefix + stream + ".raw")), row[stream]), "Original stream differs")
        if row["label"].startswith("test-"):
            validate_test_output(read(directory, prefix + "stdout.raw"), expected["targets"][row["label"][5:]])
    need(read(directory, "rust-version/stdout.raw").decode() == report["rustc_version"], "Actual rustc version differs")
    events = [json.loads(line) for line in read(directory, "cargo-test-build/stdout.raw").splitlines() if line.startswith(b"{")]
    need(events[-1].get("reason") == "build-finished" and events[-1].get("success") is True
         and exact([row for row in events if row.get("reason") == "compiler-artifact"], report["graph"]),
         "Actual original Cargo graph differs")
    need([row["name"] for row in report["rlibs"]] == ["trnm_checkpoint_store", "trnm_checkpoint_types", "fs2", "libc", "sha2"],
         "Original selected dependency roster differs")
    for row in report["rlibs"]:
        need(row["cargo_artifact"] in report["graph"] and row["path"] in row["cargo_artifact"]["filenames"]
             and exact(row["identity"], identity(read(directory, row["relative_path"]))),
             "Actual original dependency artifact differs")
    need(exact(report["adapter"], identity(read(ROOT, "hia/tests/rust_checkpoint_api_reference.rs"))),
         "Original method adapter source changed")
    need(exact(report["api"], identity(read(directory, "original-method-api")))
         and exact(report["cli"], identity(read(directory, report["relative_cli"]))), "Original executable changed")
    need([row["name"] for row in report["tests"]] == sorted(expected["targets"]), "Original test executable roster differs")
    for row in report["tests"]:
        need(exact(row["tests"], expected["targets"][row["name"]])
             and exact(row["executable"], identity(read(directory, row["relative_executable"]))),
             "Original test executable or method roster changed")
    validate_commands(report, expected)
    return report


def validate_commands(report, expected):
    """Bind receipts to the exact locked build, complete tests and strict gates.

    Evidence may be copied to another directory. Absolute invocation paths are
    interpreted under the captured roots, while artifacts are re-read through
    their validated relative paths in the observation directory.
    """
    source, output, tool = (Path(report[key]) for key in ("source_root", "output_root", "tool_bin"))
    target = output / "cargo-target"
    graph = report["graph"]
    targets = [row for row in graph if row.get("executable") and row["profile"]["test"] is True]
    need(len(targets) == len(expected["targets"])
         and {row["target"]["name"] for row in targets} == set(expected["targets"]),
         "Original Cargo test graph is not exact")
    by_name = {row["target"]["name"]: row for row in targets}
    selected = {row["name"]: row for row in report["tests"]}
    manifest = str(source / "trillionnium/Cargo.toml")
    plan = [("rust-version", [str(tool / "rustc"), "-Vv"], 10, report["tools"]["rustc"]),
            ("cargo-test-build", [str(tool / "cargo"), "test", "--locked", "--offline",
             "--all-features", "--all-targets", "--manifest-path", manifest, "-p",
             "trnm-checkpoint-store", "--target-dir", str(target), "--no-run",
             "--message-format=json"], 600, report["tools"]["cargo"])]
    for name in sorted(by_name):
        artifact = by_name[name]
        executable = str(output / selected[name]["relative_executable"])
        need(artifact["executable"] == executable and executable in artifact["filenames"],
             "Original test command is not bound to its Cargo artifact")
        plan += [("list-" + name, [executable, "--list"], 15, selected[name]["executable"]),
                 ("test-" + name, [executable, "--nocapture", "--test-threads=1"],
                  90, selected[name]["executable"])]
    adapter = str(source / "hia/tests/rust_checkpoint_api_reference.rs")
    compile_argv = [str(tool / "rustc"), "--edition", "2021", adapter,
                    "-L", "dependency=" + str(target / "debug/deps"),
                    "-o", str(output / "original-method-api")]
    for row in report["rlibs"]:
        need(row["path"] == str(output / row["relative_path"]), "Original rlib path differs")
        compile_argv += ["--extern", row["name"] + "=" + row["path"]]
    cli = [row for row in graph if row["target"]["name"] == "trnm-external-node-checkpoint-v2"
           and row.get("executable") and row["profile"]["test"] is False]
    need(len(cli) == 1 and cli[0]["executable"] == str(output / report["relative_cli"]),
         "Original production CLI Cargo identity differs")
    plan += [("adapter-rustfmt", [str(tool / "rustfmt"), "--edition", "2021", "--check",
              "--config", "skip_children=true", adapter], 15, report["tools"]["rustfmt"]),
             ("compile-method-api", compile_argv, 60, report["tools"]["rustc"]),
             ("original-clippy", [str(tool / "cargo"), "clippy", "--locked", "--offline",
              "--all-features", "--all-targets", "--manifest-path", manifest, "-p",
              "trnm-checkpoint-store", "--target-dir", str(target), "--", "-D", "warnings"],
              600, report["tools"]["cargo"]),
             ("original-rustfmt", [str(tool / "cargo"), "fmt", "--manifest-path", manifest,
              "-p", "trnm-checkpoint-store", "-p", "trnm-checkpoint-types", "--", "--check"],
              20, report["tools"]["cargo"])]
    need(len(plan) == len(report["stages"]), "Original command boundary differs")
    for row, (label, argv, timeout, executable) in zip(report["stages"], plan, strict=True):
        need(row["label"] == label and exact(row["argv"], argv)
             and row["cwd"] == str(source) and type(row["wall_limit_seconds"]) is int
             and row["wall_limit_seconds"] == timeout and exact(row["executable"], executable)
             and row["rustc"] == str(tool / "rustc") and row["cargo_incremental"] == "0"
             and row["offline"] is True and type(row["elapsed_ns"]) is int and row["elapsed_ns"] > 0,
             "Original invocation, tool identity or strict gate differs: " + label)
