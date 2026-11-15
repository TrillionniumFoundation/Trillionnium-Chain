#!/usr/bin/env python3
"""Build actual static Node and libtest artifacts for the isolated M15 suite.

This is an additional artifact build, never a replacement for the original
Chain/Hepta gates. It refuses dirty source and uses no library/model stubs.
It does not run a Rust test or create a user namespace.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import tomllib

sys.dont_write_bytecode = True
_support = Path(__file__).with_name("m15_native_build_support.py")
_spec = importlib.util.spec_from_file_location("m15_exact_build_support", _support)
support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(support)

TARGET = "x86_64-unknown-linux-gnu"
FEATURE = "pq-native-openssl"
CASE = "release_owner::native_consumer_tests::isolated_fixed_root_static_node_claim_refresh_and_revocation"
REPOSITORY = "https://github.com/TrillionniumFoundation/Trillionnium-Chain"
TOOLS = {"cargo", "rustc", "cc", "ar", "ranlib", "ld", "pkg_config", "openssl"}


def input_tools(path, expected):
    raw = support.read(path)
    if support.sha(raw) != expected:
        raise ValueError("reviewed tool-input manifest digest differs")
    value = json.loads(raw)
    if set(value) != {"schema", "rust_version", "target", "tools", "openssl_prefix",
                      "openssl_lib_dir", "openssl_version", "provider_files", "provider_origin"}:
        raise ValueError("unknown or incomplete tool-input contract")
    if (value["schema"], value["rust_version"], value["target"], value["openssl_version"]) != (
            "trnm-m15-static-native-tool-input-v1", "1.95.0", TARGET, "3.5.9"):
        raise ValueError("new static gate must preserve the original Chain toolchain/provider")
    if set(value["tools"]) != TOOLS:
        raise ValueError("complete declared compiler/tool binary inputs required")
    for tool in value["tools"].values():
        if set(tool) != {"path", "sha256"} or not Path(tool["path"]).is_absolute():
            raise ValueError("tool path/digest must be explicit")
        # Preserve the original argv path (e.g. a proxy basename); hash its real file.
        actual = support.fingerprint(Path(tool["path"]).resolve(strict=True))
        if actual["sha256"] != tool["sha256"]:
            raise ValueError("compiler/tool executable differs from reviewed input")
    prefix = Path(value["openssl_prefix"])
    library = Path(value["openssl_lib_dir"])
    if not prefix.is_absolute() or not library.is_relative_to(prefix):
        raise ValueError("explicit provider prefix/static library directory required")
    names = set()
    for item in value["provider_files"]:
        if set(item) != {"path", "sha256", "bytes"}:
            raise ValueError("provider file fields")
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or str(relative) in names:
            raise ValueError("provider path must be unique and relative")
        names.add(str(relative))
        actual = support.fingerprint(prefix / relative)
        if (actual["sha256"], actual["bytes"]) != (item["sha256"], item["bytes"]):
            raise ValueError("provider archive/header input differs")
    mandatory = {str((library / n).relative_to(prefix)) for n in ("libssl.a", "libcrypto.a")}
    headers = {p.relative_to(prefix).as_posix() for p in (prefix / "include").rglob("*") if p.is_file()}
    if not headers or not mandatory.issubset(names) or not headers.issubset(names):
        raise ValueError("all provider headers and both actual static archives must be pinned")
    origin = value["provider_origin"]
    if set(origin) != {"path", "sha256"} or not Path(origin["path"]).is_absolute():
        raise ValueError("explicit original provider preparation receipt required")
    actual = support.fingerprint(origin["path"])
    if actual["sha256"] != origin["sha256"]:
        raise ValueError("original provider preparation receipt differs")
    return value


class Commands:
    def __init__(self, output, environment, timeout):
        self.output, self.environment, self.timeout = output, environment, timeout
        self.receipts = []

    def run(self, name, argv, cwd):
        before = time.monotonic_ns()
        stdout, stderr = self.output / f"{name}.stdout", self.output / f"{name}.stderr"
        result, failure = None, None
        try:
            with stdout.open("xb") as out, stderr.open("xb") as err:
                result = subprocess.Popen(argv, cwd=cwd, env=self.environment, stdin=subprocess.DEVNULL,
                                          stdout=out, stderr=err, start_new_session=True)
                try:
                    result.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    # Only this explicitly owned command session is stopped.
                    try:
                        os.killpg(result.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    result.wait()
                    raise
                out.flush()
                err.flush()
                os.fsync(out.fileno())
                os.fsync(err.fileno())
        except Exception as error:
            failure = {"type": type(error).__name__, "message": str(error)}
        receipt = {"name": name, "argv": list(argv), "cwd": str(cwd),
                   "started_monotonic_ns": before, "ended_monotonic_ns": time.monotonic_ns(),
                   "exit_code": None if result is None else result.returncode, "failure": failure,
                   "stdout": support.fingerprint(stdout) if stdout.exists() else {"missing": True},
                   "stderr": support.fingerprint(stderr) if stderr.exists() else {"missing": True}}
        self.receipts.append(receipt)
        support.create(self.output / f"{name}.json", support.canonical(receipt))
        if failure or result.returncode:
            raise RuntimeError(f"artifact build command failed: {name}; original logs retained")
        return support.read(stdout, 256 * 1024**2)


def executable(messages, kind, test):
    found = []
    for line in messages.splitlines():
        row = json.loads(line)
        if row.get("reason") == "compiler-artifact" and row.get("executable"):
            target = row["target"]
            if target["name"] == ("trnm_pon_node" if test else "trnm-pon-node"):
                if kind in target["kind"] and bool(row["profile"]["test"]) == test:
                    found.append(row["executable"])
    if len(found) != 1:
        raise ValueError("compiler did not report exactly one actual Node/test artifact")
    return Path(found[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--tool-inputs", type=Path, required=True)
    parser.add_argument("--tool-inputs-sha256", required=True)
    parser.add_argument("--compile-timeout-seconds", type=int, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
        raise ValueError("dedicated non-root Linux x86_64 build required")
    if not 1 <= args.compile_timeout_seconds <= 14400:
        raise ValueError("explicit bounded compile timeout required")
    repo, output = args.repo.resolve(strict=True), args.output.resolve(strict=False)
    if not output.is_absolute() or output.exists() or output.is_relative_to(repo):
        raise ValueError("fresh evidence/target directory outside the source tree required")
    for key in os.environ:
        if key.startswith(("LD_", "DYLD_")) or key in {
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_TARGET"}:
            raise ValueError(f"ambient compiler/loader injection is not admitted: {key}")
    tools = input_tools(args.tool_inputs, args.tool_inputs_sha256)
    output.mkdir(mode=0o700)
    environment = {key: os.environ[key] for key in ("HOME", "USER", "CARGO_HOME", "RUSTUP_HOME") if key in os.environ}
    environment.update({"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
        "CARGO_TARGET_DIR": str(output / "target"), "CARGO_BUILD_JOBS": "2", "RUST_TEST_THREADS": "1",
        "RUSTC": tools["tools"]["rustc"]["path"], "CC": tools["tools"]["cc"]["path"],
        "AR": tools["tools"]["ar"]["path"], "RANLIB": tools["tools"]["ranlib"]["path"],
        "PKG_CONFIG": tools["tools"]["pkg_config"]["path"], "OPENSSL_STATIC": "1",
        "OPENSSL_NO_VENDOR": "1", "OPENSSL_DIR": tools["openssl_prefix"],
        "OPENSSL_LIB_DIR": tools["openssl_lib_dir"],
        "OPENSSL_INCLUDE_DIR": str(Path(tools["openssl_prefix"]) / "include"),
        "CARGO_ENCODED_RUSTFLAGS": "-C\x1ftarget-feature=+crt-static",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": tools["tools"]["cc"]["path"]})
    support.create(output / "effective-build-environment.json", support.canonical(environment))
    support.create(output / "reviewed-tool-inputs.json", support.read(args.tool_inputs))
    commands = Commands(output, environment, args.compile_timeout_seconds)
    success, failure = False, None
    try:
        commands.run("00-original-preflight", ["bash", "scripts/project-preflight.sh"], repo)
        before = support.full_source(repo, args.expected_head, args.expected_tree)
        if before["origin"] not in {REPOSITORY, REPOSITORY + ".git"}:
            raise ValueError("official source origin required by the build fixture")
        support.create(output / "source-before.json", support.canonical(before))
        toolchain_path = repo / "rust-toolchain.toml"
        if not toolchain_path.is_file():
            toolchain_path = repo / "trillionnium/rust-toolchain.toml"
        channel = tomllib.loads(support.read(toolchain_path).decode())["toolchain"]["channel"]
        if channel != tools["rust_version"]:
            raise ValueError("tracked Chain toolchain differs from reviewed build input")
        cargo = tools["tools"]["cargo"]["path"]
        cargo_version = commands.run("01-cargo-version", [cargo, "--version"], repo)
        rust_version = commands.run("02-rust-version", [environment["RUSTC"], "-vV"], repo)
        ssl_version = commands.run("03-openssl-version", [tools["tools"]["openssl"]["path"], "version", "-a"], repo)
        if not cargo_version.startswith(b"cargo 1.95.0 ") or b"release: 1.95.0\n" not in rust_version:
            raise ValueError("actual compiler versions do not equal original Chain 1.95.0")
        if not ssl_version.startswith(b"OpenSSL 3.5.9 "):
            raise ValueError("actual provider version is not original OpenSSL 3.5.9")
        workspace = repo / "trillionnium"
        metadata_raw = commands.run("04-locked-metadata", [cargo, "metadata", "--locked", "--offline",
            "--filter-platform", TARGET, "--features", "trnm-pon-node/" + FEATURE, "--format-version", "1"], workspace)
        metadata = json.loads(metadata_raw)
        closure, packages = support.production_closure(repo, metadata, before)
        support.create(output / "production-closure-before.json", support.canonical(closure))
        shared = ["--locked", "--offline", "--release", "--target", TARGET,
                  "-p", "trnm-pon-node", "--features", FEATURE, "--jobs", "2"]
        node_messages = commands.run("05-static-node-build",
            [cargo, "build", *shared, "--bin", "trnm-pon-node", "--message-format=json"], workspace)
        test_messages = commands.run("06-static-libtest-compile-only",
            [cargo, "test", *shared, "--lib", "--no-run", "--message-format=json"], workspace)
        node = executable(node_messages, "bin", False)
        tests = executable(test_messages, "lib", True)
        support.elf_static(node, 512 * 1024**2)
        support.elf_static(tests, 4 * 1024**3)
        node_copy = support.copy_exact(node, output / "node.elf", 512 * 1024**2)
        test_copy = support.copy_exact(tests, output / "tests.elf", 4 * 1024**3)
        after = support.full_source(repo, args.expected_head, args.expected_tree)
        support.create(output / "source-after.json", support.canonical(after))
        closure_after, packages_after = support.production_closure(repo, metadata, after)
        support.create(output / "production-closure-after.json", support.canonical(closure_after))
        if before != after or closure != closure_after or packages != packages_after:
            raise ValueError("source/dependency closure changed during actual build")
        input_tools(args.tool_inputs, args.tool_inputs_sha256)
        source = {"repository_digest": support.digest(REPOSITORY.encode()),
            "commit_digest": support.digest(before["head"].encode()), "tree_digest": support.digest(before["tree"].encode()),
            "cargo_lock_digest": support.digest(support.read(workspace / "Cargo.lock")),
            "toolchain_digest": support.digest(support.canonical({"input": tools, "rustc": rust_version.decode(), "cargo": cargo_version.decode()})),
            "production_closure_digest": support.digest(support.canonical(closure)), "dirty": False}
        inputs = [{"logical_name": name, "source_digest": source["tree_digest"],
                   "content_digest": support.digest(support.read(output / name, 256 * 1024**2))}
                  for name in ("source-before.json", "production-closure-before.json",
                               "reviewed-tool-inputs.json", "effective-build-environment.json")]
        build = {"schema": "trnm-m15-static-node-build-input-v1", "source_commit": before["head"],
            "source_tree": before["tree"], "source": source, "packages": packages, "build_inputs": inputs,
            "builder_identity": support.digest(support.canonical({"uid": os.getuid(), "kind": "local-fixture-builder"})),
            "workflow": support.digest(support.read(Path(__file__))),
            "run_identity": support.digest(support.canonical(commands.receipts)),
            "isolated_environment": support.digest(support.canonical({"environment": environment, "uname": list(os.uname()),
                "qualification": "observed-build-fixture-not-independent-custody"})),
            "program": "/m15/bin/node", "program_sha256": list(bytes.fromhex(node_copy["sha256"])),
            "program_bytes": node_copy["bytes"]}
        support.create(output / "build-input.json", support.canonical(build))
        artifact = {"schema": "trnm-m15-static-native-artifacts-v1", "source": {"head": before["head"], "tree": before["tree"]},
            "node": node_copy, "tests": test_copy, "build_input": support.fingerprint(output / "build-input.json"),
            "test_selector": CASE, "command_receipts": commands.receipts, "rust_tests_executed": False,
            "independent_deployment_qualified": False}
        support.create(output / "artifacts.json", support.canonical(artifact))
        success = True
    except Exception as error:
        failure = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        source_after_failure = None
        if not (output / "source-after.json").exists():
            try:
                after = support.full_source(repo, args.expected_head, args.expected_tree)
                support.create(output / "source-after.json", support.canonical(after))
            except Exception as error:
                source_after_failure = {"type": type(error).__name__, "message": str(error)}
        support.create(output / "result.json", support.canonical({"success": success, "failure": failure,
            "source_after_failure": source_after_failure,
            "command_count": len(commands.receipts), "scope": "static fixture compilation only",
            "original_native_gate_qualification": False, "independent_deployment_qualified": False,
            "builder_scope": "actual local source and declared tool/provider inputs; not an independently certified hermetic compiler environment"}))


if __name__ == "__main__":
    main()
