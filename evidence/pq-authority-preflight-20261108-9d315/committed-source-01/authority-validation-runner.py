#!/usr/bin/env python3
"""Retained validation for the reviewed PQ authority commit.

Run on desktop after committing the final source. This script never edits source,
fetches dependencies, commits, or pushes. Every ordinary command failure is kept
while later independent gates continue. The existing raw-source guard is used
before and after execution. --list-commands performs no validation or Cargo run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time


TOOLCHAIN = Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu")
CARGO = str(TOOLCHAIN / "bin/cargo")
PYTHON = "/usr/bin/python3"
GIT = "/usr/bin/git"
HOST_ROOT = Path("/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2")
PROVIDER = HOST_ROOT / "build-runtime/trnm-pq-provider-3.5.9.DYf2qEaX/install"
PROVIDER_ENV_FILE = HOST_ROOT / "build-runtime/provider.env"
PROVIDER_RECEIPT = HOST_ROOT / "build-receipts/pq-provider/provider.json"
PROVIDER_FILES = {
    "bin/openssl": (8933408, "8ff7dd91270fd4a8fc377031f0fd2f2cee1cd17a32ce30e4fd773a25730a120f"),
    "include/openssl/opensslv.h": (3449, "9647fc99758cf83e3bcf11ae310894fd4911ad62bff22d8213a614df89cfedda"),
    "include/openssl/configuration.h": (4729, "406c26f93511299b264062f9f3faf0760e7a0506e91a61717c491f3c92e1a996"),
    "lib/libcrypto.a": (12381776, "dabf2189afd2e29591c5b597ac2cb9b7cd7066eaf7ce674106123614da32eb0f"),
    "lib/libssl.a": (2123138, "f355167951857505b5b0305fd2e8ea8f224fa29d780211175d32767b07234727"),
}
PROVIDER_ENV = {
    "OPENSSL_DIR": str(PROVIDER),
    "OPENSSL_STATIC": "1",
    "TRNM_PQ_OPENSSL": str(PROVIDER / "bin/openssl"),
    "TRNM_PQ_OPENSSL_SHA256": PROVIDER_FILES["bin/openssl"][1],
    "TRNM_PQ_OPENSSL_VERSION": "3.5.9",
    "OPENSSL_CONF": "/dev/null",
    "OPENSSL_MODULES": str(PROVIDER / "lib/ossl-modules"),
}
PACKAGES = (
    "trnm-release-bundle", "trnm-protocol", "trnm-crypto-primitives",
    "trnm-checkpoint-types", "trnm-checkpoint-store", "trnm-verification-profiles",
)
LOCKS = ("trillionnium/Cargo.lock", "tests/fuzz/Cargo.lock")
RELEASE_MANIFEST = "config/pon/pq-initial-root-material-required-tests-v1.json"
TIMEOUT_SECONDS = 7200
LIBTEST_SUMMARY = re.compile(
    r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out;.*$", re.M
)
LIBTEST_NAME = re.compile(
    r"^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored(?:,.*)?)$", re.M
)


def save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_record(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": str(path), "bytes": size, "sha256": digest.hexdigest()}


def environment(target: Path) -> dict[str, str]:
    # Explicit process environment: no inherited compiler/profile/native flags.
    # Keep HOME at its existing value; Cargo/Rustup cache locations are explicit.
    env = {
        "PATH": str(TOOLCHAIN / "bin") + ":/usr/bin:/bin",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
        "CARGO_HOME": "/home/qian-qi/.cargo",
        "RUSTUP_HOME": "/home/qian-qi/.rustup",
        "RUSTUP_TOOLCHAIN": "1.95.0",
        "RUSTC": str(TOOLCHAIN / "bin/rustc"),
        "RUSTDOC": str(TOOLCHAIN / "bin/rustdoc"),
        "LD_LIBRARY_PATH": str(TOOLCHAIN / "lib"),
        "CARGO_TARGET_DIR": str(target),
        "CARGO_BUILD_JOBS": "2",
        "CARGO_TERM_COLOR": "never",
        "CARGO_NET_OFFLINE": "true",
        "RUST_TEST_THREADS": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "OPENSSL_NO_VENDOR": "1",
        **PROVIDER_ENV,
    }
    for key in ("HOME", "USER", "LOGNAME"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def source_identity(repo: Path, env: dict[str, str]) -> dict:
    def git(*argv: str) -> bytes:
        return subprocess.check_output(
            [GIT, "-C", str(repo), *argv], env=env, stderr=subprocess.PIPE
        )
    return {
        "head": git("rev-parse", "HEAD").decode().strip(),
        "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "branch": git("branch", "--show-current").decode().strip(),
        "status": git("status", "--porcelain=v1", "--untracked-files=all",
                      "--ignore-submodules=none").decode(),
        "index_entries_sha256": hashlib.sha256(git("ls-files", "--stage", "-z")).hexdigest(),
        "lockfiles": {name: file_record(repo / name) for name in LOCKS},
    }


def provider_identity() -> dict:
    parsed = {}
    for line in PROVIDER_ENV_FILE.read_text().splitlines():
        line = line.strip().removeprefix("export ")
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        words = shlex.split(value)
        if key in parsed or len(words) != 1:
            raise ValueError("duplicate or malformed provider environment entry")
        parsed[key] = words[0]
    if parsed != PROVIDER_ENV:
        raise ValueError("provider.env differs from the reviewed fixed provider")
    receipt = json.loads(PROVIDER_RECEIPT.read_text())
    if (receipt.get("result") != "PREPARED_AND_SMOKE_VERIFIED"
            or receipt.get("version") != "3.5.9"
            or type(receipt.get("exit_code")) is not int or receipt["exit_code"] != 0):
        raise ValueError("provider preparation receipt is not successful 3.5.9")
    observed = []
    expected = {}
    for relative, (size, digest) in PROVIDER_FILES.items():
        path = PROVIDER / relative
        if path.resolve() != path:
            raise ValueError(f"provider input is not canonical: {path}")
        record = file_record(path)
        if (record["bytes"], record["sha256"]) != (size, digest):
            raise ValueError(f"provider input changed: {relative}")
        observed.append(record)
        expected[str(path)] = (size, digest)
    rows = receipt.get("native_backend_inputs", [])
    if (not isinstance(rows, list) or len(rows) != len(expected)
            or len({row["path"] for row in rows}) != len(expected)
            or {row["path"]: (row["bytes"], row["sha256"]) for row in rows} != expected):
        raise ValueError("provider receipt native input set differs")
    return {"env_file": file_record(PROVIDER_ENV_FILE),
            "receipt": file_record(PROVIDER_RECEIPT), "native_inputs": observed}


def command_list(expected_head: str, out: Path) -> list[tuple[str, list[str], str]]:
    locked = ["--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml"]
    packages = [part for package in PACKAGES for part in ("-p", package)]
    other_packages = [part for package in PACKAGES[1:] for part in ("-p", package)]
    test_output = ["--", "--show-output", "--test-threads=1"]
    py = [PYTHON, "-B"]
    return [
        ("preflight", ["/bin/bash", "scripts/project-preflight.sh"], "preflight"),
        ("source-guard-before", py + ["scripts/ci/verify_ci_source.py", "--kind", "head",
         "--expected-head", expected_head, "--output", str(out / "verified-source-before.json")], "source"),
        ("rustc-version", [str(TOOLCHAIN / "bin/rustc"), "-Vv"], "rustc"),
        ("cargo-version", [CARGO, "-V"], "cargo"),
        ("openssl-version", [str(PROVIDER / "bin/openssl"), "version"], "openssl"),
        ("metadata-default", [CARGO, "metadata", *locked, "--format-version", "1"], "metadata-main"),
        ("metadata-all-features", [CARGO, "metadata", *locked, "--all-features",
         "--format-version", "1"], "metadata-main"),
        ("metadata-fuzz", [CARGO, "metadata", "--locked", "--offline",
         "--manifest-path", "tests/fuzz/Cargo.toml", "--format-version", "1"], "metadata-fuzz"),
        ("formatting", [CARGO, "fmt", "--manifest-path", "trillionnium/Cargo.toml",
         "--all", "--", "--check"], "exit"),
        ("release-non-test-library", [CARGO, "check", *locked, "-p", "trnm-release-bundle", "--lib"], "exit"),
        ("release-all-targets", [CARGO, "test", *locked, "-p", "trnm-release-bundle",
         "--all-targets", "--all-features", "--no-fail-fast", *test_output], "release-tests"),
        ("five-package-all-targets", [CARGO, "test", *locked, *other_packages,
         "--all-targets", "--all-features", "--no-fail-fast", *test_output], "rust-tests"),
        ("six-package-doc-tests", [CARGO, "test", *locked, *packages, "--doc",
         "--all-features", "--no-fail-fast", *test_output], "rust-docs"),
        ("node-release-owner", [CARGO, "test", *locked, "-p", "trnm-pon-node",
         "--lib", "--all-features", "release_owner::", *test_output], "node-tests"),
        ("workspace-strict-clippy", [CARGO, "clippy", *locked, "--workspace",
         "--all-targets", "--all-features", "--", "-D", "warnings"], "exit"),
        ("ci-contract", py + ["scripts/ci/check_ci_contract.py"], "json"),
        ("ci-contract-negatives", py + ["scripts/ci/test_ci_contract.py"], "unittest"),
        ("pq-root-quorum-research", py + ["-m", "unittest", "discover", "-s",
         "formal/pon-nakamoto-v1", "-p", "test_pq_root_quorum_research.py", "-v"], "unittest"),
        ("pq-integration", py + ["scripts/ci/check_pq_research_integration.py"], "hold-no-go"),
        ("pq-integration-negatives", py + ["-m", "unittest", "discover", "-s",
         "scripts/ci", "-p", "test_pq_research_integration.py", "-v"], "unittest"),
        ("pq-claim", py + ["scripts/ci/pq_chain_claim_guard.py"], "hold"),
        ("pq-claim-negatives", py + ["scripts/ci/test_pq_chain_claim_guard.py"], "unittest"),
        ("pq-authority", py + ["scripts/ci/pq_authority_surface_scan.py", "--summary-only"], "authority-hold"),
        ("pq-authority-negatives", py + ["-m", "unittest", "discover", "-s",
         "scripts/ci", "-p", "test_pq_authority_surface_scan.py", "-v"], "unittest"),
        ("source-integrity-negatives", py + ["scripts/ci/test_ci_source_integrity.py"], "unittest"),
        ("canonical-plan", ["/bin/bash", "scripts/ci/check_canonical_development_plan.sh"], "exit"),
        ("repository-links", py + ["scripts/ci/check_repository.py"], "repository"),
        ("source-guard-after", py + ["scripts/ci/verify_ci_source.py", "--kind", "head",
         "--expected-head", expected_head, "--output", str(out / "verified-source-after.json")], "source"),
    ]


def validate_output(kind: str, stdout: str, stderr: str, repo: Path) -> dict:
    if kind in ("exit", "source"):
        return {}
    if kind in ("rustc", "cargo", "openssl"):
        prefix = {"rustc": "rustc 1.95.0 ", "cargo": "cargo 1.95.0 ",
                  "openssl": "OpenSSL 3.5.9 "}[kind]
        if not stdout.startswith(prefix):
            raise ValueError(f"unexpected {kind} version")
        return {"version": stdout.strip()}
    if kind == "unittest":
        combined = stdout + "\n" + stderr
        counts = [int(n) for n in re.findall(r"^Ran (\d+) tests? in .+$", combined, re.M)]
        if not counts or counts[-1] <= 0 or not re.search(r"^OK(?: \(.*\))?$", combined, re.M):
            raise ValueError("Python gate did not report a nonempty successful unittest run")
        return {"reported_test_counts": counts}
    if kind in ("rust-tests", "rust-docs", "release-tests", "node-tests"):
        summaries = [tuple(map(int, row)) for row in LIBTEST_SUMMARY.findall(stdout)]
        names = LIBTEST_NAME.findall(stdout)
        passed = [name for name, outcome in names if outcome == "ok"]
        if not summaries or any(row[1] != 0 for row in summaries):
            raise ValueError("missing successful libtest summary or reported failure")
        if kind != "rust-docs" and sum(row[0] for row in summaries) <= 0:
            raise ValueError("Rust test command executed no passing tests")
        if kind == "release-tests":
            manifest = json.loads((repo / RELEASE_MANIFEST).read_text())
            groups = {"original_release": 37, "initial_root_material": 6, "quorum_preflight": 9}
            expected = manifest["complete_release_tests"]
            if (manifest["expected_controls"] != {**groups, "complete_release": 52}
                    or len(expected) != 52 or len(set(expected)) != 52):
                raise ValueError("release manifest is not the reviewed exact 37+6+9=52 inventory")
            partitions = [manifest[key + "_tests"] for key in groups]
            flat = [name for group in partitions for name in group]
            if (any(len(group) != count for group, count in zip(partitions, groups.values()))
                    or len(set(flat)) != 52 or set(flat) != set(expected)):
                raise ValueError("release manifest partitions are not disjoint exact 52")
            if (len(passed) != 52 or len(set(passed)) != 52 or set(passed) != set(expected)
                    or len(names) != 52 or sum(row[0] for row in summaries) != 52
                    or any(row[1] or row[2] or row[3] or row[4] for row in summaries)):
                raise ValueError("raw release libtest execution differs from exact 52 passed, zero ignored")
        if kind == "node-tests":
            if (len(summaries) != 1 or len(passed) != summaries[0][0]
                    or len(set(passed)) != len(passed)
                    or any(not name.startswith("release_owner::") for name, _ in names)):
                raise ValueError("Node release_owner execution names/summary do not agree")
        return {"summaries": summaries, "passed_names": passed,
                "ignored_names": [name for name, outcome in names if outcome.startswith("ignored")]}
    value = json.loads(stdout)
    if not isinstance(value, dict):
        raise ValueError("expected one JSON object")
    statuses = {"hold-no-go": "HOLD_NO_GO", "hold": "HOLD",
                "authority-hold": "HOLD_INCOMPLETE_AUTHORITY_TRACING"}
    if kind in statuses and value.get("status") != statuses[kind]:
        raise ValueError(f"expected successful status {statuses[kind]}")
    if kind == "hold" and value.get("whole_chain_pq_qualified") is not False:
        raise ValueError("whole-chain PQ qualification must remain false")
    if kind == "hold-no-go" and (
            value.get("cryptographic_acceptance") is not False or value.get("node_activated") is not False):
        raise ValueError("research source check cannot grant acceptance or activation")
    if kind in ("preflight", "repository") and value.get("result") != "PASS":
        raise ValueError("expected PASS result")
    if kind == "repository" and (
            value.get("runtime_implemented") is not False or value.get("activation") is not False):
        raise ValueError("repository check cannot promote runtime or activation")
    if kind.startswith("metadata-"):
        expected_members = 1 if kind == "metadata-fuzz" else 26
        if (value.get("version") != 1 or len(value.get("workspace_members", [])) != expected_members
                or not isinstance(value.get("resolve"), dict) or not value["resolve"].get("nodes")):
            raise ValueError("metadata is not the complete expected locked graph")
        return {"workspace_members": len(value["workspace_members"]),
                "packages": len(value["packages"]), "resolved_nodes": len(value["resolve"]["nodes"])}
    return value


def run_command(spec: tuple[str, list[str], str], repo: Path, out: Path,
                env: dict[str, str]) -> dict:
    label, argv, kind = spec
    stdout_path, stderr_path = out / (label + ".stdout.log"), out / (label + ".stderr.log")
    start = time.monotonic()
    result = {"label": label, "argv": argv, "cwd": str(repo),
              "started_unix_seconds": time.time(), "passed": False, "exit_code": None}
    print(json.dumps({"starting": label, "argv": argv}), flush=True)
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            child = subprocess.Popen(argv, cwd=repo, env=env, stdout=stdout, stderr=stderr,
                                     start_new_session=True)
            try:
                result["exit_code"] = child.wait(timeout=TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                result["exit_code"] = child.returncode
        if result["exit_code"] == 0 and not result.get("timed_out"):
            result["readback"] = validate_output(
                kind, stdout_path.read_text(errors="replace"), stderr_path.read_text(errors="replace"), repo
            )
            result["passed"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    result["elapsed_seconds"] = time.monotonic() - start
    result["finished_unix_seconds"] = time.time()
    result["logs"] = {p.name: file_record(p) for p in (stdout_path, stderr_path) if p.is_file()}
    save(out / (label + ".receipt.json"), result)
    print(json.dumps({"finished": label, "passed": result["passed"],
                      "exit_code": result["exit_code"], "elapsed_seconds": result["elapsed_seconds"]}),
          flush=True)
    return result


def sqlite_qualification(target: Path, out: Path) -> dict:
    records = []
    destination = out / "sqlite-build-outputs"
    destination.mkdir()
    for path in sorted((target / "debug/build").glob("trnm-sqlite-io-boundary-*/output")):
        text = path.read_text()
        copied = destination / (path.parent.name + ".txt")
        shutil.copyfile(path, copied)
        qualified = (
            "cargo:rustc-cfg=trnm_sqlite_layout_witness\n" in text
            and "cargo:rustc-env=TRNM_SQLITE3_BUILD_FENCE=sqlite-3.51.3-normal-native-linux-layout-v3\n" in text
            and "UNQUALIFIED:" not in text and "TRNM_SQLITE3_UNQUALIFIED_REASON=" not in text
        )
        records.append({"source": str(path), "retained": file_record(copied), "qualified": qualified})
    return {"passed": bool(records) and all(row["qualified"] for row in records),
            "outputs": records, "scope": "actual retained build-script qualification markers"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--list-commands", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_head):
        parser.error("--expected-head must be a complete lowercase Git SHA-1")
    if any(not path.is_absolute() for path in (args.repo, args.out, args.target)):
        parser.error("--repo, --out and --target must be absolute")
    commands = command_list(args.expected_head, args.out)
    if args.list_commands:
        for label, argv, kind in commands:
            print(f"{label} [{kind}]\n  {shlex.join(argv)}")
        return 0
    if any(path.resolve() != path for path in (args.repo, args.out, args.target)):
        parser.error("paths must use their canonical spelling, without symlink ancestors")
    if (args.out.is_relative_to(args.repo) or args.target.is_relative_to(args.repo)
            or args.out.is_relative_to(args.target) or args.target.is_relative_to(args.out)):
        parser.error("source, retained output and target must be separate trees")
    if args.out.exists():
        parser.error("--out must be fresh; prior attempts are never overwritten")
    args.out.mkdir(parents=True)
    env = environment(args.target)
    save(args.out / "environment.json", env)
    shutil.copyfile(Path(__file__).resolve(), args.out / "authority-validation-runner.py")
    save(args.out / "commands.json", [{"label": label, "argv": argv, "reader": kind}
                                    for label, argv, kind in commands])
    report = {"schema": "trnm-pq-authority-validation-v1", "result": "FAIL",
              "expected_head": args.expected_head, "repo": str(args.repo), "target": str(args.target),
              "runner": file_record(args.out / "authority-validation-runner.py"),
              "commands": [], "failures": [], "production_activation": False,
              "whole_chain_quantum_security_qualified": False}
    before = None
    provider_before = None
    try:
        before = source_identity(args.repo, env)
        save(args.out / "source-before.json", before)
        if before["head"] != args.expected_head or before["status"]:
            raise ValueError("initial source must be the exact expected HEAD and clean")
        for spec in commands[:2]:
            result = run_command(spec, args.repo, args.out, env)
            report["commands"].append(result)
            if not result["passed"]:
                raise ValueError("initial preflight/raw-source admission failed: " + spec[0])
        try:
            provider_before = provider_identity()
            save(args.out / "provider-before.json", provider_before)
        except Exception as error:
            report["failures"].append("provider admission: " + str(error))
        native_ready = provider_before is not None
        for spec in commands[2:]:
            label, argv, kind = spec
            is_native = argv[0] == CARGO or kind in ("rustc", "openssl")
            if is_native and not native_ready:
                report["commands"].append({"label": label, "argv": argv, "passed": False,
                                           "exit_code": None, "blocked": "native environment admission failed"})
                continue
            result = run_command(spec, args.repo, args.out, env)
            report["commands"].append(result)
            if kind in ("rustc", "cargo", "openssl") and not result["passed"]:
                native_ready = False
            save(args.out / "summary.json", report)
    except Exception as error:
        report["failures"].append(f"{type(error).__name__}: {error}")
    finally:
        try:
            after = source_identity(args.repo, env)
            save(args.out / "source-after.json", after)
            report["source_unchanged"] = before is not None and after == before
            if not report["source_unchanged"] or after["head"] != args.expected_head or after["status"]:
                report["failures"].append("final HEAD/tree/index/lockfiles/clean status differs")
        except Exception as error:
            report["failures"].append("final source observation: " + str(error))
        try:
            provider_after = provider_identity()
            save(args.out / "provider-after.json", provider_after)
            report["provider_unchanged"] = provider_before is not None and provider_before == provider_after
            if not report["provider_unchanged"]:
                report["failures"].append("provider inputs changed or initial provider admission failed")
        except Exception as error:
            report["failures"].append("final provider observation: " + str(error))
        try:
            sqlite = sqlite_qualification(args.target, args.out)
            save(args.out / "sqlite-qualification.json", sqlite)
            if not sqlite["passed"]:
                report["failures"].append("SQLite has no qualified build output or has an unqualified retained unit")
        except Exception as error:
            report["failures"].append("SQLite qualification observation: " + str(error))
        complete = len(report["commands"]) == len(commands)
        if complete and all(row["passed"] for row in report["commands"]) and not report["failures"]:
            report["result"] = "PASS"
        report["finished_unix_seconds"] = time.time()
        save(args.out / "summary.json", report)
        print(json.dumps({"result": report["result"], "summary": str(args.out / "summary.json"),
                          "failed_commands": [row["label"] for row in report["commands"] if not row["passed"]],
                          "failures": report["failures"]}), flush=True)
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
