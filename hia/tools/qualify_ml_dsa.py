"""Run and read back the bounded ML-DSA native/original qualification.

The report binds the actual compiled inputs, every retained original target,
all test methods, all raw observations and the explicit private-entry scope.
It does not turn a private borrowed-buffer interface into a foreign pointer API.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hia.tests.native_support import NativeModule, unlinked_path
from hia.tools import ml_dsa_original
from hia.tools.component_partition import ObservedResult
from hia.tools.qualify import native_build_record, validate_build_provenance

COMPILER = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
REVISION = "f33d8da316de8fdf27b504371f1a5310997ff548"
SCHEMA = "trnm.hia.ml-dsa-qualification.v1"
LIMITS = {"constant_time_qualified": False, "foreign_pointer_gate_qualified": False,
          "automatic_owner_lifetime_qualified": False, "crypto_crate_retired": False,
          "whole_chain_native": False, "production_activation": False}
COUNTS = {"original_batches": 10, "original_calls": 669, "native_verify": 514,
          "native_keygen": 112, "native_sign": 265, "native_owner": 315,
          "native_nonce": 7, "raw_owned_calls": 96, "raw_capacity_refusals": 12}
ORIGINAL_ROOTS = ("trillionnium/crates/trnm-crypto-primitives", "trillionnium/crates/trnm-protocol",
                  "trillionnium/Cargo.toml", "trillionnium/Cargo.lock", "rust-toolchain.toml",
                  "scripts/project-preflight.sh", "scripts/ci/prepare_pq_provider.sh", "AGENTS.md",
                  "config/pon/work-profile-v1.json",
                  "trillionnium/crates/trnm-pon-node/examples/support/w1_from_zero.rs",
                  "tests/fixtures/cpq1-content-v1/vectors.json")
OWNED = ("hia/src/crypto/ml_dsa.hepta", "hia/src/crypto/ml_dsa_keygen.hepta",
         "hia/src/crypto/ml_dsa_sign.hepta", "hia/src/crypto/ml_dsa_owner.hepta",
         "hia/src/crypto/ML_DSA.md", "hia/tests/rust_ml_dsa_reference.rs",
         "hia/tests/test_ml_dsa.py", "hia/tests/test_ml_dsa_qualification.py",
         "hia/tests/vectors/ml_dsa_acvp_975de31.json.xz", "hia/tools/ml_dsa_original.py",
         "hia/tools/qualify_ml_dsa.py")
DEPENDENCIES = ("hia/components.json", "hia/toolchain.lock.json", "hia/qualification/compiler-binding.json",
                "hia/src/crypto/keccak_stream.hepta", "hia/src/crypto/ml_dsa_poly.hepta",
                "hia/tests/native_support.py", "hia/tools/toolchain.py", "hia/tools/qualify.py",
                "hia/tools/component_partition.py")


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def same(a, b):
    return json.dumps(a, sort_keys=True, separators=(",", ":")) == json.dumps(b, sort_keys=True, separators=(",", ":"))


def relative(name):
    need(type(name) is str and name and "\\" not in name and "\0" not in name
         and not Path(name).is_absolute() and ".." not in Path(name).parts
         and Path(name).as_posix() == name and name != ".", "Noncanonical qualification path")
    return name


def read(directory, name):
    root = unlinked_path(directory, directory=True)
    return unlinked_path(root / relative(name)).read_bytes()


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "Duplicate qualification JSON field")
        result[key] = value
    return result


def document(raw):
    return json.loads(raw, object_pairs_hook=_pairs)


def original_paths():
    raw = subprocess.check_output(["git", "ls-tree", "-rz", "HEAD", "--", *ORIGINAL_ROOTS], cwd=ROOT)
    return [entry.split(b"\t", 1)[1].decode() for entry in raw.split(b"\0") if entry]


def sources():
    return {name: sha(read(ROOT, name)) for name in sorted(set(original_paths()) | set(OWNED) | set(DEPENDENCIES))}


def identifiers(suite):
    values = []
    for test in suite:
        values.extend(identifiers(test) if isinstance(test, unittest.TestSuite) else [test.id()])
    return sorted(values)


def roster():
    result = identifiers(unittest.defaultTestLoader.loadTestsFromName("hia.tests.test_ml_dsa"))
    need(len(result) == 16 and len(set(result)) == 16, "Changed ML-DSA method roster")
    return result


def control_roster():
    result = identifiers(unittest.defaultTestLoader.loadTestsFromName("hia.tests.test_ml_dsa_qualification"))
    need(len(result) == 20 and len(set(result)) == 20, "Changed ML-DSA integrity control roster")
    return result


def validate_provider(value, retained=None):
    need(value.get("schema") == "trnm-ci-pq-provider-v3" and value.get("version") == "3.5.9"
         and value.get("exit_code") == 0 and value.get("last_stage") == "complete"
         and value.get("source_digest_verified") is True and value.get("static_build") is True
         and value.get("ml_dsa_65_sign_verify_and_wrong_message_rejection") is True
         and value.get("source_archive_sha256_expected") == "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
         and value.get("preparation_script_sha256") == sha(read(ROOT, "scripts/ci/prepare_pq_provider.sh")),
         "Incomplete pinned OpenSSL 3.5.9 preparation")
    inputs = value.get("native_backend_inputs")
    need(type(inputs) is list and len(inputs) == 5 and len({row["path"] for row in inputs}) == 5,
         "Incomplete actual provider inputs")
    for index, row in enumerate(inputs):
        raw = (unlinked_path(row["path"]).read_bytes() if retained is None else
               read(retained, f"provider/{index:02d}-" + Path(row["path"]).name))
        need(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "Changed actual provider input")
    need(inputs[0]["path"] == value.get("cli_executable") and inputs[0]["sha256"] == value.get("cli_sha256"),
         "Provider executable differs from the linked preparation")


def provider_environment(value, environment):
    prefix = value["install_prefix"]
    expected = {"OPENSSL_DIR": prefix, "OPENSSL_STATIC": "1", "TRNM_PQ_OPENSSL": value["cli_executable"],
                "TRNM_PQ_OPENSSL_SHA256": value["cli_sha256"], "TRNM_PQ_OPENSSL_VERSION": "3.5.9",
                "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": prefix + "/lib/ossl-modules"}
    need(all(environment.get(key) == item for key, item in expected.items()),
         "Original graph used a different provider environment")


def validate_original(value, root, source_inputs):
    need(value.get("status") == "PASS" and value.get("passed") == 343 and value.get("doc_passed") == 2,
         "Incomplete original Rust gate")
    need(type(value.get("tests")) is list and len(value["tests"]) == 34, "Incomplete original target roster")
    need(same(value.get("environment_guard"), ml_dsa_original.ENVIRONMENT_GUARD),
         "Original build/runtime override policy was not applied")
    env = value["environment"]
    need(env.get("CARGO_INCREMENTAL") == "0" and env.get("CARGO_BUILD_JOBS") == "8"
         and env.get("CARGO_NET_OFFLINE") == "true" and env.get("OPENSSL_STATIC") == "1"
         and env.get("OPENSSL_CONF") == "/dev/null" and env.get("TRNM_PQ_OPENSSL_VERSION") == "3.5.9",
         "Changed original compilation environment")
    rust = Path(env["RUSTC"]).parent
    need(env["RUSTDOC"] == str(rust / "rustdoc"), "Different original Rust compiler family")
    reference = value["reference"]
    executed_out = Path(reference["path"]).parent
    need(env["CARGO_TARGET_DIR"] == str(executed_out / "target") and reference["retained"] == "original-reference",
         "Original target or adapter identity changed")
    stages = value["stages"]
    need(type(stages) is list and len(stages) == 79, "Incomplete original stage roster")
    repository = Path(stages[0]["cwd"])
    crate = repository / "trillionnium"
    expected = [
        ("git-head", ["git", "rev-parse", "HEAD", "HEAD^{tree}"], repository, 180),
        ("preflight", ["bash", "scripts/project-preflight.sh"], repository, 180),
        ("rustc-version", [rust / "rustc", "-Vv"], crate, 180),
        ("cargo-fetch", [rust / "cargo", "fetch", "--locked", "--target", "x86_64-unknown-linux-gnu"], crate, 180),
        ("cargo-metadata", [rust / "cargo", "metadata", "--locked", "--offline", "--all-features", "--format-version=1"], crate, 180),
        ("cargo-format", [rust / "cargo", "fmt", "--all", "--check"], crate, 180),
        ("cargo-no-run", [rust / "cargo", "test", "--locked", "--offline", "-p", "trnm-crypto-primitives",
                          "--all-features", "--all-targets", "--no-run", "--message-format=json"], crate, 480),
    ]
    for index, test in enumerate(value["tests"]):
        expected += [(f"list-{index:02d}", [test["path"], "--list", "--format=terse"], crate, 180),
                     (f"test-{index:02d}", [test["path"], "--test-threads=1"], crate, 360)]
    adapter = repository / "hia/tests/rust_ml_dsa_reference.rs"
    arguments = [rust / "rustc", "--edition=2021", "-D", "warnings", adapter, "-L",
                 "dependency=" + str(executed_out / "target/debug/deps"), "-L", "native=" + env["OPENSSL_DIR"] + "/lib"]
    graph = value["adapter_graph"]
    names = ("ml_dsa", "hex", "serde_json", "zeroize", "trnm_crypto_primitives")
    need(len(graph) == 5 and {row["name"] for row in graph} == set(names), "Ambiguous original adapter dependencies")
    for name in names:
        row = next(row for row in graph if row["name"] == name)
        arguments += ["--extern", name + "=" + row["path"]]
        raw = read(root, row["retained"])
        need(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "Changed retained original library")
    arguments += ["-o", executed_out / "original-reference"]
    expected += [
        ("cargo-doctests", [rust / "cargo", "test", "--locked", "--offline", "-p", "trnm-crypto-primitives", "--all-features", "--doc"], crate, 180),
        ("cargo-clippy", [rust / "cargo", "clippy", "--locked", "--offline", "-p", "trnm-crypto-primitives", "--all-features", "--all-targets", "--", "-D", "warnings"], crate, 360),
        ("adapter-format", [rust / "rustfmt", "--edition", "2021", "--check", adapter], crate, 180),
        ("adapter-build", arguments, crate, 180),
    ]
    for stage, (label, argv, cwd, limit) in zip(stages, expected):
        need(stage["label"] == label and stage["argv"] == list(map(str, argv)) and stage["cwd"] == str(cwd)
             and stage["wall_limit_seconds"] == limit and stage["exit_code"] == 0 and stage["timed_out"] is False,
             "Changed, filtered or unsuccessful original stage")
        need(same(stage, document(read(root, label + ".receipt.json"))), "Original stage receipt differs")
        for stream in ("stdout", "stderr"):
            row = stage[stream]
            need(row["path"] == label + "." + stream + ".raw", "Original raw stream identity differs")
            raw = read(root, row["path"])
            need(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "Changed original raw output")
    version = read(root, "rustc-version.stdout.raw").decode()
    need("release: 1.95.0\n" in version and "host: x86_64-unknown-linux-gnu\n" in version,
         "Original compiler version or host differs")
    need(read(root, "git-head.stdout.raw").decode().splitlines() == [value["head"], value["tree"]],
         "Original source checkout identity differs")
    artifacts = [document(line) for line in read(root, "cargo-no-run.stdout.raw").splitlines() if line.startswith(b"{")]
    artifacts = [row for row in artifacts if row.get("reason") == "compiler-artifact"]
    need(same(artifacts, document(read(root, "artifacts.json"))), "Actual Cargo artifact events differ")
    actual_tests = [row for row in artifacts if row["executable"] and row["profile"]["test"]
                    and Path(row["target"]["src_path"]).is_relative_to(repository / "trillionnium/crates/trnm-crypto-primitives")]
    need(len(actual_tests) == 34, "Original executable graph incomplete")
    total = 0
    for index, (test, event) in enumerate(zip(value["tests"], actual_tests)):
        need(test["path"] == event["executable"] and test["name"] == event["target"]["name"]
             and same(test["target"], event["target"]) and same(test["features"], event["features"])
             and test["retained"] == f"retained/{index:02d}-" + test["name"], "Original test binary differs from Cargo graph")
        need(same(test["profile"], ml_dsa_original.TEST_PROFILE) and same(event["profile"], ml_dsa_original.TEST_PROFILE),
             "Original test compilation profile differs")
        raw = read(root, test["retained"])
        need(raw.startswith(b"\x7fELF\x02\x01") and len(raw) == test["bytes"] and sha(raw) == test["sha256"],
             "Changed original test executable")
        listing = read(root, f"list-{index:02d}.stdout.raw")
        names = [line[:-6].decode() for line in listing.splitlines() if line.endswith(b": test")]
        need(len(set(names)) == len(names) and names == test["roster"] and test["passed"] == len(names),
             "Original test listing is incomplete or duplicated")
        output = read(root, f"test-{index:02d}.stdout.raw")
        summaries = re.findall(rb"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", output)
        need(len(summaries) == 1 and tuple(map(int, summaries[0])) == (len(names), 0, 0, 0, 0),
             "Original retained tests were not fully executed")
        total += len(names)
    need(total == 343, "Changed complete original retained count")
    doc = re.findall(rb"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
                     read(root, "cargo-doctests.stdout.raw"))
    need(len(doc) == 1 and tuple(map(int, doc[0])) == (2, 0, 0, 0, 0), "Original doctests incomplete")
    for row in graph:
        found = [event for event in artifacts if event["target"]["name"] == row["name"] and row["path"] in event["filenames"]]
        need(len(found) == 1 and row["package_id"] == found[0]["package_id"] and row["features"] == found[0]["features"],
             "Original adapter is not linked to its actual Cargo graph")
        if row["name"] == "ml_dsa":
            need(row["features"] == ["alloc", "zeroize"] and row["package_id"].endswith("ml-dsa@0.1.1"),
                 "Different original ML-DSA dependency or features")
    expected_sources = {name for name in source_inputs if any(name == prefix or name.startswith(prefix + "/") for prefix in ORIGINAL_ROOTS)}
    need(type(value["source"]) is list and len(value["source"]) == len(expected_sources)
         and {row["path"] for row in value["source"]} == expected_sources,
         "Original source roster was omitted or duplicated")
    for row in value["source"]:
        raw = read(ROOT, row["path"])
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        need(source_inputs.get(relative(row["path"])) == row["sha256"] == sha(raw)
             and row["bytes"] == len(raw) and row["git_blob"] == blob,
             "Original source differs from native qualification")
    need(reference["source"] == "hia/tests/rust_ml_dsa_reference.rs"
         and source_inputs.get(reference["source"]) == reference["source_sha256"], "Changed original adapter source")
    raw = read(root, reference["retained"])
    need(len(raw) == reference["bytes"] and sha(raw) == reference["sha256"], "Changed original adapter executable")


def validate(root, source_inputs=None):
    root = unlinked_path(root, directory=True)
    value = document(read(root, "report.json"))
    before = sources() if source_inputs is None else source_inputs
    need(value.get("schema") == SCHEMA and value.get("status") == "PASS", "Incomplete ML-DSA qualification")
    need(same(value.get("limits"), LIMITS), "Qualification promoted an unimplemented scope")
    need(same(value.get("source_inputs"), before) and value.get("source_set_sha256") == sha(json.dumps(before, sort_keys=True, separators=(",", ":")).encode())
         and value.get("source_unchanged_during_tests") is True, "Qualification source graph changed")
    if source_inputs is None:
        need(value["source_commit_observed"] == subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
             "Qualification belongs to a different checkout")
    wanted = roster()
    tests = value["tests"]
    need(tests["run"] == 16 and tests["failures"] == [] and tests["errors"] == [] and tests["skipped"] == []
         and sorted(tests["started"]) == wanted and sorted(tests["finished"]) == wanted,
         "ML-DSA methods were filtered, duplicated, skipped or failed")
    controls = value["controls"]
    control_ids = control_roster()
    need(controls["run"] == 20 and controls["failures"] == [] and controls["errors"] == [] and controls["skipped"] == []
         and sorted(controls["started"]) == control_ids and sorted(controls["finished"]) == control_ids,
         "Integrity controls were filtered, duplicated, skipped or failed")
    original_raw = read(root, "original/report.json")
    need(sha(original_raw) == value["original_report_sha256"], "Original qualification receipt changed")
    original = document(original_raw)
    provider = document(read(root, "provider.json"))
    need(value.get("provider_inputs_unchanged_during_original") is True,
         "Live provider inputs were not checked after original qualification")
    validate_provider(provider, retained=root)
    provider_environment(provider, original["environment"])
    validate_original(original, root / "original", before)
    observed = document(read(root, "observations/observations.json"))
    need(same(observed["counts"], COUNTS) and observed["original_artifact_sha256"] == original["reference"]["sha256"],
         "Incomplete actual native/original observations")
    need(value["native_calls_through_shared_runner"] == {"returned": 1213}, "Native execution did not complete")
    builds = value["builds"]
    need(len(builds) == 5, "Missing actual ML-DSA native build")
    named = {"hia/src/crypto/ml_dsa.hepta": "verify", "hia/src/crypto/ml_dsa_keygen.hepta": "keygen",
             "hia/src/crypto/ml_dsa_sign.hepta": "sign", "hia/src/crypto/ml_dsa_owner.hepta": "owner", None: "nonce"}
    need({build.get("source") for build in builds} == set(named), "Duplicate or unexpected native entry")
    for build in builds:
        validate_build_provenance(build, before)
        need(build["compiler_sha256"] == COMPILER and build["chain_migration"]["backend"] == "selfhost"
             and build["chain_migration"]["toolchain_revision"] == REVISION and build["exports"] == ["f0"]
             and build["claims"]["fallback_used"] is False and build["claims"]["python_emitter_used"] is False,
             "Wrong native compiler, backend, exports or fallback")
        name = named[build["source"]]
        raw = read(root, "observations/" + name + ".so")
        receipt = document(read(root, "observations/" + name + "-build.json"))
        need(sha(raw) == build["artifact_sha256"] == observed["native_artifacts"][name]
             == receipt["artifact_sha256"] and len(raw) == receipt["artifact_bytes"]
             and same(receipt["chain_migration"], build["chain_migration"]), "Actual native image or build receipt changed")
    raw_counts = Counter()
    with gzip.open(unlinked_path(root / "observations/native-calls.jsonl.gz"), "rb") as stream:
        for line in stream:
            row = document(line)
            need(row["status"] == "returned" and row["returncode"] == 0 and row["abi_status"] == 0
                 and row["test"] in wanted and row["artifact_sha256"] == observed["native_artifacts"].get(row["module"]),
                 "Changed or unsuccessful actual native call")
            raw_counts["native_" + row["module"]] += 1
    need(dict(raw_counts) == {key: count for key, count in COUNTS.items() if key.startswith("native_")},
         "Missing raw native calls")
    original_counts = [18, 270, 50, 150, 48, 72, 24, 2, 21, 14]
    for index, count in enumerate(original_counts):
        stem = f"observations/original-{index:03d}"
        sent, stdout, stderr = [read(root, stem + suffix) for suffix in (".requests.jsonl", ".stdout.raw", ".stderr.raw")]
        receipt = document(read(root, stem + ".receipt.json"))
        need(receipt["argv"] == [original["reference"]["path"]] and receipt["wall_limit_seconds"] == 120
             and receipt["executable_sha256"] == original["reference"]["sha256"] and receipt["exit_code"] == 0
             and receipt["requests"] == count and receipt["input_sha256"] == sha(sent)
             and receipt["stdout_sha256"] == sha(stdout) and receipt["stderr_sha256"] == sha(stderr)
             and len(sent.splitlines()) == len(stdout.splitlines()) == count and not stderr,
             "Missing, replaced or unsuccessful original method comparisons")
    pointer_request = read(root, "observations/pointer.requests.json")
    pointer_output = read(root, "observations/pointer.stdout.raw")
    pointer_error = read(root, "observations/pointer.stderr.raw")
    receipt = document(read(root, "observations/pointer.receipt.json"))
    from hia.tests.test_ml_dsa import POINTER_WORKER
    need(receipt["exit_code"] == 0 and receipt["wall_limit_seconds"] == 90
         and receipt["input_sha256"] == sha(pointer_request) and receipt["stdout_sha256"] == sha(pointer_output)
         and receipt["stderr_sha256"] == sha(pointer_error) and not pointer_error
         and receipt["worker_sha256"] == sha(POINTER_WORKER.encode()), "Changed private pointer worker or raw observations")
    pointer = document(pointer_output)
    need(pointer["compiler_modules_loaded"] == []
         and pointer["images"] == {name: identity for name, identity in observed["native_artifacts"].items() if name != "nonce"}
         and len(pointer["histories"]) == 16 and len(pointer["guards"]) == 12,
         "Private allocation observations incomplete")
    for history in pointer["histories"]:
        need(len(history) == 6, "Private key lifecycle incomplete")
        for row in history:
            need(row["abi_status"] == 0 and row["guards"] is True and row["input_unchanged"] is True
                 and row["work_cleared"] is True and row["work_tail"] == (b"\xa5" * 17).hex(),
                 "Private key guards or temporary cleanup failed")
    for row in pointer["guards"]:
        need(row == {"abi_status": 0, "value": 0xfffffffd, "unchanged": True},
             "Native private entry did not refuse an oversized owned allocation")
    native_logs = [name for name in value["raw_files"] if name.startswith("observations/")]
    need(native_logs, "Missing native observation inventory")
    for name, identity in value["raw_files"].items():
        raw = read(root, name)
        need(len(raw) == identity["bytes"] and sha(raw) == identity["sha256"], "Raw qualification bytes changed")
    return value


def run(args):
    need(not sys.flags.optimize and os.environ.get("PYTHONOPTIMIZE") in (None, "", "0"), "Optimized Python is not qualification")
    out = Path(args.output).absolute()
    need(not out.exists() and not out.is_symlink(), "Qualification output must be new")
    out.mkdir()
    provider = document(unlinked_path(args.provider_receipt).read_bytes())
    validate_provider(provider)
    (out / "provider.json").write_text(json.dumps(provider, sort_keys=True, indent=2) + "\n")
    shutil.copyfile(unlinked_path(args.provider_environment), out / "provider-environment")
    environment = _pairs(line.split("=", 1) for line in read(out, "provider-environment").decode().splitlines())
    provider_environment(provider, environment)
    (out / "provider").mkdir()
    for index, row in enumerate(provider["native_backend_inputs"]):
        shutil.copyfile(unlinked_path(row["path"]), out / (f"provider/{index:02d}-" + Path(row["path"]).name))
    before = sources()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    report = {"schema": SCHEMA, "status": "FAIL", "limits": LIMITS, "source_commit_observed": head,
              "source_inputs": before, "source_set_sha256": sha(json.dumps(before, sort_keys=True, separators=(",", ":")).encode()),
              "builds": [], "raw_files": {}}
    start = time.monotonic()
    old_init, old_many = NativeModule.__init__, NativeModule.call_many
    calls = Counter()
    try:
        original = ml_dsa_original.run(ROOT, out / "original", args.rust_bin, out / "provider-environment")
        validate_provider(provider)
        report["provider_inputs_unchanged_during_original"] = True
        report["original_report_sha256"] = sha(read(out, "original/report.json"))
        os.environ["TRNM_HIA_RUST_ML_DSA_REFERENCE"] = original["reference"]["path"]
        os.environ["TRNM_HIA_RUST_ML_DSA_REFERENCE_SHA256"] = original["reference"]["sha256"]
        os.environ["TRNM_HIA_ML_DSA_OBSERVATIONS"] = str(out / "observations")

        def record_init(self, *values, **options):
            old_init(self, *values, **options)
            try:
                report["builds"].append(native_build_record(self, before))
            except BaseException:
                self.close()
                raise

        def record_many(self, cases, **options):
            result = old_many(self, cases, **options)
            for row in result:
                calls[row.status] += 1
            return result

        NativeModule.__init__, NativeModule.call_many = record_init, record_many
        suite = unittest.defaultTestLoader.loadTestsFromName("hia.tests.test_ml_dsa")
        need(identifiers(suite) == roster(), "Changed actual test selection")
        with (out / "tests.stderr.raw").open("w") as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=ObservedResult).run(suite)
        report["tests"] = {"run": result.testsRun, "started": result.started_tests, "finished": result.finished_tests,
                           "failures": [(str(t), error) for t, error in result.failures],
                           "errors": [(str(t), error) for t, error in result.errors],
                           "skipped": [(str(t), reason) for t, reason in result.skipped]}
        need(result.wasSuccessful() and not result.skipped and result.testsRun == 16, "Actual ML-DSA tests failed")
        control_suite = unittest.defaultTestLoader.loadTestsFromName("hia.tests.test_ml_dsa_qualification")
        need(identifiers(control_suite) == control_roster(), "Changed actual integrity control selection")
        with (out / "controls.stderr.raw").open("w") as log:
            controls = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=ObservedResult).run(control_suite)
        report["controls"] = {"run": controls.testsRun, "started": controls.started_tests, "finished": controls.finished_tests,
                              "failures": [(str(t), error) for t, error in controls.failures],
                              "errors": [(str(t), error) for t, error in controls.errors],
                              "skipped": [(str(t), reason) for t, reason in controls.skipped]}
        need(controls.wasSuccessful() and not controls.skipped and controls.testsRun == 20, "Integrity controls failed")
        need(before == sources() and head == subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
             "Source changed during qualification")
        report["source_unchanged_during_tests"] = True
        for path in sorted(out.rglob("*")):
            if path.is_file() and "target" not in path.relative_to(out).parts and path != out / "report.json":
                raw = unlinked_path(path).read_bytes()
                report["raw_files"][path.relative_to(out).as_posix()] = {"bytes": len(raw), "sha256": sha(raw)}
        report["status"] = "PASS"
    except BaseException as error:
        report.update(error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        NativeModule.__init__, NativeModule.call_many = old_init, old_many
        report.update(seconds=time.monotonic() - start, native_calls_through_shared_runner=dict(calls))
        (out / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    try:
        validate(out)
    except BaseException as error:
        report.update(status="FAIL", readback_error=repr(error), readback_traceback=traceback.format_exc())
        (out / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        raise
    print(json.dumps({"status": "PASS", "report_sha256": sha(read(out, "report.json")), "seconds": report["seconds"],
                      "original_tests": 343, "doctests": 2, "native_methods": 16, "integrity_controls": 20,
                      "observations": COUNTS}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    execute = commands.add_parser("run")
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--rust-bin", type=Path, required=True)
    execute.add_argument("--provider-environment", type=Path, required=True)
    execute.add_argument("--provider-receipt", type=Path, required=True)
    reader = commands.add_parser("readback")
    reader.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "run":
        run(args)
    else:
        value = validate(args.input)
        print(json.dumps({"status": "PASS", "report_sha256": sha(read(args.input, "report.json")),
                          "source_set_sha256": value["source_set_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
