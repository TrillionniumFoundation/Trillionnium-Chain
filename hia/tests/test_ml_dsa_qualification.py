"""Integrity controls for qualification records, not cryptographic evidence.

The small original-record fixture below is synthetic. It exercises parser
bindings without compiling or claiming to execute a 343-test original crate.
The actual positive qualification separately uses all original/native artifacts.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hia.tools import qualify_ml_dsa as q


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def original_fixture(source, output):
    """A bounded serialization fixture, explicitly not execution evidence."""
    repository = Path("/execution/repository")
    execution = Path("/execution/qualification/original")
    rust = Path("/toolchains/1.95.0/bin")
    crate = repository / "trillionnium"
    target = execution / "target"
    environment = {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "8", "CARGO_NET_OFFLINE": "true",
                   "CARGO_HOME": "/fixture/cargo", "CARGO_TARGET_DIR": str(target),
                   "RUSTC": str(rust / "rustc"), "RUSTDOC": str(rust / "rustdoc"),
                   "OPENSSL_DIR": "/fixture/provider", "OPENSSL_STATIC": "1", "OPENSSL_CONF": "/dev/null",
                   "OPENSSL_MODULES": "/fixture/provider/lib/ossl-modules", "TRNM_PQ_OPENSSL_VERSION": "3.5.9",
                   "TRNM_PQ_OPENSSL": "/fixture/provider/bin/openssl", "TRNM_PQ_OPENSSL_SHA256": "1" * 64}
    report = {"status": "PASS", "head": "a" * 40, "tree": "b" * 40, "passed": 343, "doc_passed": 2,
              "environment": environment, "environment_guard": deepcopy(q.ml_dsa_original.ENVIRONMENT_GUARD),
              "stages": [], "tests": [], "source": [], "adapter_graph": []}
    source_inputs = {}
    names = ["trillionnium/crates/trnm-crypto-primitives/src/lib.rs", "trillionnium/crates/trnm-protocol/src/lib.rs",
             "trillionnium/Cargo.toml", "trillionnium/Cargo.lock", "rust-toolchain.toml", "AGENTS.md",
             "scripts/project-preflight.sh", "scripts/ci/prepare_pq_provider.sh",
             "config/pon/work-profile-v1.json",
             "trillionnium/crates/trnm-pon-node/examples/support/w1_from_zero.rs",
             "tests/fixtures/cpq1-content-v1/vectors.json"]
    for name in names + ["hia/tests/rust_ml_dsa_reference.rs"]:
        raw = ("synthetic parser control: " + name).encode()
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        source_inputs[name] = q.sha(raw)
        if name in names:
            report["source"].append({"path": name, "bytes": len(raw), "sha256": q.sha(raw),
                                     "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()})

    def stage(label, argv, cwd=crate, limit=180, stdout=b"", stderr=b""):
        value = {"label": label, "argv": list(map(str, argv)), "cwd": str(cwd), "wall_limit_seconds": limit,
                 "exit_code": 0, "timed_out": False, "seconds": 0.01}
        for stream, raw in (("stdout", stdout), ("stderr", stderr)):
            name = label + "." + stream + ".raw"
            (output / name).write_bytes(raw)
            value[stream] = {"path": name, "bytes": len(raw), "sha256": q.sha(raw)}
        write_json(output / (label + ".receipt.json"), value)
        report["stages"].append(value)

    artifacts = []
    for name in ("ml_dsa", "hex", "serde_json", "zeroize", "trnm_crypto_primitives"):
        path = str(target / "debug/deps" / ("lib" + name + "-fixture.rlib"))
        package = "registry+https://github.com/rust-lang/crates.io-index#" + name.replace("_", "-") + "@0.1.1"
        features = ["alloc", "zeroize"] if name == "ml_dsa" else []
        data = ("synthetic library: " + name).encode()
        relative = "dependencies/" + Path(path).name
        (output / relative).parent.mkdir(exist_ok=True)
        (output / relative).write_bytes(data)
        report["adapter_graph"].append({"name": name, "path": path, "retained": relative, "bytes": len(data),
                                         "sha256": q.sha(data), "package_id": package, "features": features})
        artifacts.append({"reason": "compiler-artifact", "target": {"name": name}, "filenames": [path],
                          "package_id": package, "features": features, "profile": {"test": False}, "executable": None})
    for index in range(34):
        name = "fixture_" + str(index)
        path = str(target / "debug/deps" / name)
        data = b"\x7fELF\x02\x01" + bytes([index]) * 16
        relative = f"retained/{index:02d}-" + name
        (output / relative).parent.mkdir(exist_ok=True)
        (output / relative).write_bytes(data)
        names = [f"synthetic_{i:03d}" for i in range(343)] if index == 33 else []
        target_record = {"name": name, "src_path": str(repository / "trillionnium/crates/trnm-crypto-primitives/tests" / (name + ".rs"))}
        report["tests"].append({"name": name, "path": path, "retained": relative, "bytes": len(data), "sha256": q.sha(data),
                                "target": target_record, "features": [], "roster": names, "passed": len(names),
                                "profile": deepcopy(q.ml_dsa_original.TEST_PROFILE)})
        artifacts.append({"reason": "compiler-artifact", "target": target_record, "filenames": [path],
                          "package_id": "fixture-crypto", "features": [],
                          "profile": deepcopy(q.ml_dsa_original.TEST_PROFILE), "executable": path})
    stage("git-head", ["git", "rev-parse", "HEAD", "HEAD^{tree}"], repository,
          stdout=(report["head"] + "\n" + report["tree"] + "\n").encode())
    stage("preflight", ["bash", "scripts/project-preflight.sh"], repository)
    stage("rustc-version", [rust / "rustc", "-Vv"], stdout=b"rustc 1.95.0\nrelease: 1.95.0\nhost: x86_64-unknown-linux-gnu\n")
    stage("cargo-fetch", [rust / "cargo", "fetch", "--locked", "--target", "x86_64-unknown-linux-gnu"])
    stage("cargo-metadata", [rust / "cargo", "metadata", "--locked", "--offline", "--all-features", "--format-version=1"], stdout=b"{}")
    stage("cargo-format", [rust / "cargo", "fmt", "--all", "--check"])
    raw_events = b"".join((json.dumps(row) + "\n").encode() for row in artifacts)
    stage("cargo-no-run", [rust / "cargo", "test", "--locked", "--offline", "-p", "trnm-crypto-primitives",
                           "--all-features", "--all-targets", "--no-run", "--message-format=json"], limit=480, stdout=raw_events)
    write_json(output / "artifacts.json", artifacts)
    for index, test in enumerate(report["tests"]):
        stage(f"list-{index:02d}", [test["path"], "--list", "--format=terse"],
              stdout=b"".join((name + ": test\n").encode() for name in test["roster"]))
        raw = f"test result: ok. {len(test['roster'])} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n".encode()
        stage(f"test-{index:02d}", [test["path"], "--test-threads=1"], limit=360, stdout=raw)
    stage("cargo-doctests", [rust / "cargo", "test", "--locked", "--offline", "-p", "trnm-crypto-primitives", "--all-features", "--doc"],
          stdout=b"test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n")
    stage("cargo-clippy", [rust / "cargo", "clippy", "--locked", "--offline", "-p", "trnm-crypto-primitives", "--all-features", "--all-targets", "--", "-D", "warnings"], limit=360)
    adapter = repository / "hia/tests/rust_ml_dsa_reference.rs"
    stage("adapter-format", [rust / "rustfmt", "--edition", "2021", "--check", adapter])
    arguments = [rust / "rustc", "--edition=2021", "-D", "warnings", adapter, "-L", "dependency=" + str(target / "debug/deps"),
                 "-L", "native=/fixture/provider/lib"]
    for row in report["adapter_graph"]:
        arguments += ["--extern", row["name"] + "=" + row["path"]]
    arguments += ["-o", execution / "original-reference"]
    stage("adapter-build", arguments)
    raw = b"synthetic adapter, not an executable"
    (output / "original-reference").write_bytes(raw)
    report["reference"] = {"path": str(execution / "original-reference"), "retained": "original-reference",
                            "bytes": len(raw), "sha256": q.sha(raw), "source": "hia/tests/rust_ml_dsa_reference.rs",
                            "source_sha256": source_inputs["hia/tests/rust_ml_dsa_reference.rs"]}
    return report, source_inputs


class MlDsaQualificationIntegrity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-ml-dsa-integrity-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source, self.output = self.root / "source", self.root / "output"
        self.source.mkdir()
        self.output.mkdir()
        self.report, self.inputs = original_fixture(self.source, self.output)
        patched = patch.object(q, "ROOT", self.source)
        self.addCleanup(patched.stop)
        patched.start()

    def validate(self):
        q.validate_original(self.report, self.output, self.inputs)

    def stage(self, label):
        return next(row for row in self.report["stages"] if row["label"] == label)

    def receipt(self, label):
        write_json(self.output / (label + ".receipt.json"), self.stage(label))

    def replace_stream(self, label, stream, raw):
        row = self.stage(label)[stream]
        (self.output / row["path"]).write_bytes(raw)
        row.update(bytes=len(raw), sha256=q.sha(raw))
        self.receipt(label)

    def test_complete_serialization_fixture_is_accepted_without_execution_claim(self):
        self.validate()

    def test_failure_and_missing_original_stages_are_rejected(self):
        self.report["status"] = "FAIL"
        with self.assertRaisesRegex(ValueError, "Incomplete original"):
            self.validate()
        self.report["status"] = "PASS"
        self.report["stages"].pop()
        with self.assertRaisesRegex(ValueError, "stage roster"):
            self.validate()

    def test_locked_offline_all_features_cannot_be_removed_from_both_receipts(self):
        for flag in ("--locked", "--offline", "--all-features", "--all-targets"):
            with self.subTest(flag=flag):
                before = deepcopy(self.stage("cargo-no-run"))
                self.stage("cargo-no-run")["argv"].remove(flag)
                self.receipt("cargo-no-run")
                with self.assertRaisesRegex(ValueError, "original stage"):
                    self.validate()
                self.stage("cargo-no-run").update(before)
                self.receipt("cargo-no-run")

    def test_test_filter_and_alternate_binary_are_rejected_even_with_matching_receipt(self):
        stage = self.stage("test-33")
        stage["argv"].append("synthetic_001")
        self.receipt("test-33")
        with self.assertRaisesRegex(ValueError, "original stage"):
            self.validate()
        stage["argv"].pop()
        stage["argv"][0] = self.report["tests"][0]["path"]
        self.receipt("test-33")
        with self.assertRaisesRegex(ValueError, "original stage"):
            self.validate()

    def test_cwd_and_timeout_are_part_of_the_original_stage_identity(self):
        for key, value in (("cwd", "/different"), ("wall_limit_seconds", 999)):
            with self.subTest(field=key):
                previous = self.stage("cargo-no-run")[key]
                self.stage("cargo-no-run")[key] = value
                self.receipt("cargo-no-run")
                with self.assertRaisesRegex(ValueError, "original stage"):
                    self.validate()
                self.stage("cargo-no-run")[key] = previous
                self.receipt("cargo-no-run")

    def test_clippy_warning_gate_is_mandatory(self):
        self.stage("cargo-clippy")["argv"] = self.stage("cargo-clippy")["argv"][:-2]
        self.receipt("cargo-clippy")
        with self.assertRaisesRegex(ValueError, "original stage"):
            self.validate()

    def test_wrong_rust_host_is_rejected_after_self_consistent_raw_update(self):
        self.replace_stream("rustc-version", "stdout", b"release: 1.95.0\nhost: aarch64-unknown-linux-gnu\n")
        with self.assertRaisesRegex(ValueError, "compiler version or host"):
            self.validate()

    def test_inherited_build_runtime_overrides_and_cargo_config_are_rejected_before_output(self):
        original = q.ml_dsa_original
        variables = sorted(original.FORBIDDEN_ENVIRONMENT | {"CARGO_PROFILE_TEST_OVERFLOW_CHECKS",
                           "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER"})
        clean = {"CARGO_HOME": str(self.root / "empty-cargo")}
        original.check_environment(self.source, clean)
        for key in variables:
            with self.subTest(variable=key):
                with self.assertRaisesRegex(ValueError, "override: " + key):
                    original.check_environment(self.source, dict(clean, **{key: "unbound"}))
        location = self.source / "trillionnium/.cargo/config.toml"
        location.parent.mkdir(parents=True)
        location.write_text('[build]\nrustflags=["--cfg", "unbound"]\n')
        with self.assertRaisesRegex(ValueError, "Unbound Cargo configuration"):
            original.check_environment(self.source, clean)
        self.report["environment_guard"]["overrides"] = ["RUSTFLAGS"]
        with self.assertRaisesRegex(ValueError, "override policy"):
            self.validate()

    def test_original_profile_cannot_change_in_both_cargo_events_and_report(self):
        events = q.document((self.output / "artifacts.json").read_bytes())
        event = next(row for row in events if row["executable"])
        event["profile"]["overflow_checks"] = False
        self.report["tests"][0]["profile"]["overflow_checks"] = False
        write_json(self.output / "artifacts.json", events)
        self.replace_stream("cargo-no-run", "stdout", b"".join((json.dumps(row) + "\n").encode() for row in events))
        with self.assertRaisesRegex(ValueError, "compilation profile"):
            self.validate()

    def test_actual_provider_input_mutation_is_rejected(self):
        files = []
        for index in range(5):
            path = self.root / ("provider-" + str(index))
            raw = ("provider fixture " + str(index)).encode()
            path.write_bytes(raw)
            files.append({"path": str(path), "bytes": len(raw), "sha256": q.sha(raw)})
        provider = {"schema": "trnm-ci-pq-provider-v3", "version": "3.5.9", "exit_code": 0,
                    "last_stage": "complete", "source_digest_verified": True, "static_build": True,
                    "ml_dsa_65_sign_verify_and_wrong_message_rejection": True,
                    "source_archive_sha256_expected": "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a",
                    "preparation_script_sha256": self.inputs["scripts/ci/prepare_pq_provider.sh"],
                    "native_backend_inputs": files, "cli_executable": files[0]["path"], "cli_sha256": files[0]["sha256"]}
        q.validate_provider(provider)
        for item in files:
            path = Path(item["path"]); raw = path.read_bytes()
            path.write_bytes(raw + b" changed")
            with self.assertRaisesRegex(ValueError, "Changed actual provider input"):
                q.validate_provider(provider)
            path.write_bytes(raw)

    def test_original_no_run_event_must_bind_each_test_executable(self):
        self.report["tests"][0]["path"] = "/not-the-actual-test"
        for label in ("list-00", "test-00"):
            self.stage(label)["argv"][0] = "/not-the-actual-test"
            self.receipt(label)
        with self.assertRaisesRegex(ValueError, "test binary differs"):
            self.validate()

    def test_ignored_filtered_or_missing_tests_are_rejected(self):
        for raw in (b"test result: ok. 342 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;\n",
                    b"test result: ok. 342 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;\n",
                    b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"):
            self.replace_stream("test-33", "stdout", raw)
            with self.assertRaisesRegex(ValueError, "not fully executed"):
                self.validate()

    def test_original_adapter_source_and_library_are_bound(self):
        previous = self.report["reference"]["source_sha256"]
        self.report["reference"]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "adapter source"):
            self.validate()
        self.report["reference"]["source_sha256"] = previous
        (self.output / self.report["adapter_graph"][0]["retained"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "original library"):
            self.validate()

    def test_missing_original_source_and_changed_canonical_dependency_are_rejected(self):
        removed = self.report["source"].pop()
        with self.assertRaisesRegex(ValueError, "source roster"):
            self.validate()
        self.report["source"].append(removed)
        path = self.source / self.report["source"][0]["path"]
        path.write_bytes(path.read_bytes() + b" changed")
        with self.assertRaisesRegex(ValueError, "source differs"):
            self.validate()

    def test_cross_crate_includes_and_example_support_cannot_be_omitted(self):
        for name in q.ORIGINAL_ROOTS[-3:]:
            with self.subTest(source=name):
                row = next(item for item in self.report["source"] if item["path"] == name)
                self.report["source"].remove(row)
                with self.assertRaisesRegex(ValueError, "source roster"):
                    self.validate()
                self.report["source"].append(row)
                path = self.source / name; raw = path.read_bytes()
                path.write_bytes(raw + b" changed external input")
                with self.assertRaisesRegex(ValueError, "source differs"):
                    self.validate()
                path.write_bytes(raw)

    def test_receipt_mismatch_and_raw_mutation_are_rejected(self):
        path = self.output / "preflight.receipt.json"
        value = json.loads(path.read_text())
        value["seconds"] += 1
        write_json(path, value)
        with self.assertRaisesRegex(ValueError, "stage receipt differs"):
            self.validate()
        self.receipt("preflight")
        (self.output / "preflight.stdout.raw").write_bytes(b"mutation")
        with self.assertRaisesRegex(ValueError, "raw output"):
            self.validate()

    def test_traversal_and_symlink_inputs_are_rejected(self):
        for name in ("../report.json", "/tmp/report.json", "a/../b", "a\\b", "a//b"):
            with self.assertRaisesRegex(ValueError, "Noncanonical"):
                q.read(self.output, name)
        target = self.root / "outside"
        target.write_bytes(b"test")
        (self.output / "linked").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "Linked"):
            q.read(self.output, "linked")

    def test_failed_and_partial_native_reports_never_read_back_as_complete(self):
        for value in ({"schema": q.SCHEMA, "status": "FAIL"}, {"schema": q.SCHEMA, "status": "RUNNING"}, {}):
            write_json(self.output / "report.json", value)
            with self.assertRaisesRegex(ValueError, "Incomplete ML-DSA"):
                q.validate(self.output, source_inputs={})

    def test_readback_does_not_promote_foreign_alias_or_constant_time_scope(self):
        for key in q.LIMITS:
            limits = dict(q.LIMITS, **{key: True})
            write_json(self.output / "report.json", {"schema": q.SCHEMA, "status": "PASS", "limits": limits})
            with self.assertRaisesRegex(ValueError, "promoted"):
                q.validate(self.output, source_inputs={})

    def test_duplicate_json_keys_and_worker_literal_damage_are_visible(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            q.document(b'{"status":"FAIL","status":"PASS"}')
        import ast
        from hia.tests.test_ml_dsa import POINTER_WORKER
        values = [node.value for node in ast.walk(ast.parse(POINTER_WORKER)) if isinstance(node, ast.Constant) and isinstance(node.value, bytes)]
        self.assertTrue(values)
        self.assertTrue(all(len(value) == 1 for value in values))


if __name__ == "__main__":
    unittest.main()
