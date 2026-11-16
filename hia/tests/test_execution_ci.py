"""Adversarial evidence boundaries; these fixtures confer no runtime qualification."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import socket
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hia.tools import qualify_execution_ci as gate


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


class ExecutionEvidenceBoundaries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="execution-ci-boundary-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = {
            "TRNM_EXPECTED_SOURCE_SHA": "a" * 40, "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2", "RUNNER_TEMP": str(self.root)}
        environment = patch.dict(os.environ, self.environment)
        environment.start()
        self.addCleanup(environment.stop)

    def parent(self):
        source = {"tested_commit": "a" * 40, "candidate": "a" * 40, "tested_tree": "b" * 40,
                  "kind": "head", "tracked_worktree_verified": True, "tracked_entries": 7}
        return {"schema": gate.SCHEMA, "stage": "prepare-semantic", "status": "PASS",
                "lineage": gate.lineage(), "native_cases": 723, "native_processes": 1,
                "original_rust": "NOT_RUN", "whole_node_or_commit_authority": False,
                "batch_execution_qualified": False,
                "source_observations": {"before": source, "after": copy.deepcopy(source)}}

    def test_predecessor_requires_complete_same_source_run_attempt_and_finite_scope(self):
        parent = self.parent()
        gate.check_parent(parent, gate.lineage())
        mutations = [
            lambda v: v.update(schema=gate.base.SCHEMA),
            lambda v: v.update(stage="prepare-physical"),
            lambda v: v.update(status="FAIL"),
            lambda v: v["lineage"].update(git_head="c" * 40),
            lambda v: v["lineage"].update(run_id="124"),
            lambda v: v["lineage"].update(attempt=1),
            lambda v: v["lineage"].update(attempt=True),
            lambda v: v.update(native_cases=722),
            lambda v: v.update(native_cases=True),
            lambda v: v.update(native_processes=2),
            lambda v: v.update(native_processes=True),
            lambda v: v.update(original_rust="PASS"),
            lambda v: v.update(whole_node_or_commit_authority=True),
            lambda v: v.update(batch_execution_qualified=True),
            lambda v: v["source_observations"].pop("after"),
            lambda v: v["source_observations"]["after"].update(tracked_worktree_verified=False),
            lambda v: v["source_observations"]["after"].update(tested_tree="d" * 40),
            lambda v: v["source_observations"]["after"].update(tracked_entries=8),
            lambda v: v["source_observations"]["before"].update(candidate="e" * 40),
            lambda v: v["source_observations"]["before"].update(kind="merge"),
            lambda v: v["source_observations"]["before"].update(tracked_entries=True),
        ]
        for index, change in enumerate(mutations):
            value = copy.deepcopy(parent)
            change(value)
            with self.subTest(control=index), self.assertRaises(ValueError):
                gate.check_parent(value, gate.lineage())

    def test_named_test_output_must_show_actual_nonignored_exact_execution(self):
        name = "pon_executor::private_observer::evaluate"
        valid = ("running 1 test\n"
                 "test " + name + " ... OBSERVATION:{\"actual\":1}\n"
                 "ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out\n").encode()
        gate.positive_test(valid, name)
        for raw in (b"", valid.replace(name.encode(), b"other::test"),
                    valid.replace(b"running 1 test", b"running 0 tests"),
                    valid.replace(b"1 passed; 0 failed; 0 ignored", b"0 passed; 0 failed; 1 ignored"),
                    valid.replace(b"test result: ok.", b"test result: FAILED."),
                    valid.replace(b"1 passed; 0 failed; 0 ignored", b"1 passed; 1 failed; 0 ignored"),
                    valid.replace(b"test " + name.encode(), b"not-test " + name.encode())):
            with self.subTest(raw=raw[:64]), self.assertRaises(ValueError):
                gate.positive_test(raw, name)

    def stage(self, name="actual-original"):
        directory = self.root / "original"
        path = directory / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "stdout.raw").write_bytes(b"complete actual output\n")
        (path / "stderr.raw").write_bytes(b"")
        receipt = {"stage": name, "argv": ["/retained/actual-test", "--exact", "a::test"],
                   "cwd": "/isolated/original", "wall_limit_seconds": 240, "cleanup_limit_seconds": 10,
                   "started_monotonic_ns": 1000, "finished_monotonic_ns": 1100, "elapsed_ns": 100,
                   "pid": 123, "exit_code": 0, "timed_out": False, "launch_error": None,
                   "cleanup_error": None, "output_files_closed": True, "status": "PASS",
                   "stdout": gate.identity(path / "stdout.raw"), "stderr": gate.identity(path / "stderr.raw")}
        put(path / "receipt.json", receipt)
        return directory, receipt

    def test_original_stage_rechecks_raw_bytes_and_independent_receipt(self):
        directory, receipt = self.stage()
        report = {"stages": [receipt]}
        gate.original_stages(directory, report, ("actual-original",))
        for name in ("stdout", "stderr"):
            file = directory / "actual-original" / (name + ".raw")
            original = file.read_bytes()
            file.write_bytes(original + b"tampered")
            with self.subTest(channel=name), self.assertRaises(ValueError):
                gate.original_stages(directory, report, ("actual-original",))
            file.write_bytes(original)
        changed = dict(receipt, pid=124)
        put(directory / "actual-original/receipt.json", changed)
        with self.assertRaises(ValueError):
            gate.original_stages(directory, report, ("actual-original",))

    def test_failed_unsettled_missing_reordered_or_repeated_original_stages_are_refused(self):
        directory, receipt = self.stage()
        for key, value in (("status", "FAIL"), ("exit_code", 1), ("exit_code", False),
                           ("timed_out", True), ("launch_error", "exec failed"),
                           ("cleanup_error", "unreaped child"), ("output_files_closed", False),
                           ("cleanup_limit_seconds", 0), ("elapsed_ns", 0), ("elapsed_ns", 99)):
            changed = dict(receipt)
            changed[key] = value
            put(directory / "actual-original/receipt.json", changed)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                gate.original_stages(directory, {"stages": [changed]}, ("actual-original",))
        put(directory / "actual-original/receipt.json", receipt)
        for stages in ([], [receipt, receipt], [dict(receipt, stage="another-original")]):
            with self.subTest(stage_count=len(stages)), self.assertRaises(ValueError):
                gate.original_stages(directory, {"stages": stages}, ("actual-original",))

    def test_composition_uses_exact_owned_function_bytes_without_reexport_or_implicit_repair(self):
        hia = self.root / "hia"
        (hia / "src").mkdir(parents=True)
        owner = b"module owner\nfn entry() -> u32\n  ret 1\nend\n"
        dependency = b"module dep\nfn selected() -> u32\n  ret 2\nend\nfn other() -> u32\n  ret 3\nend\n"
        helper = b"module helper\nfn nested() -> u32\n  ret 4\nend\n"
        (hia / "src/owner.hepta").write_bytes(owner)
        (hia / "src/dep.hepta").write_bytes(dependency)
        (hia / "src/helper.hepta").write_bytes(helper)
        manifest = {"schema": "trnm.hia.component-includes.v1", "includes": {
            "src/owner.hepta": [{"source": "src/dep.hepta", "functions": ["selected"]}],
            "src/dep.hepta": [{"source": "src/helper.hepta", "functions": ["nested"]}]}}
        put(hia / "components.json", manifest)
        self.assertEqual(gate.composed_bytes(self.root, "src/owner.hepta"),
                         owner + b"fn selected() -> u32\n  ret 2\nend\n")
        for selected in ("nested", "missing", "entry"):
            value = copy.deepcopy(manifest)
            value["includes"]["src/owner.hepta"][0]["functions"] = [selected]
            put(hia / "components.json", value)
            with self.subTest(function=selected), self.assertRaises(ValueError):
                gate.composed_bytes(self.root, "src/owner.hepta")
        value = copy.deepcopy(manifest)
        value["includes"]["src/helper.hepta"] = [{"source": "src/owner.hepta", "functions": ["entry"]}]
        put(hia / "components.json", value)
        with self.assertRaises(ValueError):
            gate.composed_bytes(self.root, "src/owner.hepta")
        put(hia / "components.json", manifest)
        (hia / "src/dep.hepta").write_bytes(dependency + b"fn selected() -> u32\n  ret 9\nend\n")
        with self.assertRaises(ValueError):
            gate.composed_bytes(self.root, "src/owner.hepta")

    def test_pack_preserves_failed_original_raw_binary_and_metadata_without_false_qualification(self):
        original = self.root / "hia-prepare-original"
        original.mkdir()
        binary = b"\x7fELFcomplete-independent-original-test-fixture"
        (original / "original-m06-tests").write_bytes(binary)
        put(original / "report.json", {"status": "FAIL", "primary_error": "retained actual failure"})
        (original / "actual-stdout.raw").write_bytes(b"failure remains failure")
        (original / "isolated").mkdir()
        (original / "isolated/reconstructible.rs").write_text("source")
        (original / "source-capture").mkdir()
        (original / "source-capture/original.rs").write_text("exact independently retained source")
        os.mkfifo(original / "never-open-fifo")
        (original / "never-follow-link").symlink_to(original / "original-m06-tests")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind(str(original / "never-open-socket"))
        gate.pack("prepare-original", self.root)
        artifact = self.root / "hia-prepare-artifact"
        record = gate.read(artifact / "package-manifest.json")
        self.assertEqual(record["packing_status"], "PASS")
        self.assertNotIn("binding", record)
        self.assertTrue(record["qualification_status_not_changed_by_packaging"])
        self.assertIn("original/original-m06-tests", record["entries"])
        self.assertIn("original/source-capture/original.rs", record["entries"])
        self.assertFalse(any("/isolated/" in name for name in record["entries"]))
        self.assertEqual(record["special_entries"]["original/never-open-fifo"]["type"], "fifo")
        self.assertTrue(all(row["opened"] is False for row in record["special_entries"].values()))
        with tarfile.open(artifact / "complete-evidence.tar.xz") as archive:
            self.assertEqual(archive.extractfile("original/original-m06-tests").read(), binary)
            self.assertEqual(json.loads(archive.extractfile("original/report.json").read())["status"], "FAIL")
            self.assertNotIn("original/never-open-fifo", archive.getnames())

    def test_independent_capture_refuses_changed_source_and_existing_destination(self):
        source, target = self.root / "raw", self.root / "retained"
        source.write_bytes(b"original bytes")
        expected = gate.identity(source)
        source.write_bytes(b"changed bytes")
        with self.assertRaises(ValueError):
            gate.captured_file(source, target, expected)
        self.assertFalse(target.exists())
        source.write_bytes(b"original bytes")
        gate.captured_file(source, target, expected)
        self.assertEqual(target.read_bytes(), b"original bytes")
        with self.assertRaises(FileExistsError):
            gate.captured_file(source, target, expected)

    def test_original_hook_requires_exact_unmodified_production_prefix_and_captured_fixtures(self):
        oracle = SimpleNamespace(OWNED="hia/platform/execution_state",
            STORE="trillionnium/crates/example/src/original.rs", HOOK="observer.rs",
            DECLARATION=b"\n#[cfg(test)] mod observer;\n")
        production, hook = b"pub fn production() {}\n", b"#[test] fn observe() {}\n"
        source = self.root / "repository"
        original = self.root / "execution"
        for root in (source, original / "isolated-source"):
            path = root / oracle.STORE
            path.parent.mkdir(parents=True)
            path.write_bytes(production if root == source else production + oracle.DECLARATION)
            (root / "trillionnium/Cargo.lock").write_bytes(b"locked fixture")
            fixture = root / "tests/vector.json"
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes(b'{"actual":"fixture"}')
        path = source / oracle.OWNED / "rust_reference.rs"
        path.parent.mkdir(parents=True)
        path.write_bytes(hook)
        hook_path = original / "isolated-source" / Path(oracle.STORE).parent / oracle.HOOK
        hook_path.write_bytes(hook)
        originals = {"trillionnium/Cargo.lock": gate.identity(source / "trillionnium/Cargo.lock"),
                     "tests/vector.json": gate.identity(source / "tests/vector.json")}
        gate.original_adaptation(original, source, oracle, originals, capture=True)
        self.assertEqual((original / "source-capture" / oracle.STORE).read_bytes(),
                         production + oracle.DECLARATION)
        self.assertEqual((original / "source-capture/tests/vector.json").read_bytes(),
                         b'{"actual":"fixture"}')
        (original / "isolated-source" / oracle.STORE).write_bytes(b"changed" + oracle.DECLARATION)
        with self.assertRaises(ValueError):
            gate.original_adaptation(original, source, oracle, originals, capture=False)

    def test_foreign_or_failed_download_is_refused_before_unpack_or_source_execution(self):
        download = self.root / "hia-prepare-download"
        download.mkdir()
        package = {"schema": gate.PACKAGE, "stage": "prepare-semantic", "lineage": gate.lineage(),
                   "packing_status": "PASS", "qualification_status_not_changed_by_packaging": True}
        mutations = (
            lambda v: v.update(schema="foreign"),
            lambda v: v.update(stage="prepare-physical"),
            lambda v: v.update(packing_status="FAIL"),
            lambda v: v.update(qualification_status_not_changed_by_packaging=False),
            lambda v: v["lineage"].update(git_head="d" * 40),
            lambda v: v["lineage"].update(run_id="124"),
            lambda v: v["lineage"].update(attempt=3),
        )
        for index, change in enumerate(mutations):
            value = copy.deepcopy(package)
            change(value)
            put(download / "package-manifest.json", value)
            with self.subTest(index=index), patch.object(gate.base, "check_source_observation",
                    return_value=self.parent()["source_observations"]["before"]), self.assertRaises(ValueError):
                gate.unpack(self.root)
            self.assertFalse((self.root / "hia-prepare-prior").exists())

    def test_compiler_binding_rejects_wrong_tool_bytes_paths_versions_and_cargo_commands(self):
        sysroot = self.root / "rust-toolchain"
        (sysroot / "bin").mkdir(parents=True)
        tools = {}
        for name in ("rustc", "cargo", "rustdoc"):
            path = sysroot / "bin" / name
            path.write_bytes(("independent tool identity fixture: " + name).encode())
            tools[name] = {"path": str(path), **gate.identity(path)}
        version = "rustc independent-test-fixture\nhost: x86_64-unknown-linux-gnu\n"
        directory = self.root / "original"
        directory.mkdir()
        target = self.root / "cargo-target"
        for component in ("state", "prepare"):
            isolated = directory / ("isolated-source" if component == "state" else "isolated")
            isolated.mkdir(exist_ok=True)
            manifest = str(isolated / "trillionnium/Cargo.toml")
            selected = "rustc" if component == "state" else tools["rustc"]["path"]
            bound = "rustc-selected-version" if component == "state" else "rustc-bound-version"
            def row(argv, raw=b""):
                return ({"argv": argv, "cwd": str(isolated), "stderr": gate.bytes_id(b"")}, raw)
            rows = {"rustc-version": row([selected, "-Vv"], version.encode()),
                    "rustc-sysroot": row([selected, "--print", "sysroot"], (str(sysroot) + "\n").encode()),
                    bound: row([tools["rustc"]["path"], "-Vv"], version.encode())}
            if component == "state":
                rows["cargo-original-metadata"] = row([tools["cargo"]["path"], "metadata", "--locked",
                    "--format-version=1", "--filter-platform", "x86_64-unknown-linux-gnu",
                    "--manifest-path", manifest])
                rows["cargo-original-test-build"] = row([tools["cargo"]["path"], "test", "--locked",
                    "--manifest-path", manifest, "-p", "trnm-mvcc-fee", "--lib", "--no-run",
                    "--message-format=json", "--target-dir", str(target)])
                report = {"actual_rust_tools": copy.deepcopy(tools), "compiler": version,
                          "source_fences": [{"observations": {"actual_rust_tools":
                              {"status": "MATCH", "tools": copy.deepcopy(tools)}}} for _ in range(2)]}
            else:
                rows["cargo-metadata"] = row([tools["cargo"]["path"], "metadata", "--locked",
                    "--format-version", "1", "--manifest-path", manifest])
                rows["cargo-original-test-build"] = row([tools["cargo"]["path"], "test", "--locked",
                    "--manifest-path", manifest, "-p", "trnm-mvcc-fee", "--lib", "--no-run",
                    "--message-format=json"])
                report = {"original_toolchain": {
                    "schema": "trnm.hia.prepare-original-toolchain.v1", "selected_rustc": selected,
                    "sysroot": str(sysroot), "rustc_version": version,
                    "compiler_executable": copy.deepcopy(tools["rustc"]),
                    "cargo_executable": copy.deepcopy(tools["cargo"])},
                    "serde_json_artifact": {"files": {"libserde.rlib":
                        {"path": str(target / "debug/deps/libserde.rlib")}}}}
                put(directory / "original-toolchain-before.json", report["original_toolchain"])
            gate.original_tools(directory, report, rows, component, target)
            mutations = [
                lambda r, s: s["rustc-version"][0].update(argv=["alternate-rustc", "-Vv"]),
                lambda r, s: s[bound][0].update(argv=["rustc", "-Vv"]),
                lambda r, s: s["rustc-version"][0]["stderr"].update(bytes=1),
                lambda r, s: s["cargo-original-test-build"][0]["argv"].remove("--locked"),
                lambda r, s: s["cargo-original-test-build"][0].update(cwd=str(self.root)),
                lambda r, s: s.update({bound: (s[bound][0], b"different actual compiler version\n")}),
                lambda r, s: s.update({"rustc-sysroot": (s["rustc-sysroot"][0], b"relative-sysroot\n")}),
            ]
            if component == "state":
                mutations += [
                    lambda r, s: r["actual_rust_tools"].pop("rustdoc"),
                    lambda r, s: r["source_fences"][-1]["observations"]["actual_rust_tools"].update(status="FAIL"),
                    lambda r, s: s["cargo-original-test-build"][0]["argv"].__setitem__(-1, str(self.root / "other-target")),
                ]
            else:
                mutations += [
                    lambda r, s: r["original_toolchain"].update(selected_rustc="relative-rustc"),
                    lambda r, s: r["serde_json_artifact"]["files"]["libserde.rlib"].update(path=str(self.root / "foreign.rlib")),
                ]
            for index, change in enumerate(mutations):
                altered, stages = copy.deepcopy(report), copy.deepcopy(rows)
                change(altered, stages)
                if component == "prepare":
                    put(directory / "original-toolchain-before.json", altered["original_toolchain"])
                with self.subTest(component=component, mutation=index), self.assertRaises(ValueError):
                    gate.original_tools(directory, altered, stages, component, target)
            if component == "prepare":
                put(directory / "original-toolchain-before.json", report["original_toolchain"])
            compiler = Path(tools["rustc"]["path"])
            old = compiler.read_bytes()
            compiler.write_bytes(old + b"changed")
            with self.subTest(component=component, mutation="actual-tool-changed"), self.assertRaises(ValueError):
                gate.original_tools(directory, report, rows, component, target)
            compiler.write_bytes(old)

    def test_private_journal_requires_complete_immutable_calls_and_explicit_counter_fixture(self):
        # These synthetic admission fixtures never claim native execution.
        zero = bytes(65536)
        raw = b"complete input fixture"
        def start(index, heap, capacity=64):
            return {"kind": "native-call-start", "index": index,
                    "input_hex": raw.hex(), "input": gate.bytes_id(raw),
                    "heap_before_hex": heap.hex(), "heap_before": gate.bytes_id(heap),
                    "output_capacity": capacity, "heap_capacity": 65536,
                    "output_before_hex": (b"[" * capacity).hex()}
        def complete(begin, heap, status=2, output=None):
            result = {**begin, "kind": "native-call-complete", "return": status,
                      "input_after_hex": begin["input_hex"], "heap_after_hex": heap.hex(),
                      "heap_after": gate.bytes_id(heap)}
            output = b"[" * begin["output_capacity"] if output is None else output
            result.update(output_hex=output.hex(), output=gate.bytes_id(output))
            return result
        journal = self.root / "private-journal.jsonl"
        def check(records, count, counter):
            journal.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in records))
            return gate.private_journal(journal, count, counter)
        first = start(1, zero, 63)
        rejected = [first, complete(first, zero, 6)]
        self.assertEqual(check(rejected, 1, None)["completed_native_calls"], 1)
        mutations = [
            lambda r: r[0].update(index=True),
            lambda r: r[1].update(index=2),
            lambda r: r[1].update(input_after_hex=b"changed input".hex()),
            lambda r: r[1].update(output_hex=(b"!" + b"[" * 62).hex(),
                                   output=gate.bytes_id(b"!" + b"[" * 62)),
            lambda r: r[1].update(heap_after_hex=(b"!" + zero[1:]).hex(),
                                   heap_after=gate.bytes_id(b"!" + zero[1:])),
            lambda r: r.pop(),
            lambda r: r.reverse(),
            lambda r: r.append(copy.deepcopy(r[-1])),
            lambda r: r[0].update(kind="declared-but-not-observed"),
        ]
        for index, change in enumerate(mutations):
            records = copy.deepcopy(rejected)
            change(records)
            with self.subTest(kind="call", mutation=index), self.assertRaises(ValueError):
                check(records, 1, None)
        counter = 64
        injected = b"\xff" * 8
        mutated = zero[:counter] + injected + zero[counter + 8:]
        first = start(1, zero)
        fixture = {"kind": "private-fixture-counter-write", "offset": counter,
                   "native_calls_before": 1, "production_input": False,
                   "heap_before_hex": zero.hex(), "heap_after_hex": mutated.hex(),
                   "bytes_hex": injected.hex()}
        second = start(2, mutated)
        sequence = [first, complete(first, zero), fixture, second, complete(second, mutated)]
        self.assertEqual(check(sequence, 2, counter)["private_fixture_writes"], 1)
        mutations = [
            lambda r: r[2].update(production_input=True),
            lambda r: r[2].update(offset=48),
            lambda r: r[2].update(bytes_hex=(b"\xfe" * 8).hex()),
            lambda r: r[2].update(native_calls_before=0),
            lambda r: r[2].update(heap_after_hex=(b"!" + mutated[1:]).hex()),
            lambda r: r[3].update(heap_before_hex=zero.hex(), heap_before=gate.bytes_id(zero)),
            lambda r: r.insert(3, copy.deepcopy(r[2])),
        ]
        for index, change in enumerate(mutations):
            records = copy.deepcopy(sequence)
            change(records)
            with self.subTest(kind="fixture", mutation=index), self.assertRaises(ValueError):
                check(records, 2, counter)
        with self.assertRaises(ValueError):
            check(sequence, 2, None)
        response = b"SVPR0001" + bytes(56) + b"[" * (512 - 64)
        first = start(1, zero, 512)
        answered = [first, complete(first, zero, 1, response)]
        self.assertEqual(check(answered, 1, None)["completed_native_calls"], 1)
        for output in (b"WRONG001" + response[8:], response[:-1] + b"!"):
            records = [first, complete(first, zero, 1, output)]
            with self.subTest(kind="response", output_tail=output[-1:]), self.assertRaises(ValueError):
                check(records, 1, None)


if __name__ == "__main__":
    unittest.main()
