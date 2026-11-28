"""Standalone identity projection controls; no native process or binary fixtures."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hia.tools import settlement_image_identity as target
from hia.tools import settlement_companion as old


HEAD = "a" * 40
TREE = "b" * 40
ORIGIN = "/original/run/qualification"
SOURCE = "/original/source"
PIN = {"schema": "trnm-ci-source-v1", "kind": "head", "tested_commit": HEAD, "candidate": HEAD,
       "tested_tree": TREE, "tracked_worktree_verified": True, "tracked_entries": 8,
       "tracked_bytes": 100}


def ident(name):
    return old.identity(name.encode())


def process(*, passed=True, argv=None):
    return {"schema": "trnm.service-settlement.owned-process.v1", "status": "PASS" if passed else "FAIL",
            "started": True, "exit_code": 0 if passed else -15, "timed_out": not passed, "cleanup_complete": True,
            "execution_deadline_seconds": 240, "cleanup_deadline_seconds": 3,
            "original_deadline_monotonic_ns": 300_000_000_000, "argv": argv}


class Model:
    def __init__(self, root, runtime="pass"):
        self.root = root
        self.items = {}
        self.jsons = {}
        for name in old.PINS:
            self.write(name, target.canonical(PIN))
        compiler = {"bytes": 100, "sha256": target.COMPILER, "resolved_path": SOURCE + "/compiler"}
        linker = {**ident("ld"), "resolved_path": "/usr/bin/ld"}
        before = {n: {"snapshot": "tools/" + n, **row} for n, row in (("compiler", compiler), ("ld", linker))}
        self.ledger("build/tools/compiler", target.identity(compiler))
        self.ledger("build/tools/ld", target.identity(linker))
        source = {target.VERSION_MAP: ident("map")}
        self.ledger("build/public/source/" + target.VERSION_MAP, source[target.VERSION_MAP])
        toolchain = {"revision": target.HEPTA_REVISION, "target": "x86_64-linux-gnu"}
        self.units, self.modules, roster = {}, {}, {}
        for role in target.ALLOWED_UNITS:
            base = "build/units/" + role + "/"
            obj, image, wire = (ident(f"{role}/{v}") for v in ("object", "image", "wire"))
            for label, value in (("module.o", obj), ("module.so", image),
                                 ("native-compile/stdin.raw", wire), ("composed.hepta", ident(role + "/composed"))):
                self.ledger(base + label, value)
            compile_request = {"stdin": wire, "argv": ["/proc/self/fd/3"],
                               "pass_fds": [3], "environment": {"PATH": ""}}
            self.doc(base + "native-compile/request.json", compile_request)
            compile_receipt = {**compile_request, "exit_code": 0, "timed_out": False,
                               "exception": None, "stdout": obj, "stderr": old.identity(b"")}
            self.doc(base + "native-compile/receipt.json", compile_receipt)
            entry = "hia/src/" + role + ".hepta"
            roster[role] = entry
            self.doc(base + "build.json", {
                "schema": "trnm.hia.service-settlement-unit-build.v1", "role": role, "entry": entry,
                "status": "NATIVE_EMITTED_NOT_EXECUTED", "compiler_fallback_used": False,
                "source_unchanged": True, "toolchain": toolchain, "compiler_sha256": target.COMPILER,
                "tools": {"compiler": compiler}, "artifact": image, "object": obj, "stages": [compile_receipt],
                "compiler_wire_sha256": wire["sha256"]})
            binding = {"build": self.items[base + "build.json"], "object": obj}
            self.units[role] = {"directory": "units/" + role, "artifact": image, **binding}
            if role != "arithmetic":
                self.modules[role] = {"directory": ORIGIN + "/" + base.rstrip("/"), "image": image, **binding}
            if role in target.LINK_ROLES:
                self.modules[role]["renamed"] = ident(role + ".o")
                self.ledger("build/public/" + role + ".o", self.modules[role]["renamed"])
        emitted = ident("engine-owned.o")
        self.ledger("build/public/engine-owned.o", emitted)
        self.ledger("build/public/emitter-execution/engine-owned.o", emitted)
        public_base = ORIGIN + "/build/public/"
        receipt = {"exit_code": 0, "timed_out": False, "exception": None, "stdin": old.identity(b""),
                   "argv": [linker["resolved_path"], *target.LINK_PREFIX,
                            "--version-script=" + SOURCE + "/" + target.VERSION_MAP,
                            public_base + "engine-owned.o",
                            *(public_base + role + ".o" for role in target.LINK_ROLES),
                            "-lc", "-o", public_base + "settlement-engine.so"]}
        self.doc(target.LINK, receipt)
        self.elf = ident("some-system-generated-elf")
        self.ledger(target.ELF, self.elf)
        public = {"schema": "trnm.hia.service-settlement-public-build.v1",
                  "status": "PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", "source_unchanged": True,
                  "artifact": self.elf, "modules": self.modules, "source_inputs": source, "stages": [receipt],
                  "emitter_execution": {"status": 0, "object": emitted, "input": ident("prebound plan"),
                                        "actual_compiled_hia_execution": True, "authored_reference_used": False}}
        self.doc(target.PUBLIC, public)
        self.doc(target.BUILD, {
            "schema": "trnm.hia.service-settlement-engine-build.v1",
            "status": "EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED", "finalized": True,
            "source_unchanged": True, "changed_inputs": [], "compiler_fallback_used": False,
            "authored_reference_used": False, "actual_hia_ownership_emitter_executed": True,
            "source_inputs": source, "source_before": source, "source_after": source,
            "source_digest": old.identity(target.canonical(source))["sha256"],
            "units": self.units, "unit_roster": roster, "toolchain": toolchain,
            "compiler_qualification_binding": {"compiler_sha256": target.COMPILER,
                                               "toolchain_revision": target.HEPTA_REVISION},
            "tools_before": before, "tools_after": {"compiler": compiler, "ld": linker},
            "public": {"directory": "public", "status": public["status"], "build": self.items[target.PUBLIC]},
            "artifact": self.elf})
        self.doc(target.REPOSITORY, {"head": HEAD, "tree": TREE, "repository_clean": True})
        self.doc(target.BUILD_STAGE, process())
        self.ledger(target.CORPUS, {"bytes": 500, "sha256": target.CORPUS_SHA256})
        if runtime != "absent":
            passed = runtime == "pass"
            argv = ["/usr/bin/python3", "-B", "-m", "hia.platform.service_settlement.qualification.native",
                    "--build", public_base.rstrip("/"),
                    "--fee-build", ORIGIN + "/build/units/arithmetic", "--output", ORIGIN + "/native"]
            self.doc(target.NATIVE, process(passed=passed, argv=argv))
            rows = [{"phase": "stage_start", "wall_ns": 5, "thread_cpu_ns": 2}]
            if runtime != "early-timeout":
                first = {"wall_ns": 6, "thread_cpu_ns": 3, "capture_records": 0,
                         "public_dispatch_wall_ns": 0, "completed_fixtures": 0,
                         "completed_operations": 0, "fixture_ordinal": 1}
                rows.extend(({**first, "phase": "fixture_start"},
                             {**first, "phase": "operation_start", "operation_ordinal": 1,
                              "opcode": 2}))
                row = {"wall_ns": 10, "thread_cpu_ns": 6, "capture_records": 3, "public_dispatch_wall_ns": 4,
                       "completed_fixtures": 1, "completed_operations": 2}
                rows.append({**row, "phase": "stage_done" if passed else "fixture_done",
                             **({} if passed else {"fixture_ordinal": 1})})
            self.blob("native/fixture-progress.jsonl", b"".join(target.canonical(r) + b"\n" for r in rows))
            if passed:
                self.doc(target.REPORT, {"public_owned_api_tested": True, "whole_engine_or_store_closed": False,
                         "status": "PASS", "image": self.elf, "build": self.items[target.PUBLIC],
                         "source_inputs": source, "complete_fixture_bytes_equal": True,
                         "fixtures": 1, "fixture_operations": 2, "live_owners": 0})
        self.final()

    def ledger(self, path, value):
        self.items[path] = value

    def doc(self, path, value):
        self.jsons[path] = value
        return self.blob(path, target.canonical(value))

    def blob(self, path, raw):
        self.ledger(path, old.identity(raw))
        return self.write("qualification/" + path, raw)

    def write(self, path, raw):
        f = self.root / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(raw)
        return f

    def final(self):
        return self.write(target.EVIDENCE, target.canonical({
            "schema": "trnm.hia.service-settlement-engine.evidence.v1",
            "origin": ORIGIN, "source_root": SOURCE, "files": self.items}))


class CompanionIdentity(unittest.TestCase):
    @contextmanager
    def model(self, runtime="pass"):
        with tempfile.TemporaryDirectory(prefix="settlement-image-control-") as root:
            yield Model(Path(root), runtime)

    def view(self, model, source_after="success"):
        return target.export(str(model.root), HEAD, "431", "1", source_after)

    def test_pass_and_timeout_distinct_identity_no_binaries(self):
        for runtime, want in (("pass", "completed-runtime-report-bound"),
                              ("timeout", "checked-path-dispatch-observed"),
                              ("early-timeout", "public-dispatch-not-observed"),
                              ("absent", "missing")):
            with self.subTest(runtime=runtime), self.model(runtime) as m:
                result = self.view(m)
                self.assertFalse(result["qualifies_execution"])
                self.assertFalse(result["substitutes_full_original_archive"])
                self.assertEqual(result["linked"]["image"], m.elf)
                self.assertFalse(result["linked"]["binary_rehashed_by_companion"])
                self.assertEqual(result["runtime"]["availability"], want)
                self.assertFalse((m.root / "qualification" / target.ELF).exists())
                if runtime in ("pass", "timeout"):
                    self.assertFalse(result["runtime"]["kernel_mapping_independently_verified"])
                    self.assertEqual(result["runtime"]["existing_fixture_corpus"]["sha256"],
                                     target.CORPUS_SHA256)
                if runtime == "timeout":
                    self.assertTrue(result["runtime"]["timed_out"])
                    self.assertEqual(result["runtime"]["final_report"], "missing")
                self.assertNotIn(ORIGIN, str(result))

    def test_refuses_stale_source_and_inventory_disagreement(self):
        with self.model() as m:
            self.assertEqual(self.view(m, "failure")["linked"], {"availability": "source-unbound"})
            m.doc(target.REPOSITORY, {"head": HEAD, "tree": "c" * 40, "repository_clean": True})
            m.final()
            self.assertEqual(self.view(m)["linked"], {"availability": "source-unbound"})
        for substitution in (target.ELF, "build/tools/compiler", "build/units/control/native-compile/stdin.raw",
                             "build/public/control.o", target.PUBLIC, target.LINK):
            with self.subTest(substitution=substitution), self.model() as m:
                m.ledger(substitution, ident("not actual"))
                m.final()
                self.assertEqual(self.view(m)["linked"], {"availability": "identity-mismatch"})

    def test_partial_terminal_report_and_path_switch_cannot_upgrade_runtime(self):
        with self.model() as m:
            r = m.jsons[target.REPORT]
            r["image"] = ident("other ELF")
            m.doc(target.REPORT, r)
            m.final()
            self.assertEqual(self.view(m)["runtime"], {"availability": "identity-mismatch"})
        with self.model() as m:
            m.ledger(target.CORPUS, ident("unexpected fixture corpus"))
            m.final()
            self.assertEqual(self.view(m)["runtime"], {"availability": "identity-mismatch"})

    def test_optional_original_run_binding_is_checked_when_present(self):
        with self.model() as m:
            b = {"schema": "trnm.hia.additional-owner-ci-binding.v1", "component": "settlement-engine",
                 "head": HEAD, "tree": TREE, "run_id": "431", "run_attempt": "1", "status": "PASS",
                 "source_set_sha256": "c" * 64}
            raw = target.canonical(b)
            m.write(old.BINDING, raw)
            self.assertEqual(self.view(m)["workflow"]["original_binding"], old.identity(raw))
            b["run_attempt"] = "2"
            m.write(old.BINDING, target.canonical(b))
            self.assertEqual(self.view(m)["linked"], {"availability": "run-unbound"})

    def test_rejects_changed_runtime_argv_and_torn_terminal_cursor(self):
        with self.model() as m:
            r = m.jsons[target.NATIVE]
            r["argv"][5] += "-other"
            m.doc(target.NATIVE, r)
            m.final()
            self.assertEqual(self.view(m)["runtime"], {"availability": "identity-mismatch"})
        with self.model() as m:
            cursor = m.root / old.CURSOR
            m.blob("native/fixture-progress.jsonl", cursor.read_bytes() + b"{")
            m.final()
            self.assertEqual(self.view(m)["runtime"], {"availability": "identity-mismatch"})

    def test_exact_link_order_and_compiler_unit_manifest(self):
        with self.model() as m:
            r = m.jsons[target.LINK]
            r["argv"][14], r["argv"][15] = r["argv"][15], r["argv"][14]
            m.doc(target.LINK, r)
            public = m.jsons[target.PUBLIC]
            public["stages"] = [r]
            m.doc(target.PUBLIC, public)
            build = m.jsons[target.BUILD]
            build["public"]["build"] = m.items[target.PUBLIC]
            m.doc(target.BUILD, build)
            m.final()
            self.assertEqual(self.view(m)["linked"], {"availability": "identity-mismatch"})

    def test_unsafe_unreadable_inputs_do_not_disclose_paths(self):
        for case in ("symlink", "hardlink", "duplicate-key", "oversize"):
            with self.subTest(case=case), self.model() as m:
                f = m.root / target.EVIDENCE
                expected = {"symlink": "unsafe-path", "hardlink": "unsafe-path",
                            "duplicate-key": "invalid-json", "oversize": "over-byte-limit"}[case]
                if case == "duplicate-key":
                    f.write_bytes(b'{"files": {}, "files": {}}')
                elif case == "oversize":
                    with f.open("wb") as stream:
                        stream.truncate(target.MAX_MANIFEST + 1)
                else:
                    other = m.root / "hidden-sensitive-name"
                    f.rename(other)
                    (f.symlink_to(other) if case == "symlink" else os.link(other, f))
                result = self.view(m)
                self.assertEqual(result["linked"], {"availability": expected})
                self.assertNotIn("hidden-sensitive-name", str(result))

    def test_cli_separate_output_and_old_v1_bytes_unchanged(self):
        with self.model("timeout") as m:
            ignored = m.root / "sidecar"
            ignored.mkdir()
            original = old.export(str(m.root), HEAD, "431", "1", ("failure", "success", "skipped"), "failure")
            route = [sys.executable, "-B", "-m", "hia.tools.settlement_image_identity", "--root", str(m.root),
                     "--head", HEAD, "--run-id", "431", "--run-attempt", "1",
                     "--source-after-outcome", "success", "--output-dir", str(ignored)]
            subprocess.run(route, check=True, capture_output=True, timeout=10)
            f = ignored / "image-identity.json"
            self.assertEqual([p.name for p in ignored.iterdir()], [f.name])
            self.assertEqual(json.loads(f.read_bytes()), self.view(m))
            self.assertLess(len(f.read_bytes()), target.MAX_OUTPUT)
            initial = hashlib.sha256(target.canonical(original)).hexdigest()
            after = old.export(str(m.root), HEAD, "431", "1", ("failure", "success", "skipped"), "failure")
            self.assertEqual(hashlib.sha256(target.canonical(after)).hexdigest(), initial)
            self.assertNotEqual(subprocess.run(route, capture_output=True, timeout=10).returncode, 0)


if __name__ == "__main__":
    unittest.main()
