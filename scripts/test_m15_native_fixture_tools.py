#!/usr/bin/env python3
"""Pure Python mechanism controls for the additional M15 native harness.

Synthetic ELF/JSON inputs below are never executed and are not Node, signed
service, namespace, native-test or deployment qualification. Real kernel
isolation and the complete actual Rust consumer remain separate gates.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


isolated = module("m15_isolated_native_support")
setup = module("m15_isolated_native_setup")
runner = module("m15_isolated_native_run")
support = isolated.support


def synthetic_elf(needed=(), soname=None, interpreter=None, forbidden=None):
    raw = bytearray(2048)
    raw[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    count = 2 + (interpreter is not None)
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    strings, offsets = bytearray(b"\0"), {}
    for name in [*needed, *([] if soname is None else [soname])]:
        if name not in offsets:
            offsets[name] = len(strings)
            strings.extend(name.encode("ascii") + b"\0")
    raw[512:512 + len(strings)] = strings
    tags = [(5, 0x400000 + 512), (10, len(strings))]
    tags.extend((1, offsets[name]) for name in needed)
    if soname is not None:
        tags.append((14, offsets[soname]))
    if forbidden is not None:
        tags.append((forbidden, 0))
    tags.append((0, 0))
    for index, entry in enumerate(tags):
        struct.pack_into("<qQ", raw, 256 + index * 16, *entry)
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 4, 0, 0x400000, 0x400000, len(raw), len(raw), 4096)
    size = len(tags) * 16
    struct.pack_into("<IIQQQQQQ", raw, 120, 2, 4, 256, 0x400100, 0x400100, size, size, 8)
    if interpreter is not None:
        value = interpreter.encode("ascii") + b"\0"
        raw[1024:1024 + len(value)] = value
        struct.pack_into("<IIQQQQQQ", raw, 176, 3, 4, 1024, 0x400400, 0x400400, len(value), len(value), 1)
    return bytes(raw)


def synthetic_reports(root):
    consumer = {"schema": "trnm-m15-real-isolated-consumer-result-v1", "actual_pid": 17,
        "node_program_sha256": "11" * 32, "attempt": "22" * 32, "observed_controller_frames": 3,
        "original_maximum_steps": 32, "original_wall_seconds": 180, "service_rpc_seconds": 2,
        "fixture_principals": [1000, 1001], "same_fd_static_exec": True, "single_claim": True,
        "actual_refresh": True, "copied_claim_refused": True, "catalog_next_launch_refused": True,
        "revoked_frame_not_recorded": True, "production_qualified": False,
        "independent_deployment_qualified": False}
    namespace = {"schema": "trnm-m15-isolated-native-namespace-result-v1", "exit_code": 0,
        "failure": None, "unexpected_owned_process_group": False,
        "retained_state": {"entries": 1, "regular_bytes": 1}, "state_error": None,
        "original_case_seconds": 180, "original_steps": 32, "service_rpc_seconds": 2,
        "independent_deployment_qualified": False}
    clocks = [{"uid": uid, "request": "33" * 32, "challenge": ("44" if uid == 1000 else "55") * 32,
               "signed_seconds": 10000} for uid in (1000, 1001)]
    (root / "native.stdout").write_text(
        "running 1 test\n" + "test " + isolated.CASE + " ... ok\n\n"
        + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s\n")
    for name, value in (("consumer-result.json", consumer), ("namespace-result.json", namespace),
                        ("clock-observations.json", clocks)):
        (root / name).write_bytes(support.canonical(value))
    return {"node": {"sha256": "11" * 32}}, consumer, namespace, clocks


@unittest.skipUnless(sys.platform == "linux", "Linux-only harness mechanisms")
class HarnessMechanismTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
    def tearDown(self):
        self.temporary.cleanup()
    def file(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        return path

    def test_json_digest_and_duplicate_keys_are_rejected(self):
        path = self.file("input.json", b'{"value":1}\n')
        value, _ = isolated.json_input(path, support.sha(path.read_bytes()))
        self.assertEqual(value, {"value": 1})
        with self.assertRaises(ValueError):
            isolated.json_input(path, "00" * 32)
        raw = b'{"value":1,"value":2}\n'
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            isolated.json_input(path, support.sha(raw))

    def test_helper_elf_reports_exact_dependency_and_interpreter(self):
        path = self.file("helper", synthetic_elf(("libc.so.6",), "helper.so", "/lib64/ld-linux-x86-64.so.2"))
        self.assertEqual(isolated.elf_dependencies(path), {"needed": ["libc.so.6"],
            "soname": "helper.so", "interpreter": "/lib64/ld-linux-x86-64.so.2"})

    def test_helper_elf_refuses_loader_search_and_ambiguous_names(self):
        for raw in (synthetic_elf(("libc.so.6",), forbidden=15),
                    synthetic_elf(("libc.so.6",), forbidden=29),
                    synthetic_elf(("../unexpected.so",)), synthetic_elf(("libc.so.6", "libc.so.6"))):
            with self.subTest(digest=support.sha(raw)):
                path = self.file("bad", raw)
                with self.assertRaises(ValueError):
                    isolated.elf_dependencies(path)

    def test_helper_elf_refuses_program_and_string_table_bounds(self):
        for offset, value in ((32, 2**63), (256 + 8, 2**63)):
            raw = bytearray(synthetic_elf(("libc.so.6",)))
            struct.pack_into("<Q", raw, offset, value)
            path = self.file("bounds", bytes(raw))
            with self.assertRaises(ValueError):
                isolated.elf_dependencies(path)

    def test_namespace_translation_does_not_ignore_other_object_changes(self):
        path = self.file("retained", b"retained\n")
        record = support.fingerprint(path)
        record["identity"][4:6] = [1234, 2345]  # Explicit simulated UID/GID view, no namespace is created.
        isolated.namespace_view(record, 1024)
        os.chmod(path, 0o400)
        with self.assertRaises(ValueError):
            isolated.namespace_view(record, 1024)
        os.chmod(path, 0o600)
        record = support.fingerprint(path)
        moved = self.root / "old"
        path.rename(moved)
        path.write_bytes(b"retained\n")
        with self.assertRaises(ValueError):
            isolated.namespace_view(record, 1024)

    def test_bounded_reader_refuses_actual_fifo_and_symlink(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            support.fingerprint(fifo, 1024)
        original = self.file("regular", b"input")
        linked = self.root / "link"
        linked.symlink_to(original)
        with self.assertRaises(OSError):
            support.read(linked, 1024)

    def test_mapping_requires_two_exact_rows_and_distinct_principals(self):
        valid = b"0 1000 1\n1 100000 2000\n"
        with patch.object(setup, "bounded_kernel", return_value=valid):
            self.assertEqual(setup.check_mapping("/proc/self/uid_map", 1000, 100000),
                             [(0, 1000, 1), (1, 100000, 2000)])
        for wrong in (b"0 0 1\n1 100000 2000\n", b"0 1000 1\n1 100000 999\n",
                      valid + b"3000 300000 1\n", b"0 1000 1\n"):
            with patch.object(setup, "bounded_kernel", return_value=wrong):
                with self.assertRaises(ValueError):
                    setup.check_mapping("/proc/self/uid_map", 1000, 100000)

    def test_artifact_source_selector_and_qualification_do_not_self_authorize(self):
        base = {"schema": "trnm-m15-static-native-artifacts-v1",
            "source": {"head": "a" * 40, "tree": "b" * 40}, "test_selector": isolated.CASE,
            "node": {}, "tests": {}, "build_input": {}, "command_receipts": [],
            "rust_tests_executed": False, "independent_deployment_qualified": False}
        for field, wrong in (("source", {"head": "c" * 40, "tree": "b" * 40}),
                             ("test_selector", "some_other_test"), ("rust_tests_executed", True),
                             ("independent_deployment_qualified", True)):
            value = copy.deepcopy(base)
            value[field] = wrong
            raw = support.canonical(value)
            path = self.file("artifacts.json", raw)
            with self.assertRaises(ValueError):
                isolated.artifact_input(path, support.sha(raw), "a" * 40, "b" * 40)

    def test_result_reader_requires_exact_one_case_and_complete_typed_fields(self):
        artifacts, consumer, _, _ = synthetic_reports(self.root)
        # This is only a reader-positive synthetic control, never an actual native PASS.
        self.assertEqual(runner.verify_native(self.root, artifacts)["native_cases"], 1)
        original = (self.root / "native.stdout").read_text()
        for changed in (original.replace("1 passed", "0 passed"), original.replace(isolated.CASE, "other"),
                        original + original):
            (self.root / "native.stdout").write_text(changed)
            with self.assertRaises(ValueError):
                runner.verify_native(self.root, artifacts)
        (self.root / "native.stdout").write_text(original)
        for field, wrong in (("same_fd_static_exec", 1), ("original_wall_seconds", 180.0),
                             ("fixture_principals", [1000.0, 1001]), ("production_qualified", True)):
            value = copy.deepcopy(consumer)
            value[field] = wrong
            (self.root / "consumer-result.json").write_bytes(support.canonical(value))
            with self.assertRaises(ValueError):
                runner.verify_native(self.root, artifacts)
        value = copy.deepcopy(consumer)
        value["extra"] = True
        (self.root / "consumer-result.json").write_bytes(support.canonical(value))
        with self.assertRaises(ValueError):
            runner.verify_native(self.root, artifacts)

    def test_result_reader_refuses_unknown_cleanup_or_unsigned_principal_shape(self):
        artifacts, _, namespace, clocks = synthetic_reports(self.root)
        for field, wrong in (("exit_code", False), ("unexpected_owned_process_group", True),
                             ("retained_state", None), ("schema", "legacy"),
                             ("service_rpc_seconds", 2.0), ("independent_deployment_qualified", True)):
            value = copy.deepcopy(namespace)
            value[field] = wrong
            (self.root / "namespace-result.json").write_bytes(support.canonical(value))
            with self.assertRaises(ValueError):
                runner.verify_native(self.root, artifacts)
        (self.root / "namespace-result.json").write_bytes(support.canonical(namespace))
        for wrong in (clocks[:1], [*clocks, {"uid": 0}], [{**clocks[0], "challenge": "0" * 64}, clocks[1]]):
            (self.root / "clock-observations.json").write_bytes(support.canonical(wrong))
            with self.assertRaises(ValueError):
                runner.verify_native(self.root, artifacts)


    def retained_scene(self, name):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        paths = tuple(directory / part for part in ("root", "outside", "evidence"))
        for path in paths:
            path.mkdir(mode=0o700)
        return paths

    def test_retained_state_keeps_real_state_and_nested_links_as_observations(self):
        root, outside, evidence = self.retained_scene("real")
        bases = ("etc/trillionnium", "m15/runtime", "m15/frontier", "tmp")
        expected = {}
        for base in bases:
            source = root / base
            source.mkdir(parents=True, exist_ok=True)
            raw = ("real retained state " + base + "\n").encode()
            (source / "state").write_bytes(raw)
            expected[base + "/state"] = raw
        (outside / "sentinel").write_bytes(b"never copy this owned sentinel\n")
        (root / "tmp/directory-link").symlink_to(outside, target_is_directory=True)
        (root / "tmp/file-link").symlink_to(outside / "sentinel")
        os.mkfifo(root / "tmp/unopened-pipe", mode=0o600)
        summary = setup.retain_state(root, evidence)
        report = json.loads((evidence / "retained-state.json").read_bytes())
        rows = {row["path"]: row for row in report["files"]}
        self.assertEqual(summary["entries"], len(rows))
        self.assertEqual(summary["regular_bytes"], sum(map(len, expected.values())))
        self.assertEqual(report["regular_bytes"], summary["regular_bytes"])
        for path, raw in expected.items():
            self.assertEqual((evidence / "retained-state" / path).read_bytes(), raw)
            self.assertEqual(rows[path]["sha256"], support.sha(raw))
        for name, target in (("directory-link", outside), ("file-link", outside / "sentinel")):
            self.assertEqual(rows["tmp/" + name]["kind"], "symlink")
            self.assertEqual(rows["tmp/" + name]["target"], str(target))
            self.assertFalse((evidence / "retained-state/tmp" / name).exists())
        self.assertEqual(rows["tmp/unopened-pipe"]["kind"], "unopened-special")
        self.assertFalse((evidence / "retained-state/tmp/unopened-pipe").exists())
        root, _, evidence = self.retained_scene("absent")
        self.assertEqual(setup.retain_state(root, evidence), {"entries": 4, "regular_bytes": 0})
        report = json.loads((evidence / "retained-state.json").read_bytes())
        self.assertEqual(report["files"], [{"path": base, "absent": True} for base in bases])

    def test_retained_state_refuses_each_symlinked_top_directory(self):
        for number, base in enumerate(("etc/trillionnium", "m15/runtime", "m15/frontier", "tmp")):
            for relative in (False, True):
                with self.subTest(base=base, relative=relative):
                    root, outside, evidence = self.retained_scene(f"top-{number}-{relative}")
                    sentinel = outside / "sentinel"
                    sentinel.write_bytes(b"owned sentinel outside the selected state root\n")
                    source = root / base
                    source.parent.mkdir(parents=True, exist_ok=True)
                    target = os.path.relpath(outside, source.parent) if relative else str(outside)
                    source.symlink_to(target, target_is_directory=True)
                    with self.assertRaisesRegex(ValueError, "roots must be real directories"):
                        setup.retain_state(root, evidence)
                    self.assertEqual(os.readlink(source), target)
                    self.assertEqual(sentinel.read_bytes(), b"owned sentinel outside the selected state root\n")
                    self.assertFalse((evidence / "retained-state" / base / "sentinel").exists())
                    self.assertFalse((evidence / "retained-state.json").exists())

    def test_retained_state_refuses_dangling_links_and_non_directory_bases(self):
        for number, base in enumerate(("etc/trillionnium", "m15/runtime", "m15/frontier", "tmp")):
            for kind in ("dangling", "regular", "fifo"):
                with self.subTest(base=base, kind=kind):
                    root, outside, evidence = self.retained_scene(f"kind-{number}-{kind}")
                    source = root / base
                    source.parent.mkdir(parents=True, exist_ok=True)
                    if kind == "dangling":
                        source.symlink_to(outside / "missing", target_is_directory=True)
                    elif kind == "regular":
                        source.write_bytes(b"not a directory\n")
                    else:
                        os.mkfifo(source, mode=0o600)
                    before = os.stat(source, follow_symlinks=False)
                    with self.assertRaisesRegex(ValueError, "roots must be real directories"):
                        setup.retain_state(root, evidence)
                    after = os.stat(source, follow_symlinks=False)
                    self.assertEqual((before.st_dev, before.st_ino, before.st_mode),
                                     (after.st_dev, after.st_ino, after.st_mode))
                    self.assertFalse((evidence / "retained-state.json").exists())

    def test_retained_state_refuses_symlinked_base_parents_and_root(self):
        for parent, leaves in (("etc", ("trillionnium",)), ("m15", ("runtime", "frontier"))):
            with self.subTest(parent=parent):
                root, outside, evidence = self.retained_scene("parent-" + parent)
                for leaf in leaves:
                    (outside / leaf).mkdir()
                    (outside / leaf / "sentinel").write_bytes(b"owned parent-link sentinel\n")
                (root / parent).symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "roots must be real directories"):
                    setup.retain_state(root, evidence)
                for leaf in leaves:
                    self.assertFalse((evidence / "retained-state" / parent / leaf / "sentinel").exists())
                self.assertFalse((evidence / "retained-state.json").exists())
        root, outside, evidence = self.retained_scene("linked-root")
        (outside / "tmp").mkdir()
        (outside / "tmp/sentinel").write_bytes(b"owned root-link sentinel\n")
        alias = root.parent / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "roots must be real directories"):
            setup.retain_state(alias, evidence)
        self.assertFalse((evidence / "retained-state").exists())


if __name__ == "__main__":
    unittest.main()
