"""Synthetic parser controls; these records are never native execution evidence.

The actual word/trap/process tests remain in test_sha256_words.  This module
builds deliberately synthetic records so the independent artifact reader can
be exercised without executing a compiler or a native image.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import unittest

from hia.tests import test_sha256_words as words
from hia.tools import qualify, sha256_word_evidence as evidence

ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_COMPILER = b"Synthetic parser fixture: no executable compiler.\n"
SYNTHETIC_IMAGE = b"Synthetic parser fixture: no executed native image.\n"
COMPILER = {"binding_sha256": "b" * 64,
            "compiler_sha256": evidence.identity(SYNTHETIC_COMPILER)["sha256"]}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def answer(case):
    """Independent byte oracle for synthetic records, not a native result."""
    original = bytes((index * 73 + 19) % 256 for index in range(case["extent"]))
    work = bytearray(original)
    output = b"\xa5" * 8
    trapped = False
    loaded = bytearray()
    for index in range(8):
        at = (case["offset"] + index) % (1 << 64)
        if at >= len(work):
            trapped = True
            break
        if case["mode"]:
            work[at] = struct.pack("<Q", case["value"])[index]
        else:
            loaded.append(work[at])
    if not trapped:
        output = bytes(8) if case["mode"] else bytes(loaded)
    return {**case, **({"status": "trapped", "signal": 4} if trapped else
                      {"status": "returned", "exit_code": 0}),
            "input_unchanged": True, "guards_unchanged": True,
            "output_hex": output.hex(), "work_before_hex": original.hex(),
            "work_after_hex": bytes(work).hex()}


def supervision(label):
    limit = 1 if label == "observer-deadline-control" else 30
    duration = 3 if label == "child-deadline-control" else 1
    finish = 100 + duration
    control = label != "complete-440"
    return {"schema": "trnm.pq.process-supervision.v1",
            "policy": "absolute-execution-single-group-cleanup-v1",
            "argv": ["/synthetic/python3", "-I", "-S", "-B", "-c", words.WORKER],
            "cwd": "/synthetic/" + label, "environment_overridden": False,
            "execution_limit_seconds": limit, "cleanup_limit_seconds": 3,
            "started_monotonic": 100, "execution_deadline_monotonic": 100 + limit,
            "execution_finished_monotonic": finish, "execution_seconds": duration,
            "cleanup_started_monotonic": finish, "cleanup_deadline_monotonic": finish + 3,
            "cleanup_finished_monotonic": finish + 0.125, "cleanup_seconds": 0.125,
            "seconds": duration + 0.125, "pid": 2000, "pgid": 2000, "session_id": 2000,
            "start_new_session": True, "subreaper": {"active": 1, "previous": 0},
            "exit_code": 0 if not control else 1 if label == "child-deadline-control" else -9,
            "outcome": "success" if not control else
                "descendants-outlived-leader" if label == "child-deadline-control" else "timeout",
            "timed_out": label == "observer-deadline-control",
            "descendants_outlived_leader": label == "child-deadline-control",
            "direct_child_reaped": True, "group_absent": True, "streams_complete": True,
            "cleanup_complete": True, "launch_error": None, "execution_error": None,
            "killpg_attempts": [{"errno": 0, "signal": 9, "monotonic": finish + 0.0625}] if control else [],
            "adopted_reaped": [{"pid": 3007, "wait_status": 9, "exit_code": -9}] if control else []}


def events(label, cases, image_sha):
    result = [{"event": "ready", "artifact_sha256": image_sha, "cases": 440,
               "dumpable": 0, "child_cpu_limit_seconds": 1, "child_wall_limit_seconds": 2}]
    for index, case in enumerate(cases if label == "complete-440" else cases[:8]):
        start = 100 + (index + 1) / 1024
        result.append({"event": "started", "index": index, "pid": 3000 + index,
                       "started_monotonic": start, "deadline_monotonic": start + 2})
        if index == 7 and label != "complete-440":
            if label == "child-deadline-control":
                result.append({"event": "child-timeout", "index": 7, "pid": 3007, "seconds": 2})
            break
        result.append({"event": "completed", "index": index, "pid": 3000 + index,
                       "seconds": 1 / 2048, "answer": answer(case)})
    if label == "complete-440":
        result.append({"event": "finished", "artifact_sha256": image_sha,
                       "completed": 440, "host_compiler_modules_loaded": []})
    return result


def capture_name(label, name):
    return evidence.PREFIX + "/" + label + "/" + name


def log_rows(files):
    rows = [files[capture_name(label, "observations.json")] for label in evidence.LABELS]
    rows += [encoded({"label": label,
                      "stdout_raw_hex": files[capture_name(label, "stdout.raw")].hex(),
                      "stderr_raw_hex": files[capture_name(label, "stderr.raw")].hex()})
             for label in evidence.LABELS[1:]]
    return b"".join(raw if raw.endswith(b"\n") else raw + b"\n" for raw in rows)


def refresh(files, label, *, observation=False, enclosing_log=False):
    """Rehash a mutant, optionally making its summaries internally coherent."""
    if observation:
        row = json.loads(files[capture_name(label, "observations.json")])
        row["supervisor"] = json.loads(files[capture_name(label, "supervision.json")])
        parsed = words.progress(files[capture_name(label, "stdout.raw")], words.native_cases())
        row.update(parsed)
        row["completed_cases"] = len(parsed["cases"])
        files[capture_name(label, "observations.json")] = encoded(row)
    manifest = json.loads(files[capture_name(label, "manifest.json")])
    manifest["files"] = {name: evidence.identity(files[capture_name(label, name)])
                         for name in evidence.FILES - {"manifest.json"}}
    files[capture_name(label, "manifest.json")] = encoded(manifest)
    if enclosing_log:
        files["hia-observations/qualification.log"] = log_rows(files)


@lru_cache(maxsize=1)
def _fixture():
    current = {name: (ROOT / path).read_bytes() for name, path in evidence.SOURCES.items()}
    sources = {path: evidence.identity(current[name])["sha256"]
               for name, path in evidence.SOURCES.items()}
    functions = dict((match.group(1).decode(), match.group(0)) for match in re.finditer(
        rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", current["production.hepta"]))
    composed = words.ENTRY.encode().rstrip() + b"\n" + b"".join(
        functions[name].rstrip() + b"\n" for name in ("tr_read", "tr_get", "tr_put"))
    wire = composed.replace(b"sha_word_boundary\n", b"selfhost_elf\n", 1)
    include = json.dumps({"schema": "trnm.hia.component-includes.v1", "includes": {
        "src/words.hepta": [{"source": "src/crypto/sha256_stream.hepta",
                             "functions": ["tr_read", "tr_get", "tr_put"]}]}}).encode()
    inputs = {"src/words.hepta": words.ENTRY.encode(), "components.json": include,
              "src/crypto/sha256_stream.hepta": current["production.hepta"]}
    identities = [{"path": path, "sha256": evidence.identity(raw)["sha256"]} for path, raw in inputs.items()]
    lock = json.loads(current["toolchain.lock.json"])
    migration = {"backend": "selfhost", "source_sha256": identities[0]["sha256"],
                 "composed_source_sha256": evidence.identity(composed)["sha256"], "core_sha256": "d" * 64,
                 "toolchain_repository": lock["repository"], "toolchain_revision": lock["revision"],
                 "hosted_build_driver": True, "whole_chain_native": False, "inputs": identities}
    image = evidence.identity(SYNTHETIC_IMAGE)
    build = {"source": None, "artifact_sha256": image["sha256"], "object_sha256": "a" * 64,
             "compiler_sha256": COMPILER["compiler_sha256"], "exports": ["f0"],
             "claims": copy.deepcopy(evidence.CLAIMS), "chain_migration": migration,
             "generated_fixture": {"owner": evidence.OWNER, "owner_sha256": sources[evidence.OWNER],
                "entry": "src/words.hepta", "inputs": [{**row, "utf8": inputs[row["path"]].decode()}
                                                       for row in identities]}}
    files = {}
    cases = words.native_cases()
    for label in evidence.LABELS:
        sup = supervision(label)
        fault = None if label == "complete-440" else {
            "mode": "child-pause" if label == "child-deadline-control" else "observer-and-child-pause", "index": 7}
        output = "/synthetic/" + label + "/module.so"
        request = {"library": output, "sha256": image["sha256"], "cases": cases}
        if fault is not None:
            request["fault"] = fault
        raw_events = b"".join(encoded(row) for row in events(label, cases, image["sha256"]))
        parsed = words.progress(raw_events, cases)
        observation = {"schema": evidence.OBSERVATION_SCHEMA, "label": label,
                       "production_sha256": sources[evidence.SOURCES["production.hepta"]],
                       "artifact_sha256": image["sha256"], "requested_cases": 440,
                       "completed_cases": len(parsed["cases"]), "fault": fault, "supervisor": sup, **parsed}
        receipt = {"schema": "trnm.hia.selfhost-build.v1", "ok": True,
                   "status": "native_emitted_not_executed", "kind": "shared", "exports": ["f0"],
                   "claims": copy.deepcopy(evidence.CLAIMS), "compiler_sha256": COMPILER["compiler_sha256"],
                   "compiler_wire_sha256": evidence.identity(wire)["sha256"], "artifact_bytes": image["bytes"],
                   "artifact_sha256": image["sha256"], "object_sha256": build["object_sha256"], "output": output,
                   "borrowed_entry_profile": "legacy-f0-private-buffers", "output_profile_selection": "selfhost_elf",
                   "chain_migration": migration}
        retained = {**current, "fixture.hepta": words.ENTRY.encode(), "worker.py": words.WORKER.encode(),
                    "compiler-input.hepta": wire, "native-compiler": SYNTHETIC_COMPILER, "module.so": SYNTHETIC_IMAGE,
                    "receipt.json": encoded(receipt), "request.json": encoded(request),
                    "supervision.json": encoded(sup), "stdout.raw": raw_events,
                    "stderr.raw": b"Traceback (most recent call last):\nTimeoutError: native fixed-width helper exceeded 2 seconds\n"
                    if label == "child-deadline-control" else b"", "observations.json": encoded(observation)}
        retained["manifest.json"] = encoded({"schema": "trnm.hia.sha256-word-boundary-capture.v2", "cases": 440,
            "exit_code": sup["exit_code"], "source_unchanged": True,
            "files": {name: evidence.identity(raw) for name, raw in retained.items()}})
        files.update({capture_name(label, name): raw for name, raw in retained.items()})
    files["hia-observations/qualification.log"] = log_rows(files)
    return files, {"builds": [copy.deepcopy(build) for _ in evidence.LABELS]}, sources


def fixture():
    return copy.deepcopy(_fixture())


class Sha256WordEvidence(unittest.TestCase):
    def validate(self, files, value, sources):
        return evidence.validate(files, value, sources, COMPILER, ROOT)

    def test_three_exact_captures_and_all_440_states_are_required(self):
        files, value, sources = fixture()
        result = self.validate(files, value, sources)
        self.assertEqual(result, {"status": "PASS", "completed_native_cases": 440, "deadline_controls": 2,
                                  "retained_files": 54, "actual_runtime_reexecuted": False})
        from hia.tools import qualify_components_ci as ci
        self.assertEqual(len(ci.artifact_files("general")), 60)
        for group in ("crypto-types", "state-root", "oracle", "ml-dsa"):
            self.assertEqual(ci.artifact_files(group), ci.FILES)
        self.assertEqual(set(files) - {"hia-observations/qualification.log"}, evidence.artifact_files())

    def test_manifest_members_and_each_member_identity_are_exact(self):
        original, value, sources = fixture()
        for label in evidence.LABELS:
            path = capture_name(label, "manifest.json")
            for kind in ("missing", "extra", "changed-hash", "changed-size", "partial"):
                with self.subTest(label=label, kind=kind):
                    files = dict(original)
                    manifest = json.loads(files[path])
                    if kind == "missing": del manifest["files"]["module.so"]
                    elif kind == "extra": manifest["files"]["unknown"] = evidence.identity(b"")
                    elif kind == "changed-hash": manifest["files"]["module.so"]["sha256"] = "0" * 64
                    elif kind == "changed-size": manifest["files"]["module.so"]["bytes"] += 1
                    else: manifest["source_unchanged"] = False
                    files[path] = encoded(manifest)
                    with self.assertRaises(ValueError): self.validate(files, value, sources)

    def test_rehashed_source_compiler_wire_worker_and_image_changes_are_rejected(self):
        original, value, sources = fixture()
        for label in evidence.LABELS:
            for name in (*evidence.SOURCES, "fixture.hepta", "worker.py", "compiler-input.hepta",
                         "native-compiler", "module.so", "stderr.raw"):
                with self.subTest(label=label, name=name):
                    files = dict(original)
                    path = capture_name(label, name)
                    files[path] += b"changed"
                    refresh(files, label)
                    with self.assertRaises(ValueError): self.validate(files, value, sources)

    def test_actual_build_receipt_and_generated_input_owner_cannot_be_substituted(self):
        files, baseline, sources = fixture()
        mutations = [lambda value: value["builds"].pop(),
                     lambda value: value["builds"][0]["generated_fixture"].update(owner="hia/tests/unbound.py"),
                     lambda value: value["builds"][0]["generated_fixture"].update(owner_sha256="0" * 64),
                     lambda value: value["builds"][0]["claims"].update(python_emitter_used=True),
                     lambda value: value["builds"][0].update(source="hia/src/crypto/sha256_stream.hepta"),
                     lambda value: value["builds"][0]["generated_fixture"]["inputs"][0].update(utf8="changed")]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                value = copy.deepcopy(baseline)
                change(value)
                with self.assertRaises(ValueError): self.validate(files, value, sources)
        for field, changed in (("object_sha256", "0" * 64), ("compiler_sha256", "0" * 64),
                               ("compiler_wire_sha256", "0" * 64), ("artifact_bytes", True),
                               ("borrowed_entry_profile", "unbound"), ("status", "PASS")):
            changed_files = dict(files)
            path = capture_name("complete-440", "receipt.json")
            row = json.loads(changed_files[path]); row[field] = changed
            changed_files[path] = encoded(row); refresh(changed_files, "complete-440")
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(changed_files, baseline, sources)

    def test_self_consistent_observations_cannot_hide_wrong_partial_writes_or_traps(self):
        original, value, sources = fixture()
        path = capture_name("complete-440", "stdout.raw")
        events_before = [json.loads(line) for line in original[path].splitlines()]
        index = next(index for index, row in enumerate(events_before) if row.get("event") == "completed"
                     and row["answer"]["mode"] == 1 and row["answer"]["status"] == "trapped"
                     and row["answer"]["work_before_hex"] != row["answer"]["work_after_hex"])
        changed_work = bytes.fromhex(events_before[index]["answer"]["work_after_hex"])
        changed_work = bytes([changed_work[0] ^ 1]) + changed_work[1:]
        for field, changed in (("work_after_hex", changed_work.hex()), ("signal", 9), ("input_unchanged", False),
                               ("guards_unchanged", False), ("output_hex", "00" * 8)):
            with self.subTest(field=field):
                files = dict(original)
                rows = copy.deepcopy(events_before); rows[index]["answer"][field] = changed
                files[path] = b"".join(encoded(row) for row in rows)
                refresh(files, "complete-440", observation=True, enclosing_log=True)
                with self.assertRaises(ValueError): self.validate(files, value, sources)

    def test_full_case_roster_order_completions_and_outer_log_are_mandatory(self):
        original, value, sources = fixture()
        path = capture_name("complete-440", "stdout.raw")
        baseline = [json.loads(line) for line in original[path].splitlines()]
        for change in (lambda rows: rows.pop(), lambda rows: rows.pop(2),
                       lambda rows: rows.insert(2, copy.deepcopy(rows[1])),
                       lambda rows: rows[2].update(index=1), lambda rows: rows[-1].update(completed=439),
                       lambda rows: rows[0].update(dumpable=1),
                       lambda rows: rows[-1].update(host_compiler_modules_loaded=["hepta"])):
            files = dict(original); rows = copy.deepcopy(baseline); change(rows)
            files[path] = b"".join(encoded(row) for row in rows)
            refresh(files, "complete-440", observation=True, enclosing_log=True)
            with self.assertRaises(ValueError): self.validate(files, value, sources)
        for raw in (b"", original["hia-observations/qualification.log"] * 2):
            files = {**original, "hia-observations/qualification.log": raw}
            with self.assertRaises(ValueError): self.validate(files, value, sources)

    def test_real_timeout_cannot_be_promoted_or_omit_the_native_child_reap(self):
        original, value, sources = fixture()
        mutations = [lambda row: row.update(adopted_reaped=[]),
                     lambda row: row["adopted_reaped"][0].update(pid=4999),
                     lambda row: row["adopted_reaped"][0].update(wait_status=0),
                     lambda row: row.update(killpg_attempts=[]),
                     lambda row: row["killpg_attempts"][0].update(errno=1),
                     lambda row: row["killpg_attempts"].append(copy.deepcopy(row["killpg_attempts"][0])),
                     lambda row: row.update(group_absent=False),
                     lambda row: row.update(direct_child_reaped=False),
                     lambda row: row.update(cleanup_complete=False),
                     lambda row: row.update(outcome="success"),
                     lambda row: row.update(environment_overridden=True),
                     lambda row: row.update(cleanup_deadline_monotonic=row["cleanup_deadline_monotonic"] + 3)]
        for label in evidence.LABELS[1:]:
            for index, change in enumerate(mutations):
                with self.subTest(label=label, index=index):
                    files = dict(original); path = capture_name(label, "supervision.json")
                    row = json.loads(files[path]); change(row); files[path] = encoded(row)
                    refresh(files, label, observation=True, enclosing_log=True)
                    with self.assertRaises(ValueError): self.validate(files, value, sources)

    def test_complete_and_partial_child_timers_cannot_expand_or_reset(self):
        original, value, sources = fixture()
        for label in evidence.LABELS:
            for field in ("execution_limit_seconds", "cleanup_limit_seconds", "seconds"):
                files = dict(original); path = capture_name(label, "supervision.json")
                row = json.loads(files[path]); row[field] += 100; files[path] = encoded(row)
                refresh(files, label, observation=True, enclosing_log=True)
                with self.subTest(label=label, field=field), self.assertRaises(ValueError):
                    self.validate(files, value, sources)
            path = capture_name(label, "stdout.raw")
            for field, changed in (("deadline_monotonic", 999), ("started_monotonic", -1)):
                files = dict(original); rows = [json.loads(line) for line in files[path].splitlines()]
                rows[1][field] = changed; files[path] = b"".join(encoded(row) for row in rows)
                refresh(files, label, observation=True, enclosing_log=True)
                with self.subTest(label=label, field=field), self.assertRaises(ValueError):
                    self.validate(files, value, sources)

    def test_nonfinite_duplicate_and_false_numeric_json_cannot_be_accepted(self):
        for raw in (b'{"a":1,"a":2}', b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): evidence.document(raw)
        for value in (True, False, float("inf"), float("nan"), -1):
            with self.subTest(value=value), self.assertRaises(ValueError): evidence.clock(value)
        files, value, sources = fixture()
        for label, field in (("observer-deadline-control", "execution_limit_seconds"),
                             ("complete-440", "exit_code"), ("complete-440", "subreaper")):
            changed = dict(files)
            path = capture_name(label, "supervision.json")
            row = json.loads(changed[path])
            row[field] = ({"active": True, "previous": 0} if field == "subreaper" else
                          False if field == "exit_code" else True)
            changed[path] = encoded(row)
            refresh(changed, label, observation=True, enclosing_log=True)
            with self.subTest(label=label, field=field), self.assertRaises(ValueError):
                self.validate(changed, value, sources)

    def test_reader_and_controls_are_bound_to_full_discovery_without_hepta_checkout(self):
        sources = qualify.sources()
        for path in ("hia/tools/sha256_word_evidence.py", "hia/tests/test_sha256_word_evidence.py"):
            self.assertEqual(sources[path], evidence.identity((ROOT / path).read_bytes())["sha256"])
        from hia.tools.component_partition import flatten, group_for
        names = [case.id() for case in flatten(unittest.defaultTestLoader.loadTestsFromName(__name__))]
        self.assertTrue(names)
        self.assertTrue(all(group_for(name) == "general" for name in names))
        code = ("import sys; sys.path.insert(0,sys.argv[1]); "
                "from hia.tools import qualify_components_ci; "
                "from hia.tests import test_sha256_word_evidence; "
                "assert not any(n == 'hepta' or n.startswith('hepta.') for n in sys.modules); "
                "print('NO_HEPTA_CHECKOUT_REQUIRED')")
        observed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code, str(ROOT)],
                                  check=True, capture_output=True, timeout=10)
        self.assertEqual(observed.stdout, b"NO_HEPTA_CHECKOUT_REQUIRED\n")
        self.assertEqual(observed.stderr, b"")


if __name__ == "__main__":
    unittest.main()
