"""Real retained native bytes plus refusal controls; no successful native stub."""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

import w1_quantum_native_bridge as bridge

PINS = bridge.NativePins(
    artifact_sha256="d9ce3ead97f87759707829220525f50420126fa0347cbd64ec46aeb69bbd57c9",
    native_source="e4abb172147e941b62483652b0ceabaae4317624",
    native_tree="016ebf3deeac88d6d7a782edf563f2291ebe17f5",
    preregistration_sha256="9ba442904cc481e8371ff90bef97908dd1f0dcf59ce442375b18d0fd8a10f443",
    binary_sha256="fe18172189e555693c701d0d6b686c519e2a4c5d7a55ecdf999cb7c4e77db7b7",
)
DEFAULT_ARCHIVE = bridge.ROOT / "evidence/pon-w1-oracle-scope-20261110/native-fullpath-e4abb172.zip"
ARCHIVE = Path(os.environ.get("TRNM_W1_NATIVE_ARTIFACT", str(DEFAULT_ARCHIVE)))


def packed(entries):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in entries:
                archive.writestr(name, raw)
    return stream.getvalue()


class SourceCommitmentControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet")
        (self.root / "relation.py").write_bytes(b"observed source\n")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-c", "user.name=Source control test", "-c", "user.email=test@example.invalid", *args],
            cwd=self.root, stderr=subprocess.PIPE, text=True).strip()

    def inputs(self, names=("relation.py",)):
        rows = {}
        for name in names:
            raw = (self.root / name).read_bytes()
            rows[name] = {"bytes": len(raw), "sha256": bridge.gate.sha256(raw),
                          "git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}
        return rows

    def record(self, rows=None):
        rows = self.inputs() if rows is None else rows
        return {**bridge.source_commitment(self.root, rows), "files": rows,
                "scope": "test declared inputs only"}

    def commit(self):
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "source control fixture")

    def test_missing_head_and_uncommitted_source_cannot_borrow_a_commit_identity(self):
        missing = self.record()
        self.assertIsNone(missing["git_head"])
        self.assertFalse(missing["all_sources_committed_at_head"])
        self.assertEqual(missing["source_commitment_state"], "NO_GIT_HEAD")
        self.assertEqual(missing["uncommitted_source_files"], ["relation.py"])
        self.commit()
        original = self.record()
        self.assertTrue(original["all_sources_committed_at_head"])
        (self.root / "relation.py").write_bytes(b"changed source\n")
        (self.root / "new.py").write_bytes(b"uncommitted input\n")
        changed = self.record(self.inputs(("relation.py", "new.py")))
        self.assertEqual(changed["git_head"], original["git_head"])
        self.assertFalse(changed["all_sources_committed_at_head"])
        self.assertEqual(changed["uncommitted_source_files"], ["relation.py", "new.py"])
        with self.assertRaisesRegex(ValueError, "BRIDGE_SOURCE_FILES"):
            bridge.verify_source_record(original, changed, self.root)

    def test_evidence_only_child_can_verify_actual_historical_source_objects(self):
        self.commit()
        recorded = self.record()
        (self.root / "evidence.txt").write_bytes(b"later observation\n")
        self.commit()
        current = self.record()
        self.assertNotEqual(recorded["git_head"], current["git_head"])
        self.assertNotEqual(recorded["git_tree"], current["git_tree"])
        self.assertEqual(bridge.verify_source_record(recorded, current, self.root), recorded)
        for field, value in (("git_head", "0" * 40), ("git_tree", "0" * 40),
                             ("uncommitted_source_files", ["relation.py"]),
                             ("all_sources_committed_at_head", False)):
            fake = {**recorded, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                bridge.verify_source_record(fake, current, self.root)

    def test_existing_old_commit_with_different_declared_blob_is_not_a_replay_source(self):
        self.commit()
        old = self.record()
        (self.root / "relation.py").write_bytes(b"new relation\n")
        self.commit()
        current = self.record()
        fake = {**current, "git_head": old["git_head"], "git_tree": old["git_tree"]}
        with self.assertRaisesRegex(ValueError, "HISTORICAL_SOURCE_TREE_OR_BLOBS"):
            bridge.verify_source_record(fake, current, self.root)


class NativeArchiveRefusalControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing real evidence is a failure, never an optional skipped control.
        cls.raw = ARCHIVE.read_bytes()
        if bridge.gate.sha256(cls.raw) != PINS.artifact_sha256:
            raise ValueError("TEST_REAL_NATIVE_ARCHIVE_DIGEST")
        with zipfile.ZipFile(io.BytesIO(cls.raw)) as archive:
            cls.members = {row.filename: archive.read(row) for row in archive.infolist()}

    def check_changed(self, changes=None, removed=(), pins=PINS, reason=None):
        members = {name: raw for name, raw in self.members.items() if name not in removed}
        members.update(changes or {})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge.extract_archive(packed(members.items()), root)
            if reason is None:
                with self.assertRaises((ValueError, OSError, KeyError, TypeError)):
                    bridge.validate_native(root, pins)
            else:
                with self.assertRaisesRegex(ValueError, reason):
                    bridge.validate_native(root, pins)

    def changed_json(self, name, mutate):
        value = json.loads(self.members[name])
        mutate(value)
        return {name: bridge.gate.canonical(value) + b"\n"}

    def test_each_external_source_tree_preregistration_and_binary_pin_is_required(self):
        for field in ("native_source", "native_tree", "preregistration_sha256", "binary_sha256"):
            with self.subTest(field=field):
                width = len(getattr(PINS, field))
                self.check_changed(pins=replace(PINS, **{field: "0" * width}))

    def test_archive_digest_cannot_be_derived_from_untrusted_archive(self):
        with self.assertRaisesRegex(ValueError, "ARCHIVE_SHA256"):
            bridge.run_bridge(ARCHIVE, replace(PINS, artifact_sha256="0" * 64))

    def test_pins_reject_wrong_types_noncanonical_hex_and_wrong_lengths(self):
        for value in (True, None, PINS.native_source.upper(), "f" * 39, "x" * 40):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(PINS, native_source=value).validate()

    def test_source_guard_cannot_claim_other_commit_tree_or_boolean_integer(self):
        for field, value in (("tested_commit", "0" * 40), ("tested_tree", "0" * 40),
                             ("tracked_worktree_verified", 1), ("tracked_entries", True)):
            with self.subTest(field=field):
                self.check_changed(self.changed_json("source-before.json", lambda x: x.update({field: value})))

    def test_guard_schema_rejects_extra_security_authority(self):
        self.check_changed(self.changed_json("source-before.json", lambda x: x.update(quantum_mining_qualified=True)),
                           reason="SOURCE_GUARD_SCHEMA")

    def test_duplicate_keys_and_nonfinite_original_json_are_refused(self):
        for raw in (b'{"schema":"trnm-ci-source-v1","schema":"trnm-ci-source-v1"}',
                    b'{"tracked_entries":NaN}', b'{"tracked_entries":1e999}'):
            with self.subTest(raw=raw):
                self.check_changed({"source-before.json": raw})

    def test_forged_native_context_source_and_binary_are_refused(self):
        for field in ("source_commit", "source_tree", "binary_sha256", "collector_sha256"):
            with self.subTest(field=field):
                self.check_changed(self.changed_json("processes/context.json", lambda x: x.update(
                    {field: "0" * len(x[field])})))

    def test_unknown_native_schema_and_promoted_scope_are_refused(self):
        self.check_changed(self.changed_json("processes/context.json", lambda x: x.update(extra_authority=True)),
                           reason="NATIVE_CONTEXT_SCHEMA")
        self.check_changed(self.changed_json("processes/context.json", lambda x: x.update(production_activation=True)),
                           reason="NATIVE_SCOPE_PROMOTION")

    def test_collection_stability_claim_is_not_optional(self):
        self.check_changed(self.changed_json("collector-output.json", lambda x: x.update(source_and_binary_unchanged=False)),
                           reason="COLLECTOR_OUTPUT_BINDING")

    def test_ninth_process_and_original_stream_cannot_be_omitted(self):
        for name in ("processes/cancelled-observe.process.json", "processes/late-product.stderr.txt"):
            with self.subTest(name=name):
                self.check_changed(removed=(name,))

    def test_process_stream_splice_is_detected_against_original_digest_and_events(self):
        name = "processes/receive.stdout.ndjson"
        rows = self.members[name].splitlines()
        value = json.loads(rows[-1])
        value["active_after_hex"] = "0" * 64
        rows[-1] = bridge.gate.canonical(value)
        self.check_changed({name: b"\n".join(rows) + b"\n"})

    def test_real_packet_mutation_cannot_borrow_original_admission(self):
        raw = bytearray(self.members["processes/candidate.pnp2"])
        raw[-1] ^= 1
        self.check_changed({"processes/candidate.pnp2": bytes(raw)})

    def test_late_product_packet_cannot_be_replaced_by_valid_packet(self):
        self.check_changed({"processes/late-product.pnp2": self.members["processes/candidate.pnp2"]})

    def test_archive_paths_aliases_and_parent_files_are_rejected_before_extraction(self):
        cases = (
            ([('/outside', b'x')], "PATH"), ([('../outside', b'x')], "PATH"),
            ([(r'processes\candidate.pnp2', b'x')], "PATH"),
            ([('a//b', b'x')], "PATH"), ([('a/./b', b'x')], "PATH"),
            ([('same', b'a'), ('same', b'b')], "DUPLICATE"),
            ([('a', b'x'), ('a/b', b'y')], "FILE_PARENT_COLLISION"),
            ([('a/b', b'y'), ('a', b'x')], "FILE_PARENT_COLLISION"),
        )
        for entries, reason in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaisesRegex(ValueError, reason):
                    bridge.extract_archive(packed(entries), root)
                self.assertEqual(list(root.iterdir()), [])

    def test_zip_symlink_and_bounded_expansion_refuse_without_following_target(self):
        symlink = zipfile.ZipInfo("linked")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for raw, reason in ((packed([(symlink, b'/tmp/outside')]), "TYPE"),
                            (packed([('large', b'x' * (bridge.MAX_MEMBER + 1))]), "SIZE")):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, reason):
                    bridge.extract_archive(raw, Path(directory))

    def test_zip_nul_truncation_cannot_alias_another_member_name(self):
        raw = packed([('fileX', b'x')]).replace(b'fileX', b'file\0')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "PATH"):
                bridge.extract_archive(raw, root)
            self.assertEqual(list(root.iterdir()), [])

    def test_archive_symlink_and_fifo_are_not_read_as_regular_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / 'link.zip'
            link.symlink_to(ARCHIVE.resolve())
            with self.assertRaises(OSError):
                bridge.run_bridge(link, PINS)
            fifo = root / 'fifo.zip'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "TYPE"):
                bridge.run_bridge(fifo, PINS)


class RetainedNativeDifferentialControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = bridge.run_bridge(ARCHIVE, PINS)

    def test_real_pgh2_scalar_macro_native_observations_share_one_statement(self):
        result = self.result
        native = result["native_readback"]
        differential = result["differential"]
        oracle = differential["oracle"]
        identity = differential["valid_packet"]["identity"]
        self.assertTrue(differential["valid_packet"]["scalar_full_relation_valid"])
        self.assertEqual(oracle["challenge"], identity["challenge_hex"])
        self.assertEqual(oracle["trace"], identity["claim"]["trace_hex"])
        self.assertEqual(oracle["ticket"], differential["valid_packet"]["scalar_ticket_hex"])
        self.assertEqual((oracle["winner"], oracle["phase"]), (True, -1))
        self.assertTrue(oracle["clean_ancillas"] and oracle["nonce_preserved"] and oracle["inverse_executed"])
        self.assertEqual(identity["block_hex"], native["attempts"][0]["block_hex"])
        self.assertEqual(len(result["native_provenance"]["processes"]), 9)

    def test_actual_late_product_counterexample_keeps_oracle_winner(self):
        differential = self.result["differential"]
        late = differential["late_product_counterexample"]
        self.assertTrue(late["oracle_winner"])
        self.assertFalse(late["scalar_full_relation_valid"])
        self.assertEqual((late["scalar_error"], late["native_error_observed"]), ("PRODUCT", "WORK:Product"))
        self.assertTrue(late["same_fixed_template_and_nonce"] and late["oracle_observation_reused_from_valid"])
        self.assertFalse(late["separate_oracle_execution"])
        self.assertEqual(differential["counts"]["native_sized_macro_executions"], 1)
        self.assertEqual(differential["counts"]["new_native_processes"], 0)

    def test_retained_native_gate_and_scientific_boundaries_are_not_promoted(self):
        result = self.result
        self.assertEqual(result["qualification"], bridge.QUALIFICATION)
        self.assertFalse(result["native_provenance"]["pin_authenticity_verified_by_bridge"])
        self.assertIsNone(result["differential"]["oracle"]["leaf_gates_executed"])
        native = result["native_readback"]
        self.assertEqual((native["overall_gate"], native["security_gate"]), ("HOLD", "HOLD"))
        self.assertFalse(native["native_relation_replayed_by_reader"])
        self.assertEqual(native["recorded_unique_new_native_blocks"], 1)
        self.assertEqual(native["timely_accepted_progress"], 0)
        attempts = {row["id"]: row for row in native["attempts"]}
        self.assertEqual(attempts["valid"]["last_canonical_depth"], 0)
        self.assertFalse(attempts["duplicate"]["full_native_replay_observed"])
        self.assertFalse(attempts["cancelled"]["full_native_replay_observed"])

    def test_saved_report_cannot_choose_its_own_external_pins(self):
        record = copy.deepcopy(self.result)
        record["external_pins"]["native_source"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "BRIDGE_REPORT_EXTERNAL_PINS"):
            bridge.verify(record, ARCHIVE, PINS)

    def test_saved_report_is_fully_rebuilt_and_changed_claims_are_rejected(self):
        record = copy.deepcopy(self.result)
        record["scope"] = "quantum hardware safety proof"
        record["differential"]["counts"]["native_sized_macro_executions"] += 1
        record["native_readback"]["attempts"][0]["status"] = "duplicate"
        record["qualification"]["quantum_mining_qualified"] = True
        with self.assertRaisesRegex(ValueError, "BRIDGE_REPORT_REBUILD_MISMATCH"):
            bridge.verify(record, ARCHIVE, PINS)




class HistoricalCollectorBindingControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Independent fixture identities; do not derive these pins from the reader.
        cls.path = "formal/pon-nakamoto-v1/fixtures/native-collector-e4abb172.py.raw"
        cls.sha256 = "f40c5d621454d0532141920724a3cfd57e240f4a3b061536162313daa676c254"
        cls.raw = bridge.gate.Evidence(bridge.ROOT).read(cls.path, 23_639)
        if len(cls.raw) != 23_639 or bridge.gate.sha256(cls.raw) != cls.sha256:
            raise ValueError("TEST_ORIGINAL_COLLECTOR_BYTES")
        if hashlib.sha1(b"blob 23639\0" + cls.raw).hexdigest() != "421b10241820580efcdabc692ccb1f6dd27b6586":
            raise ValueError("TEST_ORIGINAL_COLLECTOR_BLOB")

    def fixture(self, root, raw=None):
        path = root / self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.raw if raw is None else raw)
        return path

    def test_exact_historical_tuple_reads_data_without_executing_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            with mock.patch.object(subprocess, "run", side_effect=AssertionError("no historical Git/native run")) as run, \
                    mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no historical child")) as child, \
                    mock.patch("builtins.exec", side_effect=AssertionError("historical source is data")) as execute, \
                    mock.patch("builtins.compile", side_effect=AssertionError("historical source is data")) as compile_source:
                self.assertIsNone(bridge.validate_collector_source(PINS, self.sha256, root))
                run.assert_not_called()
                child.assert_not_called()
                execute.assert_not_called()
                compile_source.assert_not_called()

    def test_missing_or_mislocated_producer_never_falls_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(OSError):
                bridge.validate_collector_source(PINS, self.sha256, root)
            wrong = root / "formal/pon-native-fullpath-v1/collect_native.py"
            wrong.parent.mkdir(parents=True)
            wrong.write_bytes(self.raw)
            with self.assertRaises(OSError):
                bridge.validate_collector_source(PINS, self.sha256, root)

    def test_tampered_short_extended_and_current_producer_cannot_replace_history(self):
        changed = bytearray(self.raw)
        changed[-1] ^= 1
        current = (bridge.NATIVE / "collect_native.py").read_bytes()
        cases = (bytes(changed), self.raw[:-1], self.raw + b"\n", current)
        for raw in cases:
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root, raw)
                with self.assertRaises(ValueError):
                    bridge.validate_collector_source(PINS, self.sha256, root)

    def test_symlink_fifo_and_parent_alias_are_rejected(self):
        for kind in ("symlink", "fifo", "parent-alias"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / "original.py.raw"
                target.write_bytes(self.raw)
                path = root / self.path
                path.parent.mkdir(parents=True)
                if kind == "symlink":
                    path.symlink_to(target)
                elif kind == "fifo":
                    os.mkfifo(path)
                else:
                    directory = root / "aliased"
                    directory.mkdir()
                    (directory / path.name).write_bytes(self.raw)
                    path.parent.rmdir()
                    path.parent.symlink_to(directory, target_is_directory=True)
                with self.assertRaises((OSError, ValueError)):
                    bridge.validate_collector_source(PINS, self.sha256, root)

    def test_wrong_source_tree_or_context_digest_cannot_borrow_history(self):
        current_sha = bridge.gate.sha256((bridge.NATIVE / "collect_native.py").read_bytes())
        cases = (
            (replace(PINS, native_source="0" * 40), self.sha256),
            (replace(PINS, native_tree="0" * 40), self.sha256),
            (PINS, "0" * 64), (PINS, current_sha),
            (PINS, self.sha256.upper()), (PINS, True),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            for pins, declared in cases:
                with self.subTest(source=pins.native_source, tree=pins.native_tree, digest=declared):
                    with self.assertRaisesRegex(ValueError, "COLLECTOR_SOURCE_BINDING"):
                        bridge.validate_collector_source(pins, declared, root)

    def test_other_source_keeps_the_current_collector_check(self):
        # Binding-only synthetic pins do not represent another native execution.
        pins = replace(PINS, native_source="f" * 40, native_tree="e" * 40)
        current_sha = bridge.gate.sha256((bridge.NATIVE / "collect_native.py").read_bytes())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertIsNone(bridge.validate_collector_source(pins, current_sha, root))
            self.fixture(root)
            with self.assertRaisesRegex(ValueError, "COLLECTOR_SOURCE_BINDING"):
                bridge.validate_collector_source(pins, self.sha256, root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
