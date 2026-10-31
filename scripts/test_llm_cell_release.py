#!/usr/bin/env python3
"""Refusal controls for the draft Cell handoff; no model or native qualification."""
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import llm_cell_release as release


class ControlledCellDeclarationTests(unittest.TestCase):
    def test_wrong_roster_or_parent_identity_cannot_start_export(self):
        members = [dict(name=name) for name in release.ROSTER]
        parent = dict(generation=1, operation_id="controlled-operation")
        candidates = [(members[:-1], parent),
            (members[:-1] + [members[0]], parent)]
        for field, values in (("generation", (True, 0, -1, 1 << 64, 1.0)),
                              ("operation_id", ("", "has space", "é", "x" * 129))):
            for value in values:
                changed = dict(parent, **{field: value})
                candidates.append((members, changed))
        with mock.patch.object(release.subprocess, "run") as run:
            for roster, identity in candidates:
                with self.subTest(identity=identity, roster=len(roster)):
                    with self.assertRaises(ValueError):
                        release.prepare_sidecar(None, None, identity, None,
                            roster, None, None, None)
            run.assert_not_called()

    def test_create_only_write_cannot_overwrite_prior_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence"
            release.write_new(path, b"original failure")
            with self.assertRaises(FileExistsError):
                release.write_new(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original failure")


class ControlledCellReadbackTests(unittest.TestCase):
    def fixture(self, root):
        output = root / "output"
        output.mkdir()
        native = output / "controlled-original-native"
        native.mkdir()
        parent = root / "parent.json"
        parent.write_text(json.dumps(dict(file_sha256="11" * 32, generation=3)))
        sidecar = dict(path=str(root / "sidecar"), sha256="22" * 32,
            commitment="33" * 32)
        report = dict(schema="hepta-smollm-controlled-cell-loaded-readback-v1",
            sidecar_sha256=sidecar["sha256"], closure_commitment=sidecar["commitment"],
            actual_ready_sha256="44" * 32, actual_parameters_sha256="11" * 32,
            actual_generation=3, original_final_use_claims=3,
            controlled_load_query_unload_observed=True,
            product_artifact_installed=False, ordinary_cognitive_context_qualified=False,
            public_reward_eligible=False)
        args = SimpleNamespace(output=output, hepta=root / "hepta", python=root / "python",
            chain=root / "chain", hepta_target=root / "target", just=root / "just")
        return args, parent, sidecar, report, native / "controlled-cell-loaded-readback-v1.json"

    def consume(self, args, parent, sidecar, *, returncode=0, identities=None):
        identity = dict(head="55" * 20, tree="66" * 20)
        with mock.patch.object(release, "git_identity",
                side_effect=identities or [identity, identity]), \
                mock.patch.object(release.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], returncode)) as run:
            result = release.consume_controlled(args, parent, sidecar)
        return result, run

    def test_single_bounded_reads_and_fixed_original_case_grant_no_installation(self):
        # Subprocess/source checks are mocked: this is a parser/orchestration
        # control and is explicitly not evidence of an actual native load.
        with tempfile.TemporaryDirectory() as directory:
            args, parent, sidecar, report, path = self.fixture(Path(directory))
            path.write_bytes(release.canonical(report))
            with mock.patch.object(release, "read_regular", wraps=release.read_regular) as read:
                result, run = self.consume(args, parent, sidecar)
            self.assertEqual(read.call_args_list,
                [mock.call(parent, 2 * 1024 * 1024), mock.call(path, 65_536)])
            self.assertEqual(result["scope"], "CONTROLLED_LOAD_ONLY_NOT_I10_OR_INSTALLATION")
            self.assertEqual(result["readback_sha256"], release.digest(path.read_bytes()))
            command = run.call_args.args[0]
            self.assertEqual(command[1:4], ["test", "--locked", "--offline"])
            self.assertEqual(command[-1], "test(=smollm_neural_read::tests::native::real_cell_release_original_signed_load_query_and_terminal_unload)")
            self.assertNotIn("timeout", run.call_args.kwargs)
            self.assertIs(report["product_artifact_installed"], False)
            config = json.loads((args.output / "controlled-cell-native-v1.json").read_bytes())
            self.assertEqual(config["native"]["parent_sha256"], release.digest(parent.read_bytes()))
            self.assertEqual(config["schema"], "hepta-smollm-controlled-cell-native-check-v1")

    def test_rebound_or_promoted_readbacks_are_rejected(self):
        mutations = [("sidecar_sha256", "00" * 32), ("closure_commitment", "00" * 32),
            ("actual_parameters_sha256", "00" * 32), ("actual_generation", True),
            ("actual_generation", 3.0), ("original_final_use_claims", 3.0),
            ("controlled_load_query_unload_observed", 1), ("actual_ready_sha256", ""),
            ("actual_ready_sha256", "G" * 64), ("unexpected", False)]
        for flag in ("product_artifact_installed", "ordinary_cognitive_context_qualified",
                     "public_reward_eligible"):
            mutations.extend((flag, value) for value in (True, 0, None, "false"))
        for key, value in mutations:
            with self.subTest(field=key, value=value), tempfile.TemporaryDirectory() as directory:
                args, parent, sidecar, report, path = self.fixture(Path(directory))
                report[key] = value
                path.write_bytes(release.canonical(report))
                with self.assertRaises(ValueError):
                    self.consume(args, parent, sidecar)

    def test_duplicate_readback_keys_are_rejected_even_when_values_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            args, parent, sidecar, report, path = self.fixture(Path(directory))
            raw = release.canonical(report)
            path.write_bytes(b'{"actual_generation":3,' + raw[1:])
            with self.assertRaisesRegex(ValueError, "DUPLICATE"):
                self.consume(args, parent, sidecar)

    def test_failed_command_or_source_change_cannot_import_readback(self):
        for returncode, identities in ((1, None), (0, [dict(head="a"), dict(head="b")])):
            with self.subTest(returncode=returncode), tempfile.TemporaryDirectory() as directory:
                args, parent, sidecar, report, path = self.fixture(Path(directory))
                path.write_bytes(release.canonical(report))
                with mock.patch.object(release, "read_regular", wraps=release.read_regular) as read:
                    with self.assertRaises(RuntimeError):
                        self.consume(args, parent, sidecar, returncode=returncode,
                            identities=identities)
                self.assertEqual(read.call_args_list, [mock.call(parent, 2 * 1024 * 1024)])

    def test_parent_bound_and_symlink_refuse_before_native_command(self):
        for kind in ("oversize", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                args, parent, sidecar, _, _ = self.fixture(Path(directory))
                if kind == "oversize":
                    with parent.open("r+b") as stream:
                        stream.truncate(2 * 1024 * 1024 + 1)
                else:
                    actual = parent.with_suffix(".original")
                    parent.rename(actual)
                    parent.symlink_to(actual)
                with mock.patch.object(release, "git_identity", return_value={}), \
                        mock.patch.object(release.subprocess, "run") as run:
                    with self.assertRaises(ValueError):
                        release.consume_controlled(args, parent, sidecar)
                    run.assert_not_called()

    def test_readback_bound_and_symlink_cannot_supply_receipt(self):
        for kind in ("oversize", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                args, parent, sidecar, report, path = self.fixture(Path(directory))
                path.write_bytes(release.canonical(report))
                if kind == "oversize":
                    with path.open("r+b") as stream:
                        stream.truncate(65_537)
                else:
                    actual = path.with_suffix(".original")
                    path.rename(actual)
                    path.symlink_to(actual)
                with self.assertRaises(ValueError):
                    self.consume(args, parent, sidecar)


if __name__ == "__main__":
    unittest.main()
