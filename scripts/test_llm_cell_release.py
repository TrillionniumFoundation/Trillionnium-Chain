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


class OrdinaryCellContentConfigTests(unittest.TestCase):
    def fixture(self, root):
        # Untrusted declaration/config bytes only, never a qualified model Pin.
        value = {key: "11" * 32 for key in ("family_file_sha256 artifact_sha256 "
            "adapter_digest contract_digest backbone_digest tokenizer_digest "
            "execution_profile_sha256 tcr1_id").split()}
        value.update(schema=release.SCHEMA, scope="controlled-native-load-only",
            profile=release.PROFILE, operation_id="original-operation", generation=3,
            family_id="smollm2-135m-cpu-dev-v1", model="untrusted-model", revision="untrusted-revision",
            sources=[], actions=[], tcr1_hex="", members=[dict(name=name,
                manifest_id="22" * 32, payload_sha256="33" * 32, size=1, tcm1_hex="")
                for name in release.ROSTER])
        sidecar = root / "sidecar.json"
        sidecar.write_bytes(release.canonical(value))
        host = root / "host.json"
        host.write_bytes(release.canonical(dict(schema="hepta-smollm-cognitive-host-v1")))
        args = SimpleNamespace(sidecar=sidecar, sidecar_sha256=release.digest(sidecar.read_bytes()),
            host_config=host, host_config_sha256=release.digest(host.read_bytes()), output=root / "export")
        return args, value

    def test_actual_export_pins_fresh_content_and_original_host_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            args, value = self.fixture(Path(directory).resolve())
            original = args.sidecar.read_bytes()
            result = release.prepare_ordinary_host_config_v2(args)
            config = json.loads(Path(result["path"]).read_bytes())
            content_path = Path(config["cell_content"]["path"])
            content = content_path.read_bytes()
            self.assertEqual(config, dict(schema="hepta-smollm-cognitive-cell-host-v2",
                host=dict(path=str(args.host_config), sha256=args.host_config_sha256),
                cell_content=dict(path=str(content_path), sha256=release.digest(content)),
                operation_id=value["operation_id"]))
            self.assertEqual(json.loads(content), dict(value,
                schema="hepta-smollm-ordinary-cell-content-v1", scope="qualified-host-content-only"))
            self.assertEqual(result["sha256"], release.digest(Path(result["path"]).read_bytes()))
            with self.assertRaises(FileExistsError):
                release.prepare_ordinary_host_config_v2(args)
            self.assertEqual(content_path.read_bytes(), content)
            self.assertEqual(args.sidecar.read_bytes(), original)

    def test_rehashed_bad_domain_operation_roster_or_authority_fields_refuse_before_output(self):
        changes = [("schema", "hepta-smollm-ordinary-cell-content-v1"),
            ("scope", "qualified-host-content-only"), ("installation_authorized", True),
            ("operation_id", ""), ("operation_id", "has space"), ("operation_id", "é")]
        for key, changed in changes + [("members", []), ("members", "duplicate")]:
            with self.subTest(field=key, value=changed), tempfile.TemporaryDirectory() as directory:
                args, value = self.fixture(Path(directory).resolve())
                value[key] = [value["members"][0]] * 11 if changed == "duplicate" else changed
                args.sidecar.write_bytes(release.canonical(value))
                args.sidecar_sha256 = release.digest(args.sidecar.read_bytes())
                with self.assertRaises(ValueError):
                    release.prepare_ordinary_host_config_v2(args)
                self.assertFalse(args.output.exists())

    def test_actual_input_change_and_wrong_pin_refuse_before_output(self):
        for kind in ("changed-content", "wrong-host-hash"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                args, _ = self.fixture(Path(directory).resolve())
                if kind == "changed-content":
                    args.sidecar.write_bytes(args.sidecar.read_bytes() + b"\n")
                else:
                    args.host_config_sha256 = "00" * 32
                with self.assertRaises(ValueError):
                    release.prepare_ordinary_host_config_v2(args)
                self.assertFalse(args.output.exists())


if __name__ == "__main__":
    from test_llm_ordinary_action_catalog import OrdinaryCatalogTests

    unittest.main()
