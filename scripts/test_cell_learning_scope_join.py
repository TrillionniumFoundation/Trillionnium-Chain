"""Scoped reader controls over unchanged original native learning records.

Root profiles below are synthetic parser fixtures, not original Root exports.
Their JSON layout follows the fixed Hepta source 71738345326b98d88b738250d2b84ecbcb466eb8.
The unchanged historical checkpoint corpus comes from Chain e2a02f9271b49f146e70806c8a66e161b5973971;
it is not a native execution on that later Hepta candidate.
Predicate tests vary decoded objects without issuing new native checkpoints,
signatures, permissions or historical custody claims.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import cell_adoption_readback as native
import cell_learning_completion_join as completion
import cell_learning_iteration_join as iteration
import cell_learning_scope_join as scoped

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "evidence/hepta-real-native-adoption-20261108/chain-reader"
FILES = ("initial.bin", "selection.bin", "completed.bin", "readback.json", "freeze.json", "expected.json")
ORIGINAL_SHA256 = {
    "adopt-v1": (
        "ad8cab25a363c0ef8555c1178edd9fddb202c8f5c916a026285f79b8bec8a124",
        "3c4060363122831d1279133cedfefcdc9d795d4653ae56287bc962d7a7b67aa9",
        "49687e0ece90dceb6409978616700c0b32ec342631a1941994ae3b7a886a7496",
        "a11c43e68721199443ca265c35d5197f6883a732b04ae0f25e480cb9ce6adc5b",
        "00667a2e0a60f009702aeb589da642382b1a533ed0ad77f77a807bd3c472511d",
        "1fdc83d8411fa1b9c4e95f1814ae4a32df07b977e754a8676a3ad5ccf351e810"),
    "no-update-v9": (
        "0ba9420cae7fce004f4ef9bfcd9f8a0cd06c6a39b20e503320930493216e70ca",
        "21ba8a9895ca7ae052dde45d7547b50e3b656e3c99eb50e004e1c60dd3967b62",
        "c890ca0ba1f5b5190e33bc93a0947c98a5cbfc4f77ad4f65ac8f428274ab222f",
        "fdfc6d1bd390a2d6f37ac563d7fe49886e2ac0492b4dff47af95e32f403162a9",
        "ae6fbb4ea59fcf2c9ac2fbba5976501b27a7f5bc34838737a8fa99c05eb6bf69",
        "d670b3094b47e3807c8ab7a093359ef8e16af3edad9368e78f517897e0345f14"),
}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def fixture_profile(initial, snapshot, scope="cell"):
    _, replay = iteration.decode_native_learning_checkpoint(initial)
    candidate = next(r["observation"]["candidate"] for r in snapshot["receipts"] if r["observation"]["tag"] == 2)
    rule = candidate["training_lineage"]["update_rule"]
    description = dict(update_scope=scope, update_rule=rule,
        binding=hashlib.sha256(b"hepta.learning.frozen-update-scope.v2\0" + bytes.fromhex(replay["initial_head"]) +
                               bytes([1 if scope == "cell" else 2]) + bytes.fromhex(rule)).hexdigest())
    return dict(schema_version=2, identity_digest="11" * 32, writer_proof_digest="22" * 32,
                initial_snapshot=base64.b64encode(initial).decode().rstrip("="), update_scope=description)


class ScopedCompletedLearningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {}
        for case, expected in ORIGINAL_SHA256.items():
            raw = [(FIXTURES / case / name).read_bytes() for name in FILES]
            if tuple(map(native.sha, raw)) != expected:
                raise AssertionError("original source-pinned native records changed: " + case)
            cls.cases[case] = raw

    def inputs(self, case="adopt-v1"):
        initial, selection, completed, readback, frozen, expected = self.cases[case]
        snapshot, replay = iteration.decode_native_learning_checkpoint(completed)
        return (initial, selection, completed, readback, json.loads(frozen), json.loads(expected), snapshot, replay)

    def review(self, case="adopt-v1", profile=None, profile_pin=None):
        initial, selection, completed, readback, frozen, expected, snapshot, _ = self.inputs(case)
        raw = wire(fixture_profile(initial, snapshot)) if profile is None else profile
        return scoped.review_native_scoped_learning_completion(selection, completed, readback, raw,
            expected_root_profile_sha256=native.sha(raw) if profile_pin is None else profile_pin,
            expected_selection_sha256=native.sha(selection), expected_completed_sha256=native.sha(completed),
            expected_readback_sha256=native.sha(readback), frozen=frozen, expected=expected)

    def test_original_adopt_and_no_update_joins_preserve_every_authority_limit(self):
        for case in self.cases:
            with self.subTest(case=case):
                _, selection, completed, readback, frozen, expected, _, _ = self.inputs(case)
                result = self.review(case)
                scope_result = result.pop("root_scope_review")
                original = completion.review_native_learning_completion(selection, completed, readback,
                    expected_selection_sha256=native.sha(selection), expected_completed_sha256=native.sha(completed),
                    expected_readback_sha256=native.sha(readback), frozen=frozen, expected=expected)
                result.update(schema=original["schema"], scope=original["scope"])
                self.assertEqual(result, original)
                self.assertEqual(scope_result["operation_id"], frozen["request"]["operation_id"])
                self.assertEqual(scope_result["training_receipts_checked"], 1)
                self.assertFalse(scope_result["root_profile_origin_authenticated"])
                self.assertFalse(scope_result["tensor_update_mask_verified"])

    def test_original_profile_bytes_need_their_independent_pin(self):
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_PROFILE_PIN"):
            self.review(profile_pin="ab" * 32)
        for raw in (b"x" * (scoped.MAX_PROFILE + 1), bytearray(b"{}")):
            with self.subTest(kind=type(raw).__name__), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_PROFILE_LIMIT"):
                self.review(profile=raw)

    def test_legacy_unknown_or_unscoped_profiles_are_explicit_refusals(self):
        initial, _, _, _, _, _, snapshot, _ = self.inputs()
        profile = fixture_profile(initial, snapshot)
        for version in (1, True, "2"):
            changed = dict(profile, schema_version=version)
            with self.subTest(version=version), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_SCOPE_VERSION"):
                self.review(profile=wire(changed))
        for field in profile:
            changed = dict(profile); del changed[field]
            with self.subTest(field=field), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_PROFILE_FIELDS"):
                self.review(profile=wire(changed))
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_SCOPE_FIELDS"):
            self.review(profile=wire(dict(profile, update_scope=None)))

    def test_scope_kind_binding_and_original_rule_are_all_required(self):
        initial, _, _, _, _, _, snapshot, _ = self.inputs()
        profile = fixture_profile(initial, snapshot)
        changes = (("update_scope", "base_release", "LEARNING_ROOT_SCOPE_KIND"),
                   ("binding", "ab" * 32, "LEARNING_ROOT_SCOPE_BINDING"),
                   ("update_rule", "0" * 64, "LEARNING_ROOT_SCOPE_RULE"))
        for field, value, code in changes:
            changed = copy.deepcopy(profile); changed["update_scope"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(native.ReadbackRefusal, code):
                self.review(profile=wire(changed))
        changed_snapshot = copy.deepcopy(snapshot)
        changed_snapshot["receipts"][2]["observation"]["candidate"]["training_lineage"]["update_rule"] = "ab" * 32
        changed = fixture_profile(initial, changed_snapshot)
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_SCOPE_RULE"):
            self.review(profile=wire(changed))

    def test_json_duplicate_fields_are_refused_before_scope_interpretation(self):
        initial, _, _, _, _, _, snapshot, _ = self.inputs()
        profile = fixture_profile(initial, snapshot)
        original = wire(profile)
        duplicates = (original[:-1] + b',"schema_version":2}',
                      original.replace(b'"update_scope":"cell"', b'"update_scope":"cell","update_scope":"cell"', 1))
        for raw in duplicates:
            with self.subTest(raw=raw[-32:]), self.assertRaisesRegex(native.ReadbackRefusal, "NATIVE_DUPLICATE_FIELD"):
                self.review(profile=raw)

    def test_scope_types_do_not_accept_boolean_or_collection_aliases(self):
        initial, _, _, _, _, _, snapshot, _ = self.inputs()
        profile = fixture_profile(initial, snapshot)
        for value in (True, False, 1, 2, [], {}, None):
            changed = copy.deepcopy(profile)
            changed["update_scope"]["update_scope"] = value
            with self.subTest(value=value), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_SCOPE_KIND"):
                self.review(profile=wire(changed))
        for value in (True, False, 1, [], "cell"):
            with self.subTest(description=value), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_SCOPE_FIELDS"):
                self.review(profile=wire(dict(profile, update_scope=value)))

    def test_initial_profile_cannot_be_late_foreign_or_legacy(self):
        initial, selection, _, _, _, _, snapshot, _ = self.inputs()
        profile = fixture_profile(initial, snapshot)
        invalid = ((self.cases["no-update-v9"][0], "LEARNING_ROOT_ORIGINAL_ITERATION"),
                   (selection, "LEARNING_FREEZE_NOT_INITIAL"),
                   (b"HEPLCP01" + initial[8:], "LEARNING_CHECKPOINT_VERSION"))
        for raw, code in invalid:
            changed = dict(profile, initial_snapshot=base64.b64encode(raw).decode().rstrip("="))
            with self.subTest(code=code), self.assertRaisesRegex(native.ReadbackRefusal, code):
                self.review(profile=wire(changed))
        for value in ("not base64!", profile["initial_snapshot"] + "="):
            with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_INITIAL_BASE64"):
                self.review(profile=wire(dict(profile, initial_snapshot=value)))

    def test_selected_717_layout_refuses_b8e_and_mixed_scope_fields(self):
        for case in self.cases:
            initial, _, _, _, _, _, snapshot, _ = self.inputs(case)
            profile = fixture_profile(initial, snapshot)
            for mixed in (False, True):
                changed = copy.deepcopy(profile)
                description = changed["update_scope"]
                description["scope"] = description["update_scope"]
                if not mixed:
                    del description["update_scope"]
                with self.subTest(case=case, mixed=mixed), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_SCOPE_FIELDS"):
                    self.review(case, profile=wire(changed))

    def test_each_preserved_component_is_checked_even_after_no_update(self):
        for case in self.cases:
            initial, _, _, _, frozen, _, snapshot, replay = self.inputs(case)
            raw = wire(fixture_profile(initial, snapshot))
            components = snapshot["request"]["selected_bundle"]["components"]
            for field in set(components) - {"heads", "calibration", "composition", "cell_adapter"}:
                changed = copy.deepcopy(snapshot)
                changed["receipts"][2]["observation"]["candidate"]["components"][field] = "ab" * 32
                with self.subTest(case=case, field=field), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_SCOPE_COMPONENTS"):
                    scoped._review_scope(raw, native.sha(raw), changed, replay, frozen)

    def test_cell_and_organ_predicates_preserve_the_opposite_adapter(self):
        initial, _, _, _, frozen, _, snapshot, replay = self.inputs()
        for scope in ("cell", "organ"):
            changed = copy.deepcopy(snapshot)
            components = changed["receipts"][2]["observation"]["candidate"]["components"]
            components.update(snapshot["request"]["selected_bundle"]["components"])
            for field in ("heads", "calibration", "composition", scope + "_adapter"):
                components[field] = "ab" * 32
            raw = wire(fixture_profile(initial, snapshot, scope))
            result = scoped._review_scope(raw, native.sha(raw), changed, replay, frozen)
            self.assertEqual(result["allowed_changed_components"], sorted(("heads", "calibration", "composition", scope + "_adapter")))
            components[("organ" if scope == "cell" else "cell") + "_adapter"] = "cd" * 32
            with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_SCOPE_COMPONENTS"):
                scoped._review_scope(raw, native.sha(raw), changed, replay, frozen)

    def test_cli_requires_the_original_profile_and_its_pin(self):
        initial, _, _, _, _, _, snapshot, _ = self.inputs()
        with tempfile.TemporaryDirectory() as temporary:
            profile_path = Path(temporary) / "synthetic-root-profile.json"
            profile_path.write_bytes(wire(fixture_profile(initial, snapshot)))
            command = [sys.executable, str(ROOT / "scripts/cell_learning_scope_join.py")]
            names = ("selection-checkpoint", "completed-checkpoint", "readback", "freeze", "expected")
            for name, filename in zip(names, FILES[1:]):
                path = FIXTURES / "adopt-v1" / filename
                command += ["--" + name, str(path), "--" + name + "-sha256", native.sha(path.read_bytes())]
            command += ["--root-profile", str(profile_path), "--root-profile-sha256", native.sha(profile_path.read_bytes())]
            run = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout), self.review())
            for omitted in ("--root-profile", "--root-profile-sha256"):
                index = command.index(omitted)
                run = subprocess.run(command[:index] + command[index + 2:], capture_output=True, timeout=20)
                self.assertNotEqual(run.returncode, 0)
            profile = fixture_profile(initial, snapshot)
            legacy = copy.deepcopy(profile)
            legacy["update_scope"]["scope"] = legacy["update_scope"].pop("update_scope")
            mixed = copy.deepcopy(profile)
            mixed["update_scope"]["scope"] = "cell"
            boolean = copy.deepcopy(profile)
            boolean["update_scope"]["update_scope"] = True
            duplicate = wire(profile).replace(b'"update_scope":"cell"',
                b'"update_scope":"cell","update_scope":"cell"', 1)
            for malformed in (wire(legacy), wire(mixed), wire(boolean), duplicate):
                profile_path.write_bytes(malformed)
                changed_command = list(command)
                changed_command[changed_command.index("--root-profile-sha256") + 1] = native.sha(malformed)
                run = subprocess.run(changed_command, capture_output=True, timeout=20)
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, b"")


if __name__ == "__main__":
    unittest.main()
