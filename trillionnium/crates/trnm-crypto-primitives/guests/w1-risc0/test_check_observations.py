"""Research-reader boundaries; these controls do not generate or qualify a proof."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_observations as check


HERE = Path(__file__).resolve().parent


class ManifestBoundaries(unittest.TestCase):
    def setUp(self):
        self.pinned = check.load(HERE / "backend-manifest.json")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name)

    def write(self, value):
        path = self.out / "backend-manifest.json"
        path.write_text(json.dumps(value))
        return path

    def test_actual_source_manifest_is_the_only_profile_authority(self):
        check.validate_manifest(self.pinned)
        reordered = dict(reversed(list(self.pinned.items())))
        path = self.write(reordered)
        path.write_text(json.dumps(reordered, indent=4) + "\n")
        check.validate_manifest(check.load(path))

    def test_each_source_field_is_bound_including_schema_algorithm_image_and_security(self):
        for field, original in self.pinned.items():
            changed = deepcopy(self.pinned)
            if type(original) is bool:
                changed[field] = not original
            elif type(original) is int:
                changed[field] = original + 1
            elif isinstance(original, str):
                changed[field] = original + "-changed"
            elif isinstance(original, dict):
                changed[field]["unreviewed-source"] = "0" * 64
            else:
                changed[field] = "unreviewed"
            with self.subTest(field=field), self.assertRaises(ValueError):
                check.validate_manifest(changed)

    def test_source_map_cannot_drop_replace_or_add_a_guest_pin(self):
        field = "guest_source_sha256"
        name = next(iter(self.pinned[field]))
        for action in ("drop", "replace", "add"):
            changed = deepcopy(self.pinned)
            if action == "drop":
                del changed[field][name]
            elif action == "replace":
                changed[field][name] = "0" * 64
            else:
                changed[field]["new-source.rs"] = "0" * 64
            with self.subTest(action=action), self.assertRaises(ValueError):
                check.validate_manifest(changed)

    def test_missing_extra_and_numerically_equal_json_types_are_refused(self):
        changed = deepcopy(self.pinned)
        del changed["proof_commitment_hash"]
        extra = dict(self.pinned, new_authority=False)
        zero = dict(self.pinned, pq_128_security_qualified=0)
        real = dict(self.pinned, proof_fri_queries=float(self.pinned["proof_fri_queries"]))
        for value in (changed, extra, zero, real, [], None):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                check.validate_manifest(value)

    def test_manifest_is_checked_before_assets_in_build_and_full_paths(self):
        # No ELF or receipt exists. Even coordinated image/algorithm changes
        # must fail at the profile boundary, rather than reaching asset reads.
        for build_only in (False, True):
            for field, value in (("guest_image_id", "0" * 64),
                                 ("proof_receipt_kind", "Groth16"),
                                 ("proof_commitment_hash", "sha-256"),
                                 ("proof_fri_queries", 1)):
                self.write(dict(self.pinned, **{field: value}))
                args = ["check_observations.py", "--out", str(self.out)]
                if build_only:
                    args.append("--build-only")
                with self.subTest(build_only=build_only, field=field), \
                     patch.object(sys, "argv", args), \
                     self.assertRaisesRegex(ValueError, "manifest differs from checker source"):
                    check.main()

    def test_nested_unsupported_authority_requires_literal_false(self):
        for flag in check.UNSUPPORTED_AUTHORITY_FLAGS:
            path = self.write({"nested": [{flag: False}]})
            check.load(path)
            for invalid in (True, 0, 1, None, "false", [], {}):
                path = self.write({"nested": [{flag: invalid}]})
                with self.subTest(flag=flag, invalid=invalid), self.assertRaisesRegex(
                        ValueError, "unsupported research authority"):
                    check.load(path)

    def test_duplicate_json_and_nonfinite_numbers_do_not_hide_a_claim(self):
        path = self.out / "record.json"
        for raw in ('{"pq128_qualified":true,"pq128_qualified":false}',
                    '{"schema":"changed","schema":"original"}',
                    '{"nested":{"seconds":NaN}}', '{"seconds":Infinity}',
                    '{"seconds":-Infinity}', '{"seconds":1e999}', '{"seconds":-1e999}'):
            path.write_text(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                check.load(path)
        path.write_text('{"seconds":0.25}')
        self.assertEqual(check.load(path), {"seconds": 0.25})


if __name__ == "__main__":
    unittest.main()
