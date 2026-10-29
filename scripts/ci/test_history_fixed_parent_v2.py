#!/usr/bin/env python3
"""Strict predicate controls; real manager/lease controls run separately in CI."""
import copy
import unittest

import history_fixed_parent_v2 as fixture


class FixedParentControls(unittest.TestCase):
    def fresh(self):
        return {"Id": fixture.FIXED_UNIT, "Names": fixture.FIXED_UNIT,
                "LoadState": "loaded", "FragmentPath": "", "DropInPaths": "",
                "ActiveState": "inactive", "SubState": "dead", "Transient": "no",
                "ControlGroup": "", "Job": ""}

    def test_unconfigured_implicit_loaded_slice_is_distinct_from_owned_unit(self):
        state = self.fresh()
        fixture.validate_fresh(fixture.FIXED_UNIT, state, [], False)
        state["LoadState"] = "not-found"
        fixture.validate_fresh(fixture.FIXED_UNIT, state, [], False)

    def test_every_foreign_configuration_and_activity_boundary_is_refused(self):
        mutations = {"Id": "foreign.slice", "Names": fixture.FIXED_UNIT + " alias.slice",
                     "LoadState": "masked", "FragmentPath": "/etc/systemd/system/owned.slice",
                     "DropInPaths": "/run/systemd/system/slice.d/override.conf",
                     "ActiveState": "active", "SubState": "failed", "Transient": "yes",
                     "ControlGroup": "/" + fixture.FIXED_UNIT, "Job": "51"}
        for field, replacement in mutations.items():
            state = self.fresh()
            state[field] = replacement
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                fixture.validate_fresh(fixture.FIXED_UNIT, state, [], False)
        for field in self.fresh():
            state = self.fresh()
            del state[field]
            with self.subTest(missing=field), self.assertRaises(RuntimeError):
                fixture.validate_fresh(fixture.FIXED_UNIT, state, [], False)
        for path in ("/run/systemd/system/trnmponpublic.slice", "/etc/systemd/system/slice.d",
                     "/etc/systemd/system/default.target.wants/trnmponpublic.slice"):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                fixture.validate_fresh(fixture.FIXED_UNIT, self.fresh(), [path], False)
        with self.assertRaises(RuntimeError):
            fixture.validate_fresh(fixture.FIXED_UNIT, self.fresh(), [], True)

    def test_cleanup_copy_cannot_invent_root_authority_or_another_owner(self):
        record = {"schema": "history-fixed-parent-root-lease-v2", "owner": "40728166375.1",
                  "unit": fixture.FIXED_UNIT, "path": str(fixture.UNIT_ROOT / fixture.FIXED_UNIT),
                  "sha256": fixture.SOURCE_SHA256, "uid": 0, "token": "a" * 64,
                  "device": 8, "inode": 9, "exclusive_creation": True}
        fixture.validate_copy(record, copy.deepcopy(record), "40728166375.1", fixture.FIXED_UNIT)
        for field in record:
            changed = copy.deepcopy(record)
            changed[field] = None
            with self.subTest(copy_field=field), self.assertRaises(RuntimeError):
                fixture.validate_copy(record, changed, "40728166375.1", fixture.FIXED_UNIT)
        for field in ("schema", "owner", "unit", "path", "sha256", "uid", "token"):
            changed = copy.deepcopy(record)
            changed[field] = "foreign"
            with self.subTest(authority_field=field), self.assertRaises(RuntimeError):
                fixture.validate_copy(changed, changed, "40728166375.1", fixture.FIXED_UNIT)
        with self.assertRaises(RuntimeError):
            fixture.validate_copy(record, record, "40728166375.2", fixture.FIXED_UNIT)

    def test_only_fixed_or_derived_numeric_run_units_are_addressable(self):
        self.assertEqual(fixture.probe_unit("40728166375.1"), "trnmponprobe40728166375a1.slice")
        for value in ("", "1", "1/2", "../foreign", "1.0", "0.1", "1.1.service", "1.1\n", "1.1.1"):
            with self.subTest(owner=value), self.assertRaises(RuntimeError):
                fixture.probe_unit(value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
