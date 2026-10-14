#!/usr/bin/env python3
"""Mutate actual config inputs and require fail-closed declaration checks."""
import copy
import json
import pathlib
import tempfile
import unittest

from check_activation_boundary import ActivationError, BINDINGS, ROOT, check


class ActivationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.original = {}
        for relative in (*BINDINGS, 'config/activation-policy-v1.json'):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            self.original[relative] = (ROOT / relative).read_text()
            path.write_text(self.original[relative])

    def test_actual_experimental_declarations(self):
        self.assertEqual(check(self.root)['scope'], 'declaration-consistency-only')

    def test_each_binding_rejects_enabled_coerced_missing_and_null(self):
        for relative, keys in BINDINGS.items():
            for key in keys:
                for replacement in (True, 0, None, 'false', 'missing'):
                    with self.subTest(path=relative, key=key, replacement=replacement):
                        data = json.loads(self.original[relative])
                        target = data
                        parts = key.split('.')
                        for component in parts[:-1]:
                            target = target[component]
                        if replacement == 'missing':
                            del target[parts[-1]]
                        else:
                            target[parts[-1]] = replacement
                        path = self.root / relative
                        path.write_text(json.dumps(data))
                        try:
                            with self.assertRaises(ActivationError):
                                check(self.root)
                        finally:
                            path.write_text(self.original[relative])

    def test_policy_cannot_delete_binding_or_evidence(self):
        relative = 'config/activation-policy-v1.json'
        policy = json.loads(self.original[relative])
        for field in ('required_false_bindings', 'required_evidence_before_promotion'):
            with self.subTest(field=field):
                data = copy.deepcopy(policy)
                data[field].clear()
                (self.root / relative).write_text(json.dumps(data))
                with self.assertRaises(ActivationError):
                    check(self.root)

    def test_duplicate_activation_key_rejected(self):
        relative = 'config/consensus-mainline.json'
        text = self.original[relative].replace('"runtime_implemented": false', '"runtime_implemented": true, "runtime_implemented": false')
        (self.root / relative).write_text(text)
        with self.assertRaises(ActivationError):
            check(self.root)

    def test_missing_file_rejected(self):
        (self.root / 'config/pon/work-profile-v1.json').unlink()
        with self.assertRaises(OSError):
            check(self.root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
