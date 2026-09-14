#!/usr/bin/env python3
"""Behavioral tests for advisory staffing and source-observation lineage."""
from copy import deepcopy
import sys
import unittest
sys.dont_write_bytecode = True
from development_metadata_v1 import (
    MetadataError, staffing_observation, validate_observed_stack, require_same_successor,
)


class MetadataTests(unittest.TestCase):
    def stack(self):
        return {'selected_successor_pr': 501, 'stack': [
            {'pr': 501, 'base_ref': 'main', 'head_ref': 'fix/chain-parent'},
            {'pr': 509, 'base_ref': 'fix/chain-parent', 'head_ref': 'fix/chain-child'},
        ]}

    def test_staffing_is_not_fixed(self):
        for n in (1, 8, 47, 48, 49, 100):
            self.assertEqual(staffing_observation([{'id': 'M00', 'staff_target': n}])['staff_target'], n)

    def test_missing_or_malformed_staffing_is_advisory(self):
        for v in (None, 0, True, -1, '2'):
            result = staffing_observation([{'id': 'M00', 'staff_target': v}])
            self.assertEqual(result['staff_target'], 0)
            self.assertEqual(len(result['warnings']), 1)

    def test_no_active_successor(self):
        validate_observed_stack({'selected_successor_pr': None, 'stack': []})
        require_same_successor(None, None, None)

    def test_any_connected_pr_numbers(self):
        validate_observed_stack(self.stack())
        require_same_successor(501, 501, 501)

    def test_child_cannot_be_root(self):
        data = self.stack(); data['selected_successor_pr'] = 509
        with self.assertRaises(MetadataError): validate_observed_stack(data)

    def test_disconnected_stack(self):
        data = self.stack(); data['stack'][1]['base_ref'] = 'main'
        with self.assertRaises(MetadataError): validate_observed_stack(data)

    def test_unselected_nonempty_stack(self):
        data = self.stack(); data['selected_successor_pr'] = None
        with self.assertRaises(MetadataError): validate_observed_stack(data)

    def test_invalid_pr_types(self):
        for value in (False, True, 0, -1, '501', 2**31):
            with self.subTest(value=value), self.assertRaises(MetadataError):
                require_same_successor(value, value)

    def test_disagreeing_projections(self):
        with self.assertRaises(MetadataError): require_same_successor(None, 501)

    def test_duplicate_pr(self):
        data = self.stack(); data['stack'][1]['pr'] = 501
        with self.assertRaises(MetadataError): validate_observed_stack(data)

    def test_invalid_stack_entries_fail_cleanly(self):
        for row in (None, [], 3, 'main', {}):
            data = self.stack(); data['stack'][0] = row
            with self.subTest(row=row), self.assertRaises(MetadataError): validate_observed_stack(data)

    def test_invalid_or_cyclic_branch(self):
        for head in ('main', 'fix/../escape', '-bad', 'fix//bad', 'fix/name.lock', 'fix/a.', 'fix/a..b'):
            data = self.stack(); data['stack'][0]['head_ref'] = head
            with self.subTest(head=head), self.assertRaises(MetadataError): validate_observed_stack(data)


if __name__ == '__main__':
    unittest.main(verbosity=2)
