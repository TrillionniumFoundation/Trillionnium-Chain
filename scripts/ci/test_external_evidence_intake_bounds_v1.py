#!/usr/bin/env python3
"""Strict integer/resource/diagnostic-order regressions, never real evidence."""
from __future__ import annotations

import check_external_evidence_v1 as intake
import unittest

from test_external_evidence_intake_v1 import ExternalEvidenceTests, SCOPES, submission


class EvidenceBoundsTests(ExternalEvidenceTests):
    # Only collect the dedicated tests from this subclass, not inherited tests.
    def test_counter_types_are_not_booleans_floats_strings_or_containers(self):
        cases = {
            'EXT-REVIEW-001': ['replayed_p0_mutants'],
            'EXT-G1-CAMPAIGN-001': ['physical_hosts', 'operators', 'custody_domains',
                                   'conflicting_finality_count', 'double_sign_count'],
            'EXT-ANCHOR-HSM-001': ['rollback_mutants_rejected', 'cloned_namespace_mutants_rejected'],
            'EXT-AUDIT-001': ['open_critical', 'open_high'],
            'EXT-SOAK-ACTIVATION-001': ['chaos_72h_seconds', 'public_testnet_7d_seconds',
                                      'production_candidate_30d_seconds'],
        }
        for blocker, fields in cases.items():
            for field in fields:
                for value in [False, True, 0.0, 9999999.5, '0', [], {}, None, -1, 2**128]:
                    with self.subTest(blocker=blocker, field=field, value=value):
                        row = submission(blocker)
                        row['claims'][field] = value
                        label = intake.ROOT / 'type-regression.json'
                        with self.assertRaises(intake.EvidenceError):
                            intake.validate_common(label, row, set(SCOPES))
                            intake.validate_specific(label, row)

    def test_cli_false_zero_counter_is_rejected(self):
        row = submission('EXT-AUDIT-001')
        row['claims']['open_critical'] = False
        self.write(row)
        self.assert_invalid(self.run_checker())

    def test_node_counts_reject_duplicates_and_nonintegers_without_traceback(self):
        for counts in [None, {}, '4,7,31,100', [], [4, 7, 31, 100, 4],
                       [4.0, 7, 31, 100], [4, 7, 31, 100, False],
                       [4, 7, 31, 100, {}], [4, 7, 31, 100, []],
                       [4, 7, 31, 100, -1], list(range(1, 258))]:
            with self.subTest(counts=counts):
                row = submission('EXT-G1-CAMPAIGN-001')
                row['claims']['node_counts'] = counts
                self.write(row)
                self.assert_invalid(self.run_checker())

    def test_malformed_result_is_a_controlled_rejection(self):
        for result in [[], {}, None, True, 'approved']:
            with self.subTest(result=result):
                row = submission()
                row['result'] = result
                self.write(row)
                self.assert_invalid(self.run_checker())

    def test_document_and_collection_limits(self):
        row = submission()
        row['notes'] = 'x' * (1024 * 1024)
        self.write(row)
        self.assert_invalid(self.run_checker())
        for field in ['artifacts', 'signatures']:
            row = submission()
            row[field] *= 257
            self.write(row)
            self.assert_invalid(self.run_checker())

    def test_deep_json_is_a_controlled_rejection(self):
        (self.directory / 'evidence.json').write_text('{"a":' + '['*2000 + '0' + ']'*2000 + '}')
        self.assert_invalid(self.run_checker())

    def test_duplicate_signature_names_do_not_add_a_role(self):
        row = submission()
        row['signatures'].append(row['signatures'][0].copy())
        self.write(row)
        self.assert_invalid(self.run_checker())

    def test_latest_rejected_is_by_time_not_filename(self):
        old = submission()
        old['result'] = 'rejected'
        old['evidence_id'] = 'rejected-old'
        new = submission()
        new['result'] = 'rejected'
        new['evidence_id'] = 'rejected-new'
        new['started_at'] = '2026-02-01T00:00:00Z'
        new['ended_at'] = '2026-03-04T00:00:00Z'
        self.write(new, 'aaa-new.json')
        self.write(old, 'zzz-old.json')
        report = self.report(self.run_checker())
        self.assertEqual(report['rejected_latest']['EXT-REVIEW-001'], 'rejected-new')
        self.assert_unaccepted(report)

    def test_latest_rejected_tie_uses_evidence_id(self):
        for name, identifier in [('aaa.json', 'rejected-z'), ('zzz.json', 'rejected-a')]:
            row = submission()
            row['result'] = 'rejected'
            row['evidence_id'] = identifier
            self.write(row, name)
        report = self.report(self.run_checker())
        self.assertEqual(report['rejected_latest']['EXT-REVIEW-001'], 'rejected-z')
        self.assert_unaccepted(report)


def load_tests(loader, suite, pattern):
    names = sorted(name for name in EvidenceBoundsTests.__dict__ if name.startswith('test_'))
    return unittest.TestSuite(EvidenceBoundsTests(name) for name in names)


if __name__ == '__main__':
    unittest.main(verbosity=2)
