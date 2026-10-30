#!/usr/bin/env python3
"""Synthetic Cargo-event admission controls; no build, native run or claim."""
from copy import deepcopy
import json
import os
from pathlib import Path
import resource
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'scripts/ci'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
import run_pon_native_io_component as component


class NativeAbiCargoAdmissionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print(json.dumps(dict(synthetic_Cargo_predicates_only=True,
            native_or_prepared_qualification=False,
            actual_nice=os.getpriority(os.PRIO_PROCESS, 0),
            actual_AS=list(resource.getrlimit(resource.RLIMIT_AS))), sort_keys=True))

    def fixture(self):
        binding = dict(passed_fd=6, actual_target='/proc/self/fd/6')
        out = binding['actual_target'] + '/release/build/trnm-sqlite-io-boundary-0123456789abcdef/out'
        event = dict(reason='build-script-executed',
            package_id='path+' + (component.ROOT/'trillionnium/crates/trnm-sqlite-io-boundary').as_uri() + '#0.1.0',
            linked_libs=['static=trnm_sqlite_layout_witness'],
            linked_paths=['native=' + out], cfgs=['trnm_sqlite_layout_witness'],
            env=[['TRNM_SQLITE3_BUILD_FENCE', 'sqlite-3.51.3-normal-native-linux-layout-v3'],
                 ['TRNM_SQLITE3_AMALGAMATION_SHA256',
                  '9512509b1bccb7461f79bea8aad6280ae4699e925fa4804381b71f59e7efb0c5']],
            out_dir=out)
        return [event], binding

    def rejected(self, rows, binding):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            component.native_abi_build(rows, binding)

    def test_producer_shaped_event_binds_links_without_runtime_qualification(self):
        rows, binding = self.fixture()
        observed = component.native_abi_build(rows, binding)
        self.assertEqual(observed['cargo_event'], rows[0])
        self.assertIs(observed['native_runtime_qualification'], False)
        rows[0]['out_dir'] += '/later-mutation'
        self.assertNotEqual(observed['cargo_event'], rows[0])

    def test_cargo_success_with_unsupported_boundary_shape_is_rejected(self):
        # Same unsupported shape as the retained real be785 Cargo event. The
        # source identifier is a synthetic current-root binding, not a replay.
        rows, binding = self.fixture()
        rows[0].update(cfgs=[], linked_libs=[], linked_paths=[],
            env=[['TRNM_SQLITE3_UNQUALIFIED_REASON',
                  'loader directory must be a canonical existing directory']])
        self.rejected(rows, binding)
        self.rejected([], binding)
        self.rejected([dict(reason='compiler-artifact', executable='/some/ELF')], binding)

    def test_duplicate_or_foreign_source_events_cannot_supply_the_witness(self):
        rows, binding = self.fixture()
        self.rejected(rows + deepcopy(rows), binding)
        for wrong in ['registry+https://example.invalid/foreign#0.1.0',
                      rows[0]['package_id'].replace('#0.1.0', '#0.1.1'),
                      rows[0]['package_id'].replace('/trillionnium/', '/foreign/')]:
            changed = deepcopy(rows)
            changed[0]['package_id'] = wrong
            self.rejected(changed, binding)
        self.rejected([None] + rows, binding)

    def test_cfg_environment_and_link_mutations_fail_closed(self):
        rows, binding = self.fixture()
        mutations = [('cfgs', []), ('cfgs', ['trnm_sqlite_layout_witness', 'foreign']),
            ('linked_libs', []), ('linked_libs', ['dylib=trnm_sqlite_layout_witness']),
            ('linked_paths', []), ('linked_paths', ['native=/foreign']),
            ('env', [rows[0]['env'][0], rows[0]['env'][0]]),
            ('env', rows[0]['env'] + [['TRNM_SQLITE3_UNQUALIFIED_REASON', 'bad']]),
            ('env', [['TRNM_SQLITE3_BUILD_FENCE', 'sqlite-3.51.3-normal-native-linux-layout-v2'], rows[0]['env'][1]]),
            ('env', [rows[0]['env'][0], ['TRNM_SQLITE3_AMALGAMATION_SHA256', '0'*64]])]
        for key, value in mutations:
            changed = deepcopy(rows)
            changed[0][key] = value
            with self.subTest(key=key, value=value):
                self.rejected(changed, binding)

    def test_out_dir_and_links_must_keep_the_original_held_target(self):
        rows, binding = self.fixture()
        good = rows[0]['out_dir']
        for wrong in [good.replace('/fd/6/', '/fd/7/'),
                      good.replace('/fd/6/', '/fd/06/'),
                      good.replace('/release/', '/debug/'),
                      good.replace('/release/', '/other/release/'),
                      good.replace('/build/', '/build/../build/'),
                      good + '/nested', good.replace('0123456789abcdef', 'G'*16)]:
            changed = deepcopy(rows)
            changed[0].update(out_dir=wrong, linked_paths=['native=' + wrong])
            self.rejected(changed, binding)
        for changed in [dict(binding, passed_fd=True), dict(binding, passed_fd=7),
                        dict(binding, actual_target='/foreign')]:
            self.rejected(rows, changed)
        # Co-mutate every copy: rejection must be the OS descriptor type bound,
        # not an incidental mismatch with the original descriptor-six fixture.
        for descriptor in [2**31, 2**63]:
            changed_binding = dict(passed_fd=descriptor,
                actual_target='/proc/self/fd/' + str(descriptor))
            changed = deepcopy(rows)
            out = good.replace('/fd/6/', '/fd/' + str(descriptor) + '/')
            changed[0].update(out_dir=out, linked_paths=['native=' + out])
            self.rejected(changed, changed_binding)

    def test_unknown_event_fields_and_non_string_environment_are_rejected(self):
        rows, binding = self.fixture()
        changed = deepcopy(rows)
        changed[0]['unreviewed_loader_override'] = '/foreign'
        self.rejected(changed, binding)
        for environment in [True, [['TRNM_SQLITE3_BUILD_FENCE', True], rows[0]['env'][1]],
                            [['TRNM_SQLITE3_BUILD_FENCE'], rows[0]['env'][1]]]:
            changed = deepcopy(rows)
            changed[0]['env'] = environment
            self.rejected(changed, binding)


if __name__ == '__main__':
    unittest.main()
