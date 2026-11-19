"""Regression controls for omitted/stale native evidence source bindings."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from .rust_oracle import complete_source_manifest, validate_source_bindings


class BundleIntegrityTests(unittest.TestCase):
    def test_complete_current_source_set_is_required(self):
        expected = complete_source_manifest()
        native = {'source_inputs': copy.deepcopy(expected),
                  'build': {'source_inputs': copy.deepcopy(expected)}}
        self.assertEqual(validate_source_bindings(native), expected)
        targets = (
            'hia/platform/host_resource/rust_reference.rs',
            'hia/platform/host_resource/rust_oracle.py',
            'hia/platform/host_resource/test_integrity.py',
            'hia/platform/host_checkpoint/linux_emitter.hepta',
            'hia/platform/build.py',
            'trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs',
        )
        for path in targets:
            for locations in (('source_inputs',), ('source_inputs', 'build')):
                with self.subTest(path=path, locations=locations):
                    changed = copy.deepcopy(native)
                    for location in locations:
                        mapping = changed['source_inputs'] if location == 'source_inputs' else changed['build']['source_inputs']
                        del mapping[path]
                    with self.assertRaisesRegex(ValueError, 'source map|mandatory source'):
                        validate_source_bindings(changed)

    def test_matching_forged_and_extra_maps_are_rejected(self):
        expected = complete_source_manifest()
        for kind in ('empty', 'fake-hash', 'fake-size', 'extra'):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(expected)
                key = 'hia/platform/host_resource/rust_reference.rs'
                if kind == 'empty':
                    changed.clear()
                elif kind == 'fake-hash':
                    changed[key]['sha256'] = '0' * 64
                elif kind == 'fake-size':
                    changed[key]['bytes'] += 1
                else:
                    changed['hia/platform/host_resource/unbound-extra.hepta'] = {'bytes': 1, 'sha256': '0' * 64}
                with self.assertRaisesRegex(ValueError, 'mandatory source'):
                    validate_source_bindings({'source_inputs': changed, 'build': {'source_inputs': copy.deepcopy(changed)}})

    def test_optimized_python_cannot_disable_entrypoint_validation(self):
        repository = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory(prefix='hia-resource-optimization-') as temporary:
            for module in ('build', 'qualify', 'rust_oracle'):
                with self.subTest(module=module):
                    output = Path(temporary) / module
                    observed = subprocess.run([sys.executable, '-O', '-B', '-m',
                        'hia.platform.host_resource.' + module, '--output', str(output)],
                        cwd=repository, env=dict(os.environ), stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=10)
                    self.assertNotEqual(observed.returncode, 0)
                    self.assertIn(b'refuses optimized Python', observed.stderr)
                    self.assertFalse(output.exists())


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Integrity qualification refuses optimized Python')
    unittest.main()
