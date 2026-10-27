"""PAB1 isolated atomic-visibility and integrity tests; no crypto acceptance claim.

The fake fetcher is intentionally UNTRUSTED and returns arbitrary bytes. Upstream
PCS1 is responsible for *real* TPQ1 ML-DSA per-chunk verification in integration.
These tests prove a fake positive cannot bypass exact PCB1 content readback.
"""
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from dataclasses import replace
from unittest.mock import patch

from pq_cell_bundle_atomic import (
    BASE, BundleReject, Route, CONTENT_DOMAIN, MANIFEST_DOMAIN, CATALOG_DOMAIN,
    parse_manifest, publish_bundle, read_published,
)

class BundleAtomicTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pab1-tests-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.network = bytes(range(1, 33))
        self.family = bytes(range(33, 65))
        self.parent = bytes(32)
        self.generation = 9
        self.base = b'shared-base-2026-v9'
        self.data = {
            BASE: self.base,
            bytes([1])*32: b'cell-one-weight-v9',
            bytes([2])*32: b'cell-two-weight-v9',
        }
        def identity(data):
            return hashlib.sha384(CONTENT_DOMAIN + len(data).to_bytes(8,'big') + data).digest()
        self.identity = identity
        self.manifest = (b'PCB1\x01' + self.network + self.family + self.parent +
                         self.generation.to_bytes(8,'big') + identity(self.base) +
                         len(self.base).to_bytes(8,'big') + bytes([2]))
        for key in sorted(k for k in self.data if k != BASE):
            blob = self.data[key]
            self.manifest += (key + self.generation.to_bytes(8,'big') + identity(blob) +
                              len(blob).to_bytes(8,'big'))
        self.digest = hashlib.sha384(MANIFEST_DOMAIN + len(self.manifest).to_bytes(4,'big') + self.manifest).digest()
        self.routes = []
        for key, blob in self.data.items():
            raw = (b'PCC1\x01' + self.network + self.digest +
                   self.generation.to_bytes(8,'big') + len(blob).to_bytes(8,'big') +
                   len(blob).to_bytes(4,'big') + (1).to_bytes(4,'big') + bytes([0x40])*48)
            self.routes.append(Route(key, raw, hashlib.sha384(CATALOG_DOMAIN+raw).digest(), (object(),)))
        self.routes = tuple(self.routes)
        self.requester = bytes([0x72])*32
        self.kw = dict(manifest_bytes=self.manifest, expected_manifest_digest=self.digest,
                       expected_network=self.network, expected_family=self.family,
                       expected_parent=self.parent, expected_generation=self.generation,
                       root=self.root)
        self.calls = []

    def fake_fetch(self, **kwargs):
        self.calls.append(kwargs['destination'].name)
        name = kwargs['destination'].name
        selector = BASE if name == 'base.bin' else bytes.fromhex(name[5:-4])
        kwargs['destination'].write_bytes(self.data[selector])

    def publish(self, routes=None, fetcher=None, **kwargs):
        return publish_bundle(**(self.kw | dict(routes=self.routes if routes is None else routes,
                                        requester_id=self.requester,
                                        fetcher=self.fake_fetch if fetcher is None else fetcher) | kwargs))

    def test_full_base_and_two_cells_publish_together_and_cold_reverify(self):
        first = self.publish()
        self.assertEqual(first.objects_checked, 3)
        self.assertEqual(first.bytes_checked, sum(len(v) for v in self.data.values()))
        self.assertEqual(len(self.calls), 3)
        second = read_published(**self.kw)
        self.assertEqual(second, first)
        self.assertFalse(hasattr(second, 'adoption_authorized'))

    def test_no_partial_readiness_when_third_weight_missing(self):
        def fail_on_last(**kwargs):
            if kwargs['destination'].name.startswith('cell-') and '02'*32 in kwargs['destination'].name:
                raise BundleReject('missing Cell')
            self.fake_fetch(**kwargs)
        with self.assertRaisesRegex(BundleReject, 'missing Cell'):
            self.publish(fetcher=fail_on_last)
        self.assertEqual(tuple((self.root/'published').iterdir()), ())
        self.assertEqual(tuple((self.root/'pending').iterdir()), ())

    def test_trusted_digest_is_required_before_any_download(self):
        for bad in (bytes(48), bytes([7])*48):
            with self.assertRaises(BundleReject):
                self.publish(expected_manifest_digest=bad)
        self.assertEqual(self.calls, [])

    def test_signed_provider_claim_not_enough_when_whole_weight_differs(self):
        def fake_success_corrupt(**kwargs):
            self.fake_fetch(**kwargs)
            with kwargs['destination'].open('r+b') as f:
                f.seek(0); f.write(b'!')
        with self.assertRaisesRegex(BundleReject, 'wrong PCB1 whole-object bytes'):
            self.publish(fetcher=fake_success_corrupt)
        self.assertFalse(any((self.root/'published').iterdir()))

    def test_cross_release_catalog_identity_rejects_before_fetch(self):
        r = self.routes[0]
        raw = bytearray(r.catalog_bytes)
        raw[40] ^= 1
        forged = Route(r.selector, bytes(raw), hashlib.sha384(CATALOG_DOMAIN+raw).digest(), r.peers)
        with self.assertRaisesRegex(BundleReject, 'PCC1 model binding'):
            self.publish(routes=(forged, *self.routes[1:]))
        self.assertEqual(self.calls, [])

    def test_alternate_signed_merkle_catalog_refused_by_pinned_catalog(self):
        r=self.routes[0]
        raw=bytearray(r.catalog_bytes); raw[-1]^=1
        alt=Route(r.selector, bytes(raw), r.expected_catalog_digest, r.peers)
        with self.assertRaisesRegex(BundleReject, 'PCC1 digest not pinned'):
            self.publish(routes=(alt, *self.routes[1:]))

    def test_duplicate_or_missing_cell_selector_rejected(self):
        for routes in (self.routes[:2], (self.routes[0], self.routes[0], self.routes[2]),
                       (replace(self.routes[0], selector=bytes([3])*32), *self.routes[1:])):
            with self.subTest(routes=routes), self.assertRaises(BundleReject):
                self.publish(routes=routes)
        self.assertEqual(self.calls, [])

    def test_existing_published_identity_cannot_be_replaced(self):
        first=self.publish()
        blob=first.index_path.read_bytes()
        with self.assertRaisesRegex(BundleReject, 'already published'):
            self.publish()
        self.assertEqual(first.index_path.read_bytes(),blob)
        self.assertEqual(len(list((self.root/'pending').iterdir())),1)

    def test_concurrent_eight_publishers_only_one_no_clobber_index(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures=[pool.submit(self.publish) for _ in range(8)]
            outcomes=[]
            for f in futures:
                try: outcomes.append(('ok',f.result()))
                except (BundleReject,FileExistsError): outcomes.append(('reject',None))
        self.assertEqual(sum(r[0]=='ok' for r in outcomes),1)
        self.assertEqual(sum(r[0]=='reject' for r in outcomes),7)
        self.assertEqual(len(list((self.root/'published').iterdir())),1)
        self.assertEqual(len(list((self.root/'pending').iterdir())),1)
        self.assertEqual(read_published(**self.kw).objects_checked,3)

    def test_symlink_weight_from_downloader_refused(self):
        original=self.root/'outside'; original.write_bytes(self.base)
        def bad(**kwargs):
            if kwargs['destination'].name=='base.bin': kwargs['destination'].symlink_to(original)
            else: self.fake_fetch(**kwargs)
        with self.assertRaisesRegex(BundleReject, 'symlink object'):
            self.publish(fetcher=bad)
        self.assertFalse(any((self.root/'published').iterdir()))
        self.assertEqual(original.read_bytes(), self.base)

    def test_modified_published_weight_refused_on_cold_read(self):
        self.publish()
        stage=next((self.root/'pending').iterdir())
        with (stage/'base.bin').open('r+b') as f:
            f.write(b'\0')
        with self.assertRaises(BundleReject):
            read_published(**self.kw)

    def test_rehashed_fake_pointer_still_cannot_change_pcb1(self):
        self.publish()
        p=self.root/'published'/(self.digest.hex()+'.pab1')
        # Replacing the exact index with another internally consistent blob
        # does not change the independently pinned expected PCB1 bytes.
        old=p.read_bytes()
        p.unlink(); p.write_bytes(old[:-1]+bytes([old[-1]^1]))
        with self.assertRaisesRegex(BundleReject, 'published index link ownership|altered or truncated'):
            read_published(**self.kw)

    def test_unpublished_orphan_stage_has_no_readable_release(self):
        p=self.root/'pending'; p.mkdir(mode=0o700)
        (p/('stage-'+'01'*16)).mkdir()
        q=self.root/'published';q.mkdir(mode=0o700)
        with self.assertRaises(FileNotFoundError):
            read_published(**self.kw)

    def test_fsync_failure_after_publish_does_not_falsely_rollback(self):
        import pq_cell_bundle_atomic as b
        real=b._fsync_dir
        def fail_only_publication(p):
            if p.name=='published': raise OSError('simulated uncertain durability')
            return real(p)
        with patch.object(b,'_fsync_dir',side_effect=fail_only_publication):
            with self.assertRaisesRegex(OSError,'uncertain durability'):
                self.publish()
        self.assertEqual(read_published(**self.kw).objects_checked,3)

    def test_symlink_root_or_world_writable_root_rejects(self):
        alias=self.root.parent/(self.root.name+'-link')
        alias.symlink_to(self.root,target_is_directory=True)
        self.addCleanup(alias.unlink)
        with self.assertRaisesRegex(BundleReject,'private directory'):
            self.publish(root=alias)
        self.root.chmod(0o777)
        with self.assertRaisesRegex(BundleReject,'private directory'):
            self.publish()

    def test_noncanonical_manifest_and_boolean_version_reject(self):
        for raw in (self.manifest[:-1], self.manifest+b'x', b'PCX1'+self.manifest[4:],
                    self.manifest[:165]+b'\xff'+self.manifest[166:]):
            with self.assertRaises(BundleReject): parse_manifest(raw)
        with self.assertRaises(BundleReject):
            self.publish(expected_generation=True)
        with self.assertRaises(BundleReject):
            self.publish(requester_id=bytes(32))

if __name__=='__main__': unittest.main()
