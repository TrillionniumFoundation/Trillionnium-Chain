#!/usr/bin/env python3
"""Regression for named public/native W1 ingress owners, not a security theorem.

Read the actual checked-out source. Mutation tests prevent a source refactor
from quietly resurrecting known externally influenced full-W1 replay paths.
Passing these exact-text ownership controls is necessary, never sufficient,
for P1 source review, physical accounting or WAN qualification.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
FILES = {
    'ingress': 'trillionnium/crates/trnm-pon-node/src/ingress.rs',
    'v2': 'trillionnium/crates/trnm-pon-node/src/ingress/public_v2.rs',
    'v3': 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs',
    'peer': 'trillionnium/crates/trnm-pon-node/src/peer_polling.rs',
    'cli': 'trillionnium/crates/trnm-pon-node/src/main.rs',
}


def source():
    return {name: (ROOT / path).read_text(encoding='utf-8')
            for name, path in FILES.items()}


def required(ok, name):
    if not ok:
        raise AssertionError('W1_ENTRYPOINT_OWNER:' + name)


def section(value, start, end):
    """Extract a named source interval, fail rather than scan unrelated tests."""
    a = value.find(start)
    required(a >= 0, 'missing_interval_start_' + start)
    b = value.find(end, a + len(start))
    required(b > a, 'missing_interval_end_' + end)
    return value[a:b]


def verify_named_entrypoints(files):
    ingress, v2, v3, peer, cli = (files[x] for x in
                                  ('ingress', 'v2', 'v3', 'peer', 'cli'))
    required(len(re.findall(r'^fn receive_page\($', ingress, flags=re.M)) == 1,
             'original_import_must_remain_private')
    required(re.search(r'^pub(?:\(crate\))? fn receive_page\($', ingress, re.M) is None,
             'addressless_history_import_must_not_be_exported')
    original = section(ingress, '\nfn receive_page(\n',
                       '\n/// Public untrusted History import.')
    required('node.admit(packet, clock)?' in original and 'page.packets.len() <= 16' in original,
             'original_full_work_page_semantics')
    wrapper = section(ingress, '\npub fn receive_page_from(\n', '\npub fn sync_from(\n')
    require_kernel = 'host_kernel_parent::require_for_listener(source)?'
    before = wrapper.find(require_kernel)
    native = wrapper.find('let native = receive_page(node, page, tip, after, clock);')
    required(before >= 0 and native > before
             and wrapper.count('kernel.verify()?') >= 2,
             'exported_history_page_requires_actual_source_owner')
    for start, end, name in (
        ('\npub fn sync_from(\n', '\npub fn sync_from_authenticated(\n', 'sync'),
        ('\npub fn sync_from_authenticated(\n',
         '\npub fn sync_from_authenticated_durable(\n', 'authenticated_sync'),
        ('\npub fn sync_from_authenticated_durable(\n', '\n#[cfg(test)]\nmod tests {',
         'durable_authenticated_sync')):
        body = section(ingress, start, end)
        required('host_kernel_parent::require_for_listener(address)?' in body
                 and body.count('kernel.verify()?') >= 2
                 and 'receive_page_from(node, address, page' in body
                 and 'receive_page(node, page' not in body,
                 name + '_must_check_original_parent_each_page')
    legacy_start = ingress.find('\nfn serve_inner(\n')
    required(legacy_start >= 0, 'missing_legacy_listener_owner')
    native_listener = ingress[legacy_start:ingress.find('\npub fn sync_from(\n', legacy_start)]
    required('DEVELOPMENT_REMOTE_ADMISSION_REQUIRED' in native_listener
             and 'host_kernel_parent::require_for_listener(listener_address)?' in native_listener
             and 'kernel.verify()?' in native_listener,
             'legacy_nonloopback_needs_paid_admission_and_kernel_owner')
    required(v2.count('"PUBLIC_V2_LOOPBACK_ONLY"') >= 2,
             'legacy_public_v2_must_be_loopback_only')
    v3_workers = section(v3, '\nfn public_dispatch(\n',
                         '\npub fn serve_public_protected_v3(')
    required('WorkCheckedPacket::verify_with_progress(' in v3_workers
             and 'w1_rejection_cache' in v3_workers,
             'v3_keeps_full_W1_verifier_with_optional_negative_fact')
    required('PaidMutationCpuPermit::acquire_before(' in v3
             and 'mutation_cpu_domain()' in v3,
             'v3_requires_shared_original_paid_cpu_domain')
    peer_admit = section(peer, '\nfn admit_page(', '\nstruct PollContext')
    required('owner.public_service_cpu_domain()?' in peer_admit
             and 'let operation = cpu.begin()?' in peer_admit
             and 'WorkCheckedPacket::verify_with_progress(' in peer_admit
             and 'operation.worker_accounting()' in peer_admit
             and 'operation.finish()' in peer_admit
             and 'if settlement.accounting_unavailable' in peer_admit
             and 'WorkCheckedPacket::verify(packet)' not in peer_admit,
             'pinned_peer_full_W1_needs_complete_original_cpu_owner')
    public_cli = section(cli, '        "sync" => {', '        "serve" => {')
    required('host_kernel_parent::require_for_listener(address)?' in public_cli
             and 'ingress::receive_page_from(&mut node, address' in public_cli
             and 'ingress::receive_page(&mut node' not in public_cli,
             'public_CLI_sync_must_use_source_bound_host_guard')
    for name in ('ingress', 'v2', 'v3', 'peer', 'cli'):
        required('w2c_receiver_admission' not in files[name],
                 'research_tickets_must_not_enter_production_' + name)


class ExplicitW1SourceOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = source()

    def test_current_named_entrypoints_have_original_owners(self):
        verify_named_entrypoints(self.files)

    def test_reintroducing_unowned_paths_fails_closed(self):
        mutations = [
            ('ingress', '\nfn receive_page(\n',
             '\npub fn receive_page(\n'),
            ('ingress', 'host_kernel_parent::require_for_listener(source)?',
             'None /* UNSAFE former public page */'),
            ('ingress', 'host_kernel_parent::require_for_listener(address)?',
             'None /* UNSAFE remote sync */'),
            ('peer', 'let operation = cpu.begin()?',
             'let operation = unsafe_unmetered()'),
            ('peer', 'if settlement.accounting_unavailable',
             'if false /* ignore unknown CPU */'),
            ('v2', '"PUBLIC_V2_LOOPBACK_ONLY"', '"NO_LOOPBACK_GUARD"'),
            ('cli', 'ingress::receive_page_from(&mut node, address',
             'ingress::receive_page(&mut node'),
        ]
        for name, good, bad in mutations:
            with self.subTest(file=name, deleted=good):
                changed = self.files[name].replace(good, bad)
                self.assertNotEqual(changed, self.files[name])
                altered = dict(self.files, **{name: changed})
                with self.assertRaisesRegex(AssertionError, 'W1_ENTRYPOINT_OWNER'):
                    verify_named_entrypoints(altered)


if __name__ == '__main__':
    unittest.main(verbosity=2)
