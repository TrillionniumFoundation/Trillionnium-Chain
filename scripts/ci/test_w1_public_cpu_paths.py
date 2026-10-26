#!/usr/bin/env python3
"""P1 source-path sentinel for named W1 CPU owners, NOT a security proof.

Checks original source file bodies, not comments in documentation. A new
unlisted externally reachable W1 entry still requires an adversarial audit.
No network, CPU budget mutation, consensus operation or CI receipt is made.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
INGRESS = 'trillionnium/crates/trnm-pon-node/src/ingress.rs'
PEER = 'trillionnium/crates/trnm-pon-node/src/peer_polling.rs'
V2 = 'trillionnium/crates/trnm-pon-node/src/ingress/public_v2.rs'
V3 = 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
SCALAR = 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs'
MAIN = 'trillionnium/crates/trnm-pon-node/src/main.rs'

# Exact source-owned sections, never arbitrary whole-file grep.
SECTIONS = {
    'history-cpu': (INGRESS, 'fn receive_page_with_cpu(', '/// Public untrusted History import.', (
        'domain.await_history_work_credit(', 'domain.begin()?',
        'WorkCheckedPacket::verify_with_progress(',
        'node.admit_work_checked_with_control(', 'operation.worker_accounting()',
        'accounting.accounting_unavailable', 'node.activate_observed(tip, clock)',
    )),
    'history-import': (INGRESS, 'pub fn receive_page_from(', 'pub fn sync_from(', (
        'require_for_listener(source)?', 'node.public_service_cpu_domain()',
        'OwnerPublicServiceDomainUnbound', 'receive_page_with_cpu(',
        'domain.as_ref()',
    )),
    'history-cold-binding': (INGRESS, 'pub fn bind_host_verified_history_cpu_domain(',
        '/// Public untrusted History import.', (
        'require_for_listener(source)?', 'kernel.verify()?',
        'cold_for_host_verified_history_sync()',
        'node.bind_public_service_cpu_domain(&cold)?',
        'stored_credit_ns == 0',
    )),
    'history-raw': (INGRESS, 'pub fn sync_from(', 'pub fn sync_from_authenticated(', (
        'bind_host_verified_history_cpu_domain(node, address)?',
        'receive_page_from(node, address', 'kernel.verify()?',
    )),
    'history-auth': (INGRESS, 'pub fn sync_from_authenticated(',
        'pub fn sync_from_authenticated_durable(', (
        'bind_host_verified_history_cpu_domain(node, address)?',
        'receive_page_from(node, address', 'kernel.verify()?',
    )),
    'history-auth-durable': (INGRESS, 'pub fn sync_from_authenticated_durable(',
        '#[cfg(test)]', (
        'bind_host_verified_history_cpu_domain(node, address)?',
        'receive_page_from(node, address', 'kernel.verify()?',
    )),
    'pinned-peer': (PEER, 'fn admit_page(', 'struct PollContext', (
        'public_service_cpu_domain()?', 'cpu.begin()?',
        'WorkCheckedPacket::verify_with_progress(',
        'owner.admit_work_checked_with_control(',
        'operation.worker_accounting()', 'operation.finish()',
        'settlement.accounting_unavailable',
    )),
    'v2-loopback': (V2, 'pub fn serve_public_protected_v2(',
        'fn serve_public_protected_v2_with_owner(', (
        'listener.local_addr()?.ip().is_loopback()', 'PUBLIC_V2_LOOPBACK_ONLY',
    )),
    'legacy-remote-wan': (INGRESS, 'fn serve_inner(', '#[cfg(test)]', (
        'DEVELOPMENT_REMOTE_ADMISSION_REQUIRED',
        'require_for_listener(listener_address)?',
        'host_kernel_for_worker', 'measured_work_verify',
    )),
    'cpu-cold-factory': (SCALAR, 'pub(crate) fn cold_for_host_verified_history_sync()',
        'pub(crate) fn await_history_work_credit(', (
        'PaidMutationCpuBudget::cold_start()', 'budget: Arc::new',
    )),
    'cpu-natural-refill': (SCALAR, 'pub(crate) fn await_history_work_credit(',
        'pub fn shares_domain_with(', (
        'budget.refill(now)', 'MUTATION_CPU_START_RESERVE_NS',
        'MUTATION_CPU_WORKERS', 'PUBLIC_MUTATION_CPU_BUDGET',
    )),
    'public-v3-metered-work': (V3, 'fn public_dispatch(',
        'pub fn serve_public_protected_v3(', (
        'WorkCheckedPacket::verify_with_progress(',
        'mutation_cpu.ok_or(',
    )),
    'public-v3-paid-worker': (V3, 'fn serve_public_protected_v3_inner(',
        '#[cfg(test)]', (
        'PaidMutationCpuPermit::acquire_before(',
    )),
    'cli-sync': (MAIN, '"sync" => {', '"serve" => {', (
        'ingress::bind_host_verified_history_cpu_domain(&mut node, address)?',
        'ingress::receive_page_from(&mut node, address, page, tip, cursor',
    )),
}


def load_sources():
    return {path: (ROOT / path).read_text(encoding='utf-8')
            for path in {value[0] for value in SECTIONS.values()}}


def check(sources):
    for label, (path, opening, closing, expected) in SECTIONS.items():
        text = sources[path]
        first = text.find(opening)
        if first < 0:
            raise ValueError(f'{label}: missing start {opening}')
        last = text.find(closing, first + len(opening))
        if last < 0:
            raise ValueError(f'{label}: missing end {closing}')
        section = text[first:last]
        for required in expected:
            if required not in section:
                raise ValueError(f'{label}: missing original owner check {required}')


class PublicW1CpuSourceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = load_sources()

    def test_known_external_w1_paths_retain_original_owner_checks(self):
        check(self.sources)

    def test_removing_pinned_peer_paid_owner_fails_source_contract(self):
        changed = self.sources.copy()
        changed[PEER] = changed[PEER].replace('cpu.begin()?', 'cpu.bypass_begin()?', 1)
        with self.assertRaisesRegex(ValueError, 'pinned-peer'):
            check(changed)

    def test_removing_history_w1_charge_fails_source_contract(self):
        changed = self.sources.copy()
        changed[INGRESS] = changed[INGRESS].replace(
            'node.admit_work_checked_with_control(',
            'node.unmetered_admit_work_checked(',
            1,
        )
        with self.assertRaisesRegex(ValueError, 'history-cpu'):
            check(changed)

    def test_removing_remote_source_owner_fails_source_contract(self):
        changed = self.sources.copy()
        changed[INGRESS] = changed[INGRESS].replace(
            'let host_kernel = crate::host_kernel_parent::require_for_listener(source)?;',
            'let host_kernel = None;',
            1,
        )
        with self.assertRaisesRegex(ValueError, 'history-import'):
            check(changed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
