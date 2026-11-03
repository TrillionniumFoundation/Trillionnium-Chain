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
ERROR = 'trillionnium/crates/trnm-pon-node/src/error.rs'

# Exact source-owned sections, never arbitrary whole-file grep.
SECTIONS = {
    'local-cpu-owner-stop': (ERROR, 'pub fn requires_owner_stop(',
        'pub(crate) fn public_history_budget(', (
        'self.kind == ErrorKind::RemoteRefusal',
        'ErrorCode::PublicMutationCpuUnavailable',
        'ErrorCode::OwnerPublicServiceCpuDomain',
        'ErrorCode::OwnerPublicServiceDomainUnbound',
        'ErrorCode::OwnerPublicServiceUncleanEpoch',
    )),
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
        'check_admission_context_with_progress(',
        'WorkCheckedPacket::verify_with_progress(',
        'owner.admit_work_checked_with_control(',
        'operation.worker_accounting()', 'operation.finish()',
        'settlement.accounting_unavailable',
    )),
    'pinned-completion': (PEER, 'fn complete<F>(', 'fn cycle<F, R>(', (
        'owner.public_service_cpu_domain()?', 'cpu.begin()?',
        'owner.activate_observed_with_progress(', 'checkpoint.checkpoint()',
        'operation.finish()', 'settlement.accounting_unavailable',
        'host_kernel', 'kernel.verify()?',
    )),
    'pinned-fatal-priority': (PEER, 'fn reject<F>(', 'fn step<F, R>(', (
        'let fatal = error.requires_owner_stop()',
        'let observation = self.event(', 'if fatal {', 'return Err(error);',
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
    'cli-host-trigger': (MAIN, 'fn public_host_resource_address(',
        'fn validate_host_kernel_profile(', (
        '.find(|peer| !peer.ip().is_loopback())', '.unwrap_or(listener)',
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

    error = sources[ERROR]
    start = error.index('pub fn requires_owner_stop(')
    stop = error.index('pub(crate) fn public_history_budget(', start)
    classification = error[start:stop]
    remote = classification.index('if self.kind == ErrorKind::RemoteRefusal')
    local = classification.index('self.kind == ErrorKind::LocalStructure')
    if ('return false;' not in classification[remote:local] or
            'ErrorCode::PublicMutationCpuBudget' in classification):
        raise ValueError('local-cpu-owner-origin: remote and capacity remain nonfatal')

    # Ordering sentinels are source regression controls, not runtime receipts.
    peer = sources[PEER]
    rejection = peer[peer.index('fn reject<F>('):peer.index('fn step<F, R>(')]
    event = rejection.index('let observation = self.event(')
    fatal = rejection.index('if fatal {')
    if (')?;' in rejection[event:fatal] or
            not rejection[rejection.index('return Err(error);'):].rstrip().endswith('observation\n    }')):
        raise ValueError('pinned-fatal-priority: observer cannot mask original fatal')
    admission = peer[peer.index('fn admit_page('):peer.index('struct PollContext')]
    if not (admission.index('cpu.begin()?') <
            admission.index('check_admission_context_with_progress(') <
            admission.index('WorkCheckedPacket::verify_with_progress(') <
            admission.index('operation.finish()')):
        raise ValueError('pinned-context: original reservation must precede context')
    completion = peer[peer.index('fn complete<F>('):peer.index('fn cycle<F, R>(')]
    step = peer[peer.index('fn step<F, R>('):peer.index('fn complete<F>(')]
    for opening, closing in [('if known {', 'return Ok(false);'),
                             ('if complete {', 'Ok(true)')]:
        first = step.index(opening)
        arm = step[first:step.index(closing, first)]
        if 'self.complete(index, context, observe)?' not in arm:
            raise ValueError('pinned-host-entry: both completion paths need original context')
    if not (completion.index('kernel.verify()?') <
            completion.index('let activated =') <
            completion.index('operation.finish()') <
            completion.rindex('kernel.verify()?') <
            completion.index('let active = match activated') <
            completion.index('self.states[index].last_completed')):
        raise ValueError('pinned-host-completion: check before completion outcome')
    if ('.find(|peer| !peer.address.ip().is_loopback())' not in peer or
            'require_for_listener(peer.address)' not in peer or
            'host_kernel: host_kernel.as_ref()' not in peer):
        raise ValueError('pinned-outbound-host: preserve physical outgoing owner')
    main = sources[MAIN]
    serve = main[main.index('"serve" => {'):]
    start = serve.index('let kernel_source = public_host_resource_address(')
    stop = serve.index('let host_resources_before', start)
    setup = serve[start:stop]
    for required in ('listener.local_addr()?',
                     'cfg.peers.iter().map(|peer| peer.address)',
                     'require_host_kernel_budget(\n                        kernel_source,',
                     'args.get("--host-kernel-parent").map(String::as_str)'):
        if required not in setup:
            raise ValueError('cli-host-startup: require original parent before observation')


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

    def test_removing_pinned_completion_owner_or_settlement_fails(self):
        start = self.sources[PEER].index('fn complete<F>(')
        end = self.sources[PEER].index('fn cycle<F, R>(', start)
        for required in SECTIONS['pinned-completion'][3]:
            with self.subTest(required=required):
                changed = self.sources.copy()
                body = changed[PEER][start:end].replace(required, 'REMOVED_CHECK')
                changed[PEER] = changed[PEER][:start] + body + changed[PEER][end:]
                with self.assertRaisesRegex(ValueError, 'pinned-completion'):
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

    def test_context_reservation_cannot_be_moved_after_context(self):
        changed = self.sources.copy()
        text = changed[PEER]
        start = text.index('fn admit_page(')
        end = text.index('struct PollContext', start)
        body = text[start:end].replace('let operation = cpu.begin()?;', '', 1)
        marker = 'let checked = WorkCheckedPacket::verify_with_progress('
        body = body.replace(marker, 'let operation = cpu.begin()?;\n' + marker, 1)
        changed[PEER] = text[:start] + body + text[end:]
        with self.assertRaisesRegex(ValueError, 'pinned-context'):
            check(changed)

    def test_completion_host_postcheck_cannot_move_after_success_marker(self):
        changed = self.sources.copy()
        text = changed[PEER]
        start = text.index('fn complete<F>(')
        end = text.index('fn cycle<F, R>(', start)
        body = text[start:end]
        at = body.rindex('kernel.verify()?')
        body = body[:at] + body[at:].replace('kernel.verify()?', 'removed_postcheck()', 1)
        changed[PEER] = text[:start] + body + text[end:]
        with self.assertRaisesRegex(ValueError, 'pinned-host-completion'):
            check(changed)

    def test_outgoing_remote_peer_cannot_use_listener_address_policy(self):
        changed = self.sources.copy()
        changed[PEER] = changed[PEER].replace(
            '.find(|peer| !peer.address.ip().is_loopback())', '.find(|_| false)', 1)
        with self.assertRaisesRegex(ValueError, 'pinned-outbound-host'):
            check(changed)

    def test_known_head_and_page_completion_both_keep_checked_context(self):
        text = self.sources[PEER]
        marker = 'self.complete(index, context, observe)?'
        first = text.index(marker)
        second = text.index(marker, first + len(marker))
        for offset in [first, second]:
            with self.subTest(offset=offset):
                changed = self.sources.copy()
                changed[PEER] = text[:offset] + text[offset:].replace(
                    marker, 'unchecked_completion()', 1)
                with self.assertRaisesRegex(ValueError, 'pinned-host-entry'):
                    check(changed)

    def test_cli_startup_cannot_revert_to_listener_only_guard(self):
        changed = self.sources.copy()
        changed[MAIN] = changed[MAIN].replace(
            'require_host_kernel_budget(\n                        kernel_source,',
            'require_host_kernel_budget(\n                        listener.local_addr()?,', 1)
        with self.assertRaisesRegex(ValueError, 'cli-host-startup'):
            check(changed)

    def test_cli_trigger_cannot_downgrade_listener_for_local_peer(self):
        changed = self.sources.copy()
        changed[MAIN] = changed[MAIN].replace(
            '.find(|peer| !peer.ip().is_loopback())', '.next()', 1)
        with self.assertRaisesRegex(ValueError, 'cli-host-trigger'):
            check(changed)

    def test_local_cpu_owner_faults_cannot_be_removed_from_fatal_set(self):
        for code in SECTIONS['local-cpu-owner-stop'][3][1:]:
            with self.subTest(code=code):
                changed = self.sources.copy()
                start = changed[ERROR].index('pub fn requires_owner_stop(')
                changed[ERROR] = changed[ERROR][:start] + changed[ERROR][start:].replace(
                    code, 'ErrorCode::RemovedOwnerFault', 1)
                with self.assertRaisesRegex(ValueError, 'local-cpu-owner-stop'):
                    check(changed)

    def test_remote_impersonation_and_budget_cannot_become_owner_stop(self):
        for old, new in [
            ('if self.kind == ErrorKind::RemoteRefusal {\n            return false;',
             'if self.kind == ErrorKind::RemoteRefusal {\n            return true;'),
            ('| ErrorCode::PublicMutationCpuUnavailable',
             '| ErrorCode::PublicMutationCpuBudget | ErrorCode::PublicMutationCpuUnavailable'),
        ]:
            with self.subTest(old=old):
                changed = self.sources.copy()
                changed[ERROR] = changed[ERROR].replace(old, new, 1)
                with self.assertRaisesRegex(ValueError, 'local-cpu-owner-origin'):
                    check(changed)

    def test_failed_observer_cannot_short_circuit_fatal_priority(self):
        changed = self.sources.copy()
        text = changed[PEER]
        start = text.index('fn reject<F>(')
        end = text.index('fn step<F, R>(', start)
        body = text[start:end].replace('observe,\n        );', 'observe,\n        )?;', 1)
        self.assertNotEqual(body, text[start:end])
        changed[PEER] = text[:start] + body + text[end:]
        with self.assertRaisesRegex(ValueError, 'pinned-fatal-priority'):
            check(changed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
