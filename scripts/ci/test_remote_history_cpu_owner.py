#!/usr/bin/env python3
"""Fail-closed source-bound P1 regression; NOT native or physical qualification.

Do not silently restore an unmetered W1 or lose the fixed Host guard when
combining real Node History CPU metering with public-V3 loopback/peer protections.
Tests inspect exact repository source, not simulated live authority.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
INGRESS = ROOT / "trillionnium/crates/trnm-pon-node/src/ingress.rs"
NODE = ROOT / "trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs"
CPU = ROOT / "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs"
HOST = ROOT / "trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs"


def check(ingress, owner, cpu, host):
    def require(ok, label):
        if not ok:
            raise ValueError(label)

    begin = ingress.find("fn begin_history_import_cpu(")
    loader = ingress.find("fn receive_page(", begin)
    local = ingress.find("pub(crate) fn receive_page_from(", loader)
    public = ingress.find("pub fn receive_page_from_public_sync(", local)
    sync = ingress.find("pub fn sync_from(", public)
    require(-1 not in (begin, loader, local, public, sync)
            and begin < loader < local < public < sync,
            "HISTORY_API_BOUNDARY")

    paid = ingress[begin:loader]
    native = ingress[loader:local]
    guarded = ingress[local:public]
    public_guarded = ingress[public:sync]

    require("pub fn receive_page(" not in ingress and
            "node.admit(packet, clock)" not in native,
            "HISTORY_UNMETERED_W1")
    require("metered_history_packet(node, domain, packet, clock, host_check)?" in native,
            "HISTORY_METERED_W1")
    require("let (packets, next) = metered_history_operation(node, domain," in native and
            ".map(|s| hex_packet(s))" in native,
            "HISTORY_METERED_DECODE")
    require("owner.activate_observed_with_progress(" in native and
            "metered_history_operation(node, domain" in native and
            "host_check()?" in native,
            "HISTORY_METERED_ACTIVATION")
    require("domain.begin_untrusted_peer_sync()" in paid and
            "let receipt = operation.finish();" in paid and
            "if receipt.accounting_unavailable" in paid,
            "HISTORY_LOW_PRIORITY_CPU")
    require("WorkCheckedPacket::verify_with_progress" in paid and
            "operation.worker_accounting()" in paid and
            "history_host_checkpoint(point)" in paid and
            "owner.admit_work_checked_with_control" in paid,
            "HISTORY_W1_M06_CHECKPOINT")

    require("let domain = node.remote_history_cpu_domain()?;" in guarded and
            "let native = receive_page(node, &domain, page, tip, after, clock, &host_check);" in guarded,
            "HISTORY_BOUND_NODE_DOMAIN")
    require(guarded.index("require_for_listener(source)") <
            guarded.index("let domain = node.remote_history_cpu_domain()?") and
            "kernel.verify()?" in guarded,
            "HISTORY_KERNEL_FIRST")

    require("let host = crate::host_kernel_parent::require_for_untrusted_public_sync(source)?;" in public_guarded and
            "let domain = node.remote_history_cpu_domain()?;" in public_guarded and
            "receive_page(node, &domain, page, tip, after, clock, &|| host.verify())" in public_guarded and
            "host.verify()?;" in public_guarded,
            "HISTORY_PUBLIC_LOOPBACK_GUARD")
    require("pub fn require_for_untrusted_public_sync(" in host and
            "FIXED_PUBLIC_KERNEL_PARENT" in host,
            "HISTORY_REAL_FIXED_HOST_OWNER")

    require("pub(crate) fn remote_history_cpu_domain(" in owner and
            "self.bind_public_service_cpu_domain(&cold)?" in owner and
            "self.public_service_cpu_domain()" in owner,
            "HISTORY_ONE_NODE_DOMAIN")
    require("!self.public_service_epoch_unknown" in owner and
            "self.public_service_epoch_listeners == 0" in owner and
            "let prior_epoch: Option<Vec<u8>>" in owner and
            "prior_epoch.is_none()" in owner and
            "ORDINARY_PUBLIC_EPOCH_KEY" in owner,
            "HISTORY_UNKNOWN_EPOCH_FENCE")
    cold_start = cpu.find("pub(crate) fn cold_remote_history_epoch()")
    cold_end = cpu.find("pub fn standalone()", cold_start)
    require(cold_start >= 0 and cold_end > cold_start and
            "PaidMutationCpuBudget::cold_start()" in cpu[cold_start:cold_end] and
            "pub fn begin_untrusted_peer_sync(" in cpu and
            "self.begin_with_priority(true)" in cpu and
            "budget.in_flight == 0" in cpu and
            "3 * MUTATION_CPU_START_RESERVE_NS" in cpu,
            "HISTORY_ONE_COLD_LOW_PRIORITY_BUDGET")
    for name in (
        "loopback_history_false_product_charges_one_cold_node_cpu_domain",
        "loopback_history_valid_work_still_accepts_under_cold_cpu_meter",
        "mixed_false_then_valid_history_across_source_ports_reuses_one_cpu_owner",
        "four_distinct_ticket_valid_false_history_traces_never_obtain_work",
        "malformed_remote_history_decode_pays_original_cpu_and_preserves_state",
        "unclean_public_epoch_cannot_mint_fresh_remote_history_credit",
        "cold_reopen_with_durable_active_v3_epoch_cannot_mint_history_cpu",
        "clean_v3_epoch_close_permits_only_one_cold_history_owner",
    ):
        require(name in ingress, "HISTORY_NATIVE_REGRESSION_" + name)
    return True


class SourceOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ingress = INGRESS.read_text()
        cls.owner = NODE.read_text()
        cls.cpu = CPU.read_text()
        cls.host = HOST.read_text()

    def gate(self, **changes):
        return check(changes.get("ingress", self.ingress),
                     changes.get("owner", self.owner),
                     changes.get("cpu", self.cpu),
                     changes.get("host", self.host))

    def test_exact_combined_source_preserves_all_original_owners(self):
        self.assertTrue(self.gate())

    def test_restoring_unmetered_full_work_or_only_per_page_host_check_is_rejected(self):
        direct = self.ingress.replace(
            "metered_history_packet(node, domain, packet, clock, host_check)?",
            "node.admit(packet, clock)?", 1)
        with self.assertRaisesRegex(ValueError, "HISTORY_METERED_W1|HISTORY_UNMETERED_W1"):
            self.gate(ingress=direct)
        no_host = self.ingress.replace(
            "if history_host_checkpoint(point) {",
            "if false {", 1)
        with self.assertRaises(ValueError):
            self.gate(ingress=no_host)

    def test_cross_file_cold_owner_and_low_priority_cannot_be_removed(self):
        warm = self.cpu.replace(
            "budget: Arc::new(Mutex::new(PaidMutationCpuBudget::cold_start()))",
            "budget: Arc::new(Mutex::new(PaidMutationCpuBudget::new()))", 1)
        with self.assertRaises(ValueError):
            self.gate(cpu=warm)
        unfair = self.ingress.replace(
            "domain.begin_untrusted_peer_sync()", "domain.begin()", 1)
        with self.assertRaisesRegex(ValueError, "HISTORY_LOW_PRIORITY_CPU"):
            self.gate(ingress=unfair)
        unbound = self.ingress.replace(
            "let domain = node.remote_history_cpu_domain()?;",
            "let domain = public_v3::ServiceMutationCpuDomain::standalone();", 1)
        with self.assertRaises(ValueError):
            self.gate(ingress=unbound)

    def test_public_loopback_proxy_cannot_shed_kernel_or_original_cpu(self):
        not_guarded = self.ingress.replace(
            "require_for_untrusted_public_sync(source)?",
            "require_for_listener(source)?", 1)
        with self.assertRaisesRegex(ValueError, "HISTORY_PUBLIC_LOOPBACK_GUARD"):
            self.gate(ingress=not_guarded)
        missing_cpu = self.ingress.replace(
            "receive_page(node, &domain, page, tip, after, clock, &|| host.verify())",
            "receive_page(node, &public_v3::ServiceMutationCpuDomain::standalone(), page, tip, after, clock, &|| host.verify())", 1)
        with self.assertRaises(ValueError):
            self.gate(ingress=missing_cpu)


if __name__ == "__main__":
    unittest.main(verbosity=2)
