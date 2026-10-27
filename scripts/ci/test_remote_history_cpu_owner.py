#!/usr/bin/env python3
"""Fail-closed source-bound P1 regression, NOT native/physical qualification.

Guard the one public untrusted History API against accidentally restoring a
direct full-W1 admission bypass during future merges. Actual runtime,
cgroup/process budget and W1 correctness need separate native tests.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
INGRESS = ROOT / "trillionnium/crates/trnm-pon-node/src/ingress.rs"
NODE = ROOT / "trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs"
CPU = ROOT / "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs"


def check(ingress, owner, cpu):
    def require(ok, label):
        if not ok:
            raise ValueError(label)

    first = ingress.find("fn begin_history_import_cpu(")
    private = ingress.find("fn receive_page(", first)
    public = ingress.find("pub fn receive_page_from(", private)
    end = ingress.find("pub fn sync_from(", public)
    require(-1 not in (first, private, public, end) and first < private < public < end,
            "HISTORY_API_BOUNDARY")
    loader = ingress[private:public]
    wrapper = ingress[public:end]
    metering = ingress[first:private]
    require("pub fn receive_page(" not in ingress and "node.admit(packet, clock)" not in loader,
            "HISTORY_UNMETERED_W1")
    require("metered_history_packet(node, domain, packet, clock)?" in loader,
            "HISTORY_METERED_W1")
    require("let (packets, next) = metered_history_operation(node, domain," in loader
            and ".map(|s| hex_packet(s))" in loader,
            "HISTORY_METERED_DECODE")
    require("owner.activate_observed(tip, clock)" in loader
            and "metered_history_operation(node, domain" in loader,
            "HISTORY_METERED_ACTIVATION")
    require("let domain = node.remote_history_cpu_domain()?;" in wrapper
            and "let native = receive_page(node, &domain, page, tip, after, clock);" in wrapper,
            "HISTORY_BOUND_DOMAIN")
    require(wrapper.index("require_for_listener(source)")
            < wrapper.index("let domain = node.remote_history_cpu_domain()?"),
            "HISTORY_KERNEL_FIRST")
    require("WorkCheckedPacket::verify_with_progress" in metering
            and "operation.worker_accounting()" in metering
            and "let receipt = operation.finish();" in metering
            and "if receipt.accounting_unavailable" in metering,
            "HISTORY_W1_CPU_OWNER")
    require("pub(crate) fn remote_history_cpu_domain(" in owner
            and "self.bind_public_service_cpu_domain(&cold)?" in owner
            and "self.public_service_cpu_domain()" in owner,
            "HISTORY_ONE_NODE_DOMAIN")
    require("!self.public_service_epoch_unknown" in owner
            and "self.public_service_epoch_listeners == 0" in owner,
            "HISTORY_UNKNOWN_EPOCH_FENCE")
    require("pub(crate) fn cold_remote_history_epoch()" in cpu
            and "PaidMutationCpuBudget::cold_start()" in cpu,
            "HISTORY_COLD_ZERO_CREDIT")
    for name in (
        "loopback_history_false_product_charges_one_cold_node_cpu_domain",
        "loopback_history_valid_work_still_accepts_under_cold_cpu_meter",
        "mixed_false_then_valid_history_across_source_ports_reuses_one_cpu_owner",
        "four_distinct_ticket_valid_false_history_traces_never_obtain_work",
        "malformed_remote_history_decode_pays_original_cpu_and_preserves_state",
        "unclean_public_epoch_cannot_mint_fresh_remote_history_credit",
    ):
        require(name in ingress, "HISTORY_NATIVE_REGRESSION_" + name)
    return True


class SourceOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ingress = INGRESS.read_text()
        cls.owner = NODE.read_text()
        cls.cpu = CPU.read_text()

    def test_exact_source_has_one_metered_import(self):
        self.assertTrue(check(self.ingress, self.owner, self.cpu))

    def test_restored_direct_w1_bypass_is_rejected(self):
        bypass = self.ingress.replace(
            "metered_history_packet(node, domain, packet, clock)?",
            "node.admit(packet, clock)?",
            1,
        )
        with self.assertRaises(ValueError):
            check(bypass, self.owner, self.cpu)

    def test_warm_import_burst_and_unbound_domain_are_rejected(self):
        warm = self.cpu.replace(
            "budget: Arc::new(Mutex::new(PaidMutationCpuBudget::cold_start()))",
            "budget: Arc::new(Mutex::new(PaidMutationCpuBudget::new()))",
            1,
        )
        with self.assertRaises(ValueError):
            check(self.ingress, self.owner, warm)
        unbound = self.ingress.replace(
            "let domain = node.remote_history_cpu_domain()?;",
            "let domain = public_v3::ServiceMutationCpuDomain::standalone();",
            1,
        )
        with self.assertRaises(ValueError):
            check(unbound, self.owner, self.cpu)


if __name__ == "__main__":
    unittest.main(verbosity=2)
