#!/usr/bin/env python3
"""Read-only P1 W1 entrypoint source guard, NOT a security or CPU qualification.

This deliberately pins concrete production callsites rather than claiming
a sound Rust reachability/callgraph theorem. Removing a known guard must
break the source regression, while local/Host/WAN acceptance remains open.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
P = "trillionnium/crates/trnm-pon-node/src/"
FILES = {
    "v2": P + "ingress/public_v2.rs",
    "v3": P + "ingress/public_v3.rs",
    "ingress": P + "ingress.rs",
    "peer": P + "peer_polling.rs",
    "owner_continuous": P + "store/operator_continuous_owner.rs",
    "owner_mining": P + "store/operator_mining_owner.rs",
    "store": P + "store.rs",
}


def section(source: str, start: str, stop: str) -> str:
    begin = source.find(start)
    finish = source.find(stop, begin + len(start)) if begin >= 0 else -1
    if begin < 0 or finish < 0:
        return ""
    return source[begin:finish]


def verify_sources(sources: dict[str, str]) -> dict[str, bool]:
    v2, v3, ingress, peer = (sources.get(key, "") for key in ("v2", "v3", "ingress", "peer"))
    continuous = sources.get("owner_continuous", "")
    mining = sources.get("owner_mining", "")
    store = sources.get("store", "")

    # Functions contain tests and other code after them. Inspect the named
    # production spans rather than searching for a protective test-only string.
    v2serve = section(v2, "pub fn serve_public_protected_v2(", "fn serve_public_protected_v2_with_owner(")
    v2private = section(v2, "fn serve_public_protected_v2_with_owner(", "fn ")
    legacy = section(ingress, "fn serve_inner(", "pub fn ")
    sync_raw = section(ingress, "pub fn sync_from(", "pub fn sync_from_authenticated(")
    sync_auth = section(ingress, "pub fn sync_from_authenticated(", "pub fn sync_from_authenticated_durable(")
    sync_durable = section(ingress, "pub fn sync_from_authenticated_durable(", "#[cfg(test)]")
    untrusted_page = section(ingress, "pub fn receive_page_from(", "pub fn sync_from(")
    private_page = section(ingress, "\nfn receive_page(", "\npub fn receive_page_from(")
    pinned = section(peer, "fn admit_page(", "struct PollContext")
    original_w1 = section(v3, "fn serve_public_protected_v3_inner(", "\n#[cfg(test)]")
    # Exact r13 source may choose a different local function name. The actual
    # charge is in the pre-test production part of the V3 module.
    v3_work = v3.split("\n#[cfg(test)]\nmod shared_cpu_domain_source_tests", 1)[0]
    w1_continuous = section(continuous, "fn continuous_validate(", "pub fn activate_owned_continuous_packet(")
    w1_mining = section(mining, "pub fn validate_owned_mining_winner(", "pub fn activate_owned_mining_winner(")
    client_api = section(v3, "pub fn call_public_protected_v3_with_cpu_observation(", "/// Wire and signed profile")

    return {
        "v2_network_loopback_only": "PUBLIC_V2_LOOPBACK_ONLY" in v2serve
                                    and "ip().is_loopback()" in v2serve
                                    and "PUBLIC_V2_LOOPBACK_ONLY" in v2private,
        "legacy_unauthenticated_loopback_or_protected_wan": (
            "DEVELOPMENT_LOOPBACK_ONLY" in legacy
            and "DEVELOPMENT_REMOTE_ADMISSION_REQUIRED" in legacy
            and "host_kernel_parent::require_for_listener(listener_address)" in legacy
        ),
        "v3_true_cpu_reserve_and_complete_work": (
            "PaidMutationCpuPermit::acquire_before(" in v3_work
            and "WorkCheckedPacket::verify_with_progress(" in v3_work
            and "cpu_permit" in v3_work
        ),
        "pinned_history_same_original_cpu_owner": (
            "owner.public_service_cpu_domain()?" in pinned
            and "let operation = cpu.begin()?;" in pinned
            and "WorkCheckedPacket::verify_with_progress(packet," in pinned
            and "operation.worker_accounting()" in pinned
            and "operation.finish()" in pinned
            and "settlement.accounting_unavailable" in pinned
        ),
        "addressless_history_import_private_and_source_guarded": (
            private_page.startswith("\nfn receive_page(")
            and "node.admit(packet, clock)?" in private_page
            and "host_kernel_parent::require_for_listener(source)?" in untrusted_page
            and "let native = receive_page(" in untrusted_page
            and "kernel.verify()?" in untrusted_page
        ),
        "all_native_remote_sync_variants_guarded": all(
            "host_kernel_parent::require_for_listener(address)?" in body
            and "receive_page_from(node, address, page," in body
            and body.count("kernel.verify()?") >= 2
            for body in (sync_raw, sync_auth, sync_durable)
        ),
        "owned_continuous_real_cpu_before_w1": (
            "o.operation(&permit, None)?" in w1_continuous
            and "WorkCheckedPacket::verify_with_progress(packet," in w1_continuous
            and "operation.worker_accounting()" in w1_continuous
            and "operation.finish()" in w1_continuous
        ),
        "owned_mining_real_cpu_before_w1": (
            "owner.begin_cpu(cpu)?" in w1_mining
            and "WorkCheckedPacket::verify_with_progress(packet," in w1_mining
            and "operation.worker_accounting()" in w1_mining
            and "operation.finish()" in w1_mining
        ),
        "native_owner_not_public_verifier": (
            "pub fn admit(&mut self, packet: &Packet" in store
            and "WorkCheckedPacket::verify(packet.clone())?" in store
        ),
        "p2_client_cpu_observation_never_changes_old_json": (
            "pub fn call_public_protected_v3_with_cpu_observation(" in client_api
            and "client_thread_cpu_ns: cpu.and_then(ThreadCpuStamp::finish)" in client_api
            and "#[serde(skip_serializing)]" in v3_work
            and "solution_cpu_stamp.take().and_then(ThreadCpuStamp::finish)" in v3_work
        ),
    }


def load():
    return {name: (ROOT / path).read_text(encoding="utf-8") for name, path in FILES.items()}


def exercise_negative_controls(inputs: dict[str, str]):
    # Mutate ONLY in memory. A source guard that cannot reject a removed owner
    # must never report a passing source assertion.
    changes = [
        ("peer", "let operation = cpu.begin()?;", "let operation = NOT_PAID()?;",
         "pinned_history_same_original_cpu_owner"),
        ("ingress", "host_kernel_parent::require_for_listener(source)?",
         "UNMETERED_SOURCE", "addressless_history_import_private_and_source_guarded"),
        ("v3", "#[serde(skip_serializing)]", "#[serde(skip_serializing = \"not-real\")]",
         "p2_client_cpu_observation_never_changes_old_json"),
        ("v3", "PaidMutationCpuPermit::acquire_before(", "UNMETERED_START(",
         "v3_true_cpu_reserve_and_complete_work"),
        ("v2", "PUBLIC_V2_LOOPBACK_ONLY", "V2_WAN_ALLOWED",
         "v2_network_loopback_only"),
        ("ingress", "DEVELOPMENT_REMOTE_ADMISSION_REQUIRED", "UNPRICED_WAN_ALLOWED",
         "legacy_unauthenticated_loopback_or_protected_wan"),
        ("owner_continuous", "o.operation(&permit, None)?", "UNACCOUNTED_CONTINUOUS_WORK",
         "owned_continuous_real_cpu_before_w1"),
        ("owner_mining", "owner.begin_cpu(cpu)?", "UNACCOUNTED_MINING_WINNER",
         "owned_mining_real_cpu_before_w1"),
    ]
    for name, original, changed, expected in changes:
        if original not in inputs[name]:
            raise ValueError("negative control source absent: " + expected)
        trial = dict(inputs)
        trial[name] = inputs[name].replace(original, changed, 1)
        if verify_sources(trial)[expected]:
            raise ValueError("negative guard deletion accepted: " + expected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--negative-controls", action="store_true")
    args = parser.parse_args()
    sources = load()
    observations = verify_sources(sources)
    if args.negative_controls:
        exercise_negative_controls(sources)
    try:
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        head = None
    report = {
        "schema": "trnm-w1-entrypoint-static-resource-owners-v1",
        "source_head": head, "entrypoints": observations,
        "passed": all(observations.values()),
        "negative_controls_run": args.negative_controls,
        "source_audit_only": True,
        "physical_host_cgroup_tested": False,
        "all_public_transports_dynamically_reached": False,
        "gpu_cost_lower_bound_known": False,
        "a03_qualified": False,
        "external_crypto_accepted": False,
        "production_activation": False,
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
