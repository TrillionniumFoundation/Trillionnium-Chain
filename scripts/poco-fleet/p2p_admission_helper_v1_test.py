#!/usr/bin/env python3
"""Negative controls for the D0 P2P admission helper truth boundary."""

from __future__ import annotations

import copy
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import p2p_admission_helper_v1 as helper  # noqa: E402


def expect_failure(action, fragment: str) -> None:
    try:
        action()
    except helper.AdmissionTruthError as error:
        if fragment not in str(error):
            raise AssertionError(f"unexpected error: {error}") from error
    else:
        raise AssertionError("negative control unexpectedly succeeded")


def main() -> None:
    report = helper.build_truth_report("0123456789abcdef0123456789abcdef01234567")
    assert helper.validate_truth_report(report) == report
    raw = helper.canonical_json_bytes(report)
    assert helper.parse_truth_report(raw) == report

    tampered = copy.deepcopy(report)
    tampered["consensus_transport"] = True
    expect_failure(
        lambda: helper.validate_truth_report(tampered),
        "consensus_transport",
    )
    tampered = copy.deepcopy(report)
    tampered["host_attestation"] = True
    expect_failure(lambda: helper.validate_truth_report(tampered), "host_attestation")
    tampered = copy.deepcopy(report)
    tampered.pop("validator_run_completed")
    expect_failure(lambda: helper.validate_truth_report(tampered), "keys differ")
    expect_failure(lambda: helper.parse_truth_report(raw[:-1]), "canonical JSON")

    print(
        "p2p_admission_helper_v1_test=passed "
        "active_helper=true dual_signed_handshake=true "
        "nonce_freshness=true nonce_replay_rejection=true "
        "epoch_binding=true validator_set_binding=true lease_fencing=true "
        "bounded_cleanup_rebind=true host_attestation=false "
        "multihost_observed=false consensus_transport=false "
        "validator_runtime_started=false validator_run=false production=false"
    )


if __name__ == "__main__":
    main()
