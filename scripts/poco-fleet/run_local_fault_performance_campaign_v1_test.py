"""Contract tests for the real-process local fault/performance campaign."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_local_fault_performance_campaign_v1 as campaign


def test_campaign_runs_real_endpoint_and_proxy_processes() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-local-fault-campaign-test-") as raw:
        output = pathlib.Path(raw) / "evidence.json"
        result = campaign.run_campaign(output=output, messages=1)

        assert result["schema"] == campaign.SCHEMA
        assert result["campaign_scope"] == "single-host-loopback-multiprocess"
        assert result["candidate_only"] is True
        assert result["host_attestation"] is False
        assert result["independent_multihost_evidence"] is False
        assert result["physical_power_loss_evidence"] is False
        assert result["performance_acceptance"] is False
        assert result["production_activation"] is False
        assert result["restart_count"] == 1

        phases = result["phases"]
        assert [phase["name"] for phase in phases] == [
            "baseline",
            "partition",
            "heal",
            "partition",
            "heal",
            "partition",
            "heal",
            "proxy_restart",
        ]
        baseline = phases[0]
        assert baseline["accepted"] == 3
        assert baseline["rejected"] == 0
        for phase in phases:
            if phase["name"] == "partition":
                assert phase["rejected"] == phase["expected_rejected"] == 1
            if phase["name"] == "heal":
                assert phase["accepted"] == 1

        persisted = json.loads(output.read_text(encoding="utf-8"))
        assert persisted == result
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        assert output.with_suffix(output.suffix + ".sha256").read_text() == (
            f"{digest}  {output.name}\n"
        )


def test_campaign_rejects_invalid_message_bound() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-local-fault-campaign-test-") as raw:
        try:
            campaign.run_campaign(output=pathlib.Path(raw) / "bad.json", messages=0)
        except RuntimeError as error:
            assert "messages must be between" in str(error)
        else:
            raise AssertionError("invalid message bound unexpectedly accepted")


def test_campaign_does_not_replace_published_evidence() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-local-fault-campaign-test-") as raw:
        output = pathlib.Path(raw) / "evidence.json"
        campaign.run_campaign(output=output, messages=1)
        before = output.read_bytes()
        try:
            campaign.run_campaign(output=output, messages=1)
        except FileExistsError:
            pass
        else:
            raise AssertionError("existing evidence path was silently replaced")
        assert output.read_bytes() == before


def test_evidence_publisher_rejects_symlinked_parent() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-local-fault-campaign-test-") as raw:
        root = pathlib.Path(raw)
        target = root / "target"
        target.mkdir()
        alias = root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        try:
            campaign.publish_exclusive(alias / "evidence.json", b"{}\n")
        except RuntimeError as error:
            assert "real directory" in str(error)
        else:
            raise AssertionError("symlinked evidence parent was accepted")


def test_campaign_result_rejects_tampered_fault_counts_and_claim_flags() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-local-fault-campaign-test-") as raw:
        result = campaign.run_campaign(output=pathlib.Path(raw) / "evidence.json", messages=2)

        tampered_counts = json.loads(json.dumps(result))
        tampered_counts["phases"][1]["rejected"] = 1
        try:
            campaign.validate_campaign_result(tampered_counts)
        except RuntimeError as error:
            assert "partition 0 counts" in str(error)
        else:
            raise AssertionError("tampered partition counts unexpectedly accepted")

        tampered_active = json.loads(json.dumps(result))
        tampered_active["phases"][1]["active_connection_closed"] = False
        try:
            campaign.validate_campaign_result(tampered_active)
        except RuntimeError as error:
            assert "left an active connection open" in str(error)
        else:
            raise AssertionError("active connection omission unexpectedly accepted")

        tampered_claim = json.loads(json.dumps(result))
        tampered_claim["performance_acceptance"] = True
        try:
            campaign.validate_campaign_result(tampered_claim)
        except RuntimeError as error:
            assert "performance_acceptance flag" in str(error)
        else:
            raise AssertionError("promoted performance claim unexpectedly accepted")

        tampered_source = json.loads(json.dumps(result))
        tampered_source["source_proxy_sha256"] = "0" * 64
        try:
            campaign.validate_campaign_result(tampered_source)
        except RuntimeError as error:
            assert "does not match the checked-in proxy" in str(error)
        else:
            raise AssertionError("tampered source digest unexpectedly accepted")

        tampered_runner = json.loads(json.dumps(result))
        tampered_runner["source_campaign_sha256"] = "0" * 64
        try:
            campaign.validate_campaign_result(tampered_runner)
        except RuntimeError as error:
            assert "does not match the checked-in campaign" in str(error)
        else:
            raise AssertionError("tampered campaign digest unexpectedly accepted")


def test_campaign_result_rejects_non_monotonic_latency() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-local-fault-campaign-test-") as raw:
        result = campaign.run_campaign(output=pathlib.Path(raw) / "evidence.json", messages=1)
        tampered = json.loads(json.dumps(result))
        tampered["phases"][0]["latency_ms"]["p95"] = tampered["phases"][0]["latency_ms"]["max"] + 1
        try:
            campaign.validate_campaign_result(tampered)
        except RuntimeError as error:
            assert "percentiles are not monotonic" in str(error)
        else:
            raise AssertionError("non-monotonic latency unexpectedly accepted")


def main() -> None:
    test_campaign_runs_real_endpoint_and_proxy_processes()
    test_campaign_rejects_invalid_message_bound()
    test_campaign_result_rejects_tampered_fault_counts_and_claim_flags()
    test_campaign_result_rejects_non_monotonic_latency()
    print(
        "trnm_local_fault_performance_campaign_v1_test=passed "
        "real_endpoint_processes=true real_proxy_process=true "
        "partition_heal=true proxy_restart=true "
        "candidate_only=true independent_multihost=false performance_acceptance=false"
    )


if __name__ == "__main__":
    main()
