"""Read-only phase-II/III qualification joins; never an owner or installer.

Supplied signatures/telemetry do not establish physical execution or independent
control. The existing V3 sequence verifier retains ownership of model evidence.
"""
import copy
import math
import sys
from pathlib import Path
from protocol import require, digest, integer, canonical, identity, Refusal

PAIR_FIELDS = ("chain_source", "chain_tree", "hepta_source", "hepta_tree")

def source_pair(value):
    require(type(value) is dict and set(value) == set(PAIR_FIELDS), "PAIR_FIELDS")
    for item in value.values():
        require(type(item) is str and len(item) == 40 and all(c in "0123456789abcdef" for c in item), "GIT_ID")
    return value

def verify_learning_packet(packet, trusted):
    """Calls the original signed/parent/context/exposure V3 relation, not a mock.

    trusted must come from the existing qualification owner, NOT packet fields.
    Reports missing external executions separately; no claimed receipt proves
    independence just by naming a different control-domain string.
    """
    require(type(packet) is dict and type(trusted) is dict, "LEARNING_PACKET")
    source_pair(trusted["pair"])
    require(packet["pair"] == trusted["pair"], "SOURCE_PAIR")
    require(packet["campaign"] == trusted["campaign"], "CAMPAIGN_PIN")
    digest(trusted["campaign"]); digest(trusted["initial_model"]); digest(trusted["history"])
    require(type(packet["history_hex"]) is str and len(packet["history_hex"]) <= 4*1024*1024, "HISTORY_LIMIT")
    required = ("generations", "receipts", "attestations", "run_plans", "contexts")
    for name in required:
        require(type(packet[name]) is list and len(packet[name]) == 3, "THREE_GENERATIONS")
    require(len(canonical(packet)) <= 2*1024*1024, "PACKET_LIMIT")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"pon-nakamoto-v1"))
    from model_generation_sequence import verify_parent_bound_generation_sequence
    p = copy.deepcopy(packet)
    result = verify_parent_bound_generation_sequence(
        bytes.fromhex(p["history_hex"]), trusted["history"], p["generations"], p["receipts"],
        p["attestations"], p["run_plans"], trusted["initial_model"], p["contexts"])
    return dict(schema="release-learning-input-review-v1", original_v3_result=result,
                frozen_pair=trusted["pair"], campaign=trusted["campaign"],
                independent_control_accepted=False, physical_installation_accepted=False,
                prospective_neural_gain_accepted=False, hepta_final_use=False,
                missing_external_acceptance=["independent-control review", "actual predecessor installation",
                                             "authorized untouched future tasks", "real neural training and service use"])


def finite_number(value, positive=False):
    require(type(value) in (int, float) and math.isfinite(value) and
            (value > 0 if positive else value >= 0), "MEASUREMENT_NUMBER")
    return value


def pipeline_observation(summary):
    """Consumes the existing continuous_pipeline.rs summary, including failures."""
    require(summary.get("schema") == "trnm-continuous-native-pipeline-v1", "PIPELINE_SCHEMA")
    for key in ("requested_blocks", "transactions_per_block", "accepted_transactions", "confirmed_transactions", "pending_confirmation_blocks"):
        integer(summary[key])
    seconds = finite_number(summary["whole_campaign_seconds"], positive=True)
    expected = summary["requested_blocks"] * summary["transactions_per_block"]
    confirmed, accepted = summary["confirmed_transactions"], summary["accepted_transactions"]
    require(confirmed <= accepted <= expected, "COUNT_CONSERVATION")
    stages = summary["stage_counts"]
    chain = [stages[k] for k in ("input_constructed", "execution_and_work_completed", "local_durable_admitted",
                               "local_active", "remote_acknowledged", "remote_membership_verified", "policy_confirmed")]
    for value in chain:
        integer(value)
    require(expected >= chain[0] and all(a >= b for a,b in zip(chain,chain[1:])), "STAGE_CONSERVATION")
    require(chain[-1] == confirmed and chain[-2] == accepted, "STAGE_COUNTS")
    require(type(summary["logical_pacing"]) is bool and type(summary["campaign_passed"]) is bool, "BOOLEAN")
    success = summary["campaign_passed"]
    require(not success or (confirmed == expected and summary["pending_confirmation_blocks"] == 0 and
                            summary["producer_validator_heads_agree"] is True), "FALSE_SUCCESS")
    rate = confirmed/seconds
    reported = finite_number(summary["whole_campaign_confirmed_transactions_per_second"])
    require(math.isclose(rate, reported, rel_tol=1e-9, abs_tol=1e-12), "RATE_RECOMPUTATION")
    return dict(schema="release-pipeline-observation-v1", input_digest=identity(summary),
                run_passed=success, requested_transactions=expected, confirmed_transactions=confirmed,
                unsuccessful_or_unobserved_transactions=expected-confirmed, whole_campaign_seconds=seconds,
                confirmed_goodput_including_drain=rate, logical_pacing=summary["logical_pacing"],
                saturation_accepted=False, independent_wan_accepted=False, model_download_to_use_latency=None)


def compare_pipeline(baseline, candidate, baseline_environment, candidate_environment):
    a, b = pipeline_observation(baseline), pipeline_observation(candidate)
    require(baseline_environment == candidate_environment, "ENVIRONMENT_MISMATCH")
    comparable = ("network", "parameters", "genesis", "transaction_type", "pattern", "requested_blocks",
                  "transactions_per_block", "pace_ms", "admission_profile", "logical_pacing")
    require(all(baseline[k] == candidate[k] for k in comparable), "WORKLOAD_OR_SECURITY_MISMATCH")
    both = a["run_passed"] and b["run_passed"]
    ratio = (b["confirmed_goodput_including_drain"]/a["confirmed_goodput_including_drain"]
             if both and a["confirmed_goodput_including_drain"] > 0 else None)
    return dict(baseline=a, candidate=b, observed_goodput_ratio=ratio,
                general_speedup_accepted=False, reason="single controlled observation; no confidence, saturation, WAN or ML inference claim")
