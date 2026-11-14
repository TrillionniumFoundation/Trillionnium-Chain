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


def review_learning_control_material(packet, trusted, manifest_raw, policy_raw,
                                    control_trusted, *, now):
    """Compose the original V3 learning verifier with pinned role-control review.

    Both trust inputs belong to the existing qualification owner. In particular,
    controller bindings are original owner observations, never inferred from
    packet signatures, process counts, or the submitted control manifest. This
    read-only entry retains every old physical-use and authority boundary.
    """
    from control_separation import review_control_separation

    require(type(control_trusted) is dict and set(control_trusted) == {
        "manifest", "policy", "revision", "bindings"}, "CONTROL_TRUST_FIELDS")
    # Preserve the original verifier, signed bytes, parent lineage and NoUpdate
    # semantics. A successful role-material review cannot repair bad learning.
    learning = verify_learning_packet(packet, trusted)
    controls = review_control_separation(
        manifest_raw, policy_raw,
        expected_manifest=control_trusted["manifest"],
        expected_policy=control_trusted["policy"],
        expected_campaign=trusted["campaign"], expected_pair=trusted["pair"],
        expected_revision=control_trusted["revision"],
        expected_bindings=control_trusted["bindings"], now=now)
    return dict(
        schema="release-learning-control-review-v2",
        learning_input_review=learning, control_material_review=controls,
        frozen_pair=copy.deepcopy(trusted["pair"]), campaign=trusted["campaign"],
        qualification="HOLD_NO_GO", independent_control_accepted=False,
        learning_actor_control_binding_verified=False,
        physical_installation_accepted=False, prospective_neural_gain_accepted=False,
        hepta_final_use=False, production_activation=False,
        missing_external_acceptance=list(learning["missing_external_acceptance"]) +
            ["original learning actor-to-control binding"])


def review_learning_control_domains(packet, trusted, manifest_raw, policy_raw,
                                    control_trusted, domains_raw, documents, *,
                                    expected_domains, now):
    """Additional four-domain material join; no new native acceptance authority.

    Retain V3 signature/parent/NoUpdate validation and the original V1 control
    graph. This entry reads document bytes and catches declared funding/fault
    dependencies that the V1 material schema does not express.
    """
    from control_domains import review_control_domains

    require(type(control_trusted) is dict and set(control_trusted) == {
        "manifest", "policy", "revision", "bindings"}, "CONTROL_TRUST_FIELDS")
    learning = verify_learning_packet(packet, trusted)
    controls = review_control_domains(
        manifest_raw, policy_raw, domains_raw, documents,
        expected_domains=expected_domains,
        expected_manifest=control_trusted["manifest"],
        expected_policy=control_trusted["policy"],
        expected_campaign=trusted["campaign"], expected_pair=trusted["pair"],
        expected_revision=control_trusted["revision"],
        expected_bindings=control_trusted["bindings"], now=now)
    return dict(schema="release-learning-control-domains-review-v1",
        learning_input_review=learning, control_domain_material_review=controls,
        frozen_pair=copy.deepcopy(trusted["pair"]), campaign=trusted["campaign"],
        qualification="HOLD_NO_GO", independent_control_accepted=False,
        learning_actor_control_binding_verified=False,
        physical_installation_accepted=False, prospective_neural_gain_accepted=False,
        hepta_final_use=False, production_activation=False,
        missing_external_acceptance=list(learning["missing_external_acceptance"]) +
            ["original learning actor-to-control binding",
             "authenticated complete administration, fault, funding and custody observations"])


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
