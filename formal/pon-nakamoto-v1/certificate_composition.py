"""CC1: exact local evidence joins and probability-scope separation.

Raw journal/packet bytes and real WLC signatures are rechecked. A successful
join authenticates neither the OS nor all-world work. Model reports are
recomputed; a global prior bound is never an allowance at an observed prefix.
No production rule, signed domain, or existing research relation is changed.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction as F
import hashlib
import json
from math import comb
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

import certificate_observability_models as co
import lifecycle_query_bound as lqc
import mandatory_units_relation as mu
import work_lifecycle_certificate as wlc
from work_lifecycle_help import HelpPolicy, HelpSlot


SCHEMA = "pon-certificate-composition-v1"
BASE_COMMIT = "88bce414d7ba7f7f6a60dba03943ee20dc501ed7"
GLOBAL_SCOPE = "global_unconditioned_from_independent_joint_initial_state"
PREFIX_SCOPE = "conditional_on_complete_coalition_prefix"
HEX = re.compile(r"[0-9a-f]{64}\Z")


class CompositionError(ValueError):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise CompositionError(code)


def digest(value: bytes) -> str:
    need(type(value) is bytes, "RAW_BYTES_REQUIRED")
    return hashlib.sha256(value).hexdigest()


def hex32(value, code: str = "HASH_ENCODING") -> str:
    need(type(value) is str and HEX.fullmatch(value) is not None, code)
    return value


def raw_file(path: Path, maximum: int, code: str) -> bytes:
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, code)
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    need(len(data) <= maximum, code)
    return data


def public_json(value):
    if type(value) is F:
        return {"numerator": value.numerator, "denominator": value.denominator}
    if type(value) is dict:
        return {key: public_json(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [public_json(item) for item in value]
    return value


def canonical(value) -> bytes:
    return json.dumps(public_json(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def fraction(value) -> F:
    if type(value) is F:
        return value
    need(type(value) is dict and set(value) == {"numerator", "denominator"}, "RATIONAL_ENCODING")
    n, d = value["numerator"], value["denominator"]
    need(type(n) is int and type(d) is int and d > 0
         and n.bit_length() <= 20000 and d.bit_length() <= 20000, "RATIONAL_ENCODING")
    return F(n, d)


def recheck_query_model(report: dict) -> dict:
    """Recompute the entire report, not merely its supplied probability label.

    This checks theorem arithmetic under declared assumptions. It does not
    authenticate C/Q/M, the prefix, its initial joint state, or the oracle law.
    """
    need(type(report) is dict, "QUERY_MODEL_REPORT")
    try:
        p = fraction(report["p"])
        need(p == mu.IDEAL_TICKET_PROBABILITY, "FROZEN_MU1_PROBABILITY")
        if report["model"] == "mu1-ideal-lifetime-prefix-list-v1":
            caps = lqc.LifetimeCaps(report["classical_prefix_cap_C"], report["post_prefix_cap_Q"],
                                    report["complete_outputs_cap_M"], report["terminal_domain_size"])
            recomputed = lqc.global_lifecycle_weight_bound(caps, report["credit_threshold"], p)
        elif report["model"] == "mu1-complete-classical-prefix-continuation-v1":
            recomputed = lqc.continuation_given_complete_prefix(
                distinct_seen=report["actual_distinct_seen"], marked_seen=report["actual_marked_seen"],
                post_queries=report["post_prefix_Q"], output_slots=report["complete_outputs_M"],
                credit=report["credit_threshold"], domain_size=report["domain_size"], p=p)
        else:
            raise CompositionError("QUERY_MODEL_NAMESPACE")
        need(set(report) == set(recomputed) and canonical(report) == canonical(recomputed),
             "QUERY_MODEL_REPORT_MISMATCH")
    except (KeyError, TypeError) as error:
        raise CompositionError("QUERY_MODEL_REPORT_FIELDS") from error
    return recomputed


@dataclass(frozen=True)
class ModelRiskUse:
    name: str
    start_history: tuple[str, ...]
    failure_leaves: tuple[str, ...]
    query_report: dict


def check_model_risk_bank(law: co.ProbabilityTree, uses: tuple[ModelRiskUse, ...],
                          allowance: F) -> dict:
    """A complete declared finite law supplies the real conditional ratios.

    All non-root uses require the conditional-prefix theorem; its numeric
    bound must also dominate the independently computed conditional event in
    this same law. This is not a validator of an actual network probability law.
    """
    need(type(law) is co.ProbabilityTree and type(uses) is tuple and len(uses) <= 64,
         "FINITE_DECLARED_RISK_LAW")
    attempts, scopes = [], []
    for use in uses:
        need(type(use) is ModelRiskUse, "MODEL_RISK_USE")
        report = recheck_query_model(use.query_report)
        scope = report["probability_scope"]
        if use.start_history:
            need(scope == PREFIX_SCOPE, "GLOBAL_BOUND_IS_NOT_CONDITIONAL")
        attempts.append(co.Attempt(use.name, use.start_history, use.failure_leaves, report["bound"]))
        scopes.append(scope)
    checked = co.check_predictable_risk_bank(law, tuple(attempts), allowance)
    return {"schema": "pon-composition-declared-risk-bank-v1", "probability_scopes": scopes,
            "model_reports_recomputed": True, "finite_declared_joint_law": checked,
            "independence_between_attempts_required": False,
            "actual_prefix_and_initial_state_authenticated": False,
            "actual_native_probability_law_authenticated": False,
            "native_six_successor_risk_certified": False}


def post_quantum_classical_reveal_counterexample() -> dict:
    """Exact 16-address Bernoulli phase/diffusion calculation, not hardware.

    For m marked entries, a uniform phase query then diffusion gives each
    marked address amplitude (3-4m/D)/sqrt(D). Measuring an address and then
    classically revealing it has success a(3-4a)^2, a=m/D. It is not fresh p.
    """
    size, p = 16, F(1, 16)
    rows, total = [], F(0)
    for marks in range(size + 1):
        mass = F(comb(size, marks)) * p ** marks * (1 - p) ** (size - marks)
        a = F(marks, size)
        hit = a * (3 - 4 * a) ** 2
        unmarked = (1 - a) * (1 - 4 * a) ** 2
        need(hit + unmarked == 1, "PHASE_DIFFUSION_NORMALIZATION")
        total += mass * hit
        rows.append({"oracle_mark_count": marks, "probability": mass, "conditional_hit": hit})
    need(total == F(13073, 32768) and total > p, "PHASE_PREFIX_COUNTEREXAMPLE")
    return {"model": "exact-finite-Bernoulli-phase-diffusion-v1", "domain_size": size,
            "p": p, "prior_coherent_bit_queries": 1, "subsequent_classical_reveals": 1,
            "actual_reveal_hit_probability_in_model": total,
            "incorrect_new_classical_prefix_probability": p,
            "oracle_count_cases": rows, "actual_quantum_hardware_executed": False,
            "later_owner_may_reset_global_prefix": False}


def empty_payload_timing_counterexample() -> dict:
    """A fixed empty payload does not make the complete helper alphabet one."""
    p, size = F(1, 16), 16
    success = 1 - (1 - p) ** size
    empty = b""
    complete = HelpPolicy((HelpSlot(("helper",), size, 0, 0),))
    coarse = HelpPolicy((HelpSlot(("helper",), 1, 0, 0),))
    actual_bins = []
    for i in range(size):
        event = {"slot": 0, "status": "data", "source": "helper", "delivery_bin": i,
                 "payload_bytes": 0, "error_code": None}
        complete.validate_delivery(event, empty)
        actual_bins.append(event)
    # A recorder which coarsens all visible arrival times to one bin can fit
    # its declared policy, but that fact does not mediate the receiver's clock.
    coarse.validate_delivery({**actual_bins[-1], "delivery_bin": 0}, empty)
    fresh = lqc.global_lifecycle_weight_bound(lqc.LifetimeCaps(0, 0, 1), 128)["bound"]
    return {"model": "finite-empty-payload-visible-timing-help-v1", "p": p,
            "helper_fresh_classical_queries": size, "receiver_new_queries": 0,
            "distinct_payload_values": 1, "payload_sha256": digest(empty),
            "visible_arrival_bins": size, "success_probability": success,
            "unpaid_helper_fresh_bound": fresh,
            "success_exceeds_fresh_bound": success > fresh,
            "complete_policy_support_including_absence": complete.support_capped(1000),
            "coarse_record_can_fit_policy_without_complete_mediation": True,
            "record_fit_authenticates_complete_observable_alphabet": False,
            "physical_time_channel_experiment": False}


def retained_unit_verify_input(directory: Path) -> tuple[bytes, str]:
    """Read a retained real W1 verifier input; validate raw bytes, not a label."""
    directory = directory.resolve(strict=True)
    doc_path = directory / "signed_observations.json"
    documents = wlc.strict_load(doc_path.read_bytes())
    for document in documents.values():
        for event in document["events"]:
            body = event["body"]
            if event["kind"] != "native_call" or body.get("mode") != "verify" or body.get("returncode") != 0:
                continue
            sha = hex32(body["input_sha256"])
            path = directory / "artifacts" / (sha + ".bin")
            need(not (directory / "artifacts").is_symlink() and not path.is_symlink()
                 and path.resolve(strict=True).parent == directory / "artifacts", "ARTIFACT_PATH_ESCAPE")
            data = path.read_bytes()
            need(digest(data) == sha and len(data) == body["input_bytes"]
                 and len(data) == 96 + mu.w1.PROOF_BYTES, "RETAINED_UNIT_INPUT")
            mu.w1.verify(data[:32], data[32:64], data[64:96], data[96:])
            return data, hex32(body["program_sha256"])
    raise CompositionError("RETAINED_VALID_W1_INPUT_REQUIRED")


def signed_valid_proof_without_producer(verify_input: bytes, program_sha256: str) -> dict:
    """Make a deliberately false execution statement using real signatures.

    Only old valid bytes are rearranged; no producer or native subprocess is
    invoked. A subsequent verifier still recomputes the complete W1 predicate.
    The control disproves execution attribution, not predicate validity.
    """
    need(type(verify_input) is bytes and len(verify_input) == 96 + mu.w1.PROOF_BYTES,
         "RETAINED_UNIT_INPUT")
    hex32(program_sha256)
    proof = verify_input[96:]
    producer_input = verify_input[:32] + proof[4:4 + 8 * mu.w1.CELLS]
    artifacts = {digest(value): value for value in (producer_input, proof, b"")}
    key = MLDSA65PrivateKey.generate()
    writer = wlc.ObservationWriter(key, session=digest(b"CC1 false producer " + wlc.public_spki(key)),
        source_commit=BASE_COMMIT, source_manifest={"retained_program_declaration": program_sha256},
        help_policy=HelpPolicy(()))
    writer.append("native_call", {"mode": "prove", "program_sha256": program_sha256,
        "input_sha256": digest(producer_input), "input_bytes": len(producer_input),
        "output_sha256": digest(proof), "output_bytes": len(proof),
        "stderr_sha256": digest(b""), "stderr_bytes": 0, "returncode": 0})
    writer.append("publish_artifact", {"artifact_sha256": digest(proof),
        "artifact_bytes": len(proof), "role": "full_w1_proof"})
    document, pin = writer.close()
    return {"documents": {"false-producer": document}, "pins": {"false-producer": pin},
            "artifacts": artifacts, "root": "false-producer",
            "native_producer_invocations_while_constructing_statement": 0}


@dataclass(frozen=True)
class PacketJoin:
    signed_source: str
    publish_event: str
    packet_sha256: str
    native_block_id: str


def join_local_evidence(*, journal_directory: Path, expected_checkpoint: dict | None,
                        documents: dict, pins: dict, artifacts: dict[str, bytes],
                        signed_root: str, links: tuple[PacketJoin, ...]) -> dict:
    """Read raw durable journal + packets, verify actual WLC, then join bytes.

    The optional expected checkpoint is an externally supplied expectation;
    its real independent retention is not established by this API. The journal
    reader is mandatory. No serialized 'verified' result is an alternate input.
    """
    from native_owner_journal import MAX_BYTES, read_journal

    need(isinstance(journal_directory, Path), "RAW_JOURNAL_DIRECTORY_REQUIRED")
    need(not journal_directory.is_symlink(), "RAW_JOURNAL_DIRECTORY_SYMLINK")
    journal_directory = journal_directory.resolve(strict=True)
    source = journal_directory / "journal.pnoj1"
    before = digest(raw_file(source, MAX_BYTES, "RAW_JOURNAL_FILE"))
    native = read_journal(journal_directory, expected_checkpoint=expected_checkpoint)
    signed = wlc.verify_collection(documents, pins, artifacts, signed_root)
    need(type(links) is tuple and 0 < len(links) <= 64, "PACKET_JOIN_LIMIT")
    valid = native["valid_packet_bindings"]
    need(type(valid) is dict, "RAW_NATIVE_PACKET_BINDINGS_REQUIRED")
    joined, unique = [], {}
    for link in links:
        need(type(link) is PacketJoin, "PACKET_JOIN_TYPE")
        for value in (link.publish_event, link.packet_sha256, link.native_block_id):
            hex32(value)
        need(link.signed_source in signed["verified_sources"], "SIGNED_SOURCE_NOT_VERIFIED")
        signed_source = signed["verified_sources"][link.signed_source]
        need(signed_source["exports"].get(link.publish_event) == link.packet_sha256,
             "SIGNED_EXACT_ARTIFACT_BINDING")
        need(link.packet_sha256 in valid, "EXACT_SIGNED_PACKET_NOT_NATIVE_VALIDATED")
        binding = valid[link.packet_sha256]
        need(binding["block_id"] == link.native_block_id, "NATIVE_BLOCK_ID_BINDING")
        raw = wlc.artifact(artifacts, link.packet_sha256)
        weight_hex = binding["required_work_hex"]
        need(type(weight_hex) is str and re.fullmatch("[0-9a-f]{128}", weight_hex) is not None,
             "NATIVE_REQUIRED_WORK_ENCODING")
        weight = int(weight_hex, 16)
        prior = unique.get(link.native_block_id)
        need(prior is None or prior == weight, "NATIVE_IDENTITY_WEIGHT_CONFLICT")
        unique[link.native_block_id] = weight
        joined.append({"block_id": link.native_block_id, "packet_sha256": link.packet_sha256,
                       "packet_bytes": len(raw), "native_required_work": weight,
                       "signed_source": link.signed_source, "signer_key_id": signed_source["key_id"],
                       "signed_publish_event": link.publish_event,
                       "native_binding": binding})
    need(digest(raw_file(source, MAX_BYTES, "RAW_JOURNAL_FILE")) == before,
         "JOURNAL_CHANGED_DURING_COMPOSITION")
    return {"schema": SCHEMA, "journal_sha256": before, "checkpoint": native["checkpoint"],
            "supplied_checkpoint_matches": native["supplied_checkpoint_matches"],
            "raw_journal_and_exact_packet_sources_rechecked": True,
            "actual_wlc_signatures_and_fragments_rechecked": True, "joined_packets": joined,
            "distinct_native_packet_ids": len(unique),
            "distinct_native_required_work_observed": sum(unique.values()),
            "repeated_publications_add_no_distinct_native_work": len(joined) - len(unique),
            "native_unresolved_intents": native["unresolved_intents"],
            "native_outside_lease_intervals": native["outside_lease_intervals"],
            "native_clock_regressions": native["clock_regressions"],
            "native_orphan_artifact_observations": native["orphan_artifact_observations"],
            "native_unreferenced_artifacts": native["unreferenced_artifacts"],
            "signer_is_metered_producer_established": False,
            "independent_external_anchor_retention_established": False,
            "global_first_ready_time_established": False,
            "new_generation_credit_established": False,
            "complete_world_view_established": False,
            "authenticated_global_clock_established": False,
            "joint_initial_state_established": False,
            "physical_query_upper_bound_established": False,
            "hidden_inventory_output_extraction_and_cap_attested": False,
            "native_identity_and_mu1_credit_bridge_established": False,
            "native_six_successor_failure_probability": None,
            "production_qualified": False}


def native_risk_from_join(_anything):
    """No combination of these local observations supplies the missing proof."""
    raise CompositionError("NATIVE_RELATION_RESOURCE_STATE_AND_WORLD_BRIDGES_UNPROVED")
