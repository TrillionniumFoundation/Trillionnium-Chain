"""Literal fixed-header W1 nonce censuses and conditional shared-domain search.

A target is part of the challenged header. Retargeting, changing a witness root
or changing any other fixed header byte therefore requires new ticket values;
old tickets must not just be compared with a new threshold. A census enumerates
the complete *declared low-nonce subspace*, never the unenumerated nonce64 space.

The scalar predicate computes the challenge, bounded rejection sampler and full
ordered prefix trace. Public AB is computed once, outside each winner predicate,
and every native-shape winner is independently checked as a complete PNW1 proof
by work_oracle. Other native admission preconditions are outside this module.
Reduced-shape controls are not native W1. No circuit cost minimum, independent
ticket distribution, quantum machine execution or consensus theorem is claimed.
"""
from __future__ import annotations

from dataclasses import asdict
from fractions import Fraction
import hashlib
import random
import struct

from quantum_adversarial_search import TrialCosts, batch_success, upward_float
from w1_quantum_oracle import FixedTemplate, canonical, h_bytes, template_from_spec

SCHEMA = "trnm-w1-literal-marked-domain-v1"
SEARCH_SCHEMA = "trnm-w1-literal-domain-measurements-v1"
MAX_NATIVE_NONCE_BITS = 6
MAX_REDUCED_NONCE_BITS = 12
MAX_DOMAINS = 16
MAX_TRIALS = 256
MAX_PROCESSORS = 64
MAX_ITERATIONS = 100_000_000
CLAIMS = {
    "complete_declared_low_nonce_subspace": True,
    "actual_sha_and_bounded_noise_relation": True,
    "native_shape_winners_independently_scalar_verified": True,
    "native_task_parent_time_target_admission_checked": False,
    "unsearched_nonce64_space_characterized": False,
    "uniform_or_independent_W1_tickets_proved": False,
    "quantum_hardware_executed": False,
    "physical_resources_calibrated": False,
    "attacker_minimum_cost_proved": False,
    "consensus_security_theorem": False,
    "production_consensus_activation": False,
}


def _integer(value, name, high, low=0):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(name)
    return value


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _template(value):
    if type(value) is not FixedTemplate:
        raise ValueError("FIXED_TEMPLATE_TYPE")
    if (type(value.header) is not bytes or type(value.target) is not int
            or type(value.nonce_offset) is not int or type(value.profile) is not str
            or type(value.challenge_tag) is not bytes):
        raise ValueError("NONCANONICAL_FIXED_TEMPLATE")
    rebuilt = template_from_spec(value.spec())
    # Dataclass construction is public. Do not trust a forged target, profile,
    # offset, challenge tag, matrix tuple or unnormalised nonce field.
    if value != rebuilt or type(value.a) is not tuple or type(value.b) is not tuple:
        raise ValueError("NONCANONICAL_FIXED_TEMPLATE")
    return rebuilt


def _field_bytes(values):
    return struct.pack("<" + "I" * len(values), *values)


def _matrix_product(a, b, rows, inner, columns, modulus):
    return [sum(a[i * inner + k] * b[k * columns + j] for k in range(inner)) % modulus
            for i in range(rows) for j in range(columns)]


def _noise(challenge, label, shape):
    required, mask = shape.n * shape.r, (1 << shape.field_bits) - 1
    accepted, prefix = [], []
    counters = 0
    for counter in range(shape.noise_counters):
        chunk = hashlib.sha256(h_bytes(b"noise", challenge, bytes([label]),
                                      struct.pack("<I", counter))).digest()
        counters += 1
        words = [word & mask for (word,) in struct.iter_unpack("<I", chunk)]
        prefix.extend(words[:max(0, required - len(prefix))])
        accepted.extend(word for word in words if word < shape.q)
        if len(accepted) >= required:
            break
    return accepted[:required], {
        "complete": len(accepted) >= required,
        "sampled_counters": counters,
        "accepted_words_in_sampled_counters": len(accepted),
        "prefix_all_accepted": len(prefix) == required and all(x < shape.q for x in prefix),
    }


def _evaluate_nonce(template, nonce):
    header = template.header_for(nonce)
    challenge = hashlib.sha256(h_bytes(template.challenge_tag, header)).digest()
    shape = template.shape
    samples = [_noise(challenge, label, shape) for label in range(4)]
    flags = [sample[1]["complete"] for sample in samples]
    prefixes = [sample[1]["prefix_all_accepted"] for sample in samples]
    row = {
        "nonce": nonce,
        "challenge": challenge.hex(),
        "noise_complete": flags,
        "noise_sampled_counters": [sample[1]["sampled_counters"] for sample in samples],
        "noise_accepted_words_in_sampled_counters": [
            sample[1]["accepted_words_in_sampled_counters"] for sample in samples],
        "prefix_all_accepted_by_label": prefixes,
        "prefix_all_accepted": all(prefixes),
        "trace": None,
        "ticket": None,
        "winner": False,
        "refusal": None,
    }
    if not all(flags):
        row["refusal"] = "NOISE_BUDGET"
        return row
    el, er, fl, fr = [sample[0] for sample in samples]
    n, r, q = shape.n, shape.r, shape.q
    e = _matrix_product(el, er, n, r, n, q)
    f = _matrix_product(fl, fr, n, r, n, q)
    aa = [(x + y) % q for x, y in zip(template.a, e)]
    bb = [(x + y) % q for x, y in zip(template.b, f)]
    product_prefix = [0] * (n * n)
    trace = hashlib.sha256(b"TRNM-PON-TRACE1\0" + challenge)
    for i0 in range(0, n, r):
        for j0 in range(0, n, r):
            for k0 in range(0, n, r):
                tile = []
                for i in range(i0, i0 + r):
                    for j in range(j0, j0 + r):
                        pos = i * n + j
                        product_prefix[pos] = (product_prefix[pos] + sum(
                            aa[i * n + k] * bb[k * n + j] for k in range(k0, k0 + r))) % q
                        tile.append(product_prefix[pos])
                trace.update(_field_bytes(tile))
    trace_bytes = trace.digest()
    ticket = hashlib.sha256(h_bytes(b"ticket", challenge, trace_bytes)).digest()
    row.update({"trace": trace_bytes.hex(), "ticket": ticket.hex(),
                "winner": int.from_bytes(ticket, "big") <= template.target})
    return row


def evaluate_nonce(template, nonce):
    """Evaluate one literal nonce; does not construct a proof or native admission.

    On exhaustion there is no legal W1 trace/proof, so trace and ticket are null.
    The reversible circuit may internally calculate an unmarked zero-filled
    branch; such an internal ticket is deliberately not counted as legal work.
    """
    return _evaluate_nonce(_template(template), nonce)


def enumerate_domain(template):
    """Enumerate the declared low-nonce subspace and verify every native winner.

    All other nonce bits are fixed to zero by FixedTemplate. The initial public
    product and each winning proof verification are observer work, not claimed
    to be a minimum mining cost or charged to every coherent query.
    """
    template = _template(template)
    limit = MAX_NATIVE_NONCE_BITS if template.shape.native else MAX_REDUCED_NONCE_BITS
    _integer(template.nonce_bits, "CENSUS_NONCE_BITS_BOUND", limit, 1)
    spec = template.spec()
    spec_digest = _digest(canonical(spec))
    product = None
    if template.shape.native:
        import work_oracle
        product = _matrix_product(template.a, template.b, 64, 64, 64, template.shape.q)
        proof_prefix = b"PNW1" + _field_bytes(template.a) + _field_bytes(template.b) + _field_bytes(product)
        base = 0 if template.profile == "PNH1" else 4
        task = template.header[base + 278:base + 310]
    rows = []
    for nonce in range(1 << template.nonce_bits):
        row = _evaluate_nonce(template, nonce)
        row.update({"proof_sha256": None, "complete_PNW1_scalar_verified": False})
        if row["winner"] and template.shape.native:
            proof = proof_prefix + bytes.fromhex(row["trace"])
            ticket, checked_product = work_oracle.verify(bytes.fromhex(row["challenge"]), task,
                                                        template.target.to_bytes(32, "big"), proof)
            if ticket.hex() != row["ticket"] or checked_product != product:
                raise ValueError("INDEPENDENT_NATIVE_WINNER_MISMATCH")
            row.update({"proof_sha256": _digest(proof), "complete_PNW1_scalar_verified": True})
        rows.append(row)
    marked = [row["nonce"] for row in rows if row["winner"]]
    size = len(rows)
    return {
        "schema": SCHEMA,
        "template": spec,
        "template_sha256": spec_digest,
        "domain_sha256": _digest(b"TRNM-W1-LITERAL-DOMAIN1\0" + bytes.fromhex(spec_digest)),
        "profile": template.profile,
        "native_shape": template.shape.native,
        "enumerated_low_nonce_bits": template.nonce_bits,
        "unsearched_nonce_bits": 64 - template.nonce_bits,
        "domain_size": size,
        "marked_count": len(marked),
        "marked_nonces": marked,
        "marked_fraction": {"numerator": len(marked), "denominator": size},
        "uniform_ticket_premise": {"numerator": template.target + 1, "denominator": 1 << 256},
        "no_solution": not marked,
        "noise_budget_refusals": sum(row["refusal"] == "NOISE_BUDGET" for row in rows),
        "prefix_all_accepted_count": sum(row["prefix_all_accepted"] for row in rows),
        "prefix_restricted_marked_count": sum(row["prefix_all_accepted"] and row["winner"] for row in rows),
        "public_AB_sha256": _digest(_field_bytes(product)) if product is not None else None,
        "public_AB_products_computed": int(product is not None),
        "native_winning_proofs_verified": sum(row["complete_PNW1_scalar_verified"] for row in rows),
        "outcomes": rows,
        "assertions": dict(CLAIMS),
    }


def replay_domain(record):
    """Recompute the literal relation; a self-consistent digest alone is insufficient."""
    if type(record) is not dict or record.get("schema") != SCHEMA:
        raise ValueError("CENSUS_SCHEMA")
    template = template_from_spec(record.get("template"))
    rebuilt = enumerate_domain(template)
    if canonical(record) != canonical(rebuilt):
        raise ValueError("CENSUS_REPLAY_MISMATCH")
    return rebuilt


def compare_domains(left, right):
    """Descriptive overlap of records already produced/replayed by this module.

    This is not a hypothesis test of independence. The campaign re-enumerates
    saved records before calling it; do the same with untrusted saved inputs.
    """
    for record in (left, right):
        if type(record) is not dict or record.get("schema") != SCHEMA:
            raise ValueError("CENSUS_SCHEMA")
    count = min(left["domain_size"], right["domain_size"])
    pairs = list(zip(left["outcomes"][:count], right["outcomes"][:count]))
    if any(a["nonce"] != b["nonce"] for a, b in pairs):
        raise ValueError("CENSUS_NONCE_ALIGNMENT")
    both = sum(a["winner"] and b["winner"] for a, b in pairs)
    a_count, b_count = (sum(row[index]["winner"] for row in pairs) for index in (0, 1))
    covariance = Fraction(both, count) - Fraction(a_count * b_count, count * count)
    return {
        "left_domain_sha256": left["domain_sha256"],
        "right_domain_sha256": right["domain_sha256"],
        "same_template": left["template_sha256"] == right["template_sha256"],
        "aligned_nonce_count": count,
        "matching_challenges": sum(a["challenge"] == b["challenge"] for a, b in pairs),
        "matching_complete_tickets": sum(a["ticket"] is not None and a["ticket"] == b["ticket"] for a, b in pairs),
        "left_marked": a_count,
        "right_marked": b_count,
        "jointly_marked": both,
        "indicator_covariance": {"numerator": covariance.numerator, "denominator": covariance.denominator},
        "ticket_independence_inferred": False,
    }


def _ratio(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def simulate_measurements(domains, schedule, processors, seed, costs):
    """Simulate a predeclared schedule over rechecked literal marked sets.

    Each schedule entry is (domain_index, Grover_iterations), chosen before
    seeing M. All processors measure independently conditional on the SAME
    domain's M. A measurement returns an actual nonce from that marked/unmarked
    set; failed retries never resample the domain. The experiment stops on its
    first successful batch, so duplicate measurements are not extra blocks.

    Costs are explicit caller assumptions. Parallel coherent stages take their
    longest common clock; classical candidate checks run serially for all P
    measurements, including failures. A single resident template is modeled:
    first use or a different template pays setup, a retry of the same template
    does not. A revisit after eviction pays again; better caching is possible.
    Every batch pays fresh preparation. No physical speed or attacker optimum
    follows from this schedule. Saved censuses are fully re-enumerated first.
    """
    if type(domains) is not tuple or not 1 <= len(domains) <= MAX_DOMAINS:
        raise ValueError("SEARCH_DOMAINS")
    if type(schedule) is not tuple or not 1 <= len(schedule) <= MAX_TRIALS:
        raise ValueError("SEARCH_SCHEDULE")
    _integer(processors, "SEARCH_PROCESSORS", MAX_PROCESSORS, 1)
    _integer(seed, "SEARCH_SEED", (1 << 64) - 1)
    if type(costs) is not TrialCosts:
        raise ValueError("SEARCH_COSTS")
    costs.validate()
    for pair in schedule:
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError("SEARCH_SCHEDULE_ENTRY")
        _integer(pair[0], "SEARCH_DOMAIN_INDEX", len(domains) - 1)
        _integer(pair[1], "SEARCH_ITERATIONS", MAX_ITERATIONS)
    checked = [replay_domain(record) for record in domains]
    numbers = {name: Fraction(value) for name, value in asdict(costs).items() if name != "clock_rounding"}
    rng = random.Random(seed)
    elapsed = processor_time = Fraction(0)
    setup_charges = 0
    resident = None
    trials = []
    for index, (domain_index, iterations) in enumerate(schedule):
        domain = checked[domain_index]
        marked = domain["marked_nonces"]
        marked_set = set(marked)
        unmarked = [nonce for nonce in range(domain["domain_size"]) if nonce not in marked_set]
        probability = batch_success(len(marked) / domain["domain_size"], iterations)
        sampled = []
        for _ in range(processors):
            success = rng.random() < probability
            nonce = rng.choice(marked if success else unmarked)
            sampled.append({"nonce": nonce, "winner": domain["outcomes"][nonce]["winner"]})
        success = any(row["winner"] for row in sampled)
        setup = domain["domain_sha256"] != resident
        resident = domain["domain_sha256"]
        setup_charges += int(setup)
        coherent = (numbers["prepare_seconds"] + iterations * numbers["iteration_seconds"]
                    + numbers["measurement_seconds"])
        duration = (int(setup) * numbers["domain_setup_seconds"] + coherent
                    + processors * numbers["candidate_check_seconds"]
                    + int(success) * numbers["proof_seconds"])
        processor_time += processors * coherent
        elapsed += duration
        trials.append({
            "schedule_index": index,
            "domain_index": domain_index,
            "domain_sha256": domain["domain_sha256"],
            "iterations": iterations,
            "evaluator_marked_count": len(marked),
            "domain_size": domain["domain_size"],
            "conditional_batch_success_probability": batch_success(
                len(marked) / domain["domain_size"], iterations, processors),
            "domain_setup_charged": setup,
            "measurements": sampled,
            "success": success,
            "duration_assumed_seconds_exact": _ratio(duration),
            "finished_assumed_seconds_exact": _ratio(elapsed),
        })
        if success:
            break
    plan = {"domain_sha256": [record["domain_sha256"] for record in checked],
            "schedule": [list(pair) for pair in schedule], "processors": processors,
            "costs": asdict(costs), "seed": seed}
    return {
        "schema": SEARCH_SCHEMA,
        "plan": plan,
        "plan_sha256": _digest(canonical(plan)),
        "strategy_reads_marked_count": False,
        "domain_sampler": "literal-census-no-Bernoulli-resampling",
        "template_setup_policy": "single-resident-template",
        "candidate_check_policy": "all-processor-measurements-serial",
        "domain_setup_charges": setup_charges,
        "trials": trials,
        "success": trials[-1]["success"],
        "unused_predeclared_trials": len(schedule) - len(trials),
        "elapsed_assumed_seconds_exact": _ratio(elapsed),
        "elapsed_assumed_seconds_upper_float": upward_float(elapsed),
        "coherent_processor_seconds_exact": _ratio(processor_time),
        "quantum_hardware_executed": False,
        "native_blocks_admitted": 0,
        "independent_ticket_prior_used": False,
        "physical_clock_calibrated": False,
        "attacker_optimality_proved": False,
    }
