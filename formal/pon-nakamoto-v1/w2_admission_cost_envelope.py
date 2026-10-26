"""P2 research: refuse to price public W1 verification from CPU-only Hashcash.

This deliberately never returns a 'production ready' outcome. Measured GPU
costs and real signed-cookie overhead must be supplied, not derived from the
Python W1 simulator or substituted with a hypothetical hardware multiplier.
"""
import argparse
import json
import math
from pathlib import Path

SCHEMA = "trnm-w1-admission-conditional-cost-envelope-v1"
BITS = (8, 12, 16, 20)
KEYS = {
    "honest_hash_cpu_ns", "attacker_fastest_hash_ns", "invalid_w1_cpu_ns",
    "honest_nonhash_ns", "honest_deadline_ns", "observation_scope",
}


def positive_real(value, name, allow_zero=False):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(name)
    if value < 0 or (value == 0 and not allow_zero):
        raise ValueError(name)
    return float(value)


def quantile_trials(bits, quantile=0.95):
    if type(bits) is not int or not 8 <= bits <= 20:
        raise ValueError("BITS")
    if type(quantile) is not float or not 0 < quantile < 1:
        raise ValueError("QUANTILE")
    probability = 2.0 ** -bits
    return math.ceil(math.log1p(-quantile) / math.log1p(-probability))


def strict_json(raw):
    def unique_pairs(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("DUPLICATE_JSON_FIELD")
            result[name] = value
        return result

    def nonfinite(_):
        raise ValueError("NONFINITE_JSON")

    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=nonfinite)


def evaluate(payload):
    if type(payload) is not dict or set(payload) != KEYS:
        raise ValueError("EXACT_INPUT_SCHEMA")
    scope = payload["observation_scope"]
    if scope not in ("synthetic", "measured_unattested"):
        raise ValueError("OBSERVATION_SCOPE")
    required = ("honest_hash_cpu_ns", "attacker_fastest_hash_ns",
                "invalid_w1_cpu_ns", "honest_nonhash_ns", "honest_deadline_ns")
    numbers = {}
    for key in required:
        value = payload[key]
        if value is None:
            numbers[key] = None
        else:
            numbers[key] = positive_real(value, key, key == "honest_nonhash_ns")
    if numbers["honest_nonhash_ns"] is not None and numbers["honest_deadline_ns"] is not None:
        if numbers["honest_nonhash_ns"] >= numbers["honest_deadline_ns"]:
            raise ValueError("HONEST_NO_TIME_FOR_TICKET")
    rows = []
    for bits in BITS:
        expected_trials = 1 << bits
        q95 = quantile_trials(bits)
        attacker = numbers["attacker_fastest_hash_ns"]
        receiver = numbers["invalid_w1_cpu_ns"]
        honest = numbers["honest_hash_cpu_ns"]
        overhead = numbers["honest_nonhash_ns"]
        deadline = numbers["honest_deadline_ns"]
        expected_attacker_cpu_ns = expected_trials * attacker if attacker is not None else None
        p95_honest_cpu_ns = q95 * honest + overhead if honest is not None and overhead is not None else None
        expected_cost_ratio = expected_attacker_cpu_ns / receiver if expected_attacker_cpu_ns is not None and receiver is not None else None
        viable = None if expected_cost_ratio is None or p95_honest_cpu_ns is None or deadline is None else (
            expected_cost_ratio >= 1 and p95_honest_cpu_ns <= deadline
        )
        rows.append({
            "bits":bits,
            "expected_hash_attempts":expected_trials,
            "p95_attempts_geometric_unbounded":q95,
            "expected_attacker_ticket_cost_ns":expected_attacker_cpu_ns,
            "p95_honest_ticket_plus_fixed_ns":p95_honest_cpu_ns,
            "expected_attacker_over_receiver_cpu":expected_cost_ratio,
            "conditional_feasibility":viable,
            "conditional_only":True,
            "worst_case_one_hash_attack_possible":True,
        })
    assessed = [x for x in rows if x["conditional_feasibility"] is not None]
    return {
        "schema":SCHEMA,"scope":scope,
        "unmeasured_values_remain_null":True,
        "gpu_asic_independence_proven":False,
        "permissionless_sybil_safety_proven":False,
        "real_cookie_crypto_and_network_overhead_complete":False,
        "physical_multihost_verification":False,
        "full_A03_accepted":False,
        "production_consensus_activation":False,
        "research_verdict":"UNKNOWN_INCOMPLETE_MEASUREMENTS" if len(assessed) != len(BITS)
            else ("SOME_BITS_EXPECTED_COST_ONLY" if any(row["conditional_feasibility"] for row in assessed)
                  else "NO_BIT_FEASIBLE_UNDER_DECLARED_COSTS"),
        "rows":rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--out")
    options = parser.parse_args()
    source = Path(options.input)
    with source.open("rb") as f:
        raw = f.read(65537)
    if len(raw) > 65536:
        raise SystemExit("BOUNDED_INPUT_REQUIRED")
    report = evaluate(strict_json(raw))
    rendered = json.dumps(report,sort_keys=True,indent=2)+"\n"
    if options.out:
        with open(options.out,"x",encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered,end="")


if __name__ == "__main__":
    main()
