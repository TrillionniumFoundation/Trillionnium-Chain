#!/usr/bin/env python3
"""Exact low-bit sampling component bounds; not a Poseidon2/NIZK certificate.

Assume each base-field draw is independently uniform over Goldilocks. For
Y = X & (2**b - 1), derive exact atoms, total variation and a joint density
ratio relative to independent uniform b-bit queries. All bound arithmetic is
Fraction arithmetic; Decimal is used only for displayed decimal/log values.
"""

import argparse
from collections import Counter
from decimal import Decimal, localcontext
from fractions import Fraction
import json
from pathlib import Path

P = 18_446_744_069_414_584_321


def fraction_record(value):
    with localcontext() as ctx:
        ctx.prec = 80
        decimal = Decimal(value.numerator) / Decimal(value.denominator)
        return {
            "numerator": str(value.numerator),
            "denominator": str(value.denominator),
            "decimal": str(decimal),
        }


def distribution(modulus, bits):
    if bits < 1 or bits >= modulus.bit_length():
        raise ValueError("require 1 <= bits and 2**bits < modulus")
    count = 1 << bits
    if count >= modulus:
        raise ValueError("require 1 <= bits and 2**bits < modulus")
    quotient, remainder = divmod(modulus, count)
    low_atom = Fraction(quotient, modulus)
    high_atom = Fraction(quotient + bool(remainder), modulus)
    uniform_atom = Fraction(1, count)
    total_variation = Fraction(remainder * (count - remainder), count * modulus)
    ratio = count * high_atom
    assert remainder * high_atom + (count - remainder) * low_atom == 1
    assert (remainder * abs(high_atom - uniform_atom)
            + (count - remainder) * abs(low_atom - uniform_atom)) / 2 == total_variation
    return count, quotient, remainder, low_atom, high_atom, total_variation, ratio


def check_small_exact_enumerations():
    """Check the algebra against direct residue counts, without large draws."""
    cases = [(13, 2), (11, 3), (17, 3), (31, 4)]
    for modulus, bits in cases:
        count, quotient, remainder, low, high, tv, ratio = distribution(modulus, bits)
        actual = Counter(x & (count - 1) for x in range(modulus))
        assert [actual[i] for i in range(count)] == [
            quotient + (i < remainder) for i in range(count)
        ]
        atoms = [Fraction(actual[i], modulus) for i in range(count)]
        assert max(atoms) == high
        assert min(atoms) == low
        assert sum(abs(a - Fraction(1, count)) for a in atoms) / 2 == tv
        assert max(atoms) / Fraction(1, count) == ratio
    return len(cases)


def evaluate(bits, queries):
    if not 1 <= queries <= 128:
        raise ValueError("query count must be 1..128 for this bounded audit tool")
    count, quotient, remainder, low, high, tv, ratio = distribution(P, bits)
    joint_ratio = ratio ** queries
    assert joint_ratio == high ** queries / Fraction(1, count) ** queries
    if bits <= 32:
        assert remainder == 1
        assert ratio == 1 + Fraction(count - 1, P)
        assert tv == Fraction(count - 1, count * P)
    with localcontext() as ctx:
        ctx.prec = 80
        decimal_ratio = Decimal(joint_ratio.numerator) / Decimal(joint_ratio.denominator)
        loss_bits = decimal_ratio.ln() / Decimal(2).ln()
    return {
        "bits": bits,
        "positions": count,
        "queries": queries,
        "modulus_div_positions": quotient,
        "modulus_remainder": remainder,
        "heavier_residues": {"first_inclusive": 0, "last_inclusive": remainder - 1},
        "maximum_point_mass": fraction_record(high),
        "other_point_mass": fraction_record(low),
        "single_query_total_variation": fraction_record(tv),
        "single_query_max_density_ratio": fraction_record(ratio),
        "joint_max_density_ratio": fraction_record(joint_ratio),
        "joint_density_excess_above_one": fraction_record(joint_ratio - 1),
        "joint_log2_density_loss_bits_decimal": str(loss_bits),
        "joint_total_variation_union_upper_bound_not_used_for_multiplicative_composition":
            fraction_record(min(Fraction(1), queries * tv)),
        "application": "For every event B on the query vector, Pr_actual[B] <= joint_max_density_ratio * Pr_uniform[B], under the stated independent-uniform-base-field model.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bits", nargs="+", type=int, default=[15, 19])
    parser.add_argument("--queries", type=int, default=64)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    checked = check_small_exact_enumerations()
    result = {
        "schema": "goldilocks-low-bits-density-component-bound-v1",
        "qualification": "HOLD_NO_GO",
        "modulus": str(P),
        "assumption": "Each base-field draw is independent and uniform over Goldilocks, including conditional on the preceding transcript. This script does not establish that assumption for concrete Poseidon2 or a Fiat-Shamir transcript.",
        "scope": "Sampling component only, not a complete ROM/QROM/NIZK soundness bound",
        "small_exact_enumeration_checks": checked,
        "cases": [evaluate(bits, args.queries) for bits in args.bits],
    }
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
        print(json.dumps({
            "output": str(args.output),
            "cases": [{"bits": c["bits"], "queries": c["queries"],
                       "joint_log2_density_loss_bits": c["joint_log2_density_loss_bits_decimal"]}
                      for c in result["cases"]],
        }, indent=2))
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
