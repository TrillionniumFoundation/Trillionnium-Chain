"""Author-slide Fast DAA retarget arithmetic, on an explicit partial domain.

Source: Yu Shen, *Parallel Blockchains and Applications*, 2026-09-15,
slides 52--54 (PDF pages 61--63). See the pinned source manifest in vectors/.
This is NOT the complete CRYPTO 2026 protocol or its September ePrint revision.
It does not implement mining, cross-chain validation, epochs, ledger agreement,
quantum security, or target/chainwork encoding. The full-backend refusal stays.

The slide's Reduce/Select operation is interpreted on globally ascending values:
remove eta extremes on each end, retain the first item of each eta-sized chunk,
then average representatives. Ascending grouping is an explicit interpretation;
the slide does not give sorting pseudocode. This component refuses incomplete
chunks, even-length medians, empty histories and missing references rather than
inventing protocol rules for cases not specified by the inspected slides.

Only positive int/Fraction values and finite, bounded containers are accepted.
These operational bounds and synthetic reference names are research API limits,
not parameters or wire rules certified by the paper. No kappa-to-mu/m mapping is
claimed. All reference histories must already be valid prior-epoch histories;
this component cannot establish that fact from their numeric difficulties.
"""
from dataclasses import dataclass
from fractions import Fraction


COMPONENT_ID = "fast-daa-author-slides-2026-09-15-retarget-v1"
MAX_CHAINS = 4096
MAX_BLOCKS_PER_CHAIN = 4095
MAX_TOTAL_BLOCKS = 16384
MAX_INPUT_BITS = 256
MAX_EXACT_BITS = 4096
MAX_REFERENCE_LENGTH = 128


class UnspecifiedCase(ValueError):
    """The inspected source does not specify this component input case."""


def _bounded(value):
    if (value.numerator.bit_length() > MAX_EXACT_BITS or
            value.denominator.bit_length() > MAX_EXACT_BITS):
        raise ValueError("EXACT_ARITHMETIC_BUDGET")
    return value


def _positive(value, name):
    if type(value) not in (int, Fraction):
        raise ValueError(name + "_EXACT_RATIONAL_TYPE")
    result = Fraction(value)
    if (result <= 0 or result.numerator.bit_length() > MAX_INPUT_BITS or
            result.denominator.bit_length() > MAX_INPUT_BITS):
        raise ValueError(name + "_RANGE")
    return result


def _sequence(values, name, maximum):
    if type(values) not in (list, tuple) or len(values) > maximum:
        raise ValueError(name + "_BOUNDED_SEQUENCE")
    return values


def _trim_parameters(count, eta):
    # mu=eta/m in (0,1/3), as in the displayed AA lemma, is only a
    # component precondition. It is not the full protocol's parameter mapping.
    if type(eta) is not int or eta < 1 or 3 * eta >= count:
        raise ValueError("TRIM_REQUIRES_INTEGER_ETA_AND_0_LT_ETA_OVER_M_LT_1_OVER_3")
    if (count - 2 * eta) % eta:
        raise UnspecifiedCase("UNSPECIFIED_PARTIAL_REPRESENTATIVE_CHUNK")


def _sum(values):
    total = Fraction(0)
    for value in values:
        total = _bounded(total + value)
    return total


def _agreement(values, eta):
    # Inputs here were already validated, or computed with bounded arithmetic.
    retained = sorted(values)[eta:len(values) - eta]
    representatives = tuple(retained[::eta])
    return _bounded(_sum(representatives) / len(representatives)), representatives


def approx_agree(values, eta):
    """Exact slide Reduce/Select/average with the declared ascending grouping."""
    _sequence(values, "VALUES", MAX_CHAINS)
    _trim_parameters(len(values), eta)
    checked = tuple(_positive(value, "VALUE") for value in values)
    return _agreement(checked, eta)[0]


@dataclass(frozen=True)
class RetargetResult:
    references: tuple
    chain_medians: tuple
    chain_ratios: tuple
    difficulty_representatives: tuple
    ratio_representatives: tuple
    reference_difficulty: Fraction
    reference_ratio: Fraction
    clipped_ratio: Fraction
    next_difficulty: Fraction

    def report(self):
        def rational(value):
            return {"numerator": value.numerator, "denominator": value.denominator}

        return {
            "component_id": COMPONENT_ID,
            "scope": "author_slide_retarget_component_under_declared_partial_domain",
            "complete_protocol_implemented": False,
            "production_activation": False,
            "quantum_security_established": False,
            "references": list(self.references),
            "chain_medians": [rational(x) for x in self.chain_medians],
            "chain_ratios": [rational(x) for x in self.chain_ratios],
            "difficulty_representatives": [rational(x) for x in self.difficulty_representatives],
            "ratio_representatives": [rational(x) for x in self.ratio_representatives],
            "reference_difficulty": rational(self.reference_difficulty),
            "reference_ratio": rational(self.reference_ratio),
            "clipped_ratio": rational(self.clipped_ratio),
            "next_difficulty": rational(self.next_difficulty),
        }


def retarget_component(references, histories, *, eta, ideal_blocks, dampening):
    """Evaluate slide 54 for supplied, fully present odd-length chain histories.

    Dref = AA(median(Diff(C_i))); rho = AA(sum(Diff(C_i))/(Lambda*median)).
    Dnew = Dref * clamp(rho, 1/tau, tau). All results remain rational, without
    any conversion into a native target or per-block integer chain weight.
    """
    _sequence(references, "REFERENCES", MAX_CHAINS)
    _trim_parameters(len(references), eta)
    if any(type(ref) is not str or not 1 <= len(ref) <= MAX_REFERENCE_LENGTH
           for ref in references):
        raise ValueError("REFERENCE_NAME")
    if len(set(references)) != len(references):
        raise ValueError("DUPLICATE_REFERENCE")
    if type(histories) is not dict or len(histories) > MAX_CHAINS:
        raise ValueError("HISTORIES_BOUNDED_MAPPING")
    if any(ref not in histories or histories[ref] is None for ref in references):
        raise UnspecifiedCase("UNSPECIFIED_MISSING_CHAIN_REFERENCE")
    if set(histories) != set(references):
        raise ValueError("UNREFERENCED_CHAIN_HISTORY")

    # Validate all shapes before arithmetic or creating rational copies.
    total_blocks = 0
    for ref in references:
        values = _sequence(histories[ref], "CHAIN_HISTORY", MAX_BLOCKS_PER_CHAIN)
        if not values:
            raise UnspecifiedCase("UNSPECIFIED_EMPTY_CHAIN_HISTORY")
        if len(values) % 2 == 0:
            raise UnspecifiedCase("UNSPECIFIED_EVEN_LENGTH_MEDIAN")
        total_blocks += len(values)
        if total_blocks > MAX_TOTAL_BLOCKS:
            raise ValueError("TOTAL_BLOCK_BUDGET")
    ideal = _positive(ideal_blocks, "IDEAL_BLOCKS")
    tau = _positive(dampening, "DAMPENING")
    if tau < 1:
        raise ValueError("DAMPENING_BELOW_ONE")

    medians, ratios = [], []
    for ref in references:
        values = tuple(_positive(value, "BLOCK_DIFFICULTY") for value in histories[ref])
        median = sorted(values)[len(values) // 2]
        medians.append(median)
        denominator = _bounded(ideal * median)
        ratios.append(_bounded(_sum(values) / denominator))
    dref, drepresentatives = _agreement(medians, eta)
    rhoref, rrepresentatives = _agreement(ratios, eta)
    clipped = max(Fraction(1, 1) / tau, min(rhoref, tau))
    return RetargetResult(tuple(references), tuple(medians), tuple(ratios),
                          drepresentatives, rrepresentatives, dref, rhoref,
                          clipped, _bounded(dref * clipped))
