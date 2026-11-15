"""Exact numeric semantics for the existing bounded source-routing Cell.

This is an independent scalar reference, not a proof system or a model-quality
qualification.  The artifact already contains integers.  There is no BF16
interpretation, inference-time quantizer, floating-point reduction or implicit
rounding.  Consumers must separately bind the artifact, upstream features,
state, decision policy and proof identity to their task contract.
"""
from __future__ import annotations

from fractions import Fraction

from contract_wire import canonical
from model_contract import DIM, SCALE, load_model_bytes
from work_oracle import Q

FEATURE_ABS_MAX = 8
WEIGHT_ABS_MAX = 32767
BIAS_VALUE = 8
MAX_BATCH = 64
CLASSES = 3
OPERATORS = ("base", "router", "delta-0", "delta-1", "delta-2")
OUTPUT_ROWS = CLASSES * len(OPERATORS)

# This descriptor is committed as part of the new useful-Cell relation.  It is
# not a set of caller-selectable execution options; all functions below use the
# fixed constants and rules directly.  Changing it requires a new relation.
NUMERIC_PROFILE = {
    "id": "hepta-source-integer-numeric-v1",
    "scalar_type": "signed-integer",
    "feature_dimensions": DIM,
    "feature_min": -FEATURE_ABS_MAX,
    "feature_max": FEATURE_ABS_MAX,
    "bias_coordinate": DIM - 1,
    "bias_value": BIAS_VALUE,
    "weight_min": -WEIGHT_ABS_MAX,
    "weight_max": WEIGHT_ABS_MAX,
    "coefficient_scale": SCALE,
    "feature_scale": FEATURE_ABS_MAX,
    "output_scale": SCALE * FEATURE_ABS_MAX,
    "field_modulus": Q,
    "field_encoding": "canonical-residue-of-signed-integer",
    "field_decoding": "centered-odd-modulus-with-strict-double-bound",
    "accumulator": "exact-signed-integer",
    "reduction_order": "ascending-feature-index",
    "inference_rounding": "none",
    "overflow": "reject",
    "saturation": "none",
    "quantization": "frozen-integer-artifact-only",
    "runtime_quantizer": "none",
    "floating_point_support": "none",
    "single_dot_absolute_bound": DIM * FEATURE_ABS_MAX * WEIGHT_ABS_MAX,
    "merged_weight_absolute_bound": 2 * WEIGHT_ABS_MAX,
    "merged_logit_absolute_bound": 2 * DIM * FEATURE_ABS_MAX * WEIGHT_ABS_MAX,
    "tie_break": "lowest-index",
    "stop": "separate-explicit-task-policy",
}


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _check_modulus(p):
    # Centered decoding only needs an odd modulus.  This helper does not prove
    # primality.  The relation fixes the already selected W1 prime Q; alternate
    # moduli are useful for exact small boundary tests, not protocol negotiation.
    _require(type(p) is int and p >= 3 and p % 2 == 1, "FIELD_MODULUS")


def checked_signed_bound(d, mx, mw, bias=0, p=Q):
    """Return d * mx * mw + abs(bias) only when 2 * bound < p.

    All arithmetic is exact Python integer arithmetic, including construction of
    the bound and abs of the most-negative finite-width integer.  mx and mw are
    nonnegative absolute limits; bias is a signed additive term.  Bias is already
    a feature coordinate in evaluate_exact, so that caller passes bias=0.
    """
    _check_modulus(p)
    _require(all(type(value) is int for value in (d, mx, mw, bias)),
             "SIGNED_BOUND_TYPE")
    _require(d >= 0 and mx >= 0 and mw >= 0, "SIGNED_BOUND_RANGE")
    bound = d * mx * mw + abs(bias)
    # p // 2 followed by a strict comparison incorrectly rejects the largest
    # legal positive value when p is odd (48 for p=97).
    _require(2 * bound < p, "SIGNED_DECODE_RANGE")
    return bound


def centered_decode(value, p=Q):
    """Decode one canonical residue; this alone does not prove a dot-product bound."""
    _check_modulus(p)
    _require(type(value) is int and 0 <= value < p, "FIELD_ELEMENT")
    return value - p if 2 * value > p else value


def _feature_rows(rows):
    _require(type(rows) is list and 1 <= len(rows) <= MAX_BATCH, "INFERENCE_BATCH")
    result = []
    for row in rows:
        _require(type(row) is list and len(row) == DIM, "INPUT_SHAPE")
        _require(all(type(value) is int and -FEATURE_ABS_MAX <= value <= FEATURE_ABS_MAX
                     for value in row) and row[-1] == BIAS_VALUE, "INPUT_RANGE")
        result.append(tuple(row))
    return result


def _lowest_index(values):
    # Strict comparison preserves the first index for equal scores, including
    # ties between nonzero expert/class indices and ties at negative values.
    best = 0
    for index in range(1, len(values)):
        if values[index] > values[best]:
            best = index
    return best


def evaluate_exact(model, rows):
    """Evaluate validated raw feature rows and return only Python lists/integers.

    rows is a list of 1..64 feature vectors, each a list of DIM=257 integers;
    callers with source-task dictionaries explicitly pass [task['x'] for task
    in tasks].  products has shape 15 x batch in base, router, delta-0, delta-1,
    delta-2 order.  logits has shape batch x 3.  routes and predictions are
    batch-length lists.  No divisions by output_scale are performed.
    """
    _require(type(model) is dict, "MODEL_OBJECT")
    # Reuse the existing strict artifact schema/ranges, then calculate the
    # complete operator here without calling its infer or a NumPy implementation.
    model = load_model_bytes(canonical(model))
    rows = _feature_rows(rows)
    single_bound = checked_signed_bound(DIM, FEATURE_ABS_MAX, WEIGHT_ABS_MAX)
    merged_bound = checked_signed_bound(DIM, FEATURE_ABS_MAX, 2 * WEIGHT_ABS_MAX)
    weights = model["base"] + model["router"] + [
        row for delta in model["deltas"] for row in delta
    ]
    products = []
    for weight_row in weights:
        product_row = []
        for features in rows:
            total = 0
            for coordinate in range(DIM):
                total += weight_row[coordinate] * features[coordinate]
            _require(abs(total) <= single_bound, "PRODUCT_SIGNED_BOUND")
            product_row.append(total)
        products.append(product_row)

    routes, logits, predictions = [], [], []
    for request in range(len(rows)):
        expert = _lowest_index([products[CLASSES + index][request]
                                for index in range(CLASSES)])
        scores = [products[index][request]
                  + products[2 * CLASSES + CLASSES * expert + index][request]
                  for index in range(CLASSES)]
        _require(all(abs(score) <= merged_bound for score in scores),
                 "LOGIT_SIGNED_BOUND")
        routes.append(expert)
        logits.append(scores)
        predictions.append(_lowest_index(scores))
    return {"products": products, "routes": routes, "logits": logits,
            "predictions": predictions}


def _numeric_observations(values):
    _require(type(values) is list and 1 <= len(values) <= MAX_BATCH,
             "BEHAVIOR_BATCH")
    _require(type(values[0]) is list and 1 <= len(values[0]) <= OUTPUT_ROWS,
             "BEHAVIOR_SHAPE")
    width = len(values[0])
    normalized = []
    for row in values:
        _require(type(row) is list and len(row) == width, "BEHAVIOR_SHAPE")
        # Fractions are supported only for diagnostics, to construct arbitrarily
        # small exact error counterexamples.  Inference remains integer-only.
        _require(all(type(value) in (int, Fraction) for value in row),
                 "BEHAVIOR_NUMBER")
        normalized.append([Fraction(value) for value in row])
    return normalized


def _fraction_pair(value):
    return [value.numerator, value.denominator]


def _agreement(reference, candidate):
    matches = sum(left == right for left, right in zip(reference, candidate))
    count = len(reference)
    return {"count": count, "matches": matches, "all_agree": matches == count,
            "agreement_fraction": _fraction_pair(Fraction(matches, count))}


def compare_behavior(reference_values, candidate_values, *, reference_routes,
                     candidate_routes, reference_stops, candidate_stops):
    """Describe numeric, route and STOP observations as three separate reports.

    Numeric values are batch x width lists of exact int/Fraction values (1..15
    values per request).  Routes are explicit indices 0..2; stops are explicit
    bools from the declared decision policy.  No route or STOP conclusion is
    inferred from mean error, and this utility never issues an acceptance or
    model-quality verdict.  Rational error/rate values are [numerator, denominator]
    pairs so the report can be serialized without floating-point rounding.
    """
    reference = _numeric_observations(reference_values)
    candidate = _numeric_observations(candidate_values)
    _require(len(reference) == len(candidate)
             and len(reference[0]) == len(candidate[0]), "BEHAVIOR_SHAPE")
    batch = len(reference)
    for routes in (reference_routes, candidate_routes):
        _require(type(routes) is list and len(routes) == batch
                 and all(type(route) is int and 0 <= route < CLASSES for route in routes),
                 "BEHAVIOR_ROUTES")
    for stops in (reference_stops, candidate_stops):
        _require(type(stops) is list and len(stops) == batch
                 and all(type(stop) is bool for stop in stops), "BEHAVIOR_STOPS")
    errors = [abs(left - right)
              for old, new in zip(reference, candidate)
              for left, right in zip(old, new)]
    equal = sum(error == 0 for error in errors)
    return {
        "numeric": {
            "count": len(errors), "matches": equal, "all_agree": equal == len(errors),
            "mean_absolute_error": _fraction_pair(sum(errors, Fraction(0)) / len(errors)),
            "max_absolute_error": _fraction_pair(max(errors)),
        },
        "routes": _agreement(reference_routes, candidate_routes),
        "stops": _agreement(reference_stops, candidate_stops),
    }
