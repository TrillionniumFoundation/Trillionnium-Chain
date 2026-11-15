"""Exact factored adapter control; no dense materialization on execution path.

This separate generic control does not convert the existing 3-output trained
model. MAC counts describe the declared representation, not a security lower
bound or useful-demand credit. A deployment must compare legal merged, sparse,
reused and factored strategies before choosing its baseline.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json

MAX_DIM = 1024
MAX_RANK = 64
MAX_BATCH = 64
MAX_MACS = 4_194_304


def require(ok, code):
    if not ok:
        raise ValueError(code)


def matrix(value, rows, cols, bound):
    require(type(value) is list and len(value) == rows and
            all(type(row) is list and len(row) == cols for row in value), 'FACTOR_SHAPE')
    require(all(type(x) is int and abs(x) <= bound for row in value for x in row), 'FACTOR_RANGE')


def apply_factors(up, down, inputs):
    """Return U(Vx) for batch-row inputs, keeping exact signed-integer semantics."""
    require(type(up) is list and type(down) is list and type(inputs) is list,
            'FACTOR_CONTAINER')
    out_dim, rank, batch = len(up), len(down), len(inputs)
    require(1 <= out_dim <= MAX_DIM and 1 <= rank <= MAX_RANK and
            1 <= batch <= MAX_BATCH, 'FACTOR_LIMIT')
    require(type(down[0]) is list, 'FACTOR_SHAPE')
    in_dim = len(down[0])
    require(1 <= in_dim <= MAX_DIM, 'FACTOR_DIMENSION')
    macs = batch * rank * (in_dim + out_dim)
    require(macs <= MAX_MACS, 'FACTOR_MAC_LIMIT')
    matrix(up, out_dim, rank, 32767)
    matrix(down, rank, in_dim, 32767)
    matrix(inputs, batch, in_dim, 8)
    bound = rank * in_dim * 32767 * 32767 * 8
    require(bound <= (1 << 63) - 1, 'FACTOR_ACCUMULATOR_BOUND')
    intermediate = [[sum(d * x for d, x in zip(row, sample)) for row in down]
                    for sample in inputs]
    output = [[sum(u * z for u, z in zip(row, hidden)) for row in up]
              for hidden in intermediate]
    payload = {'schema': 'pon-factored-integer-adapter-control-v0', 'up': up, 'down': down,
               'shape': [out_dim, rank, in_dim], 'numeric': 'exact-signed-i64'}
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return {'outputs': output, 'factor_commitment': hashlib.sha256(
                b'pon.grouped.low-rank.v0\0' + len(raw).to_bytes(8, 'big') + raw).hexdigest(),
            'executed_macs': macs, 'dense_equivalent_macs_for_comparison': batch * out_dim * in_dim,
            'dense_expansion_executed': False, 'rank': rank,
            'maximum_absolute_output_bound': bound, 'business_credit_awarded': 0,
            'production_activation': False, 'pow_qualified': False}


@dataclass(frozen=True, slots=True)
class _PreparedAdapter:
    """Local immutable admission result, not an external authorization token."""
    adapter_bytes: bytes
    artifact: str
    function_fingerprint: str
    normalization_macs: int
    binding: str


def _binding(raw, artifact, fingerprint, macs):
    value = {'adapter_sha256': hashlib.sha256(raw).hexdigest(), 'artifact': artifact,
             'function_fingerprint': fingerprint, 'normalization_macs': macs}
    return hashlib.sha256(b'pon.grouped.adapter-admission.v0\0' +
                          json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prepare_existing_adapter(adapter, contract):
    """Reuse retained exact BA admission; charge normalization only at preparation.

    No ILF2 codec, model schema, adoption authority, or untrusted prepared-object
    verification is added. Execution reconstructs factors from immutable canonical
    bytes, and checks their identity without expanding BA again. Inner widths
    1..8 remain legal even when factors cost more MACs than a merged dense update.
    """
    from contract_wire import canonical
    from model_attribution import normalize_adapter
    normalized = normalize_adapter(adapter, contract)
    raw = canonical(adapter)
    artifact = normalized['artifact']
    fingerprint = normalized['function_fingerprint']
    macs = normalized['product_multiplications']
    return _PreparedAdapter(raw, artifact, fingerprint, macs,
                            _binding(raw, artifact, fingerprint, macs))


def apply_existing_adapter(prepared, inputs):
    from contract_wire import H, unique
    require(type(prepared) is _PreparedAdapter, 'ADAPTER_PREPARATION')
    require(_binding(prepared.adapter_bytes, prepared.artifact,
                     prepared.function_fingerprint, prepared.normalization_macs) == prepared.binding,
            'ADAPTER_PREPARATION_BINDING')
    adapter = json.loads(prepared.adapter_bytes, object_pairs_hook=unique)
    require(H('integer-linear-adapter-v1', prepared.adapter_bytes).hex() == prepared.artifact,
            'ADAPTER_ARTIFACT')
    result = apply_factors(adapter['B'], adapter['A'], inputs)
    result.update(existing_adapter_artifact=prepared.artifact,
                  existing_function_fingerprint=prepared.function_fingerprint,
                  one_time_normalization_macs=prepared.normalization_macs)
    return result
