#!/usr/bin/env python3
"""Read-only independent arithmetic review of the locked W1 calculator.

This audit reconstructs the *equations*, not upstream f32 rounding. It is not a
proof that an equation is a valid cryptographic bound and is not QROM analysis.
No prover, build, network call, repository mutation or upstream script is run.

The source bundle contains original Apache-2.0 RISC Zero files fetched at the
immutable commit below. The independent evaluator uses Decimal(160), whereas
the implementation under review uses Fraction and sqrt interval enclosures.
The bundle is checked against fixed SHA-256 pins before extracting parameters.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from decimal import Decimal as D, ROUND_CEILING, localcontext
from fractions import Fraction
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
COMMIT = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
PINS = {
    'locked-soundness': '6d814ec839d0f4b33f275cdfa2d382f4ce455957b1ec7932d9bc717ccf732921',
    'locked-rng': '8c5868a8b258896835e2c3c93a84cfe01167f1a446e4d74a3b7be94ae1bf8017',
    'locked-lib': '107521d2426442fbc9358b7b9ae5650be92d670ea85e9a34aec7b9e9cc27dc6d',
    'locked-fri': 'a601cfad5d01b294f934d697d6d832c57662e4778eac20ac549b1da53d11e377',
    'locked-field': 'df3e77d606dd74d78fb6b6f3dbbe72455c5ed5b091f7a74de8c049e85b857ff3',
    'actual-risc0/circuit/recursion/src/taps.rs': 'd32cbf5350d6f724cf3582ef92fb6c392f993b51ee89c5384f7ad79bab43ce83',
    'actual-risc0/circuit/rv32im/src/zirgen/taps.rs': 'b423f7bd396cd4a7ea25c326ba077dca7f96dd144fd8e44d9474bfb2489818d2',
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_parameters(text: str) -> dict:
    # Derive column widths and combo size from individual tapped registers.
    # This does not call the reviewed module's parser, group_begin or combo_begin.
    tapped = defaultdict(set)
    offsets = defaultdict(set)
    entries = re.findall(r'TapData\s*\{([^}]*)\}', text)
    for entry in entries:
        fields = {k: int(v) for k, v in re.findall(r'(\w+)\s*:\s*(\d+)', entry)}
        assert set(fields) == {'offset', 'back', 'group', 'combo', 'skip'}
        offsets[fields['group']].add(fields['offset'])
        tapped[(fields['group'], fields['offset'])].add(fields['back'])
    assert set(offsets) == {0, 1, 2}
    widths = [max(offsets[group]) + 1 for group in range(3)]
    assert all(offsets[group] == set(range(widths[group])) for group in range(3))
    return {'w_accum': widths[0], 'w_code': widths[1], 'w_data': widths[2],
            'n_trace_polys': sum(widths),
            'biggest_combo': max(map(len, tapped.values())), 'tap_count': len(entries)}


def decimal_fraction(value: Fraction) -> D:
    return D(value.numerator) / D(value.denominator)


def independent_terms(po2: int, queries: int, taps: dict) -> dict:
    # Direct translation of equations in the pinned soundness.rs; no reviewed
    # component calculator helper is used to derive these expected values.
    extension = D(4)
    field = D(2013265921) ** 4
    rows = D(2) ** po2
    domain = D(4) * rows
    rate = D(1) / D(4)
    johnson = D(16)
    degree = D(5)
    segment_polys = degree - 1
    combo = D(taps['biggest_combo'])
    polynomials = D(taps['n_trace_polys'])
    accum = D(taps['w_accum']) / extension * (degree - 2) * rows / field
    constraint = 1 / field
    toy = accum + constraint + rate ** queries
    alpha = (1 + 1 / (2 * johnson)) * rate.sqrt()
    rho_plus = (rows + combo) / domain
    m_plus = int((1 / (combo * (alpha / rho_plus.sqrt() - 1))).to_integral_value(rounding=ROUND_CEILING))
    l_plus = (D(m_plus) + D('0.5')) / rho_plus.sqrt()
    proximity = (johnson + D('0.5')) ** 7 / (3 * rate.sqrt() ** 3) * domain ** 2 / field
    # A fold divides degree by 16=2^4 until it is <=256=2^8.
    rounds = max(0, (po2 - 8 + 3) // 4)
    terms = {
        'plonk_plookup': accum,
        'fri_proximity': (polynomials + segment_polys - D('0.5')) * proximity,
        'fri_folding': (2 * johnson + 1) * (domain + 1) * (16 * rounds) / (rate.sqrt() * field),
        'fri_queries': alpha ** queries,
        'deep_ali_upper': l_plus * (segment_polys * (rows + combo - 1) + (rows - 1)) / (field - rows - domain) + l_plus * polynomials / field,
    }
    return {'toy': toy, 'toy_fixed': accum + constraint,
            'proven_terms': terms, 'proven_sum': sum(terms.values()),
            'm_plus': m_plus, 'rounds': rounds}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--calculator', type=Path, required=True)
    parser.add_argument('--source-bundle', type=Path, default=Path(__file__).with_name('w1-independent-8c215e2-sources.json'))
    args = parser.parse_args()
    bundle_bytes = args.source_bundle.read_bytes()
    bundle = json.loads(bundle_bytes)
    assert bundle['source_commit'] == COMMIT
    sources = {f['key']: f for f in bundle['files']}
    assert set(sources) == set(PINS)
    checks = []
    for key, expected in PINS.items():
        source = sources[key]
        data = source['content'].encode()
        assert f'/blob/{COMMIT}/' in source['url']
        assert digest(data) == expected, (key, 'source SHA-256 mismatch')
        assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == source['github_blob_sha1']
        checks.append({'key': key, 'url': source['url'], 'sha256': expected, 'github_blob_sha1': source['github_blob_sha1'], 'bytes': len(data)})
    module_spec = importlib.util.spec_from_file_location('reviewed_w1_budget', args.calculator)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    assert module.SOURCE_COMMIT == COMMIT
    circuits = {
        'rv32im': source_parameters(sources['actual-risc0/circuit/rv32im/src/zirgen/taps.rs']['content']),
        'recursion': source_parameters(sources['actual-risc0/circuit/recursion/src/taps.rs']['content']),
    }
    cases = []
    biggest_slack = D(0)
    with localcontext() as ctx:
        ctx.prec = 160
        for circuit, taps in circuits.items():
            for po2 in range(13, 25):
                for queries in [1, 2, 50, 64, 65, 4096]:
                    expected = independent_terms(po2, queries, taps)
                    actual = module.component_errors(po2, queries, taps)
                    assert actual['rounds'] == expected['rounds']
                    assert actual['m_plus'] == expected['m_plus']
                    toy_delta = abs(decimal_fraction(actual['toy_sum']) - expected['toy'])
                    assert toy_delta <= D('1e-150') * expected['toy']
                    for key, value in expected['proven_terms'].items():
                        got = decimal_fraction(actual['proven_terms'][key])
                        # Decimal has its own rounding. All rational exact terms
                        # agree to precision; the sqrt dependent term must be an
                        # upper enclosure within 1e-150 relative evaluation noise.
                        assert got >= value - abs(value) * D('1e-150'), (circuit, po2, queries, key)
                        if key != 'deep_ali_upper':
                            assert abs(got - value) <= abs(value) * D('1e-150')
                    got_sum = decimal_fraction(actual['proven_sum_upper'])
                    relative_slack = (got_sum - expected['proven_sum']) / expected['proven_sum']
                    assert relative_slack >= -D('1e-150')
                    biggest_slack = max(biggest_slack, relative_slack)
                    cases.append({'circuit': circuit, 'po2': po2, 'queries': queries,
                                  'rounds': expected['rounds'], 'm_plus': expected['m_plus'],
                                  'toy_equation_agrees': True, 'proven_terms_agree_with_upward_sqrt_enclosure': True,
                                  'toy_negative_log2': str(-expected['toy'].ln() / D(2).ln()),
                                  'proven_equation_negative_log2': str(-expected['proven_sum'].ln() / D(2).ln()),
                                  'relative_upward_sqrt_slack': str(relative_slack)})
        floor_checks = []
        for circuit, taps in circuits.items():
            for po2 in range(13, 25):
                expected = independent_terms(po2, 50, taps)
                # The source-fixed field/accumulator floor alone exceeds 2^-128.
                assert expected['toy_fixed'] > D(2) ** -128
                assert module.min_queries_for_toy_budget(po2, taps, 128) is None
                floor_checks.append({'circuit': circuit, 'po2': po2,
                                     'query_only_128_bit_target_impossible_under_this_formula': True})
    result = {
        'status': 'PASS', 'source_commit': COMMIT,
        'scope': 'Independent equation reproduction only, not protocol soundness or quantum qualification',
        'does_not_run_upstream_f32_implementation': True,
        'does_not_build_or_run_prover': True,
        'calculator': str(args.calculator.resolve()),
        'calculator_sha256': digest(args.calculator.read_bytes()),
        'audit_script_sha256': digest(Path(__file__).read_bytes()),
        'source_bundle_sha256': digest(bundle_bytes),
        'source_hash_checks': checks, 'independently_extracted_circuit_parameters': circuits,
        'decimal_precision': 160, 'arithmetic_cases': len(cases),
        'maximum_relative_upward_sqrt_slack': str(biggest_slack),
        'cases': cases, 'independent_floor_checks': floor_checks,
        'quantum_security_bits': None, 'full_recursive_security_bits': None,
        'limitations': [
            'No claim that the upstream toy conjecture remains tenable.',
            'No complete W1 transcript, multi-proof, recursion, hash or QROM bound is produced.',
            'The source bundle hashes match the pinned source-file hashes; crate archive checks were not rerun.',
            'The 2026-10-26 Fenzi/Sanso publication is separate evidence and not folded into these source equations.',
        ],
    }
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
