#!/usr/bin/env python3
"""Reproduce the locked W1 backend's component error estimates offline.

The equations are from RISC Zero's Apache-2.0 licensed soundness.rs at
8c215e2f4ccdd935f0517bf05d90f1ae032840a9. This is an independent exact-rational
evaluation of those equations, not a soundness proof or a QROM reduction.
The upstream f32 implementation is not reproduced bit for bit. Square roots in
its list-decoding formula are enclosed by rationals with 128 fractional bits;
the reported error is rounded upwards. Only display logarithms use floats.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import tarfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
DEFAULT_LOCK = ROOT / 'formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.lock'
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
PACKAGES = {
    'risc0-zkp-3.0.5': {
        'archive': '21c0c921e5e2d44197940d387a45e29c6165e318b5a168fdfdbd50f50ba03678',
        'files': {
            'src/lib.rs': '107521d2426442fbc9358b7b9ae5650be92d670ea85e9a34aec7b9e9cc27dc6d',
            'src/adapter.rs': '1d1aca1dd7cc4c12477e0d887a3edfa0825b822efee671170ec667c7dd65ca1d',
            'src/taps.rs': 'f5f69bcbed730cc8acd43da89dd4e37ca7560b9eb991a37238482f3655f7e402',
            'src/prove/soundness.rs': '6d814ec839d0f4b33f275cdfa2d382f4ce455957b1ec7932d9bc717ccf732921',
            'src/core/hash/poseidon2/rng.rs': '8c5868a8b258896835e2c3c93a84cfe01167f1a446e4d74a3b7be94ae1bf8017',
            'src/core/hash/poseidon2/mod.rs': 'a2993a2e29fa33345a6a9ce0b4f192efe7412746b92b172b0eed8ce78ee8471f',
            'src/verify/fri.rs': 'a601cfad5d01b294f934d697d6d832c57662e4778eac20ac549b1da53d11e377',
        },
    },
    'risc0-core-3.0.2': {
        'archive': 'd6eb2d2b2c6cac0e43cbb2202daacee1a2f24d0dfa03fd08887a11dc6defdcc1',
        'files': {
            'src/field/baby_bear.rs': 'df3e77d606dd74d78fb6b6f3dbbe72455c5ed5b091f7a74de8c049e85b857ff3',
        },
    },
    'risc0-circuit-recursion-4.0.5': {
        'archive': '40dd640122abcc67d4d4e4f055c68cbc3ad2efb8589c65c2b23d354632971b60',
        'files': {'src/taps.rs': 'd32cbf5350d6f724cf3582ef92fb6c392f993b51ee89c5384f7ad79bab43ce83'},
    },
    'risc0-circuit-rv32im-4.0.5': {
        'archive': 'cb11231aa4b74bcc0c8d16597893fbd7ea6f6a9ebbc35e16bfd06b467c7ee104',
        'files': {'src/zirgen/taps.rs': 'b423f7bd396cd4a7ea25c326ba077dca7f96dd144fd8e44d9474bfb2489818d2'},
    },
}


class BudgetError(ValueError):
    """The pinned analysis cannot be applied to the supplied inputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BudgetError(message)


def bounded_file(path: Path, limit: int) -> bytes:
    require(not path.is_symlink(), f'{path.name}: symlink input')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, f'{path.name}: input exceeds bound')
    return data


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_sources(lockfile: Path, crate_cache: Path) -> tuple[dict, list, str]:
    lockbytes = bounded_file(lockfile, 2 * 1024 * 1024)
    parsed = tomllib.loads(lockbytes.decode('utf-8'))
    locked = {}
    require(isinstance(parsed.get('package'), list), 'lock package roster is missing')
    for package in parsed['package']:
        require(isinstance(package, dict), 'invalid lock package entry')
        key = f"{package.get('name')}-{package.get('version')}"
        if key in PACKAGES:
            require(key not in locked, f'{key}: duplicate lock package')
            require(package.get('source') == REGISTRY, f'{key}: unexpected registry')
            require(package.get('checksum') == PACKAGES[key]['archive'],
                    f'{key}: lock checksum differs from supported source')
            locked[key] = package
    require(set(locked) == set(PACKAGES), 'missing pinned lock package')
    sources, records = {}, []
    for package, pin in PACKAGES.items():
        path = crate_cache / f'{package}.crate'
        archive = bounded_file(path, 16 * 1024 * 1024)
        require(sha(archive) == pin['archive'], f'{package}: archive checksum mismatch')
        # Open the bytes just hashed, not a path that may change afterwards.
        import io
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
            members = tar.getmembers()
            files = []
            for relative, expected in pin['files'].items():
                name = package + '/' + relative
                matches = [m for m in members if m.name == name]
                require(len(matches) == 1 and matches[0].isfile(),
                        f'{name}: absent, duplicate or nonregular member')
                require(matches[0].size <= 2 * 1024 * 1024, f'{name}: oversized member')
                stream = tar.extractfile(matches[0])
                require(stream is not None, f'{name}: unreadable member')
                data = stream.read(2 * 1024 * 1024 + 1)
                require(sha(data) == expected, f'{name}: source checksum mismatch')
                sources[name] = data.decode('utf-8')
                files.append({'path': relative, 'bytes': len(data), 'sha256': expected})
        records.append({'package': package, 'archive_sha256': pin['archive'],
                        'archive_matches_lock_and_pin': True, 'files': files})
    return sources, records, sha(lockbytes)


def tap_parameters(text: str) -> dict:
    pattern = (r'TapData\s*\{\s*offset:\s*(\d+),\s*back:\s*(\d+),'
               r'\s*group:\s*(\d+),\s*combo:\s*(\d+),\s*skip:\s*(\d+),\s*\}')
    taps = [tuple(map(int, m)) for m in re.findall(pattern, text)]
    require(taps and len(taps) == len(re.findall(r'\bTapData\s*\{', text)),
            'unparsed tap declaration')
    require({t[2] for t in taps} == {0, 1, 2}, 'unsupported register groups')
    arrays = {}
    for name in ('combo_begin', 'group_begin'):
        matches = re.findall(r'\b' + name + r':\s*&\[([\d,\s]+)\]', text)
        require(len(matches) == 1, f'{name}: unsupported declaration')
        arrays[name] = [int(x) for x in matches[0].split(',') if x.strip()]
    group_begin = arrays['group_begin']
    require(len(group_begin) == 4 and group_begin[0] == 0
            and group_begin[-1] == len(taps), 'invalid group boundaries')
    sizes = []
    for group in range(3):
        segment = taps[group_begin[group]:group_begin[group + 1]]
        require(segment and all(t[2] == group for t in segment), 'invalid tap group')
        size = segment[-1][0] + 1  # TapSet::group_size, checked source above.
        require({t[0] for t in segment} == set(range(size)), 'noncontiguous tap offsets')
        sizes.append(size)
    begins = arrays['combo_begin']
    require(len(begins) >= 2 and begins[0] == 0
            and all(b > a for a, b in zip(begins, begins[1:])), 'invalid combo boundaries')
    return {'w_accum': sizes[0], 'w_code': sizes[1], 'w_data': sizes[2],
            'n_trace_polys': sum(sizes),
            'biggest_combo': max(b - a for a, b in zip(begins, begins[1:])),
            'tap_count': len(taps)}


def sqrt_interval(value: Fraction, fractional_bits: int = 128) -> tuple[Fraction, Fraction]:
    require(value > 0 and type(fractional_bits) is int and fractional_bits >= 1,
            'invalid rational sqrt input')
    scale = 1 << fractional_bits
    low_int = math.isqrt(value.numerator * scale * scale // value.denominator)
    low = Fraction(low_int, scale)
    high = low if low * low == value else Fraction(low_int + 1, scale)
    require(low > 0 and low * low <= value <= high * high, 'sqrt enclosure failed')
    return low, high


def exact_ceil_m(rho_plus: Fraction, combo: int, alpha: Fraction) -> int:
    """ceil(1 / (combo * (alpha / sqrt(rho_plus) - 1))), without floats."""
    require(combo > 0 and alpha * alpha > rho_plus > 0, 'invalid list-decoding domain')
    def sufficient(m: int) -> bool:
        return (m * combo * alpha) ** 2 >= (m * combo + 1) ** 2 * rho_plus
    lo, hi = 0, 1
    while not sufficient(hi):
        hi *= 2
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if sufficient(mid):
            hi = mid
        else:
            lo = mid
    return hi


def valid_inputs(po2: int, queries: int, taps: dict) -> None:
    require(type(po2) is int and 13 <= po2 <= 24, 'po2 outside locked source range')
    require(type(queries) is int and 1 <= queries <= 4096, 'invalid query count')
    for key in ('w_accum', 'n_trace_polys', 'biggest_combo'):
        require(type(taps[key]) is int and taps[key] > 0, f'invalid {key}')


def component_errors(po2: int, queries: int, taps: dict) -> dict:
    valid_inputs(po2, queries, taps)
    p, ext_degree, max_degree = 2013265921, 4, 5
    n, field = 1 << po2, p ** ext_degree
    domain, combo = n * 4, taps['biggest_combo']
    accum = Fraction(taps['w_accum'] * (max_degree - 2) * n, ext_degree * field)
    constraint = Fraction(1, field)
    toy_queries = Fraction(1, 4 ** queries)
    toy_fixed = accum + constraint
    rounds, size = 0, n
    while size > 256:
        size //= 16
        rounds += 1
    # M=16, rho=1/4; alpha=(1+1/(2M))*sqrt(rho)=33/64.
    alpha = Fraction(33, 64)
    rho_plus = Fraction(n + combo, domain)
    m_plus = exact_ceil_m(rho_plus, combo, alpha)
    root_low, root_high = sqrt_interval(rho_plus)
    l_plus_upper = (m_plus + Fraction(1, 2)) / root_low
    proximity = Fraction(33 ** 7, 48) * Fraction(domain ** 2, field)
    fri_constant_1 = (taps['n_trace_polys'] + Fraction(7, 2)) * proximity
    fri_constant_2 = Fraction(1056 * (domain + 1) * rounds, field)
    ali = l_plus_upper * Fraction(taps['n_trace_polys'], field)
    deep = l_plus_upper * Fraction(4 * (n + combo - 1) + (n - 1), field - n - domain)
    proven_terms = {
        'plonk_plookup': accum,
        'fri_proximity': fri_constant_1,
        'fri_folding': fri_constant_2,
        'fri_queries': alpha ** queries,
        'deep_ali_upper': deep + ali,
    }
    return {
        'toy_terms': {'plonk_plookup': accum, 'constraints': constraint, 'fri_queries': toy_queries},
        'toy_sum': toy_fixed + toy_queries, 'toy_query_independent_floor': toy_fixed,
        'proven_terms': proven_terms, 'proven_sum_upper': sum(proven_terms.values()),
        'proven_query_independent_subtotal': accum + fri_constant_1 + fri_constant_2,
        'rounds': rounds, 'm_plus': m_plus, 'sqrt_low': root_low, 'sqrt_high': root_high,
    }


def error_record(error: Fraction) -> dict:
    require(error > 0, 'nonpositive error')
    return {'numerator': str(error.numerator), 'denominator': str(error.denominator),
            'negative_log2_display_only': math.log2(error.denominator) - math.log2(error.numerator)}


def min_queries_for_toy_budget(po2: int, taps: dict, target_bits: int) -> int | None:
    budget = Fraction(1, 1 << target_bits)
    fixed = component_errors(po2, 1, taps)['toy_query_independent_floor']
    if fixed >= budget:
        return None
    for queries in range(1, 4097):
        if fixed + Fraction(1, 4 ** queries) <= budget:
            return queries
    raise BudgetError('query search exceeded supported range')


def ideal_sampler_bias(domain_size: int, bits: int) -> Fraction:
    """TV distance for first-nonzero-of-four iid uniform words, then low bits.

    This evaluates an ideal sampling experiment. It does not prove that a
    concrete Poseidon2 sponge produces iid uniform words after any transcript.
    """
    require(type(domain_size) is int and 2 <= domain_size <= 2 ** 32,
            'invalid ideal sampling domain')
    require(type(bits) is int and 1 <= bits <= 27, 'unsupported low-bit sampler width')
    outputs = 1 << bits
    require((domain_size - 1) % outputs == 0, 'nonzero words do not evenly cover low bits')
    # Conditional on at least one nonzero draw, the selected nonzero word is
    # uniform, and each low-bit residue occurs equally often. All-zero draws
    # add probability domain_size^-4 to output zero.
    return Fraction(outputs - 1, outputs * domain_size ** 4)


def make_report(sources: dict, records: list, lock_sha: str, target_bits: int) -> dict:
    require(type(target_bits) is int and 1 <= target_bits <= 256, 'invalid research target')
    budget = Fraction(1, 1 << target_bits)
    circuits = {
        'rv32im': tap_parameters(sources['risc0-circuit-rv32im-4.0.5/src/zirgen/taps.rs']),
        'recursion': tap_parameters(sources['risc0-circuit-recursion-4.0.5/src/taps.rs']),
    }
    expected = {'rv32im': (103, 1, 211, 315, 6, 790), 'recursion': (12, 23, 128, 163, 6, 643)}
    for name, params in circuits.items():
        require(tuple(params.values()) == expected[name], f'{name}: parameter extraction drift')
    rows = []
    for circuit, taps in circuits.items():
        for po2 in (13, 14, 18, 20, 22, 24):
            value = component_errors(po2, 50, taps)
            rows.append({
                'circuit': circuit, 'po2': po2, 'trace_rows': 1 << po2,
                'upstream_toy_model': {
                    'error': error_record(value['toy_sum']),
                    'terms': {k: error_record(v) for k, v in value['toy_terms'].items()},
                    'meets_research_error_budget': value['toy_sum'] <= budget,
                    'query_independent_floor': error_record(value['toy_query_independent_floor']),
                    'query_increase_alone_can_meet_budget': value['toy_query_independent_floor'] < budget,
                    'minimum_queries_with_other_parameters_unchanged': min_queries_for_toy_budget(po2, taps, target_bits),
                },
                'upstream_proven_list_decoding_formula': {
                    'error_upper_rational': error_record(value['proven_sum_upper']),
                    'terms': {k: error_record(v) for k, v in value['proven_terms'].items()},
                    'meets_research_error_budget': value['proven_sum_upper'] <= budget,
                    'query_independent_subtotal': error_record(value['proven_query_independent_subtotal']),
                    'query_increase_alone_excluded_by_subtotal': value['proven_query_independent_subtotal'] >= budget,
                    'folding_rounds': value['rounds'], 'm_plus': value['m_plus'],
                },
            })
    return {
        'schema': 'TRNM-W1-COMPONENT-SECURITY-BUDGET1',
        'generator': 'scripts/w1_security_budget.py',
        'scope': 'Exact-source component formula evaluation; no whole-proof or QROM security claim.',
        'source_commit': SOURCE_COMMIT,
        'source_lock_sha256': lock_sha,
        'source_integrity': records,
        'research_target': {
            'failure_probability_bits': target_bits, 'error_budget': error_record(budget),
            'protocol_policy_adopted': False,
            'quantum_query_work_factor_bits': None,
        },
        'parameters': {
            'base_field_modulus': 2013265921, 'extension_degree': 4,
            'extension_field_cardinality': str(2013265921 ** 4),
            'extension_field_log2_display_only': math.log2(2013265921 ** 4),
            'fri_queries': 50, 'inverse_rate': 4, 'fri_fold': 16, 'fri_min_degree': 256,
            'max_degree_assumed_by_upstream_calculator': 5,
            'max_degree_independently_proved_for_every_accepted_program': False,
            'circuits': circuits,
        },
        'hash_and_sampling_arithmetic': {
            'poseidon2_digest_stored_bits': 256,
            'poseidon2_digest_field_elements': 8,
            'canonical_digest_codomain_cardinality': str(2013265921 ** 8),
            'canonical_digest_codomain_log2_display_only': math.log2(2013265921 ** 8),
            'qrom_random_oracle_sigma_instantiated': None,
            'ideal_iid_field_sampler': {
                'uniform_independent_field_outputs_assumed_not_proved': True,
                'draws_per_random_bits_call': 4,
                'max_fri_query_index_bits_from_source_cycle_bound': 26,
                'all_zero_probability': error_record(Fraction(1, 2013265921 ** 4)),
                'single_call_total_variation_at_26_bits': error_record(ideal_sampler_bias(2013265921, 26)),
                'full_transcript_distance': None,
            },
        },
        'rows': rows,
        'query_only_necessary_condition': {
            'queries_for_strictly_smaller_fri_term': target_bits // 2 + 1,
            'sufficient_for_full_toy_sum': False,
            'changes_the_locked_verifier': True,
        },
        'source_comment_check': {
            'comment_rv32im_po2_20_bits': 97,
            'computed_rv32im_po2_20_display': -math.log2(component_errors(20, 50, circuits['rv32im'])['toy_sum']),
            'comment_rv32im_po2_24_bits': 95,
            'computed_rv32im_po2_24_display': -math.log2(component_errors(24, 50, circuits['rv32im'])['toy_sum']),
            'po2_24_comment_reproduced': False,
        },
        'qualification': {
            'qrom_theorem_instantiated': False,
            'quantum_security_bits': None,
            'full_recursive_security_bits': None,
            'consensus_admission': False,
            'production_qualified': False,
            'attack_on_complete_w1_established': False,
        },
        'limitations': [
            'The toy formula depends on upstream conjectures; a failed budget is not an attack.',
            'The upstream proven formula is a component estimator, not a verified RBR or QROM theorem for this implementation.',
            'The sqrt enclosure evaluates the mathematical formula conservatively; it does not emulate f32 rounding.',
            'The four-archive scope omits SHA-extension semantics, all accepted recursive programs, transcript/hash instantiation and composition.',
            'po2 24 diagnoses the source-wide comment; it is above the saved profile default control-set maximum po2 22.',
            'A per-proof failure budget and a quantum query/work budget are different inputs; the latter is not supplied or inferred.',
            'Sampler bias is proved only for an ideal iid field-output experiment; concrete sponge and adaptive transcript assumptions remain unproved.',
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--crate-cache', type=Path, required=True,
                        help='Directory containing the four exact .crate archives (offline).')
    parser.add_argument('--lockfile', type=Path, default=DEFAULT_LOCK)
    parser.add_argument('--target-bits', type=int, required=True,
                        help='Explicit research comparison failure budget; does not adopt policy.')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        sources, records, lock_sha = load_sources(args.lockfile, args.crate_cache)
        report = make_report(sources, records, lock_sha, args.target_bits)
        encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded)
        else:
            sys.stdout.write(encoded)
        # Successful reproduction of a negative result is not qualification.
        return 0
    except (BudgetError, OSError, UnicodeError, tomllib.TOMLDecodeError, tarfile.TarError) as error:
        print(json.dumps({'result': 'INPUT_REJECTED', 'reason': str(error),
                          'qrom_theorem_instantiated': False, 'quantum_security_bits': None}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
