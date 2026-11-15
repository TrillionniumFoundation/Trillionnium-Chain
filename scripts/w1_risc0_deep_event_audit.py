#!/usr/bin/env python3
"""Count two named DEEP exceptional sets under ideal field sampling.

This checks fixed upstream source identities and finite-set algebra only. It
does not prove that the stateful Poseidon2 sampler is uniform, that these events
are all soundness failures, or that they exhaust the protocol's bad events.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys

SCHEMA = 'TRNM-W1-RISC0-DEEP-EVENT-AUDIT1'
SNAPSHOT = 'evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz'
SNAPSHOT_SHA256 = 'f6be3667106df6843f5f29c0954cdce8e2617da36c9c91a7a5198665675e0253'
UPSTREAM = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
P = 2013265921
MAX_BYTES = 2 * 1024 * 1024
SOURCE_SHA256 = {
    'risc0/zkp/src/verify/mod.rs': '003a67af89a7cfaeac9ff23808225cdc4d81c41d64956f20243574531b166c4f',
    'risc0/zkp/src/core/hash/poseidon2/rng.rs': '8c5868a8b258896835e2c3c93a84cfe01167f1a446e4d74a3b7be94ae1bf8017',
    'risc0/zkp/src/lib.rs': '107521d2426442fbc9358b7b9ae5650be92d670ea85e9a34aec7b9e9cc27dc6d',
    'risc0/core/src/field/baby_bear.rs': 'df3e77d606dd74d78fb6b6f3dbbe72455c5ed5b091f7a74de8c049e85b857ff3',
}


class DeepEventError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise DeepEventError(message)


def prime(value):
    require(type(value) is int and 2 <= value < 2**31, 'prime input outside bounded exact check')
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def probability(count, size):
    value = Fraction(count, size)
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


def count_events(p, trace_log2, shift=3):
    """Exact cardinalities in abstract F_(p^4), for D <= F_p^* of order 4N.

    The first event covers existence of a zero queried rational denominator for
    ANY x in D. The second event is the separate trace-zerofier event. It is not
    asserted to cause a verifier error or a soundness failure.
    """
    require(prime(p), 'base modulus is not prime')
    require(type(trace_log2) is int and 0 <= trace_log2 <= 24, 'unsupported trace log')
    require(type(shift) is int and 0 < shift < p, 'invalid nonzero trace shift')
    n = 1 << trace_log2
    domain = 4 * n
    size = p**4
    require((p - 1) % domain == 0, 'evaluation domain does not lie in the base field')
    require((size - 1) % (4 * domain) == 0, 'fourth-power preimage cardinality premise fails')
    # x-z*omega_N^(-b)=0 gives z in D, since omega_N^b belongs to D.
    # x-z^4=0 for some x in D iff z^(4*|D|)=1. The latter contains D.
    poles = 4 * domain
    # (shift*z)^N=1 is a coset of H_N. That entire coset is either inside
    # or disjoint from the subgroup of order 4*|D|, according to this test.
    zerofier = n
    intersects = pow(shift, 4 * domain, p) == 1
    overlap = zerofier if intersects else 0
    union = poles + zerofier - overlap
    return {
        'trace_log2': trace_log2, 'trace_size': str(n), 'evaluation_domain_size': str(domain),
        'challenge_space_size': str(size),
        'rational_denominator_pole_set_size': str(poles),
        'trace_zerofier_zero_set_size': str(zerofier),
        'intersection_size': str(overlap),
        'two_named_events_union_size': str(union),
        'shift_power_mod_p': str(pow(shift, 4 * domain, p)),
        'ideal_uniform_pole_probability': probability(poles, size),
        'ideal_uniform_zerofier_probability': probability(zerofier, size),
        'ideal_uniform_two_events_union_probability': probability(union, size),
    }


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def fixed_sources(root):
    path = Path(root) / SNAPSHOT
    require(not path.is_symlink() and path.is_file(), 'snapshot is not a regular nonsymlink file')
    with path.open('rb') as handle:
        raw = handle.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES and hashlib.sha256(raw).hexdigest() == SNAPSHOT_SHA256,
            'fixed upstream snapshot identity differs')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
        decoded = handle.read(MAX_BYTES + 1)
    require(len(decoded) <= MAX_BYTES, 'snapshot expanded above bound')
    snapshot = json.loads(decoded, object_pairs_hook=unique_object)
    require(snapshot['repository'] == 'risc0/risc0' and snapshot['commit'] == UPSTREAM,
            'snapshot repository/revision differs')
    sources = {}
    for row in snapshot['files']:
        require(row['path'] not in sources, 'duplicate snapshot source')
        data = row['content'].encode('utf-8')
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'],
                'snapshot inner source identity differs')
        sources[row['path']] = row
    for path, digest in SOURCE_SHA256.items():
        require(path in sources and sources[path]['sha256'] == digest, 'selected source identity differs')
    return [{key: sources[path][key] for key in ('path', 'bytes', 'sha256')}
            for path in SOURCE_SHA256]


def build_report(root):
    sources = fixed_sources(root)
    rows = [count_events(P, log) for log in range(25)]
    require(all(row['intersection_size'] == '0' for row in rows), 'unexpected fixed-shift intersection')
    return {
        'schema': SCHEMA, 'status': 'TWO_NAMED_IDEAL_FIELD_EVENTS_COUNTED_SECURITY_HOLD',
        'target_profile_id': 'trnm-w1-risc0-3.0.6-poseidon2-join-v2',
        'source_scope': 'fixed generic SDK denominator declarations and abstract subgroup algebra; project guest/control/parameter identity is not reverified here',
        'upstream_commit': UPSTREAM, 'source_snapshot_sha256': SNAPSHOT_SHA256,
        'selected_source_identities': sources,
        'field': {'characteristic': str(P), 'extension_degree': 4},
        'conditional_sampling_premise': 'z is uniform on F_(p^4), conditional on the prior transcript; the four base coordinates are conditionally independent uniform F_p values',
        'rational_pole_event': 'exists x in D: x-z^4=0, or x-z*omega_N^(-b)=0 for a tap back b; D is the multiplicative subgroup of F_p^* of order 4N',
        'separate_zerofier_event': '(3*z)^N=1',
        'cardinality_argument': {
            'rational_poles': '{z:z^4 in D}={z:z^(16N)=1}, has exactly 16N elements, and contains D',
            'zerofier': '3^(-1)*H_N has N elements; it is disjoint from the pole subgroup since 3^(16N) != 1 for each displayed N',
            'named_union': '17N elements; its displayed probability is exact under the conditional uniform sampling premise',
        },
        'trace_domain_scope': 'algebraic candidate domains for raw parser logs 0..24; these rows do not certify accepted or reachable recursive traces',
        'domains': rows,
        'qualification': {
            'two_named_exceptional_set_cardinalities_checked': True,
            'conditional_uniform_sampling_probability_arithmetic_checked': True,
            'target_profile_binding_reverified': False,
            'compiled_field_and_root_table_equivalence_proved': False,
            'actual_poseidon2_conditional_uniformity_proved': False,
            'complete_bad_event_coverage_proved': False,
            'exceptional_event_implies_soundness_failure': False,
            'rbr_or_fri_soundness_bound_established': False,
            'state_restoration_or_quantum_extractor_qualified': False,
            'recursive_composition_qualified': False,
            'lifetime_failure_bound': None, 'quantum_security_bits': None,
            'native_binary_executed': False, 'production_qualified': False, 'consensus_admission': False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(build_report(args.repo_root), indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, EOFError) as error:
        print(json.dumps({'schema': SCHEMA, 'status': 'INPUT_REJECTED', 'error': str(error),
                          'quantum_security_bits': None, 'production_qualified': False,
                          'consensus_admission': False}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
