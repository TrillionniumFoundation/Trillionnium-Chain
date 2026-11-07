#!/usr/bin/env python3
"""Reproduce the frozen v2 recursion seal's encoding and FS source map.

This is NOT a receipt verifier or a QROM instantiation. It does not evaluate
Poseidon2, reconstruct these STARK roots, draw the actual challenges, check any
opening, or prove any algebraic relation. The caller must separately pin the
historical receipt identity and build features. Upstream Rust is hashed and
parsed as data, never executed. Only these pinned sources and the saved-v2
encoding shape are supported; canonical value changes need not change the shape.
"""
from __future__ import annotations

import hashlib
import re
import struct

UPSTREAM_COMMIT = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
P = 2013265921
FIXED_PO2 = 18
FIXED_RECEIPT_BYTES = 257014
SEAL_OFFSET = 12
LIB = 'risc0/zkp/src/lib.rs'
VERIFY = 'risc0/zkp/src/verify/mod.rs'
FRI = 'risc0/zkp/src/verify/fri.rs'
MERKLE = 'risc0/zkp/src/verify/merkle.rs'
READ_IOP = 'risc0/zkp/src/verify/read_iop.rs'
MERKLE_PARAMS = 'risc0/zkp/src/merkle.rs'
TAPS_API = 'risc0/zkp/src/taps.rs'
ADAPTER = 'risc0/zkp/src/adapter.rs'
INFO = 'risc0/circuit/recursion/src/info.rs'
TAPS = 'risc0/circuit/recursion/src/taps.rs'
FIELD = 'risc0/core/src/field/baby_bear.rs'
HASH = 'risc0/zkp/src/core/hash/poseidon2/mod.rs'
RNG = 'risc0/zkp/src/core/hash/poseidon2/rng.rs'
CONSTS = 'risc0/zkp/src/core/hash/poseidon2/consts.rs'
DIGEST = 'risc0/zkp/src/core/digest.rs'
SUCCINCT = 'risc0/zkvm/src/receipt/succinct.rs'
SOURCE_SHA256 = {
    LIB: '107521d2426442fbc9358b7b9ae5650be92d670ea85e9a34aec7b9e9cc27dc6d',
    VERIFY: '003a67af89a7cfaeac9ff23808225cdc4d81c41d64956f20243574531b166c4f',
    FRI: 'a601cfad5d01b294f934d697d6d832c57662e4778eac20ac549b1da53d11e377',
    MERKLE: '267ab31c38f7502d9d0d3feebe7eb2fc2cbed9d3af4db66fde349e2c3b61a478',
    READ_IOP: '40a7027486fbce5979bd045860e3014ebc1d40f242c4b71ce2adf5722b6d81bc',
    MERKLE_PARAMS: '87bf97f1eb09235bce50b62c4a5fef5517400f6c57554853e9c8043f4b32c64a',
    TAPS_API: 'f5f69bcbed730cc8acd43da89dd4e37ca7560b9eb991a37238482f3655f7e402',
    ADAPTER: '1d1aca1dd7cc4c12477e0d887a3edfa0825b822efee671170ec667c7dd65ca1d',
    INFO: '128c29a8ddf0560fb3a69c03fa1d959fab542d2fa09eae6794d28be871e345e9',
    TAPS: 'd32cbf5350d6f724cf3582ef92fb6c392f993b51ee89c5384f7ad79bab43ce83',
    FIELD: 'df3e77d606dd74d78fb6b6f3dbbe72455c5ed5b091f7a74de8c049e85b857ff3',
    HASH: 'a2993a2e29fa33345a6a9ce0b4f192efe7412746b92b172b0eed8ce78ee8471f',
    RNG: '8c5868a8b258896835e2c3c93a84cfe01167f1a446e4d74a3b7be94ae1bf8017',
    CONSTS: '5ee51bce046bce1306181a43136aa0731dcf976ab10e2e8d82db88711efdcc41',
    DIGEST: '15ea8c15627e5074eea6d0e71895bd006d28f0cfe9ddb2f2dd73de6cbcd22772',
    SUCCINCT: '8e0165b3210e30e77074763d71d85fd0595e4190b96725182f33665b7df90d60',
}


class TranscriptAuditError(ValueError):
    """The fixed source or saved-v2 encoding geometry was not reproduced."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TranscriptAuditError(message)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _one(pattern: str, text: str, label: str) -> re.Match:
    found = list(re.finditer(pattern, text, re.S))
    require(len(found) == 1, f'{label}: missing or ambiguous source declaration')
    return found[0]


def _uint(text: str, name: str) -> int:
    return int(_one(r'\bconst\s+' + re.escape(name)
                    + r':\s*usize\s*=\s*(\d+)\s*;', text, name).group(1))


def _integers(text: str, name: str) -> list[int]:
    payload = _one(r'\b' + re.escape(name) + r':\s*&\[(.*?)\]', text, name).group(1)
    require(re.fullmatch(r'[\s\d,]*', payload) is not None,
            f'{name}: unsupported array syntax')
    return [int(value) for value in re.findall(r'\d+', payload)]


def _verify_sources(sources: dict[str, str]) -> list[dict]:
    require(type(sources) is dict, 'source mapping must be a dict')
    records = []
    for path, expected in SOURCE_SHA256.items():
        require(path in sources and type(sources[path]) is str,
                f'{path}: missing source text')
        data = sources[path].encode('utf-8')
        require(len(data) <= 2 * 1024 * 1024, f'{path}: oversized source')
        require(_sha(data) == expected, f'{path}: fixed source SHA-256 mismatch')
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        records.append({'path': path, 'sha256': expected, 'bytes': len(data),
                        'git_blob_sha1': blob})
    return records


def _parameters(sources: dict[str, str]) -> dict:
    lib, field, info, taps = (sources[path] for path in (LIB, FIELD, INFO, TAPS))
    modulus = _one(r'\bconst P: u32 = (\d+) \* \(1 << (\d+)\) \+ (\d+);',
                   field, 'BabyBear modulus')
    a, exponent, b = map(int, modulus.groups())
    require(a * (1 << exponent) + b == P, 'unsupported BabyBear modulus')
    entries = [tuple(map(int, match.groups())) for match in re.finditer(
        r'TapData\s*\{\s*offset:\s*(\d+),\s*back:\s*(\d+),\s*group:\s*(\d+),'
        r'\s*combo:\s*(\d+),\s*skip:\s*(\d+),\s*\}', taps)]
    begins = _integers(taps, 'group_begin')
    require(len(begins) == 4 and begins[0] == 0 and begins[-1] == len(entries),
            'unsupported recursion tap partition')
    require(all(left < right for left, right in zip(begins, begins[1:])),
            'invalid recursion tap partition')
    widths = {}
    for group, name in enumerate(('accum', 'code', 'data')):
        require(_uint(sources[ADAPTER], 'REGISTER_GROUP_' + name.upper()) == group,
                'unexpected register group order')
        selected = entries[begins[group]:begins[group + 1]]
        require(all(row[2] == group for row in selected), 'tap group mismatch')
        offsets = [row[0] for row in selected]
        width = offsets[-1] + 1  # TapSet::group_size; not the number of taps.
        require(offsets == sorted(offsets) and set(offsets) == set(range(width)),
                'unsupported tap offsets')
        widths[name] = width
    register_count = int(_one(r'\breg_count:\s*(\d+),', taps, 'reg_count').group(1))
    require(register_count == sum(widths.values()), 'tap/register count mismatch')
    ext, inverse_rate = _uint(field, 'EXT_SIZE'), _uint(lib, 'INV_RATE')
    output_size, mix_size = _uint(info, 'OUTPUT_SIZE'), _uint(info, 'MIX_SIZE')
    fold = 1 << _uint(lib, 'FRI_FOLD_PO2')
    widths.update(check=inverse_rate * ext, fri=fold * ext)
    protocol = _one(r'PROOF_SYSTEM_INFO: ProtocolInfo = ProtocolInfo\(\*b"([^"]+)"\)',
                    sources[ADAPTER], 'proof system info').group(1)
    circuit = _one(r'CIRCUIT_INFO: ProtocolInfo = ProtocolInfo\(\*b"([^"]+)"\)',
                   info, 'circuit info').group(1)
    require(len(protocol.encode('ascii')) == len(circuit.encode('ascii')) == 16,
            'unexpected protocol context width')
    require(ext == 4 and output_size == 32 and mix_size == 20,
            'outside frozen recursion profile')
    return {
        'field_modulus': P, 'extension_degree': ext, 'extension_polynomial': 'X^4+11',
        'inverse_rate': inverse_rate, 'queries': _uint(lib, 'QUERIES'),
        'fold': fold, 'final_coefficient_threshold': _uint(lib, 'FRI_MIN_DEGREE'),
        'explicit_generic_po2_max': _uint(lib, 'MAX_CYCLES_PO2'),
        'output_base_elements': output_size, 'accum_mix_base_elements': mix_size,
        'tap_count': len(entries), 'register_count': register_count,
        'leaf_widths_base_elements': widths,
        'u_coefficients_extension_elements': len(entries) + widths['check'],
        'digest_words': _uint(sources[DIGEST], 'DIGEST_WORDS'),
        'rng_rate_cells': _uint(sources[HASH], 'CELLS_RATE'),
        'rng_width_cells': _uint(sources[CONSTS], 'CELLS'),
        'proof_system_info_ascii': protocol, 'circuit_info_ascii': circuit,
    }


def _tree(name: str, rows: int, width: int, params: dict) -> dict:
    require(rows > 0 and rows & (rows - 1) == 0, 'non-power-of-two Merkle domain')
    height = rows.bit_length() - 1
    cap_depth = min(params['queries'].bit_length() - 1, max(0, height - 1))
    siblings = height - cap_depth
    return {'oracle': name, 'rows': rows, 'height': height, 'leaf_words': width,
            'cap_depth': cap_depth, 'cap_digests': 1 << cap_depth,
            'sibling_digest_count': siblings,
            'opening_words': width + siblings * params['digest_words']}


def _rng_cost(params: dict, rounds: int) -> dict:
    # Count only the frozen RNG call schedule, excluding every commitment hash.
    pool = permutations = squeezes = 0

    def commit() -> None:
        nonlocal pool, permutations
        if pool:
            permutations += 1
            pool = 0
        permutations += 1

    def squeeze(count: int) -> None:
        nonlocal pool, permutations, squeezes
        for _ in range(count):
            if pool == params['rng_rate_cells']:
                permutations += 1
                pool = 0
            pool += 1
            squeezes += 1

    for _ in range(5):  # Protocol, circuit, globals+po2, code, data.
        commit()
    squeeze(params['accum_mix_base_elements'])
    for _ in range(3):  # accum/poly_mix, check/z, U/batch_mix.
        commit()
        squeeze(params['extension_degree'])
    for _ in range(rounds):
        commit()
        squeeze(params['extension_degree'])
    commit()  # Final polynomial coefficients.
    squeeze(4 * params['queries'])  # Four draws even if the first is nonzero.
    return {'base_squeezes': squeezes, 'rng_permutation_calls': permutations,
            'count_kind': 'Source-level RNG call schedule, not a QROM query budget.',
            'includes_commitment_hash_calls': False,
            'includes_nested_verification_or_adversary_queries': False,
            'qrom_queries_inferred': None}


def _transcript_map(params: dict, rounds: list[dict]) -> list[dict]:
    # This is a manually reviewed state-machine map attached to exact source pins.
    # It is deliberately not advertised as AST extraction or formal verification.
    definitions = [
        ('rng_init', 'initialize', RNG, 'new: zero cells; pool_used=0'),
        ('proof_system_info', 'commit', VERIFY,
         'commit_circuit_info: H_elem(16 byte-to-field elements)'),
        ('circuit_info', 'commit', VERIFY,
         'commit_circuit_info: H_elem(16 byte-to-field elements)'),
        ('public_outputs_and_po2', 'commit', VERIFY,
         'read_slice_with_po2: H_elem(32 outputs + raw po2 word); values vary, size is fixed'),
        ('code_root', 'commit_then_code_check', VERIFY,
         'verify_group(CODE): reconstruct cap root, mix, then call check_code(po2,root)'),
        ('data_root', 'commit', VERIFY, 'verify_group(DATA): reconstruct cap root and mix'),
        ('accum_mix', 'challenge', VERIFY,
         f'read_rng: {params["accum_mix_base_elements"]} base-field squeezes'),
        ('accum_root', 'commit', VERIFY, 'verify_group(ACCUM): reconstruct cap root and mix'),
        ('constraint_mix', 'challenge', VERIFY, 'verify_validity: one Fp4 before check root'),
        ('check_root', 'commit', MERKLE, 'MerkleTreeVerifier::new: reconstruct cap root and mix'),
        ('deep_point_z', 'challenge', VERIFY,
         'one Fp4 after check root; requires circuit_debug disabled'),
        ('u_coefficients', 'commit_then_constraint_check', VERIFY,
         'H_ext(num_taps+CHECK_SIZE extension coefficients); reject failed validity equation'),
        ('fri_batch_mix', 'challenge', VERIFY, 'one Fp4 after U commitment and validity check'),
    ]
    for tree in rounds:
        definitions.extend([
            (tree['oracle'] + '_root', 'commit', FRI,
             f'VerifyRoundInfo::new: root for {tree["rows"]} rows of {tree["leaf_words"]} base words'),
            (tree['oracle'] + '_fold_mix', 'challenge', FRI,
             'one Fp4 after the corresponding root commitment'),
        ])
    definitions.extend([
        ('final_polynomial', 'commit', FRI,
         'H_elem(4*d_final base elements), component-major layout'),
        ('query_loop', 'challenge_and_openings', FRI,
         '50 positions, with replacement; accum,code,data,check then each FRI round; openings do not mix RNG'),
        ('seal_exhaustion', 'check', READ_IOP, 'verify_complete rejects unread seal words'),
    ])
    return [dict(order=i, id=name, kind=kind, source=source, operation=operation)
            for i, (name, kind, source, operation) in enumerate(definitions)]


def audit_sources(sources: dict[str, str], receipt_bytes: bytes) -> dict:
    """Return a fixed-source encoding report, never a receipt-validity verdict.

    The opaque outer receipt suffix is only length-accounted and hashed. Its
    metadata/claim/journal bindings and the receipt's exact identity are checked
    by the parent audit, not here. Canonical mutations can preserve this geometry.
    """
    records = _verify_sources(sources)
    params = _parameters(sources)
    require(type(receipt_bytes) is bytes, 'receipt input must be bytes')
    require(len(receipt_bytes) == FIXED_RECEIPT_BYTES, 'fixed saved-v2 receipt length mismatch')
    kind, declared_words = struct.unpack_from('<IQ', receipt_bytes)
    require(kind == 1, 'fixed receipt must carry the Succinct variant')
    require(params['output_base_elements'] < declared_words
            <= (len(receipt_bytes) - SEAL_OFFSET) // 4, 'invalid seal vector length')
    po2 = struct.unpack_from('<I', receipt_bytes,
                            SEAL_OFFSET + 4 * params['output_base_elements'])[0]
    require(po2 == FIXED_PO2, 'outside frozen saved-v2 raw po2=18 scope')
    require(po2 <= params['explicit_generic_po2_max'], 'generic po2 bound')
    degree = 1 << po2
    domain = degree * params['inverse_rate']
    widths = params['leaf_widths_base_elements']
    trees = [_tree(name, domain, widths[name], params)
             for name in ('accum', 'code', 'data', 'check')]
    by_name = {tree['oracle']: tree for tree in trees}
    fri_trees = []
    final_domain = domain
    while degree > params['final_coefficient_threshold']:
        degree //= params['fold']
        final_domain //= params['fold']
        fri_trees.append(_tree(f'fri{len(fri_trees)}', final_domain, widths['fri'], params))
    ext = params['extension_degree']
    prefix_specs = [('outputs_and_po2', params['output_base_elements'] + 1)]
    prefix_specs += [(name + '_cap', by_name[name]['cap_digests'] * params['digest_words'])
                     for name in ('code', 'data', 'accum', 'check')]
    prefix_specs.append(('u_coefficients', params['u_coefficients_extension_elements'] * ext))
    prefix_specs += [(tree['oracle'] + '_cap', tree['cap_digests'] * params['digest_words'])
                     for tree in fri_trees]
    prefix_specs.append(('final_polynomial_coefficients', ext * degree))
    prefix_words = sum(count for _, count in prefix_specs)
    query_words = sum(tree['opening_words'] for tree in trees + fri_trees)
    expected_words = prefix_words + params['queries'] * query_words
    require(declared_words == expected_words, 'declared seal length differs from derived geometry')
    seal_end = SEAL_OFFSET + 4 * declared_words
    seal = receipt_bytes[SEAL_OFFSET:seal_end]
    words = tuple(value for (value,) in struct.iter_unpack('<I', seal))
    require(len(words) == expected_words, 'truncated seal words')
    for index, value in enumerate(words):
        require(value < P, f'noncanonical seal word at index {index}')
    ranges = []
    cursor = 0
    for name, count in prefix_specs:
        end = cursor + count
        require(end <= len(words), f'truncated {name}')
        ranges.append({'id': name, 'seal_word_start_inclusive': cursor,
                       'seal_word_end_exclusive': end, 'base_word_count': count,
                       'raw_bytes_sha256': _sha(seal[4 * cursor:4 * end])})
        cursor = end
    query_template = []
    relative = 0
    for tree in trees + fri_trees:
        count = tree['opening_words']
        query_template.append({**tree, 'query_word_start_inclusive': relative,
                               'query_word_end_exclusive': relative + count})
        relative += count
    # Consume every opening using fixed geometry, without interpreting its values.
    for _ in range(params['queries']):
        for tree in trees + fri_trees:
            cursor += tree['opening_words']
            require(cursor <= len(words), 'truncated query opening')
    require(cursor == len(words), 'unconsumed or extra seal words')
    tail = receipt_bytes[seal_end:]
    return {
        'schema': 'TRNM-W1-FRI-TRANSCRIPT-GEOMETRY1',
        'result': 'SOURCE_MAPPING_AND_ENCODING_GEOMETRY_REPRODUCED_SECURITY_HOLD',
        'upstream_commit': UPSTREAM_COMMIT,
        'source_files': records,
        'scope': 'Fixed po2=18 saved-v2 recursion seal; static source map and encoding only.',
        'build_precondition': 'circuit_debug disabled; this module does not attest build features.',
        'qualification': {
            'fresh_cryptographic_verification': False, 'qrom_instantiated': False,
            'arithmetic_relation_verified': False, 'merkle_openings_verified': False,
            'fiat_shamir_challenges_recomputed': False, 'post_quantum_soundness_qualified': False,
            'whole_receipt_identity_enforced_here': False, 'security_bits_quantum': None,
        },
        'parameters': params,
        'saved_v2_geometry': {
            'receipt_bytes': len(receipt_bytes), 'receipt_sha256': _sha(receipt_bytes),
            'seal_file_offset_bytes': SEAL_OFFSET, 'seal_po2_raw_word_index': 32,
            'po2': po2, 'N': 1 << po2, 'D': domain, 'R': len(fri_trees),
            'seal_words': len(words), 'seal_bytes': len(seal), 'seal_sha256': _sha(seal),
            'all_seal_words_canonical': True, 'all_seal_words_accounted_for': True,
            'prequery_words': prefix_words, 'per_query_words': query_words,
            'queries': params['queries'], 'final_coefficients_extension': degree,
            'final_coefficients_base': degree * ext, 'prequery_ranges': ranges,
            'query_template': query_template, 'query_end_word_exclusive': cursor,
            'opaque_outer_suffix_bytes': len(tail), 'opaque_outer_suffix_sha256': _sha(tail),
            'opaque_outer_suffix_semantically_parsed': False,
        },
        'ordered_fs_events': _transcript_map(params, fri_trees),
        'merkle_binding': {
            'leaf_length': 'Trusted taps/CHECK_SIZE/FRI constants set exact consumed field-word counts.',
            'leaf_position': 'idx<row_size; idx+row_size and low bits determine ordered hash_pair path.',
            'tree_depth': 'Derived from committed raw po2 and fixed circuit; consume L-cap_depth siblings.',
            'cap': 'Read fixed cap in order, validate digests, reconstruct root; only root is mixed.',
            'dimensions_or_positions_tagged_inside_hash': False,
            'leaf_node_purpose_tags_present': False,
            'encoding': 'Reduced Montgomery u32 words; digest has eight words; widths are typed externally.',
            'u_coefficients_layout': 'Each Fp4 coefficient has four consecutive base words.',
            'fri_leaf_layout': 'component-major: element i component j is data[j*16+i].',
            'final_polynomial_layout': 'component-major: coefficient i component j is final[j*d_final+i].',
            'source': [VERIFY, FRI, MERKLE, MERKLE_PARAMS, READ_IOP, HASH],
        },
        'po2_boundary': {
            'raw_word_not_as_u32_decoded': True,
            'succinct_code_callback_ignores_po2_argument': True,
            'generic_explicit_max': params['explicit_generic_po2_max'],
            'default_lift_name_limit_is_not_proven_outer_seal_limit': True,
            'reachable_outer_po2_set_proved': False,
            'all_po2_up_to_generic_max_accepted_claimed': False,
            'source': [VERIFY, FIELD, SUCCINCT],
        },
        'rng': {
            'sampling_with_replacement': True, 'base_draws_per_query': 4,
            'query_position_bits': po2 + 2,
            'openings_change_rng_state': False,
            'commit_rule': 'If pool_used!=0 permute and reset; add 8 raw digest cells; permute.',
            'extension_rule': 'Four consecutive base squeezes in the fixed Fp4 basis.',
            'bit_rule': 'Always draw four; first nonzero as_u32 or zero; mask low bits.',
            'ideal_sampler_deviation': {
                'assumption': 'Conditionally independent uniform Fp draws and k<=27.',
                'per_query_tv': '(1-2^-k)/p^4 <= p^-4',
                'fifty_queries_tv_upper_bound': '50/p^4',
                'real_poseidon2_qrom_distribution_proved': False,
            },
            'derived_rng_cost': _rng_cost(params, len(fri_trees)),
        },
        'grinding': {
            'explicit_gate_found_in_inspected_path': False, 'credited_grinding_bits': 0,
            'method': 'Manual control-flow review tied to exact six-file source hashes.',
            'source_scope': [VERIFY, FRI, MERKLE, READ_IOP, HASH, RNG],
            'limits': 'Does not exclude offline transcript search, wrapper gates, the separate rv32im protocol, or generated recursive verifier behavior. PoN lottery supplies no credit here.',
        },
        'qrom_interface_obligations': [
            'Bind vector widths, lengths, heights, field encodings and phase/circuit context throughout extraction.',
            'Instantiate the selected theorem\'s quantum commitment-extraction property for the cap-Merkle construction.',
            'Account for unpadded hashing and cross-length/type aliases; parser typing is not an arbitrary-length CRH proof.',
            'Prove the required joint quantum oracle model for commitment hashing and stateful RNG sharing Poseidon2.',
            'Match actual commit/challenge order, raw po2, sampling, statement adaptivity and build features to the theorem.',
            'Prove generated recursive verifiers implement this relation for all allowed control programs.',
            'Instantiate RBR/state-restoration and circuit/proximity bounds including exceptional DEEP points.',
            'Bound lifetime queries across every use and attempt, with compiler losses; RNG call counts are not that budget.',
        ],
    }


def main() -> int:
    import argparse
    import gzip
    import json
    from pathlib import Path
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    try:
        with gzip.open(args.snapshot, 'rb') as stream:
            decoded = stream.read(2 * 1024 * 1024 + 1)
        require(len(decoded) <= 2 * 1024 * 1024, 'source snapshot exceeds bound')
        snapshot = json.loads(decoded)
        require(type(snapshot) is dict and snapshot.get('repository') == 'risc0/risc0'
                and snapshot.get('commit') == UPSTREAM_COMMIT, 'source snapshot identity')
        sources = {}
        for row in snapshot['files']:
            require(row['path'] not in sources, 'duplicate source path')
            sources[row['path']] = row['content']
        with args.receipt.open('rb') as stream:
            receipt = stream.read(FIXED_RECEIPT_BYTES + 1)
        report = audit_sources(sources, receipt)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'FRI transcript geometry audit failed: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
