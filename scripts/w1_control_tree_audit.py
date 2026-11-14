#!/usr/bin/env python3
"""Recompute the frozen W1 control catalog/tree; no receipt or QROM verification.

Poseidon2 arithmetic is transcribed from RISC Zero's Apache-2.0 implementation
at UPSTREAM_COMMIT. Constants are parsed only from SHA-256-pinned source bytes.
The archived upstream LICENSE accompanies the source snapshot. The independent
normal-form implementation is checked against upstream known-answer vectors;
digest inputs/outputs use the SDK's little-endian Montgomery representation.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
from collections.abc import Sequence

UPSTREAM_COMMIT = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
P = 2013265921
WIDTH = 24
RATE = 16
DIGEST_WORDS = 8
HALF_FULL_ROUNDS = 4
PARTIAL_ROUNDS = 21
DEPTH = 8
MONTGOMERY_R = (1 << 32) % P
MONTGOMERY_R_INV = pow(MONTGOMERY_R, -1, P)
EXPECTED_ROOT = 'a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56'
EXPECTED_JOIN = '7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e'
CONST_PATH = 'risc0/zkp/src/core/hash/poseidon2/consts.rs'
CONTROL_PATH = 'risc0/circuit/recursion/src/control_id.rs'
SUCCINCT_PATH = 'risc0/zkvm/src/receipt/succinct.rs'
MERKLE_PATH = 'risc0/zkvm/src/receipt/merkle.rs'
# Each digest matches the selected member of the lockfile-verified crate snapshot.
# This helper verifies these source snapshots, not the complete Cargo graph.
SOURCE_SHA256 = {
    'risc0/core/src/field/baby_bear.rs': 'df3e77d606dd74d78fb6b6f3dbbe72455c5ed5b091f7a74de8c049e85b857ff3',
    CONST_PATH: '5ee51bce046bce1306181a43136aa0731dcf976ab10e2e8d82db88711efdcc41',
    'risc0/zkp/src/core/hash/poseidon2/mod.rs': 'a2993a2e29fa33345a6a9ce0b4f192efe7412746b92b172b0eed8ce78ee8471f',
    'risc0/zkp/src/core/digest.rs': '15ea8c15627e5074eea6d0e71895bd006d28f0cfe9ddb2f2dd73de6cbcd22772',
    CONTROL_PATH: '6fedf46fad3ca0ce3e537139be7873a43dd68fee5fc803d3e58604b4e9ae16cb',
    MERKLE_PATH: 'b3eeb7cc62bba1dfa9ba32a75b905510b4777b9f61004891163d8f43ee8072d6',
    SUCCINCT_PATH: '8e0165b3210e30e77074763d71d85fd0595e4190b96725182f33665b7df90d60',
    'risc0/zkvm/src/receipt.rs': 'ec445670befb0fad19bfe46eede73e551de03d9f91fa1fb81c9149dc04912fed',
    'risc0/zkp/src/lib.rs': '107521d2426442fbc9358b7b9ae5650be92d670ea85e9a34aec7b9e9cc27dc6d',
}
BASE_PROGRAMS = (
    'identity.zkr', 'join.zkr', 'join_povw.zkr', 'join_unwrap_povw.zkr',
    'resolve.zkr', 'resolve_povw.zkr', 'resolve_unwrap_povw.zkr',
    'union.zkr', 'unwrap_povw.zkr',
)
EXPECTED_PROGRAMS = tuple(sorted(
    BASE_PROGRAMS + tuple(f'lift_rv32im_v2_{i}.zkr' for i in range(14, 23))
    + tuple(f'lift_rv32im_v2_povw_{i}.zkr' for i in range(14, 23))
))
EXPECTED_CATALOG = tuple(sorted(
    BASE_PROGRAMS + ('test_recursion_circuit.zkr',)
    + tuple(f'lift_rv32im_v2_{i}.zkr' for i in range(14, 25))
    + tuple(f'lift_rv32im_v2_povw_{i}.zkr' for i in range(14, 25))
))


class ControlTreeError(ValueError):
    """Unsupported snapshot, encoding, catalog, or proof path."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ControlTreeError(message)


def _one(pattern: str, source: str, label: str) -> re.Match:
    matches = list(re.finditer(pattern, source, re.S))
    require(len(matches) == 1, f'{label}: missing or ambiguous declaration')
    return matches[0]


def _int_const(source: str, name: str) -> int:
    return int(_one(r'\bconst\s+' + re.escape(name) + r':\s*usize\s*=\s*(\d+);',
                    source, name).group(1))


def verify_sources(sources: dict[str, str]) -> list[dict]:
    records = []
    for name, expected in SOURCE_SHA256.items():
        require(name in sources and isinstance(sources[name], str), f'{name}: missing source')
        data = sources[name].encode('utf-8')
        require(len(data) <= 2 * 1024 * 1024, f'{name}: source too large')
        actual = hashlib.sha256(data).hexdigest()
        require(actual == expected, f'{name}: fixed source SHA-256 mismatch')
        records.append({'path': name, 'sha256': actual, 'bytes': len(data)})
    return records


def _field_array(source: str, name: str, count: int) -> tuple[int, ...]:
    payload = _one(r'\bconst\s+' + re.escape(name)
                   + r':\s*&\[Elem\]\s*=\s*&baby_bear_array!\[(.*?)\];',
                   source, name).group(1)
    payload = re.sub(r'//[^\n]*', '', payload)
    tokens = [x.strip() for x in payload.split(',')]
    if tokens and not tokens[-1]:
        tokens.pop()
    require(len(tokens) == count, f'{name}: wrong array length')
    require(all(re.fullmatch(r'0x[0-9a-fA-F]+|\d+', x) for x in tokens),
            f'{name}: unsupported constant expression')
    values = tuple(int(x, 16) if x.startswith('0x') else int(x) for x in tokens)
    require(all(0 <= x < P for x in values), f'{name}: noncanonical field constant')
    return values


def _canonical(values: Sequence[int], count: int, label: str) -> tuple[int, ...]:
    require(len(values) == count, f'{label}: wrong length')
    require(all(type(x) is int and 0 <= x < P for x in values),
            f'{label}: noncanonical BabyBear element')
    return tuple(values)


def _digest_words(digest: str) -> tuple[int, ...]:
    require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) is not None,
            'digest: expected exactly 32 bytes of lowercase hexadecimal')
    return _canonical(struct.unpack('<8I', bytes.fromhex(digest)), DIGEST_WORDS, 'digest')


class Poseidon2:
    """Normal-form BabyBear arithmetic, with explicit Montgomery byte boundaries."""

    def __init__(self, constants: Sequence[int], diagonal: Sequence[int]):
        self.constants = _canonical(constants, WIDTH * (2 * HALF_FULL_ROUNDS + PARTIAL_ROUNDS),
                                    'round constants')
        self.diagonal = _canonical(diagonal, WIDTH, 'internal diagonal')

    @classmethod
    def from_source(cls, source: str) -> Poseidon2:
        require((_int_const(source, 'CELLS'), _int_const(source, 'ROUNDS_HALF_FULL'),
                 _int_const(source, 'ROUNDS_PARTIAL')) == (WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS),
                'unsupported Poseidon2 parameters')
        return cls(_field_array(source, 'ROUND_CONSTANTS', WIDTH * 29),
                   _field_array(source, 'M_INT_DIAG_HZN', WIDTH))

    @staticmethod
    def _external(state: Sequence[int]) -> list[int]:
        out = []
        for start in range(0, WIDTH, 4):
            x0, x1, x2, x3 = state[start:start + 4]
            t0, t1 = x0 + x1, x2 + x3
            t2, t3 = 2 * x1 + t1, 2 * x3 + t0
            t4, t5 = 4 * t1 + t3, 4 * t0 + t2
            out.extend((t3 + t5, t5, t2 + t4, t4))
        sums = [sum(out[i::4]) for i in range(4)]
        return [(v + sums[i % 4]) % P for i, v in enumerate(out)]

    def permute(self, values: Sequence[int]) -> tuple[int, ...]:
        state = self._external(_canonical(values, WIDTH, 'state'))
        for round_index in range(2 * HALF_FULL_ROUNDS + PARTIAL_ROUNDS):
            if round_index < HALF_FULL_ROUNDS or round_index >= HALF_FULL_ROUNDS + PARTIAL_ROUNDS:
                state = [pow((v + self.constants[round_index * WIDTH + i]) % P, 7, P)
                         for i, v in enumerate(state)]
                state = self._external(state)
            else:
                state[0] = pow((state[0] + self.constants[round_index * WIDTH]) % P, 7, P)
                total = sum(state)
                state = [(total + self.diagonal[i] * v) % P for i, v in enumerate(state)]
        return tuple(state)

    def hash_elements(self, values: Sequence[int]) -> tuple[int, ...]:
        """SDK unpadded overwrite sponge; the result is in normal field form.

        This is not a variable-length collision-resistant encoding. The tree
        below uses exactly 16 input elements for every internal-node hash.
        """
        _canonical(values, len(values), 'hash input')
        state = [0] * WIDTH
        if not values:
            return self.permute(state)[:DIGEST_WORDS]
        for start in range(0, len(values), RATE):
            block = list(values[start:start + RATE])
            state[:RATE] = block + [0] * (RATE - len(block))
            state = list(self.permute(state))
        return tuple(state[:DIGEST_WORDS])

    def hash_pair(self, left: str, right: str) -> str:
        words = _digest_words(left) + _digest_words(right)
        normal = tuple(w * MONTGOMERY_R_INV % P for w in words)
        result = self.hash_elements(normal)
        return struct.pack('<8I', *(x * MONTGOMERY_R % P for x in result)).hex()


def parse_controls(source: str) -> list[dict]:
    payload = _one(r'pub const ALLOWED_CONTROL_IDS:\s*&\[Digest\]\s*=\s*&\[(.*?)\n\];',
                   source, 'ALLOWED_CONTROL_IDS').group(1)
    records = []
    for line in payload.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*digest!\("([0-9a-f]{64})"\),\s*// recursion ([a-z0-9_]+\.zkr)\s*', line)
        require(match is not None, 'ALLOWED_CONTROL_IDS: unsupported entry')
        records.append({'program': match.group(2), 'control_id': match.group(1)})
    return records


def parse_catalog(source: str) -> list[dict]:
    match = _one(r'pub const POSEIDON2_CONTROL_IDS:\s*\[\(&str,\s*Digest\);\s*(\d+)\]\s*=\s*\[(.*?)\n\];',
                 source, 'POSEIDON2_CONTROL_IDS')
    payload = match.group(2)
    pattern = r'\s*\(\s*"([a-z0-9_]+\.zkr)",\s*digest!\("([0-9a-f]{64})"\),\s*\),'
    records, pos = [], 0
    for item in re.finditer(pattern, payload):
        require(not payload[pos:item.start()].strip(), 'POSEIDON2_CONTROL_IDS: unsupported entry')
        records.append({'program': item.group(1), 'control_id': item.group(2)})
        pos = item.end()
    require(not payload[pos:].strip(), 'POSEIDON2_CONTROL_IDS: trailing unparsed entry')
    require(len(records) == int(match.group(1)), 'POSEIDON2_CONTROL_IDS: declared size mismatch')
    return records


def validate_catalog(allowed: Sequence[dict], catalog: Sequence[dict]) -> None:
    for records, names, label in ((allowed, EXPECTED_PROGRAMS, 'allowed'),
                                  (catalog, EXPECTED_CATALOG, 'catalog')):
        require(tuple(r.get('program') for r in records) == names,
                f'{label}: program roster/order differs from the fixed profile')
        ids = [r.get('control_id') for r in records]
        for digest in ids:
            _digest_words(digest)
        require(len(set(ids)) == len(ids), f'{label}: duplicate control ID')
    named = {r['program']: r['control_id'] for r in catalog}
    require(all(named[r['program']] == r['control_id'] for r in allowed),
            'allowed control ID differs from named catalog')
    require(named['join.zkr'] == EXPECTED_JOIN, 'final join control ID drift')


def build_tree(control_ids: Sequence[str], hasher: Poseidon2) -> list[list[str]]:
    # Match MerkleGroup::new's strict < 256 bound, not <= 256.
    require(0 < len(control_ids) < 1 << DEPTH, 'control tree: expected 1..255 leaves')
    for digest in control_ids:
        _digest_words(digest)
    levels = [list(control_ids) + ['00' * 32] * ((1 << DEPTH) - len(control_ids))]
    while len(levels[-1]) > 1:
        previous = levels[-1]
        levels.append([hasher.hash_pair(previous[i], previous[i + 1])
                       for i in range(0, len(previous), 2)])
    return levels


def _inclusion_root(control_id: str, index: int, siblings: Sequence[str], hasher: Poseidon2) -> str:
    require(type(index) is int and 0 <= index < 1 << DEPTH, 'control path: index outside depth-8 tree')
    require(len(siblings) == DEPTH, 'control path: expected exactly 8 siblings')
    _digest_words(control_id)
    # Reject all malformed nodes before any permutation work.
    for sibling in siblings:
        _digest_words(sibling)
    current = control_id
    for sibling in siblings:
        current = (hasher.hash_pair(sibling, current) if index & 1
                   else hasher.hash_pair(current, sibling))
        index >>= 1
    return current


def _hasher(sources: dict[str, str]) -> Poseidon2:
    verify_sources(sources)
    require(_int_const(sources[MERKLE_PATH], 'ALLOWED_CODE_MERKLE_DEPTH') == DEPTH,
            'unsupported control Merkle depth')
    return Poseidon2.from_source(sources[CONST_PATH])


def hash_pair(left: str, right: str, sources: dict[str, str]) -> str:
    return _hasher(sources).hash_pair(left, right)


def control_root(control_ids: Sequence[str], sources: dict[str, str]) -> str:
    return build_tree(control_ids, _hasher(sources))[-1][0]


def inclusion_root(control_id: str, index: int, siblings: Sequence[str], sources: dict[str, str]) -> str:
    """Recompute one depth-8 path; caller must compare it with the pinned root."""
    return _inclusion_root(control_id, index, siblings, _hasher(sources))


def audit_sources(sources: dict[str, str]) -> dict:
    source_checks = verify_sources(sources)
    hasher = _hasher(sources)
    require(_int_const(sources[CONTROL_PATH], 'MIN_LIFT_PO2') == 14,
            'unsupported minimum lift po2')
    require(_int_const(sources['risc0/zkvm/src/receipt.rs'], 'DEFAULT_MAX_PO2') == 22,
            'unsupported default maximum po2')
    require(_int_const(sources['risc0/zkp/src/lib.rs'], 'MAX_CYCLES_PO2') == 24,
            'unsupported SDK maximum po2')
    allowed = parse_controls(sources[CONTROL_PATH])
    catalog = parse_catalog(sources[CONTROL_PATH])
    validate_catalog(allowed, catalog)
    declared = _one(r'pub const ALLOWED_CONTROL_ROOT:\s*Digest\s*=\s*digest!\("([0-9a-f]{64})"\)',
                    sources[CONTROL_PATH], 'ALLOWED_CONTROL_ROOT').group(1)
    levels = build_tree([r['control_id'] for r in allowed], hasher)
    root = levels[-1][0]
    require(root == declared == EXPECTED_ROOT, 'recomputed control root differs from declared/fixed root')
    programs, join = [], None
    for index, record in enumerate(allowed):
        siblings = [levels[level][(index >> level) ^ 1] for level in range(DEPTH)]
        require(_inclusion_root(record['control_id'], index, siblings, hasher) == root,
                'generated control inclusion path disagrees with recomputed root')
        programs.append({'index': index, **record, 'inclusion_recomputed': True,
                         'program_semantics_audited': False})
        if record['program'] == 'join.zkr':
            join = {'index': index, 'control_id': record['control_id'], 'merkle_path': siblings}
    return {
        'schema': 'TRNM-W1-CONTROL-TREE-AUDIT1',
        'upstream_commit': UPSTREAM_COMMIT,
        'status': 'CATALOG_AND_TREE_RECOMPUTED',
        'field_modulus': P,
        'digest_encoding': '8 canonical Montgomery u32 words, little-endian bytes',
        'node_hash': 'Poseidon2 unpadded overwrite sponge on exactly 16 field elements',
        'leaf_encoding': 'control ID itself; no additional leaf hash',
        'ordering': 'lexicographic program-name order, matching BTreeSet<String>',
        'depth': DEPTH,
        'level_widths': [len(level) for level in levels],
        'allowed_program_count': len(allowed),
        'sdk_catalog_count': len(catalog),
        'zero_padding_leaves': (1 << DEPTH) - len(allowed),
        'internal_node_hashes': (1 << DEPTH) - 1,
        'declared_root': declared,
        'root': root,
        'matches_fixed_root': True,
        'allowed_programs': programs,
        'sdk_programs_outside_default_root': [r for r in catalog if r['program'] not in EXPECTED_PROGRAMS],
        'final_join': join,
        'source_checks': source_checks,
        'complete_cargo_graph_audited': False,
        'zkr_binaries_rebuilt': False,
        'control_ids_derived_from_zkr_binaries': False,
        'program_semantics_audited': False,
        'complete_qrom_bound_established': False,
    }


def load_source_bundle(path: Path) -> dict[str, str]:
    with path.open('rb') as handle:
        compressed = handle.read(4 * 1024 * 1024 + 1)
    require(len(compressed) <= 4 * 1024 * 1024, 'source bundle exceeds compressed size bound')
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as archive:
        data = archive.read(16 * 1024 * 1024 + 1)
    require(len(data) <= 16 * 1024 * 1024, 'source bundle exceeds decoded size bound')
    envelope = json.loads(data)
    require(envelope['schema'] == 'TRNM-W1-UPSTREAM-SOURCE-SNAPSHOT1', 'unsupported source bundle schema')
    require(envelope['commit'] == UPSTREAM_COMMIT, 'source bundle commit drift')
    sources = {}
    for record in envelope['files']:
        name, content = record['path'], record['content']
        require(name not in sources, f'{name}: duplicate source bundle record')
        raw = content.encode('utf-8')
        require(record['bytes'] == len(raw) and record['sha256'] == hashlib.sha256(raw).hexdigest(),
                f'{name}: source bundle record differs from its content')
        sources[name] = content
    verify_sources(sources)
    return sources


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-bundle', type=Path, default=Path(__file__).resolve().parents[1]
                        / 'evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz')
    parser.add_argument('--out', type=Path, help='Create a new output; an existing file is never overwritten')
    args = parser.parse_args()
    try:
        result = audit_sources(load_source_bundle(args.source_bundle))
        encoded = json.dumps(result, indent=2, sort_keys=True) + '\n'
        if args.out is None:
            print(encoded, end='')
        else:
            with args.out.open('x', encoding='utf-8') as output:
                output.write(encoded)
        return 0
    except (ControlTreeError, OSError, ValueError, KeyError, TypeError) as error:
        print(f'control-tree audit refused: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
