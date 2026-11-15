#!/usr/bin/env python3
"""Replay the fixed v2 seal's Poseidon2 transcript and all 350 Merkle openings.

This is NOT a STARK/receipt verifier or a QROM instantiation. The AIR validity
equation, DEEP evaluation, FRI folding equations and terminal evaluation are
deliberately not evaluated. Replay follows the path on which those omitted
checks have succeeded. No native RNG/permutation count becomes a quantum query
budget. Only the frozen po2=18 receipt and SHA-256-pinned source/helper bytes
are supported; the outer receipt suffix is identity-bound, not interpreted.

Poseidon2 arithmetic is reused from the pinned local control-tree helper.
Upstream permutation and aligned/unaligned sponge golden vectors are parsed
from the pinned Apache-2.0 source and checked before any receipt replay. Source
text is data; only the pinned repository audit helpers are executed.
"""
from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
INPUT_PROFILE_SOURCE_HEAD = '0c830e0be8939ce80c8443c9ad68021b87343a00'
PROFILE = 'trnm-w1-risc0-3.0.6-poseidon2-join-v2'
P = 2013265921
MONTGOMERY_R = (1 << 32) % P
MONTGOMERY_R_INV = pow(MONTGOMERY_R, -1, P)
WIDTH, RATE, DIGEST_WORDS = 24, 16, 8
RECEIPT_PATH = 'evidence/pon-w1-full-v2-20261105/succinct.bin'
RECEIPT_BYTES = 257014
RECEIPT_SHA256 = '6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee'
SNAPSHOT_PATH = 'evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz'
SNAPSHOT_BYTES = 69332
SNAPSHOT_SHA256 = 'f6be3667106df6843f5f29c0954cdce8e2617da36c9c91a7a5198665675e0253'
HELPERS = {
    'scripts/w1_control_tree_audit.py':
        '0e9b8e2fd9f6905f98b3df1a52b4ac2a46481b101b1d1a6afd29c2f5502f4865',
    'scripts/w1_fri_transcript_audit.py':
        '12cc991999f68d925f078888d1e18302739171ee6187bbeb2f3bfb17c19a88fc',
}
JOIN = '7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e'
HASH_SOURCE = 'risc0/zkp/src/core/hash/poseidon2/mod.rs'
RNG_SOURCE = 'risc0/zkp/src/core/hash/poseidon2/rng.rs'
MERKLE_SOURCE = 'risc0/zkp/src/verify/merkle.rs'
VERIFY_SOURCE = 'risc0/zkp/src/verify/mod.rs'
FRI_SOURCE = 'risc0/zkp/src/verify/fri.rs'


class ReplayError(ValueError):
    """The fixed-source replay or an explicit encoding/path check failed."""


def require(condition, message):
    if not condition:
        raise ReplayError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def words_bytes(words):
    return struct.pack('<' + 'I' * len(words), *words)


def normal_words(raw):
    require(all(type(word) is int and 0 <= word < P for word in raw),
            'noncanonical Montgomery word')
    return tuple(word * MONTGOMERY_R_INV % P for word in raw)


def raw_words(normal):
    require(all(type(word) is int and 0 <= word < P for word in normal),
            'noncanonical normal-form element')
    return tuple(word * MONTGOMERY_R % P for word in normal)


def digest_hex(raw):
    require(len(raw) == DIGEST_WORDS, 'digest must contain eight words')
    normal_words(raw)
    return words_bytes(raw).hex()


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise ReplayError('nonintegral JSON value: ' + value)

    return json.loads(data, object_pairs_hook=unique, parse_float=invalid,
                      parse_constant=invalid)


def bounded_file(root, relative, limit):
    rel = PurePosixPath(relative)
    require(not rel.is_absolute() and '..' not in rel.parts and str(rel) == relative,
            'noncanonical relative input path')
    path = root
    for part in rel.parts:
        path = path / part
        require(not path.is_symlink(), 'symlink input: ' + relative)
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, 'input size bound: ' + relative)
    return data


def load_helpers(root):
    modules, records = {}, []
    for path, expected in HELPERS.items():
        data = bounded_file(root, path, 65536)
        require(sha(data) == expected, 'fixed helper SHA-256 mismatch: ' + path)
        # Compile the exact checked bytes; do not use sys.path or cached modules.
        module = ModuleType('_w1_replay_' + Path(path).stem)
        module.__file__ = str(root / path)
        exec(compile(data, module.__file__, 'exec'), module.__dict__)
        modules[Path(path).stem] = module
        records.append({'path': path, 'bytes': len(data), 'sha256': expected})
    return modules, records


def load_snapshot(root):
    data = bounded_file(root, SNAPSHOT_PATH, SNAPSHOT_BYTES)
    require(len(data) == SNAPSHOT_BYTES and sha(data) == SNAPSHOT_SHA256,
            'fixed source snapshot identity mismatch')
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as archive:
        decoded = archive.read(2 * 1024 * 1024 + 1)
    require(len(decoded) <= 2 * 1024 * 1024, 'source snapshot expansion bound')
    snapshot = strict_json(decoded)
    require(type(snapshot) is dict and snapshot.get('schema') == 'TRNM-W1-UPSTREAM-SOURCE-SNAPSHOT1'
            and snapshot.get('repository') == 'risc0/risc0'
            and snapshot.get('commit') == UPSTREAM, 'source snapshot scope')
    sources = {}
    for row in snapshot['files']:
        path, text = row['path'], row['content']
        require(path not in sources and type(text) is str, 'duplicate/invalid source record')
        data = text.encode('utf-8')
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        require(row['bytes'] == len(data) and row['sha256'] == sha(data)
                and row['git_blob_sha1'] == blob, 'source snapshot content identity')
        require(row['source_url'] == f'https://github.com/risc0/risc0/blob/{UPSTREAM}/{path}',
                'source snapshot URL identity')
        sources[path] = text
    require(len(sources) == 24 and 'LICENSE' in sources, 'source snapshot roster')
    return sources


def one(pattern, text, name):
    found = list(re.finditer(pattern, text, re.S))
    require(len(found) == 1, name + ': missing or ambiguous pinned-source declaration')
    return found[0]


def numeric_array(payload, count, name):
    require(re.fullmatch(r'[\s,0-9a-fA-Fx]*', payload) is not None,
            name + ': unsupported golden array syntax')
    values = [int(token.strip(), 0) for token in payload.split(',') if token.strip()]
    require(len(values) == count and all(0 <= value < P for value in values),
            name + ': malformed golden vector')
    return tuple(values)


def upstream_golden_checks(hasher, source):
    """Expected values come from the pinned upstream tests, not this replay."""
    vector = one(r'fn poseidon2_test_vectors\(\)\s*\{(.*?)\n    \}', source,
                 'permutation golden').group(1)
    inputs = numeric_array(one(r'baby_bear_array!\[(.*?)\];', vector,
                               'permutation input').group(1), WIDTH, 'permutation input')
    output = numeric_array(one(r'let goal: \[u32; CELLS\] = \[(.*?)\];', vector,
                               'permutation output').group(1), WIDTH, 'permutation output')
    require(hasher.permute(inputs) == output, 'upstream permutation golden mismatch')
    checks = [{'upstream_test': 'poseidon2_test_vectors', 'input_elements': WIDTH,
               'expected_normal_words': list(output), 'matched': True}]
    for name, count in (('hash_elem_slice_compare_golden', 32),
                        ('hash_elem_slice_compare_golden_unaligned', 17)):
        body = one(r'fn ' + name + r'\(\)\s*\{(.*?)\n    \}', source, name).group(1)
        inputs = numeric_array(one(r'baby_bear_array!\[(.*?)\];', body, name).group(1),
                               count, name)
        goal_body = one(r'let goal: \[u32; DIGEST_WORDS\] = \[(.*?)\];', body, name).group(1)
        literals = re.findall(r'BabyBearElem::from\((0x[0-9a-f]+)_u32\)', goal_body)
        output = tuple(int(value, 16) for value in literals)
        require(len(output) == DIGEST_WORDS, name + ': unsupported golden digest')
        require(hasher.hash_elements(inputs) == output, name + ': upstream sponge golden mismatch')
        checks.append({'upstream_test': name, 'input_elements': count,
                       'expected_normal_words': list(output),
                       'expected_raw_digest_hex': digest_hex(raw_words(output)), 'matched': True})
    return {'source': HASH_SOURCE, 'checks': checks,
            'independent_expected_values': 'Pinned upstream tests; sponge tests cite an independent interpreter.',
            'proves_general_implementation_equivalence': False}


class TranscriptRng:
    """Normal-form transcription of the pinned Poseidon2Rng state machine."""

    def __init__(self, hasher):
        self.hasher = hasher
        self.cells = (0,) * WIDTH
        self.pool_used = 0
        self.permutations = 0
        self.squeezes = 0
        self.events = []

    def _permute(self):
        self.cells = self.hasher.permute(self.cells)
        self.permutations += 1

    def state(self):
        return {'pool_used': self.pool_used, 'base_squeezes': self.squeezes,
                'rng_permutation_calls': self.permutations,
                'cells_raw_montgomery_le_sha256': sha(words_bytes(raw_words(self.cells)))}

    def commit(self, name, digest, **details):
        require(len(digest) == DIGEST_WORDS, 'RNG commit digest length')
        incoming = normal_words(digest)
        before = self.state()
        if self.pool_used != 0:
            self._permute()
            self.pool_used = 0
        state = list(self.cells)
        for index, value in enumerate(incoming):
            state[index] = (state[index] + value) % P
        self.cells = tuple(state)
        self._permute()
        self.events.append({'order': len(self.events), 'id': name, 'kind': 'commit',
                            'digest_raw_le_hex': digest_hex(digest),
                            'before': before, 'after': self.state(), **details})

    def _element(self):
        if self.pool_used == RATE:
            self._permute()
            self.pool_used = 0
        value = self.cells[self.pool_used]
        self.pool_used += 1
        self.squeezes += 1
        return value

    def draw(self, name, count, **details):
        require(type(count) is int and 0 < count <= 20, 'unsupported RNG draw count')
        before = self.state()
        values = tuple(self._element() for _ in range(count))
        self.events.append({'order': len(self.events), 'id': name, 'kind': 'challenge',
                            'normal_words': list(values), 'raw_montgomery_words': list(raw_words(values)),
                            'before': before, 'after': self.state(), **details})
        return values

    def query(self, number, bits):
        require(type(bits) is int and 0 < bits <= 27, 'unsupported random_bits width')
        values = self.draw(f'query_{number:02d}', 4, source=RNG_SOURCE,
                           interpretation='first nonzero normal word, then low-bit mask')
        chosen = next((value for value in values if value != 0), 0)
        position = chosen & ((1 << bits) - 1)
        self.events[-1].update(selected_normal_word=chosen, query_bits=bits, index=position)
        return position, list(values)


class SealReader:
    def __init__(self, words):
        self.words = words
        self.cursor = 0

    def read(self, count, label):
        require(type(count) is int and count >= 0, label + ': invalid read length')
        start, end = self.cursor, self.cursor + count
        require(end <= len(self.words), label + ': truncated seal')
        self.cursor = end
        return self.words[start:end], [start, end]

    def complete(self):
        require(self.cursor == len(self.words), 'unconsumed/surplus seal words')


class MerkleTree:
    def __init__(self, spec, cap, word_range, engine):
        self.spec, self.engine = spec, engine
        count = spec['cap_digests']
        require(len(cap) == count * DIGEST_WORDS, 'cap length')
        self.cap = tuple(tuple(cap[start:start + DIGEST_WORDS])
                         for start in range(0, len(cap), DIGEST_WORDS))
        current = list(self.cap)
        self.cap_levels = [[digest_hex(digest) for digest in current]]
        while len(current) > 1:
            require(len(current) % 2 == 0, 'cap must be a power of two')
            current = [engine.hash_pair(current[index], current[index + 1])
                       for index in range(0, len(current), 2)]
            self.cap_levels.append([digest_hex(digest) for digest in current])
        self.root = current[0]
        self.report = {**spec, 'cap_word_range_half_open': word_range,
                       'cap_levels_leaf_to_root_raw_le_hex': self.cap_levels,
                       'root_raw_le_hex': digest_hex(self.root),
                       'cap_digests_canonical': True, 'root_recomputed': True,
                       'opened_leaf_count': 0, 'checked_sibling_nodes': 0}

    def opening(self, reader, index, query_number):
        spec = self.spec
        label = f'query {query_number} {spec["oracle"]}'
        require(type(index) is int and 0 <= index < spec['rows'], label + ': row index out of range')
        leaf, leaf_range = reader.read(spec['leaf_words'], label + ' leaf')
        current = self.engine.hash_raw(leaf)
        leaf_digest = digest_hex(current)
        node = index + spec['rows']
        path = []
        siblings_start = reader.cursor
        while node >= 2 * len(self.cap):
            sibling, word_range = reader.read(DIGEST_WORDS, label + ' sibling')
            low_bit = node & 1
            current = (self.engine.hash_pair(sibling, current) if low_bit
                       else self.engine.hash_pair(current, sibling))
            path.append({'virtual_node_index': node, 'sibling_side': 'left' if low_bit else 'right',
                         'sibling_word_range_half_open': word_range,
                         'sibling_raw_le_hex': digest_hex(sibling),
                         'parent_raw_le_hex': digest_hex(current)})
            node //= 2
        require(len(path) == spec['sibling_digest_count'], label + ': sibling count drift')
        slot = node - len(self.cap)
        require(0 <= slot < len(self.cap), label + ': cap index out of range')
        require(current == self.cap[slot], label + f': Merkle opening mismatch at cap index {slot}')
        self.report['opened_leaf_count'] += 1
        self.report['checked_sibling_nodes'] += len(path)
        return {'oracle': spec['oracle'], 'index': index,
                'leaf_word_range_half_open': leaf_range,
                'leaf_raw_bytes_sha256': sha(words_bytes(leaf)),
                'leaf_digest_raw_le_hex': leaf_digest,
                'sibling_word_range_half_open': [siblings_start, reader.cursor],
                'path': path, 'cap_index': slot,
                'computed_cap_digest_raw_le_hex': digest_hex(current),
                'expected_cap_digest_raw_le_hex': digest_hex(self.cap[slot]),
                'merkle_opening_verified': True}


def repeated_indices(values):
    counts = Counter(values)
    return {'samples': len(values), 'distinct_indices': len(counts),
            'repeated_samples_after_first_occurrence': len(values) - len(counts),
            'colliding_pairs': sum(count * (count - 1) // 2 for count in counts.values()),
            'repeated_indices': [{'index': index, 'multiplicity': count,
                                  'query_numbers': [i for i, value in enumerate(values) if value == index]}
                                 for index, count in sorted(counts.items()) if count > 1]}


class ReplayEngine:
    def __init__(self, sources, root=ROOT):
        modules, self.helper_records = load_helpers(root)
        self.control = modules['w1_control_tree_audit']
        self.geometry = modules['w1_fri_transcript_audit']
        # Both reviewed source sets are pinned before extracting constants or context.
        self.control.verify_sources(sources)
        self.geometry._verify_sources(sources)
        self.sources = dict(sources)
        self.params = self.geometry._parameters(sources)
        self.hasher = self.control.Poseidon2.from_source(sources[self.control.CONST_PATH])
        self.golden_checks = upstream_golden_checks(self.hasher, sources[HASH_SOURCE])
        self.proof_context = self.params['proof_system_info_ascii'].encode('ascii')
        self.circuit_context = self.params['circuit_info_ascii'].encode('ascii')

    def hash_raw(self, values):
        return raw_words(self.hasher.hash_elements(normal_words(values)))

    def hash_pair(self, left, right):
        require(len(left) == len(right) == DIGEST_WORDS, 'pair input length')
        return self.hash_raw(tuple(left) + tuple(right))

    def _context(self, rng, name, value):
        require(type(value) is bytes and len(value) == 16, name + ': expected 16 context bytes')
        # ProtocolInfo::encode uses Elem::from_u64, unlike raw receipt field words.
        digest = raw_words(self.hasher.hash_elements(tuple(value)))
        rng.commit(name, digest, source=VERIFY_SOURCE,
                   encoding='one NORMAL field value per context byte', context_ascii=value.decode('ascii'))

    def run(self, receipt):
        # The geometry helper enforces byte length, variant, raw po2, canonical
        # values and the derived exact vector length. Our reader then consumes it
        # sequentially and independently checks every recorded boundary.
        geometry = self.geometry.audit_sources(self.sources, receipt)
        layout = geometry['saved_v2_geometry']
        params = geometry['parameters']
        require((params['queries'], params['fold'], params['extension_degree']) == (50, 16, 4),
                'unsupported replay profile')
        start = layout['seal_file_offset_bytes']
        seal = receipt[start:start + layout['seal_bytes']]
        words = tuple(word for word, in struct.iter_unpack('<I', seal))
        reader = SealReader(words)
        specs = {tree['oracle']: tree for tree in layout['query_template']}
        ranges = {row['id']: row for row in layout['prequery_ranges']}
        trees, commitments = {}, []
        rng = TranscriptRng(self.hasher)

        def read_prefix(name):
            row = ranges[name]
            expected_range = [row['seal_word_start_inclusive'], row['seal_word_end_exclusive']]
            values, actual_range = reader.read(row['base_word_count'], name)
            require(actual_range == expected_range, name + ': independent cursor/geometry disagreement')
            require(sha(words_bytes(values)) == row['raw_bytes_sha256'], name + ': range hash disagreement')
            return values, actual_range

        def tree(name):
            cap, word_range = read_prefix(name + '_cap')
            item = MerkleTree(specs[name], cap, word_range, self)
            trees[name] = item
            rng.commit(name + '_root', item.root, source=MERKLE_SOURCE,
                       cap_word_range_half_open=word_range, rows=specs[name]['rows'])
            return item

        def coefficients(name, event):
            values, word_range = read_prefix(name)
            digest = self.hash_raw(values)
            rng.commit(event, digest, source=VERIFY_SOURCE if event == 'u_coefficients' else FRI_SOURCE,
                       seal_word_range_half_open=word_range,
                       encoding='raw Montgomery words, decoded as field elements before hashing')
            commitments.append({'id': event, 'word_range_half_open': word_range,
                                'base_words': len(values), 'digest_raw_le_hex': digest_hex(digest)})

        self._context(rng, 'proof_system_info', self.proof_context)
        self._context(rng, 'circuit_info', self.circuit_context)
        public, word_range = read_prefix('outputs_and_po2')
        require(public[32] == 18, 'fixed raw po2 word mismatch')
        rng.commit('public_outputs_and_po2', self.hash_raw(public), source=VERIFY_SOURCE,
                   seal_word_range_half_open=word_range,
                   encoding='all 33 raw Montgomery words hashed; po2 interpreted separately as raw u32')
        code = tree('code')
        require(digest_hex(code.root) == JOIN, 'reconstructed code root differs from pinned join control ID')
        tree('data')
        rng.draw('accum_mix', 20, source=VERIFY_SOURCE, field='BabyBear')
        tree('accum')
        rng.draw('constraint_mix', 4, source=VERIFY_SOURCE, field='BabyBear^4')
        tree('check')
        rng.draw('deep_point_z', 4, source=VERIFY_SOURCE, field='BabyBear^4',
                 build_precondition='circuit_debug disabled')
        coefficients('u_coefficients', 'u_coefficients')
        rng.draw('fri_batch_mix', 4, source=VERIFY_SOURCE, field='BabyBear^4',
                 omitted_preceding_check='AIR validity equation not evaluated')
        fri_names = [row['oracle'] for row in layout['query_template'] if row['oracle'].startswith('fri')]
        for name in fri_names:
            tree(name)
            rng.draw(name + '_fold_mix', 4, source=FRI_SOURCE, field='BabyBear^4')
        coefficients('final_polynomial_coefficients', 'final_polynomial')
        require(reader.cursor == layout['prequery_words'], 'prequery cursor mismatch')
        prefix_rng_state = rng.state()
        query_records = []
        opened = {name: [] for name in specs}
        for number in range(params['queries']):
            query_start = reader.cursor
            initial, samples = rng.query(number, layout['po2'] + 2)
            before_openings = rng.state()
            openings = []
            for name in ('accum', 'code', 'data', 'check'):
                openings.append(trees[name].opening(reader, initial, number))
                opened[name].append(initial)
            position, folding = initial, []
            for name in fri_names:
                domain = specs[name]['rows']
                quotient, group = divmod(position, domain)
                require(0 <= quotient < params['fold'], 'FRI quotient outside radix-16 leaf')
                openings.append(trees[name].opening(reader, group, number))
                opened[name].append(group)
                folding.append({'oracle': name, 'input_position': position, 'domain_rows': domain,
                                'quotient': quotient, 'group': group,
                                'selected_component_word_offsets': [j * 16 + quotient for j in range(4)]})
                position = group
            require(reader.cursor - query_start == layout['per_query_words'], 'query consumption mismatch')
            require(rng.state() == before_openings, 'openings changed transcript state')
            query_records.append({'query_number': number, 'base_samples_normal': samples,
                                  'initial_index': initial, 'folding_positions': folding,
                                  'terminal_evaluation_index': position,
                                  'seal_word_range_half_open': [query_start, reader.cursor],
                                  'openings': openings})
        reader.complete()
        costs = geometry['rng']['derived_rng_cost']
        require((rng.squeezes, rng.permutations) == (costs['base_squeezes'], costs['rng_permutation_calls']),
                'independent RNG cost/geometry disagreement')
        # Do this last so canonical mutation controls exercise the cryptographic
        # path checks. Even a mutation invisible to these partial checks cannot
        # produce a successful fixed-fixture report or alter its opaque suffix.
        require(sha(receipt) == RECEIPT_SHA256, 'fixed receipt SHA-256 mismatch after replay')
        return {
            'schema': 'TRNM-W1-FRI-QUERY-REPLAY1',
            'result': 'FIXED_TRANSCRIPT_AND_MERKLE_OPENINGS_REPLAYED_SECURITY_HOLD',
            'profile_id': PROFILE, 'input_profile_source_head': INPUT_PROFILE_SOURCE_HEAD,
            'upstream_commit': UPSTREAM,
            'qualification': {
                'complete_receipt_verified': False, 'air_validity_checked': False,
                'deep_ali_evaluation_checked': False, 'fri_folding_equations_checked': False,
                'terminal_polynomial_evaluations_checked': False,
                'all_recursive_program_semantics_verified': False,
                'qrom_instantiated': False, 'post_quantum_soundness_qualified': False,
                'complete_w1_soundness_qualified': False, 'quantum_work_qualified': False,
                'production_qualified': False, 'consensus_admission': False,
                'security_bits_quantum': None,
            },
            'reproduced_checks': {
                'whole_saved_receipt_identity_pinned': True,
                'fiat_shamir_challenges_recomputed': True, 'merkle_openings_verified': 350,
                'code_root_matches_fixed_join': True, 'exact_seal_consumption': True,
                'canonical_montgomery_words': True, 'little_endian_word_encoding': True,
                'independent_upstream_golden_vectors_matched': 3,
                'opaque_outer_suffix_semantically_parsed': False,
            },
            'receipt': {'path': RECEIPT_PATH, 'bytes': len(receipt), 'sha256': sha(receipt),
                        'seal_words': len(words), 'seal_bytes': len(seal), 'seal_sha256': sha(seal),
                        'seal_file_offset_bytes': start, 'raw_po2': public[32],
                        'po2_word_normal_field_value_when_hashed': normal_words(public[32:33])[0],
                        'outputs_normal_words': list(normal_words(public[:32])),
                        'opaque_suffix_bytes': layout['opaque_outer_suffix_bytes'],
                        'opaque_suffix_sha256': layout['opaque_outer_suffix_sha256']},
            'source_snapshot': {'path': SNAPSHOT_PATH, 'bytes': SNAPSHOT_BYTES, 'sha256': SNAPSHOT_SHA256},
            'helper_execution': {'mode': 'compile_exact_pinned_local_audit_bytes',
                                 'records': self.helper_records, 'upstream_source_executed': False},
            'source_files': geometry['source_files'], 'upstream_golden_checks': self.golden_checks,
            'generator_sha256': sha(Path(__file__).read_bytes()),
            'parameters': params, 'ordered_transcript_events': rng.events,
            'rng_state_before_query_loop': prefix_rng_state,
            'rng_state_after_query_loop': rng.state(),
            'rng_cost': {**costs, 'query_base_samples': 200, 'protocol_base_samples': rng.squeezes - 200},
            'merkle_trees': [trees[name].report for name in specs],
            'coefficient_commitments': commitments,
            'queries': query_records,
            'index_multiplicities': {name: repeated_indices(values) for name, values in opened.items()},
            'query_interpretation': {
                'sampling_with_replacement': True, 'query_draw_count': 50,
                'all_four_samples_consumed_even_if_first_nonzero': True,
                'fold_rule': 'quotient=pos//round.domain; group=pos%round.domain; pos=group',
                'round_query_sets_are_correlated_projections': True,
                'distinct_indices_substituted_for_theorem_query_count': False,
                'qrom_distribution_or_extractor_proved_by_this_replay': False,
            },
            'scope': [
                'One exact historical po2=18 join seal, standard circuit_debug-disabled transcript.',
                'Follows the verifier path conditional on omitted algebraic checks succeeding.',
                'Neither accepted malformed receipts nor actual cryptographic attacks are established by fault injection.',
                'No statistics from this one receipt establish an ideal-oracle distribution or security estimate.',
                'All cap/leaf/path encodings remain externally typed; no domain separation or QROM extractor is added.',
            ],
        }


def ideal_four_draw_index_law(modulus, bits):
    """Finite counting, conditional on four iid uniform integer draws.

    No field or hash property is proved here. If m=2**bits divides modulus-1,
    each residue has the same number of nonzero representatives. Each selected
    nonzero x has probability sum(modulus**(-j), j=1..4). The all-zero tuple
    has mass modulus**(-4), giving (1-eps)U_m + eps*delta_0 after masking.
    """
    require(type(modulus) is int and modulus >= 3, 'ideal sampler alphabet size')
    require(type(bits) is int and 0 < bits <= 27, 'ideal sampler bit width')
    size = 1 << bits
    require((modulus - 1) % size == 0, 'ideal sampler nonzero residue counts unequal')
    epsilon = Fraction(1, modulus ** 4)
    uniform = Fraction(1, size)
    other = (1 - epsilon) * uniform
    zero = other + epsilon
    return {
        'modulus': modulus, 'bits': bits, 'index_count': size,
        'nonzero_values_per_residue': (modulus - 1) // size,
        'all_zero_draw_probability': epsilon,
        'uniform_mixture_weight': 1 - epsilon,
        'zero_point_mixture_weight': epsilon,
        'zero_index_probability': zero,
        'each_nonzero_index_probability': other,
        'maximum_index_probability': zero,
        'single_query_total_variation': epsilon * (1 - uniform),
    }


def ideal_sampler_product_tv_bounds(modulus, query_count):
    """Upper bounds conditional also on independence of four-draw blocks.

    Couple a mixture draw to uniform unless its delta_0 branch is selected.
    The chance that any branch is selected is 1-(1-modulus**(-4))**k, at most
    k*modulus**(-4). This does not assert exact product total variation.
    """
    require(type(modulus) is int and modulus >= 3, 'ideal sampler alphabet size')
    require(type(query_count) is int and query_count >= 0, 'ideal sampler query count')
    epsilon = Fraction(1, modulus ** 4)
    return {
        'independent_query_blocks': query_count,
        'coupling_total_variation_upper_bound': 1 - (1 - epsilon) ** query_count,
        'union_total_variation_upper_bound': query_count * epsilon,
    }


def exact_probability_json(value):
    """Serialize reduced rationals without floating point or security bits."""
    if isinstance(value, Fraction):
        return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}
    if isinstance(value, dict):
        return {key: exact_probability_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [exact_probability_json(item) for item in value]
    return value


def build_ideal_sampler_report(root=ROOT):
    """Check frozen sampler correspondence and an assumed law, not a seal."""
    sources = load_snapshot(root)
    modules, helpers = load_helpers(root)
    geometry = modules['w1_fri_transcript_audit']
    records = geometry._verify_sources(sources)
    params = geometry._parameters(sources)
    require((params['field_modulus'], params['inverse_rate'], params['queries']) == (P, 4, 50),
            'ideal sampler fixed-source parameters')
    fixed_po2 = geometry.FIXED_PO2
    require(fixed_po2 == 18 and params['explicit_generic_po2_max'] == 24,
            'ideal sampler fixed-source size declarations')
    laws = [ideal_four_draw_index_law(P, bits) for bits in (fixed_po2 + 2, 24 + 2)]
    return exact_probability_json({
        'schema': 'TRNM-W1-CONDITIONAL-IID-QUERY-SAMPLER1',
        'result': 'CONDITIONAL_IID_SAMPLER_ARITHMETIC_REPRODUCED_SECURITY_HOLD',
        'hypotheses': {
            'single_query': 'All four normal-form base-field draws are mutually independent and uniform in [0,p).',
            'multiple_queries': 'All four-draw blocks are also independent, conditional on the fixed prequery context.',
            'hypotheses_established_for_actual_poseidon2_transcript': False,
            'uniform_marginals_alone_suffice': False,
        },
        'profile_id': PROFILE, 'upstream_commit': UPSTREAM,
        'source_snapshot': {'path': SNAPSHOT_PATH, 'bytes': SNAPSHOT_BYTES, 'sha256': SNAPSHOT_SHA256},
        'source_files': records, 'helper_execution': helpers,
        'source_correspondence': {
            'sampler_source': RNG_SOURCE, 'query_source': FRI_SOURCE,
            'sampler': 'consume four normal-form values; select first nonzero or zero; mask low bits',
            'modulus_minus_one': P - 1, 'factorization': '15 * 2^27',
            'fixed_saved_profile_po2': fixed_po2,
            'declared_generic_max_po2': params['explicit_generic_po2_max'],
            'inverse_rate': 4, 'queries': 50,
            'all_declared_trace_sizes_reachable_or_accepted_proved': False,
            'receipt_bytes_read_or_verified': False,
        },
        'conditional_index_laws': laws,
        'conditional_independent_query_bounds': ideal_sampler_product_tv_bounds(P, 50),
        'proof': [
            'Each selected nonzero value has probability sum(p^(-j), j=1..4); the all-zero tuple has mass p^-4.',
            'Since 2^b divides p-1, every masked residue has the same number of nonzero representatives.',
            'Thus the index law is (1-p^-4)U_(2^b)+p^-4 delta_0; TV is p^-4(1-2^-b).',
            'For independent blocks couple to uniform unless any delta branch is selected; the product TV bound need not be exact.',
        ],
        'qualification': {
            'actual_transcript_iid_uniformity_proved': False,
            'adversarial_or_quantum_conditioning_proved': False,
            'qrom_instantiated': False, 'quantum_extractor_qualified': False,
            'complete_w1_soundness_qualified': False, 'production_qualified': False,
            'consensus_admission': False, 'security_bits_quantum': None,
            'actual_lifetime_failure_bound': None,
        },
        'scope': 'Conditional finite counting only; actual joint-oracle, FRI, Fiat-Shamir and quantum extraction arguments remain open.',
        'generator_sha256': sha(Path(__file__).read_bytes()),
    })


def build_report(root=ROOT):
    sources = load_snapshot(root)
    receipt = bounded_file(root, RECEIPT_PATH, RECEIPT_BYTES)
    return ReplayEngine(sources, root).run(receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--ideal-sampler-law', action='store_true',
                        help='Separate conditional iid arithmetic report, without receipt replay or actual randomness qualification')
    parser.add_argument('--output', type=Path,
                        help='Create a new report; never overwrite an existing evidence file')
    args = parser.parse_args()
    try:
        report = (build_ideal_sampler_report(args.repo_root) if args.ideal_sampler_law
                  else build_report(args.repo_root))
        encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
        if args.output is None:
            print(encoded, end='')
        else:
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(encoded)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print(f'FRI query replay refused: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
