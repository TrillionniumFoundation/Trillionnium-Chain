#!/usr/bin/env python3
"""Map selected locked W1 verifier sources and saved receipt metadata offline.

This is a source-integrity/parameter reader, not a cryptographic verifier or
security qualification. No network requests or compilation are performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tarfile
import tomllib


class SourceMapError(ValueError):
    """An input does not match this explicitly supported research profile."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceMapError(message)


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded_bytes(path: Path, limit: int) -> bytes:
    require(not path.is_symlink(), f'{path.name}: symlink input')
    with path.open('rb') as stream:
        value = stream.read(limit + 1)
    require(len(value) <= limit, f'{path.name}: input exceeds bound')
    return value


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate JSON key: {key}')
        result[key] = value
    return result


def read_json(path: Path) -> dict:
    value = json.loads(bounded_bytes(path, 2 * 1024 * 1024), object_pairs_hook=unique_object)
    require(isinstance(value, dict), f'{path.name}: expected JSON object')
    return value


def unique_match(pattern: str, text: str, name: str, flags: int = 0) -> re.Match:
    matches = list(re.finditer(pattern, text, flags))
    require(len(matches) == 1, f'{name}: expected exactly one supported declaration')
    return matches[0]


def int_const(text: str, name: str) -> int:
    match = unique_match(
        r'^\s*(?:pub )?const\s+' + re.escape(name)
        + r'\s*:\s*[^=]+?=\s*(\d+)\s*;', text, name, re.M,
    )
    return int(match.group(1))


def extract_stark_parameters(text: str) -> dict[str, int]:
    expected = {
        'QUERIES': 50, 'INV_RATE': 4, 'FRI_FOLD_PO2': 4,
        'FRI_MIN_DEGREE': 256, 'MIN_CYCLES_PO2': 13, 'MAX_CYCLES_PO2': 24,
    }
    actual = {name: int_const(text, name) for name in expected}
    require(actual == expected, 'unsupported STARK parameter value drift')
    unique_match(r'^pub const FRI_FOLD: usize = 1 << FRI_FOLD_PO2;$', text, 'FRI_FOLD', re.M)
    return actual


SELECTED = {
    'risc0-zkp-3.0.5': [
        'src/lib.rs', 'src/adapter.rs', 'src/core/digest.rs',
        'src/core/hash/mod.rs', 'src/core/hash/poseidon2/mod.rs',
        'src/core/hash/poseidon2/consts.rs', 'src/core/hash/poseidon2/rng.rs',
        'src/core/hash/sha/mod.rs', 'src/core/hash/sha/cpu.rs',
        'src/core/hash/sha/rng.rs', 'src/prove/soundness.rs',
        'src/verify/mod.rs', 'src/verify/fri.rs', 'src/verify/merkle.rs',
        'src/verify/read_iop.rs',
    ],
    'risc0-zkvm-3.0.6': [
        'src/receipt.rs', 'src/receipt/succinct.rs',
        'src/receipt/segment.rs', 'src/receipt/merkle.rs',
    ],
    'risc0-core-3.0.2': ['src/field/baby_bear.rs'],
    'risc0-circuit-recursion-4.0.5': [
        'src/control_id.rs', 'src/info.rs', 'src/poly_ext.rs', 'src/taps.rs',
    ],
    'risc0-circuit-rv32im-4.0.5': ['src/zirgen/info.rs'],
    'risc0-binfmt-3.0.5': ['src/hash.rs'],
    'sha2-0.10.9': ['src/lib.rs', 'src/sha256.rs', 'src/sha256/soft.rs', 'src/consts.rs'],
}

REGISTRY_SOURCE = 'registry+https://github.com/rust-lang/crates.io-index'


def load_locked_packages(path: Path) -> dict:
    parsed = tomllib.loads(bounded_bytes(path, 2 * 1024 * 1024).decode('utf-8'))
    require(isinstance(parsed.get('package'), list), 'lockfile package roster is missing')
    locked = {}
    for item in parsed['package']:
        require(isinstance(item, dict), 'invalid lockfile package record')
        key = f"{item.get('name')}-{item.get('version')}"
        if key not in SELECTED:
            continue
        require(key not in locked, f'duplicate selected lock package: {key}')
        require(item.get('source') == REGISTRY_SOURCE, f'{key}: unexpected registry source')
        checksum = item.get('checksum')
        require(isinstance(checksum, str) and re.fullmatch('[0-9a-f]{64}', checksum) is not None,
                f'{key}: invalid lock checksum')
        locked[key] = item
    require(set(locked) == set(SELECTED), 'missing selected lock package or unsupported version')
    return locked


def registry_paths(cargo_home: Path) -> tuple[Path, Path]:
    registry = cargo_home / 'registry'
    sources = sorted((registry / 'src').glob('index.crates.io-*'))
    caches = sorted((registry / 'cache').glob('index.crates.io-*'))
    require(len(sources) == len(caches) == 1 and sources[0].name == caches[0].name,
            'expected one matching downloaded crates.io source/cache registry')
    return sources[0], caches[0]


def inspect_package(src: Path, cache: Path, package: str, locked: dict) -> tuple[dict, dict]:
    """Compare fixed selected files with the exact archive identified by Cargo.lock."""
    require(package in SELECTED, 'package outside the selected mapping scope')
    archive = cache / f'{package}.crate'
    actual = sha_file(archive)
    expected = locked['checksum']
    require(actual == expected, f'{package}: archive differs from Cargo.lock')
    selected = SELECTED[package] + ['.cargo_vcs_info.json']
    records = []
    files = {}
    vcs = None
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        for relative in selected:
            name = f'{package}/{relative}'
            matches = [entry for entry in members if entry.name == name]
            require(len(matches) == 1 and matches[0].isfile(),
                    f'{name}: missing, duplicate or nonregular archive member')
            stream = tar.extractfile(matches[0])
            require(stream is not None, f'{name}: unreadable archive member')
            h = hashlib.sha256()
            for block in iter(lambda: stream.read(65536), b''):
                h.update(block)
            archive_sha = h.hexdigest()
            local = src / name
            require(not local.is_symlink(), f'{name}: symlink source')
            local_sha = sha_file(local)
            require(archive_sha == local_sha, f'{name}: local source differs from locked archive')
            entry = {
                'path': relative, 'bytes': local.stat().st_size, 'sha256': local_sha,
                'matches_locked_archive_member': True,
            }
            records.append(entry)
            files[name] = entry
            if relative == '.cargo_vcs_info.json':
                value = bounded_bytes(local, 65536)
                require(sha_bytes(value) == local_sha, f'{name}: source changed during inspection')
                vcs = json.loads(value, object_pairs_hook=unique_object)
                require(isinstance(vcs, dict), f'{name}: invalid provenance record')
    return {
        'name': locked['name'], 'version': locked['version'],
        'registry_source': locked['source'], 'locked_archive_sha256': expected,
        'observed_archive_sha256': actual, 'archive_matches_lock': True,
        'crate_vcs': vcs, 'selected_source_files': records,
    }, files


def build_profile(repo_root: Path, cargo_home: Path) -> dict:
    lock_path = repo_root / 'formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.lock'
    locked = load_locked_packages(lock_path)
    src, cache = registry_paths(cargo_home)
    packages = []
    files = {}
    for package in SELECTED:
        record, selected_files = inspect_package(src, cache, package, locked[package])
        packages.append(record)
        files.update(selected_files)

    def source(package: str, relative: str) -> str:
        name = f'{package}/{relative}'
        value = (src / name).read_bytes()
        require(sha_bytes(value) == files[name]['sha256'], f'{name}: source changed during inspection')
        return value.decode('utf-8')

    zkp = 'risc0-zkp-3.0.5'
    vm = 'risc0-zkvm-3.0.6'
    recursion = 'risc0-circuit-recursion-4.0.5'
    core = 'risc0-core-3.0.2'
    lib = source(zkp, 'src/lib.rs')


    stark = extract_stark_parameters(lib)
    queries, inv_rate, fold_po2, fri_min = (stark[k] for k in ('QUERIES', 'INV_RATE', 'FRI_FOLD_PO2', 'FRI_MIN_DEGREE'))

    consts = source(zkp, 'src/core/hash/poseidon2/consts.rs')
    poseidon = source(zkp, 'src/core/hash/poseidon2/mod.rs')
    require(
        (int_const(consts, 'CELLS'), int_const(poseidon, 'CELLS_RATE'),
         int_const(poseidon, 'CELLS_OUT'), int_const(consts, 'ROUNDS_HALF_FULL'),
         int_const(consts, 'ROUNDS_PARTIAL')) == (24, 16, 8, 4, 21),
        'unsupported Poseidon2 parameter value drift',
    )
    field_source = source(core, 'src/field/baby_bear.rs')
    modulus = unique_match(
        r'pub const P: u32 = (\d+) \* \(1 << (\d+)\) \+ (\d+);',
        field_source, 'BabyBear modulus',
    )
    require(int(modulus.group(1)) * (1 << int(modulus.group(2))) + int(modulus.group(3)) == 2013265921
            and int_const(field_source, 'EXT_SIZE') == 4, 'unsupported proof field value drift')


    def constant_array(name: str) -> dict:
        match = unique_match(r'const\s+' + re.escape(name) + r':\s*&\[Elem\]\s*=\s*&baby_bear_array!\[(.*?)\];', consts, name, re.S)
        # This source uses literal field constants only; comments are not values.
        payload = re.sub(r'//[^\n]*', '', match.group(1))
        values = [int(v, 16) if v.lower().startswith('0x') else int(v)
                  for v in re.findall(r'0x[0-9a-fA-F]+|\b\d+\b', payload)]
        require(bool(values) and all(0 <= v < 2013265921 for v in values), f'{name}: noncanonical field constant')
        data = b''.join(struct.pack('<I', v) for v in values)
        return {
            'elements': len(values), 'all_canonical_baby_bear': True,
            'normal_form_u32_le_sha256': sha_bytes(data),
            'source': f'{zkp}/src/core/hash/poseidon2/consts.rs',
            'source_file_sha256': files[f'{zkp}/src/core/hash/poseidon2/consts.rs']['sha256'],
        }


    controls = source(recursion, 'src/control_id.rs')
    root_match = unique_match(r'ALLOWED_CONTROL_ROOT: Digest\s*=\s*digest!\("([0-9a-f]{64})"\)', controls, 'ALLOWED_CONTROL_ROOT')
    control_root = root_match.group(1)
    allowed_text = controls.split('pub const ALLOWED_CONTROL_IDS:')[1].split('];', 1)[0]
    default_ids = [
        {'control_id': digest, 'program': program}
        for digest, program in re.findall(r'digest!\("([0-9a-f]{64})"\),\s*// recursion ([^\s]+)', allowed_text)
    ]
    require(len(default_ids) == 27, 'default control roster must have 27 entries')
    require(len({x['program'] for x in default_ids}) == 27 and len({x['control_id'] for x in default_ids}) == 27, 'duplicate default control program or ID')
    named_controls = {x['program']: x['control_id'] for x in default_ids}
    default_max = int_const(source(vm, 'src/receipt.rs'), 'DEFAULT_MAX_PO2')
    require(default_max == 22, 'unsupported DEFAULT_MAX_PO2')
    proof_info = unique_match(r'PROOF_SYSTEM_INFO: ProtocolInfo = ProtocolInfo\(\*b"([^"]+)"\)', source(zkp, 'src/adapter.rs'), 'PROOF_SYSTEM_INFO').group(1)
    circuit_info = unique_match(r'CIRCUIT_INFO: ProtocolInfo = ProtocolInfo\(\*b"([^"]+)"\)', source(recursion, 'src/info.rs'), 'recursion CIRCUIT_INFO').group(1)
    rv_info = unique_match(r'CIRCUIT_INFO: ProtocolInfo = ProtocolInfo\(\*b"([^"]+)"\)', source('risc0-circuit-rv32im-4.0.5', 'src/zirgen/info.rs'), 'RV32IM CIRCUIT_INFO').group(1)
    require((proof_info, circuit_info, rv_info) == ('RISC0_STARK:v1__', 'RECURSION:rev1v1', 'RV32IM:v2rev2___'), 'unsupported protocol or circuit info')
    param_tag = 'risc0.SuccinctReceiptVerifierParameters'
    parameter_digest = sha_bytes(
        hashlib.sha256(param_tag.encode()).digest()
        + bytes.fromhex(control_root) * 2
        + hashlib.sha256(proof_info.encode()).digest()
        + hashlib.sha256(circuit_info.encode()).digest()
        + struct.pack('<H', 4)
    )
    succinct = source(vm, 'src/receipt/succinct.rs')
    require(parameter_digest == 'ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013', 'unsupported recomputed verifier parameter digest')
    require(parameter_digest in succinct, 'recomputed parameter digest differs from SDK stability vector')

    packet = repo_root / 'evidence/pon-w1-complete-succinct-20261028'
    receipt_path = packet / 'full-proof/succinct.bin'
    receipt = bounded_bytes(receipt_path, 16 * 1024 * 1024)
    require(len(receipt) >= 12, 'receipt is too short')
    historical_path = packet / 'measurements/fresh-hardened-full-gate/stdout.log'
    historical = read_json(historical_path)
    require(sha_bytes(receipt) == historical['receipt_sha256'], 'saved receipt hash differs from historical verifier record')
    require(historical['hash_function'] == 'poseidon2', 'historical receipt uses an unsupported hash suite')
    tag, seal_words = struct.unpack_from('<IQ', receipt)
    require(tag == 1 and seal_words == historical['seal_words'], 'saved receipt tag or seal length mismatch')
    require(seal_words >= 16 and 12 + seal_words * 4 + 32 <= len(receipt), 'saved receipt seal bounds')
    control_offset = 12 + seal_words * 4
    wire_control = receipt[control_offset:control_offset + 32].hex()
    require(wire_control == historical['control_id'] == named_controls['join.zkr'], 'saved control ID is not the recorded join program')
    hash_encoding = struct.pack('<Q', len('poseidon2')) + b'poseidon2'
    hash_offsets = [m.start() for m in re.finditer(re.escape(hash_encoding), receipt)]
    require(len(hash_offsets) == 1 and hash_offsets[0] > control_offset + 32, 'ambiguous or missing saved hash-suite encoding')
    parameter_offset = hash_offsets[0] + len(hash_encoding)
    require(receipt[parameter_offset:parameter_offset + 32].hex() == parameter_digest == historical['verifier_parameters_digest'], 'saved verifier parameter bytes disagree with source and record')

    base_p = 2013265921
    mont_inverse = pow(1 << 32, -1, base_p)
    first_16_seal_words = struct.unpack_from('<16I', receipt, 12)
    require(all(w < base_p for w in first_16_seal_words), 'noncanonical saved seal output')
    decoded = [w * mont_inverse % base_p for w in first_16_seal_words]
    seal_root = struct.pack('<8I', *decoded[::2]).hex()
    require(seal_root == control_root, 'saved inner control root differs from default')

    manifest_path = packet / 'full-proof/manifest.json'
    manifest = read_json(manifest_path)
    require(len(manifest['segments']) == 59, 'unsupported frozen segment count')
    require(manifest['segment_limit_po2'] == 18, 'unsupported frozen segment po2')

    unknowns = [
        {
            'id': 'whole_qrom_reduction', 'state': 'UNRESOLVED',
            'reason': 'No complete instantiated reduction maps the exact AIR/IOR, Merkle construction, transcript RNG, recursive composition and concrete hashes to a quantum acceptance bound.',
        },
        {
            'id': 'theorem_fulltext_and_constants', 'state': 'UNRESOLVED',
            'reason': 'No full-text theorem mapping or concrete loss calculation is part of this source map. Its literature annotations describe a manual abstract review, not a new network fetch or instantiated security theorem.',
        },
        {
            'id': 'hash_instantiation', 'state': 'UNRESOLVED',
            'reason': 'An ideal QROM theorem is not a proof for the implemented Poseidon2 sponge/RNG. W1 SHA-256, padded claim hashes, unpadded field-leaf hashes and one-block Merkle compression have distinct interfaces. Fixed message lengths/tree shape may justify uses, but every use must be mapped before applying an extraction theorem.',
        },
        {
            'id': 'ior_state_restoration', 'state': 'UNRESOLVED',
            'reason': 'Classical round-by-round or quantum state-restoration security has not been instantiated for each accepted recursion program, RV32IM circuit and SHA extension under these exact parameters.',
        },
        {
            'id': 'conjectures_and_composition', 'state': 'UNRESOLVED',
            'reason': 'The locked component calculator distinguishes conjectured and proven regimes; its 97-bit target comment is not a 59-segment, complete-recursion or quantum bound. Per-layer, adaptive/multi-proof, quantum-query and total composition terms remain unqualified.',
        },
        {
            'id': 'accepted_control_set', 'state': 'UNRESOLVED',
            'reason': 'The historical receipt binds a default root allowing 27 recursion programs up to po2=22, although this frozen execution used segment po2=18. Security must cover the actual accepted set; narrowing the root silently invalidates the original receipt and requires a new profile/proof.',
        },
        {
            'id': 'prover_guest_graph', 'state': 'PARTIAL',
            'reason': 'This audit validates selected exact local verifier crate bytes against locked .crate archives. The frozen 3.0.3 prover/r0vm and guest toolchain/SHA extension require their separate immutable-source and artifact mapping; this is not a full dependency graph or compiler proof.',
        },
    ]

    doc = {
        'schema': 'TRNM-W1-PROFILE-SECURITY-NOTES1',
        'profile_revision': '20261104',
        'generator': {'repo_path': 'scripts/w1_profile_source_map.py', 'sha256': sha_file(Path(__file__))},
        'scope': 'Read-only extraction of exact cached verifier crate source, historical full receipt metadata and explicit security gaps. No fresh proving, cryptographic verification, consensus admission or quantum-bit qualification is claimed by this script.',
        'decision': {
            'consensus_admission': False, 'post_quantum_soundness_qualified': False,
            'security_bits_quantum': None, 'production_qualified': False,
            'full_dependency_semantic_audit_complete': False,
            'selected_source_archive_integrity_checks_passed': True,
        },
        'lockfile': {
            'repo_path': str(lock_path.relative_to(repo_root)), 'sha256': sha_file(lock_path),
            'package_scope': 'Seven exact packages; the selected files are byte-equal to locked archive members. This does not claim an audit of all transitive source files or enabled build features.',
        },
        'packages': packages,
        'stark_parameters': {
            'source': f'{zkp}/src/lib.rs', 'queries': queries,
            'inverse_rate': inv_rate, 'rate_numerator': 1, 'rate_denominator': inv_rate,
            'fri_fold_po2': fold_po2, 'fri_fold': 1 << fold_po2,
            'fri_min_degree': fri_min,
            'supported_cycle_po2_min': int_const(lib, 'MIN_CYCLES_PO2'),
            'supported_cycle_po2_max': int_const(lib, 'MAX_CYCLES_PO2'),
            'component_security_comment': {
                'model': 'conjectured Toy Problem model, not a complete quantum theorem',
                'target_bits_at_segment_po2_20': 97,
                'comment_bits_at_segment_po2_24': 95,
                'source': f'{zkp}/src/prove/soundness.rs',
                'measured_or_proved_full_w1_security_bits': None,
            },
        },
        'fields': {
            'w1_modulus': 4294967291,
            'stark_base_modulus': base_p,
            'extension_degree': 4, 'extension_polynomial': 'X^4 + 11',
            'representation': 'u32 reduced Montgomery field words; canonical-value conversion is distinct from raw digest words',
            'source': f'{core}/src/field/baby_bear.rs',
            'relation_preservation': 'The frozen zkVM proves the original integer instruction semantics using W1 modulus 4294967291. Direct AIR translation would require explicit range/carry/modular-reduction constraints; substituting the proof field would change the relation.',
        },
        'hash_interfaces': {
            'poseidon2': {
                'source': f'{zkp}/src/core/hash/poseidon2/mod.rs',
                'state_elements': int_const(consts, 'CELLS'),
                'rate_elements': int_const(poseidon, 'CELLS_RATE'),
                'capacity_elements': int_const(consts, 'CELLS') - int_const(poseidon, 'CELLS_RATE'),
                'output_elements': int_const(poseidon, 'CELLS_OUT'),
                'full_rounds_first': int_const(consts, 'ROUNDS_HALF_FULL'),
                'full_rounds_last': int_const(consts, 'ROUNDS_HALF_FULL'),
                'partial_rounds': int_const(consts, 'ROUNDS_PARTIAL'),
                'sbox_exponent': 7,
                'round_constants': constant_array('ROUND_CONSTANTS'),
                'internal_matrix_diagonal': constant_array('M_INT_DIAG_HZN'),
                'reference_external_matrix': constant_array('_M_EXT'),
                'merkle_pair': 'Two 8-word reduced Montgomery digests are passed as 16 BabyBear elements to unpadded_hash.',
                'leaf': 'Field elements, or flattened extension subelements, use unpadded_hash. The source explicitly limits its collision-resistance statement to equal-size vectors; variable input size requires separate binding.',
                'encoding': 'The first eight output elements become raw Montgomery u32 digest words.',
                'fiat_shamir_source': f'{zkp}/src/core/hash/poseidon2/rng.rs',
                'fiat_shamir_notes': 'Initial all-zero 24-element state; mix adds eight digest elements and permutes. random_bits draws four field elements, replaces a zero candidate, then masks low bits. This concrete transcript/sampling algorithm needs theorem mapping; it is not defined by an abstract hash name.',
            },
            'sha256': {
                'source': f'{zkp}/src/core/hash/sha/mod.rs',
                'native_cpu_implementation': f'{zkp}/src/core/hash/sha/cpu.rs',
                'rustcrypto_package': 'sha2-0.10.9',
                'standard_bytes_hash': 'Sha256::hash_bytes uses padded FIPS 180-4 SHA-256.',
                'merkle_pair': 'Sha256::hash_pair is a single compression block with the standard IV, not padded SHA-256(A || B).',
                'field_leaf': 'hash_raw_data_slice zero-pads the final partial block but does not add the standard SHA-256 trailer.',
                'claim_and_parameter_tags': 'risc0-binfmt tagged_struct hashes a padded SHA-256 tag digest, child digests, little-endian data words and u16 child count, then padded SHA-256.',
                'fiat_shamir_source': f'{zkp}/src/core/hash/sha/rng.rs',
                'fiat_shamir_notes': 'Two pools are initialized with padded SHA-256 of Hello and World; mixing XORs into pool0 and performs ordered hash_pair updates. This alternative proof hash suite is in the SDK default map; the historical full receipt actually selects poseidon2.',
            },
        },
        'recursive_verifier_defaults': {
            'source': f'{vm}/src/receipt/succinct.rs',
            'control_source': f'{recursion}/src/control_id.rs',
            'control_root': control_root,
            'inner_control_root_option': None,
            'effective_inner_control_root': control_root,
            'default_max_cycle_po2': default_max,
            'minimum_lift_cycle_po2': int_const(controls, 'MIN_LIFT_PO2'),
            'default_control_ids': default_ids,
            'control_merkle_depth': int_const(source(vm, 'src/receipt/merkle.rs'), 'ALLOWED_CODE_MERKLE_DEPTH'),
            'control_tree_layout': 'The sorted-name control list occupies initial leaves of a depth-eight binary Merkle tree, with zero digests for remaining leaves; tree pair hashing uses Poseidon2.',
            'proof_system_info_ascii': proof_info,
            'recursion_circuit_info_ascii': circuit_info,
            'rv32im_circuit_info_ascii': rv_info,
            'parameter_digest_tag': param_tag,
            'parameter_digest_independently_recomputed_from_source': parameter_digest,
            'parameter_digest_matches_sdk_stability_vector': True,
            'default_hash_suite_names': ['blake2b', 'poseidon2', 'sha-256'],
            'must_not_silently_change_control_root_to_execution_segment_po2': True,
        },
        'saved_full_receipt': {
            'repo_path': str(receipt_path.relative_to(repo_root)),
            'sha256': sha_bytes(receipt), 'bytes': len(receipt),
            'wire_tag': tag, 'receipt_kind': 'Succinct',
            'seal_words': seal_words,
            'control_id': wire_control, 'control_program': 'join.zkr',
            'hash_function': historical['hash_function'],
            'verifier_parameters_digest': parameter_digest,
            'inner_control_root_from_seal_output': seal_root,
            'metadata_observation_kind': 'Partial direct wire parsing plus hash-bound historical verifier log; not fresh cryptographic verification by this script.',
            'partial_wire_checks': {
                'control_id_offset': control_offset,
                'hash_name_length_and_bytes_offset': hash_offsets[0],
                'parameter_digest_offset': parameter_offset,
                'log_receipt_hash_matches_actual_bytes': True,
                'wire_control_id_matches_join_zkr_and_historical_log': True,
                'wire_parameter_digest_matches_recomputed_default_and_historical_log': True,
                'decoded_inner_control_root_matches_default': True,
            },
            'historical_log': {'repo_path': str(historical_path.relative_to(repo_root)), 'sha256': sha_file(historical_path)},
            'frozen_manifest': {
                'repo_path': str(manifest_path.relative_to(repo_root)), 'sha256': sha_file(manifest_path),
                'prover_guest_source': manifest['source_commit'], 'guest_sha256': manifest['guest_sha256'],
                'r0vm_sha256': manifest['r0vm_sha256'], 'full_claim_digest': manifest['full_claim_digest'],
                'segments': len(manifest['segments']), 'segment_limit_po2': manifest['segment_limit_po2'],
            },
            'same_work_rule': 'Unchanged header+trace work ID; proof randomness, encoding, recursion and batching grant zero extra tickets.',
        },
        'research_mapping': {
            'qrom_framework': {
                'url': 'https://eprint.iacr.org/2025/2166',
                'title': 'How to Prove Post-Quantum Security for Succinct Non-Interactive Reductions',
                'metadata_revision': '2026-03-02', 'venue': 'EUROCRYPT 2026',
                'manual_review_as_of': '2026-11-04',
                'review_basis': 'Manually reviewed publication metadata and abstract at the cited URL; this offline tool does not retrieve or reverify the publication.',
                'full_text_review_available': False,
                'known_conditions_from_abstract': [
                    'Extended BCS transformation for an IOR',
                    'Post-quantum state-restoration security of the IOR; classical round-by-round security is sufficient in the framework',
                    'Quantum extraction property of vector commitments; Merkle commitments are analyzed',
                    'Adaptive straightline quantum extraction in the QROM',
                ],
                'exact_theorem_ids': None, 'concrete_reduction_constants': None,
                'full_parameter_instantiation_complete': False,
            },
            'rs_counterexample': {
                'url': 'https://eprint.iacr.org/2025/2046',
                'title': 'On Reed-Solomon Proximity Gaps Conjectures',
                'scope': 'Refutes the stated up-to-capacity correlated-agreement / WHIR mutual-correlated-agreement / DEEP-FRI list-decodability conjectures; does not alone refute all FRI or proven decoding regimes.',
            },
            'prime_field_near_capacity': {
                'url': 'https://arxiv.org/abs/2604.09724',
                'scope': 'A specific family fails at radii O(1/log n) below capacity. No direct break of this concrete RISC0 profile has been established here.',
            },
            'whir_comparison_only': {
                'url': 'https://github.com/worldfnd/whir/blob/main/README.md',
                'readme_git_blob': 'ef91b05da5b048b51399f1c2045813d974e85b26',
                'upstream_state': 'Academic prototype, explicitly not ready for production',
                'default_security_level': 100, 'default_soundness_type': 'ConjectureList',
                'default_field': 'Goldilocks2', 'default_merkle_hash': 'Blake3',
                'actual_dependency_of_saved_w1_candidate': False,
            },
        },
        'unresolved_obligations': unknowns,
    }
    return doc


def write_new_json(path: Path, value: dict) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation also refuses a concurrent writer after the CLI precheck.
    with path.open('x', encoding='utf-8') as stream:
        stream.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo-home', type=Path, required=True,
                        help='Existing local Cargo home containing downloaded locked sources and .crate archives')
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--out', type=Path, required=True, help='New output JSON path; an existing path is refused')
    args = parser.parse_args(argv)
    try:
        require(not args.out.exists() and not args.out.is_symlink(), 'output already exists; refusing overwrite')
        profile = build_profile(args.repo_root, args.cargo_home)
        write_new_json(args.out, profile)
        print(json.dumps({
            'status': 'SOURCE_MAPPING_COMPLETE', 'output': str(args.out),
            'sha256': sha_file(args.out), 'verified_packages': len(profile['packages']),
            'verified_selected_source_files': sum(len(p['selected_source_files']) for p in profile['packages']),
            'post_quantum_soundness_qualified': False, 'consensus_admission': False,
        }, sort_keys=True))
        return 0
    except (SourceMapError, OSError, UnicodeError, json.JSONDecodeError,
            tomllib.TOMLDecodeError, tarfile.TarError, KeyError, TypeError, struct.error) as error:
        print(json.dumps({'status': 'REFUSED', 'error': str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
