#!/usr/bin/env python3
"""Offline, fixed-source W1 v2 implementation mapping; never a proof verifier.

The input contract fixes both the selected source and the historical artifacts.
This audit reconstructs their bindings and the allowed control tree. It does not
establish AIR/RBR soundness, hash idealization, a fresh STARK verification, the
guest ELF image algorithm, a deployed query budget, or consensus authority.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import tomllib
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'config/pon/w1-qrom-implementation-v1.json'
CONTRACT_SHA256 = '7761787fca9ea92c7b678186ccb302900bfabc974460b7f6793c7a0aabb6cf22'
UPSTREAM = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
PROFILE = 'trnm-w1-risc0-3.0.6-poseidon2-join-v2'
CONTROL_ROOT = 'a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56'
PARAMETERS = 'ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013'
JOIN = '7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e'
IMAGE = (1958252411, 3287394615, 1805488136, 1516578702,
         78549041, 790278610, 301018785, 4279049364)
P = 2013265921
Q = 4294967291
DOMAIN = b'TRNM-W1-ZK-JOURNAL2\0'
JOURNAL_BYTES = 16882
HEADER_BYTES = 318
FIXTURE = 'evidence/pon-w1-full-v2-20261105/'
QUALIFICATION = {
    'post_quantum_soundness_qualified': False,
    'complete_w1_soundness_qualified': False,
    'quantum_work_qualified': False,
    'pq_signature_qualification_inferred': False,
    'production_qualified': False,
    'consensus_admission': False,
    'security_bits_quantum': None,
}


class AuditError(ValueError):
    """A fixed research input or binding was not reproduced."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AuditError(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f'duplicate JSON key: {key}')
            result[key] = value
        return result

    def invalid(value):
        raise AuditError(f'nonfinite JSON value: {value}')

    def finite(value):
        number = float(value)
        require(math.isfinite(number), 'nonfinite JSON number')
        return number

    value = json.loads(data, object_pairs_hook=unique, parse_constant=invalid, parse_float=finite)
    require(type(value) is dict, 'JSON object required')
    return value


def bounded_file(root: Path, relative: str, limit: int) -> bytes:
    rel = PurePosixPath(relative)
    require(not rel.is_absolute() and '..' not in rel.parts and str(rel) == relative,
            'noncanonical relative input path')
    path = root
    for part in rel.parts:
        path = path / part
        require(not path.is_symlink(), f'symlink input: {relative}')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, f'input exceeds bound: {relative}')
    return data


def load_contract(root: Path) -> tuple[dict, bytes]:
    data = bounded_file(root, CONTRACT, 65536)
    require(sha(data) == CONTRACT_SHA256, 'unsupported implementation contract')
    contract = strict_json(data)
    require(contract['schema'] == 'TRNM-W1-QROM-IMPLEMENTATION-CONTRACT1', 'contract schema')
    require(contract['profile_id'] == PROFILE, 'contract profile')
    require(contract['qualification'] == QUALIFICATION, 'qualification escalation')
    require(contract['lifetime_budget']['policy_adopted'] is False, 'unadopted lifetime policy')
    require(all(value is None for key, value in contract['lifetime_budget'].items()
                if key != 'policy_adopted'), 'unreviewed lifetime value')
    return contract, data


def load_pinned_files(root: Path, records: list[dict]) -> dict[str, bytes]:
    result = {}
    for item in records:
        path = item['path']
        require(path not in result, 'duplicate pinned path')
        require(type(item['bytes']) is int and 0 < item['bytes'] <= 2 * 1024 * 1024,
                f'invalid pinned size: {path}')
        data = bounded_file(root, path, item['bytes'])
        require(len(data) == item['bytes'] and sha(data) == item['sha256'],
                f'pinned input drift: {path}')
        result[path] = data
    return result


def checked_helper(root: Path, path: str, data: bytes) -> ModuleType:
    """Execute the already-pinned local audit code, never upstream source text.

    Ordinary imports can execute a different search-path copy or cached module.
    Compile the same immutable bytes whose hash the contract checked instead.
    Helpers are trusted repository audit code and use only the standard library;
    this is provenance binding, not a sandbox for hostile Python code.
    """
    allowed = {'scripts/w1_control_tree_audit.py', 'scripts/w1_profile_source_map.py',
               'scripts/w1_fri_transcript_audit.py'}
    require(path in allowed, 'unsupported audit helper')
    name = '_w1_qrom_snapshot_' + Path(path).stem
    module = ModuleType(name)
    module.__file__ = str(root / path)
    exec(compile(data, module.__file__, 'exec'), module.__dict__)
    return module


def load_snapshot(data: bytes, expected_commit: str) -> tuple[dict[str, str], list[dict]]:
    # Bounded decompression and parse use the exact bytes checked against the contract.
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        decoded = stream.read(2 * 1024 * 1024 + 1)
    require(len(decoded) <= 2 * 1024 * 1024, 'source snapshot expands beyond bound')
    snapshot = strict_json(decoded)
    require(snapshot['schema'] == 'TRNM-W1-UPSTREAM-SOURCE-SNAPSHOT1', 'source snapshot schema')
    require(snapshot['repository'] == 'risc0/risc0'
            and snapshot['commit'] == expected_commit == UPSTREAM, 'upstream identity mismatch')
    sources, records = {}, []
    for row in snapshot['files']:
        path, content = row['path'], row['content']
        require(path not in sources and type(content) is str, 'duplicate or invalid source')
        value = content.encode('utf-8')
        require(len(value) == row['bytes'] and sha(value) == row['sha256'], 'source snapshot digest')
        blob = hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest()
        require(blob == row['git_blob_sha1'], 'source snapshot Git blob identity')
        require(row['source_url'] == f'https://github.com/risc0/risc0/blob/{UPSTREAM}/{path}',
                'source URL identity mismatch')
        sources[path] = content
        records.append({key: row[key] for key in ('path', 'bytes', 'sha256', 'git_blob_sha1',
                                                 'matches_historical_selected_archive_source')})
    require(len(sources) == 24 and 'LICENSE' in sources, 'source snapshot scope drift')
    return sources, records


def pon_hash(tag: bytes, *parts: bytes) -> bytes:
    payload = b'TRNM-PON1\0' + struct.pack('<H', len(tag)) + tag
    payload += b''.join(struct.pack('<I', len(part)) + part for part in parts)
    return hashlib.sha256(payload).digest()


def parameter_digest(root: str, proof_info: str, circuit_info: str) -> str:
    payload = hashlib.sha256(b'risc0.SuccinctReceiptVerifierParameters').digest()
    payload += bytes.fromhex(root) * 2
    payload += hashlib.sha256(proof_info.encode()).digest()
    payload += hashlib.sha256(circuit_info.encode()).digest()
    return sha(payload + struct.pack('<H', 4))


def inspect_v2(assets: dict[str, bytes], expected_branch: list[str]) -> dict:
    """Inspect the fixed artifact's metadata; no general receipt/claim decoder."""
    receipt, header, artifacts, witness = (assets[FIXTURE + name] for name in
                                         ('succinct.bin', 'header.bin', 'expected-artifacts.bin', 'input.bin'))
    require(len(header) == HEADER_BYTES and header[:4] == b'PNH1', 'header framing')
    require(len(artifacts) == 64 and len(witness) == 49506, 'public input lengths')
    require(witness[:HEADER_BYTES] == header, 'witness/header mismatch')
    work = witness[HEADER_BYTES:]
    require(work[:4] == b'PNW1' and len(work) == 49188, 'witness work framing')
    matrices = [work[4 + i * 16384:4 + (i + 1) * 16384] for i in range(3)]
    require(all(value < Q for matrix in matrices for (value,) in struct.iter_unpack('<I', matrix)),
            'noncanonical work matrix')
    expected = pon_hash(b'artifact', matrices[0]) + pon_hash(b'qualified-task-input-v1', matrices[1])
    require(expected == artifacts, 'external A/B not the original raw matrix commitments')
    require(header[278:310] == pon_hash(b'task', matrices[0], matrices[1]), 'header work task')
    require(12 <= len(receipt) <= 16 * 1024 * 1024, 'receipt byte bound')
    tag, words = struct.unpack_from('<IQ', receipt)
    require(tag == 1 and 33 <= words <= (len(receipt) - 12) // 4, 'succinct seal framing')
    seal_end = 12 + 4 * words
    require(receipt[seal_end:seal_end + 32].hex() == JOIN, 'final join control')
    marker = struct.pack('<Q', 9) + b'poseidon2'
    positions = [m.start() for m in re.finditer(re.escape(marker), receipt)]
    require(len(positions) == 1 and positions[0] > seal_end + 32, 'fixed hash-suite metadata')
    param_at = positions[0] + len(marker)
    require(receipt[param_at:param_at + 32].hex() == PARAMETERS, 'inner parameter digest')
    require(receipt[-32:].hex() == PARAMETERS, 'outer metadata parameter digest')
    branch_at = param_at + 32
    require(branch_at + 12 <= len(receipt), 'control branch bounds')
    index, count = struct.unpack_from('<IQ', receipt, branch_at)
    require(index == 1 and count == 8, 'canonical join control branch')
    branch_end = branch_at + 12 + 32 * count
    require(branch_end <= len(receipt), 'control branch byte bounds')
    siblings = [receipt[branch_at + 12 + 32 * i:branch_at + 44 + 32 * i].hex() for i in range(count)]
    require(siblings == expected_branch, 'control branch differs from independently reconstructed tree')
    journal_start = branch_end + 8
    require(journal_start + JOURNAL_BYTES + 32 == len(receipt), 'fixed outer journal framing')
    require(receipt[branch_end:journal_start] == struct.pack('<Q', JOURNAL_BYTES), 'journal Vec length')
    journal = receipt[journal_start:journal_start + JOURNAL_BYTES]
    require(journal[:20] == DOMAIN and journal[20:338] == header, 'v2 journal/header binding')
    require(journal[434:498] == artifacts, 'v2 independent A/B binding')
    require(journal[498:] == matrices[2], 'public product/witness mismatch')
    trace = work[-32:]
    ticket = pon_hash(b'ticket', pon_hash(b'challenge', header), trace)
    work_id = pon_hash(b'block', header, trace)
    require(journal[338:370] == trace and journal[370:402] == ticket
            and journal[402:434] == work_id, 'trace/ticket/work identity binding')
    require(ticket <= header[118:150], 'ticket exceeds header target')
    seal_output = struct.unpack_from('<32I', receipt, 12)
    require(all(word < P for word in seal_output), 'noncanonical recursion output word')
    decoded = [word * pow(1 << 32, -1, P) % P for word in seal_output]
    inner_root = struct.pack('<8I', *decoded[:16:2]).hex()
    require(inner_root == CONTROL_ROOT, 'inner root from seal differs')
    require(all(word < (1 << 16) for word in decoded[16:]), 'claim half-word encoding')
    # read_sha_halfs combines low and high halves of each raw digest word.
    claim = struct.pack('<8I', *(decoded[i] | (decoded[i + 1] << 16)
                                for i in range(16, 32, 2))).hex()
    # The po2 slot uses to_u32_words(), unlike the as_u32() output slots above.
    outer_po2 = struct.unpack_from('<I', receipt, 12 + 32 * 4)[0]
    require(outer_po2 == 18, 'frozen outer recursion trace po2')
    history = strict_json(assets[FIXTURE + 'proof-result.json'])
    identity, manifest = history['identity'], history['manifest']
    require(identity['receipt_sha256'] == sha(receipt) and identity['receipt_bytes'] == len(receipt),
            'historical receipt identity mismatch')
    require(identity['image_id'] == manifest['image_id'] == list(IMAGE), 'historical v2 image mismatch')
    require(identity['journal_sha256'] == manifest['journal_sha256'] == sha(journal), 'historical journal mismatch')
    require(identity['input_sha256'] == manifest['input_sha256'] == sha(witness)
            and identity['header_sha256'] == sha(header)
            and identity['external_artifacts_sha256'] == sha(artifacts), 'historical public input identities')
    require(identity['work_id'] == work_id.hex() and manifest['full_claim_digest'] == claim, 'historical claim/work binding')
    require(manifest['guest_sha256'] == sha(assets[FIXTURE + 'guest.bin']), 'historical guest bytes')
    require(len(manifest['segments']) == 43 and manifest['segment_limit_po2'] == 18, 'v2 historical segment scope')
    return {
        'receipt_kind': 'Succinct', 'hash_suite': 'poseidon2', 'bytes': len(receipt),
        'receipt_sha256': sha(receipt), 'seal_words': words, 'final_control_id': JOIN,
        'control_inclusion_index': index, 'control_inclusion_depth': count,
        'control_inclusion_matches_reconstructed_tree': True,
        'parameter_digest': PARAMETERS, 'both_parameter_fields_match': True,
        'inner_control_root_from_seal': inner_root, 'outer_recursion_seal_po2_raw': outer_po2,
        'historical_rv32im_segments': 43, 'historical_segment_limit_po2': 18,
        'guest_image_words': list(IMAGE), 'guest_image_u32_le_hex': struct.pack('<8I', *IMAGE).hex(),
        'guest_elf_sha256': manifest['guest_sha256'], 'guest_elf_to_image_recomputed': False,
        'journal_bytes': JOURNAL_BYTES, 'journal_sha256': sha(journal),
        'public_artifact_commitments_recomputed': True, 'work_id': work_id.hex(),
        'full_claim_digest_from_output': claim,
        'fresh_cryptographic_verification': False, 'complete_native_work_replayed': False,
        'scope': 'Fixed-byte partial metadata and public-identity reconstruction. Historical verification remains a separate record.',
    }


def fri_schedule(po2: int) -> dict:
    require(type(po2) is int and 0 <= po2 <= 24, 'unsupported schedule po2')
    degree, domain = 1 << po2, 4 << po2
    rounds = []
    while degree > 256:
        degree //= 16
        domain //= 16
        rounds.append({'committed_domain_rows': domain, 'leaf_base_elements': 64})
    return {'po2': po2, 'initial_rows': 4 << po2, 'folding_rounds': rounds,
            'final_coefficients_extension': degree, 'final_coefficients_base': 4 * degree,
            'queries': 50, 'query_position_bits': po2 + 2}


def build_report(root: Path) -> dict:
    contract, contract_bytes = load_contract(root)
    helpers = load_pinned_files(root, contract['audit_helpers'])
    project = load_pinned_files(root, contract['project_files'])
    assets = load_pinned_files(root, contract['saved_v2_files'])
    snapshot_record = contract['upstream_snapshot']
    snapshot = load_pinned_files(root, [snapshot_record])[snapshot_record['path']]
    sources, upstream_records = load_snapshot(snapshot, contract['upstream_commit'])
    control_path = 'scripts/w1_control_tree_audit.py'
    control = checked_helper(root, control_path, helpers[control_path])
    control_tree = control.audit_sources(sources)
    # audit_sources recomputes the root and each inclusion branch independently.
    require(control_tree['root'] == CONTROL_ROOT and control_tree['matches_fixed_root'] is True,
            'independently reconstructed control root')
    join_branch = control_tree['final_join']['merkle_path']
    v2 = inspect_v2(assets, join_branch)
    image_text = project['formal/pon-nakamoto-v1/w1_v2_verifier/src/image.rs'].decode()
    matches = re.findall(r'IMAGE_ID: \[u32; 8\] = \[([^]]+)\]', image_text)
    require(len(matches) == 1 and tuple(int(x.strip()) for x in matches[0].split(',') if x.strip()) == IMAGE,
            'compiled v2 image pin')
    profile_text = project['formal/pon-nakamoto-v1/w1_hardened_verifier/src/profile.rs'].decode()
    require(f'PARAMETERS: &str = "{PARAMETERS}"' in profile_text
            and f'CONTROL_ID: &str = "{JOIN}"' in profile_text, 'compiled receipt profile')
    profile_path = 'scripts/w1_profile_source_map.py'
    profile = checked_helper(root, profile_path, helpers[profile_path])
    stark = profile.extract_stark_parameters(sources['risc0/zkp/src/lib.rs'])
    transcript_path = 'scripts/w1_fri_transcript_audit.py'
    transcript = checked_helper(root, transcript_path, helpers[transcript_path])
    transcript_report = transcript.audit_sources(sources, assets[FIXTURE + 'succinct.bin'])
    def protocol(path, name):
        values = re.findall(name + r': ProtocolInfo = ProtocolInfo\(\*b"([^\"]+)"\)', sources[path])
        require(len(values) == 1, f'unique protocol declaration: {name}')
        return values[0]
    proof_info = protocol('risc0/zkp/src/adapter.rs', 'PROOF_SYSTEM_INFO')
    circuit_info = protocol('risc0/circuit/recursion/src/info.rs', 'CIRCUIT_INFO')
    require(parameter_digest(CONTROL_ROOT, proof_info, circuit_info) == PARAMETERS, 'parameter recomputation')
    locks = {}
    for path, data in project.items():
        if path.endswith('Cargo.lock'):
            selected = [{'name': p['name'], 'version': p['version'], 'source': p.get('source'),
                         'checksum': p.get('checksum')} for p in tomllib.loads(data.decode())['package']
                        if p['name'].startswith('risc0-') or p['name'] == 'sha2']
            locks[path] = {'sha256': sha(data), 'selected_packages': selected}
    return {
        'schema': 'TRNM-W1-QROM-IMPLEMENTATION-AUDIT1', 'result': 'MAPPING_REPRODUCED_SECURITY_HOLD',
        'profile_id': PROFILE, 'contract_sha256': sha(contract_bytes),
        'source_base_commit': contract['source_base_commit'],
        'generator_sha256': sha(Path(__file__).read_bytes()),
        'helper_execution': {'mode': 'compile_exact_pinned_repository_audit_bytes',
                             'sources': contract['audit_helpers'],
                             'upstream_source_executed': False},
        'qualification': dict(QUALIFICATION),
        'project_files': contract['project_files'], 'saved_fixture_files': contract['saved_v2_files'],
        'upstream_commit': UPSTREAM, 'upstream_snapshot': snapshot_record,
        'upstream_selected_sources': upstream_records, 'locked_package_mapping': locks,
        'field': {'work_modulus': Q, 'proof_base_modulus': P,
                  'extension_degree': 4, 'extension_polynomial': 'X^4 + 11',
                  'digest_support_size': str(P ** 8), 'digest_storage_bits': 256,
                  'uniform_bit_oracle_sigma_justified': None},
        'stark_parameters': stark, 'control_tree': control_tree,
        'parameter_digest_independently_recomputed': PARAMETERS,
        'control_scope': {
            'fixed_final_program': 'join.zkr', 'named_default_inner_programs': 27,
            'padding_leaf_count': 229, 'padding_leaf_digest': '0' * 64,
            'padding_digest_has_no_accepting_code_proved': False,
            'allowed_lift_po2_min': 14, 'allowed_lift_po2_max': 22,
            'generic_outer_verifier_explicit_po2_max': 24,
            'generic_outer_verifier_explicit_po2_min': None,
            'all_recursive_trace_sizes_reachable': None,
            'warning': 'The default lift-name limit 22 is not a standalone upper bound for every recursion seal. The succinct check_code closure ignores its po2 argument; code-root constraints may restrict feasibility, which is not proved here.',
            'all_program_bytecode_to_control_ids_recomputed': False,
            'all_program_relations_and_rbr_proved': False,
        },
        'fri_schedules': [fri_schedule(po2) for po2 in range(0, 25)],
        'fri_schedule_scope': 'Public arithmetic for each explicit parser po2 value, not a claim that every value admits a valid seal. No FRI folding-round count is substituted for the full IOR round count.',
        'saved_v2': v2, 'fri_transcript_audit': transcript_report,
        'lifetime_budget': contract['lifetime_budget'],
        'open_obligations': [{'id': item, 'state': 'UNRESOLVED'} for item in contract['proof_obligations']],
        'independent_conclusions': {
            'pq_signature_authorization': 'Not assessed or certified by this proof map.',
            'complete_computation_proof': 'Selected construction and historical v2 bindings reproduced; QROM qualification remains open.',
            'quantum_work_and_chainweight': 'Not implied by proof or signature validation; remains a separate analysis.',
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        report = build_report(args.repo_root)
        data = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
        if args.output:
            with args.output.open('x') as stream:
                stream.write(data)
        else:
            sys.stdout.write(data)
        return 0
    except (ValueError, OSError, KeyError, TypeError, struct.error, EOFError) as error:
        print(json.dumps({'result': 'INPUT_REJECTED', 'reason': str(error),
                          'qualification': QUALIFICATION}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
