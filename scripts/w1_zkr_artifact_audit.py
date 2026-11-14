#!/usr/bin/env python3
"""Audit fixed ZKR bytes/catalog/capacity; do not certify program semantics.

The 57 MiB official ZIP is supplied explicitly with --zkr.  This audit hashes
and reads that complete artifact; it does not execute bytecode, rebuild Zirgen,
recompute FRI code commitments, or prove that any satisfying trace is reachable.
The evaluated capacity po2=18 is the recorded outer W1 receipt's size, not a
claim that every recursively accepted seal must use that size.
"""
from __future__ import annotations

import argparse
from array import array
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import tarfile
from types import ModuleType
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = 'evidence/pon-w1-qrom-semantics-20261107'
ZIP_SHA256 = '744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849'
ZIP_BYTES = 59768781
UPSTREAM = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
HELPER = 'scripts/w1_control_tree_audit.py'
HELPER_SHA256 = '0e9b8e2fd9f6905f98b3df1a52b4ac2a46481b101b1d1a6afd29c2f5502f4865'
SNAPSHOT = 'evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz'
SNAPSHOT_SHA256 = 'f6be3667106df6843f5f29c0954cdce8e2617da36c9c91a7a5198665675e0253'
ARCHIVES = {
    'risc0-circuit-recursion-4.0.5': (
        '40dd640122abcc67d4d4e4f055c68cbc3ad2efb8589c65c2b23d354632971b60',
        ('build.rs', 'src/prove/mod.rs', 'src/prove/program.rs', 'src/prove/zkr.rs')),
    'risc0-zkp-3.0.5': (
        '21c0c921e5e2d44197940d387a45e29c6165e318b5a168fdfdbd50f50ba03678',
        ('src/lib.rs',)),
}
P = 2013265921
CODE_WIDTH = 23
ZK_CYCLES = 1024
CAPACITY_PO2 = 18


class ZkrAuditError(ValueError):
    """Malformed, unpinned, or out-of-scope ZKR audit input."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ZkrAuditError(message)


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def read_pinned(path: Path, expected: str, limit: int) -> bytes:
    with path.open('rb') as stream:
        blob = stream.read(limit + 1)
    require(len(blob) <= limit, f'{path.name}: input size limit')
    require(sha256(blob) == expected, f'{path.name}: SHA-256 mismatch')
    return blob


def load_context(root: Path) -> tuple[dict[str, str], set[str], dict]:
    helper_data = read_pinned(root / HELPER, HELPER_SHA256, 128 * 1024)
    helper = ModuleType('_w1_zkr_pinned_catalog_helper')
    helper.__file__ = str(root / HELPER)
    exec(compile(helper_data, helper.__file__, 'exec'), helper.__dict__)
    snapshot_blob = read_pinned(root / SNAPSHOT, SNAPSHOT_SHA256, 512 * 1024)
    with gzip.GzipFile(fileobj=io.BytesIO(snapshot_blob)) as stream:
        expanded = stream.read(8 * 1024 * 1024 + 1)
    require(len(expanded) <= 8 * 1024 * 1024, 'source snapshot expansion limit')
    snapshot = json.loads(expanded)
    require(snapshot['schema'] == 'TRNM-W1-UPSTREAM-SOURCE-SNAPSHOT1'
            and snapshot['commit'] == UPSTREAM, 'source snapshot identity')
    sources = {row['path']: row['content'] for row in snapshot['files']}
    require(len(sources) == len(snapshot['files']), 'duplicate source paths')
    helper.verify_sources(sources)
    allowed_rows = helper.parse_controls(sources[helper.CONTROL_PATH])
    catalog_rows = helper.parse_catalog(sources[helper.CONTROL_PATH])
    helper.validate_catalog(allowed_rows, catalog_rows)
    catalog = {row['program']: row['control_id'] for row in catalog_rows}
    allowed = {row['program'] for row in allowed_rows}
    records = []
    selected = {}
    for name, (expected, members) in ARCHIVES.items():
        blob = read_pinned(root / EVIDENCE / (name + '.crate'), expected, 512 * 1024)
        with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as archive:
            for member in members:
                info = archive.getmember(name + '/' + member)
                require(info.isfile() and info.size < 1024 * 1024, 'source member size/type')
                data = archive.extractfile(info).read()
                selected[name + '/' + member] = data.decode('utf-8')
                records.append({'crate': name, 'archive_sha256': expected, 'member': member,
                                'member_sha256': sha256(data), 'member_bytes': len(data)})
    build = selected['risc0-circuit-recursion-4.0.5/build.rs']
    width = selected['risc0-circuit-recursion-4.0.5/src/prove/mod.rs']
    zkp = selected['risc0-zkp-3.0.5/src/lib.rs']
    require(re.findall(r'const SHA256_HASH: &str = "([0-9a-f]{64})";', build) == [ZIP_SHA256],
            'ZKR build artifact pin changed')
    require(re.findall(r'const RECURSION_CODE_SIZE: usize = (\d+);', width) == [str(CODE_WIDTH)],
            'code width differs from pinned source')
    require(re.findall(r'pub const ZK_CYCLES: usize = (\d+);', zkp) == [str(ZK_CYCLES)],
            'ZK reserved cycles differ from pinned source')
    return catalog, allowed, {
        'upstream_commit': UPSTREAM,
        'catalog_helper': {'path': HELPER, 'sha256': sha256(helper_data)},
        'catalog_snapshot': {'path': SNAPSHOT, 'sha256': sha256(snapshot_blob)},
        'selected_source_members': records,
    }


def validate_inventory(names: list[str], expected: set[str]) -> None:
    require(len(names) == len(set(names)), 'duplicate ZKR ZIP entry')
    require(set(names) == expected and all(re.fullmatch(r'[a-z0-9_]+\.zkr', name) for name in names),
            'ZKR ZIP inventory differs from fixed named catalog')


def program_shape(data: bytes, capacity_po2: int = CAPACITY_PO2) -> dict:
    require(type(data) is bytes and 0 < len(data) <= 32 * 1024 * 1024, 'ZKR member size limit')
    require(type(capacity_po2) is int and 11 <= capacity_po2 <= 24, 'audit capacity exponent range')
    require(len(data) % 4 == 0, 'ZKR bytes are not whole u32 words')
    count = len(data) // 4
    require(count % CODE_WIDTH == 0, 'ZKR word count is not whole code rows')
    words = array('I')
    require(words.itemsize == 4, 'audit platform unsigned-int width')
    words.frombytes(data)
    if sys.byteorder != 'little':
        words.byteswap()
    noncanonical = sum(word >= P for word in words)
    rows = count // CODE_WIDTH
    available = (1 << capacity_po2) - ZK_CYCLES
    require(rows <= available, 'ZKR code exceeds the selected trace capacity')
    # Canonicality is checked explicitly to establish a lossless normal-form
    # u32-to-field interpretation for these artifacts. It is not claimed as a
    # universal rejection condition of BabyBearElem::from in the SDK.
    require(noncanonical == 0, 'ZKR audit requires canonical normal-form field words')
    return {
        'bytes': len(data), 'sha256': sha256(data), 'u32_words': count,
        'u32_word_encoding': 'little endian, canonical normal-form BabyBear inputs',
        'noncanonical_word_count': noncanonical, 'maximum_word': max(words),
        'all_code_words_zero': not any(words), 'code_columns': CODE_WIDTH, 'code_rows': rows,
        'evaluated_capacity_po2': capacity_po2, 'total_trace_rows': 1 << capacity_po2,
        'reserved_zk_rows': ZK_CYCLES, 'available_code_rows': available,
        'unused_code_rows_at_evaluated_capacity': available - rows,
        'minimum_po2_from_capacity_inequality_only': (rows + ZK_CYCLES - 1).bit_length(),
        'declared_control_id_recomputed_from_bytecode': False,
        'bytecode_execution_or_reachable_trace_verified': False,
    }


def audit_zip(root: Path, archive_path: Path) -> dict:
    catalog, allowed, provenance = load_context(root)
    blob = read_pinned(archive_path, ZIP_SHA256, 64 * 1024 * 1024)
    require(len(blob) == ZIP_BYTES, 'fixed ZKR ZIP length mismatch')
    entries = []
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        infos = archive.infolist()
        validate_inventory([info.filename for info in infos], set(catalog))
        require(sum(info.file_size for info in infos) <= 1024 * 1024 * 1024,
                'ZKR ZIP expansion audit limit')
        for info in sorted(infos, key=lambda item: item.filename):
            require(not info.is_dir() and not (info.flag_bits & 1)
                    and info.file_size <= 32 * 1024 * 1024, 'unsupported ZKR member')
            data = archive.read(info)
            entries.append({
                'program': info.filename, 'in_default_named_allowlist': info.filename in allowed,
                'declared_poseidon2_control_id': catalog[info.filename],
                'zip_compressed_bytes': info.compress_size,
                **program_shape(data),
            })
    named = [entry for entry in entries if entry['in_default_named_allowlist']]
    require(len(entries) == 32 and len(named) == 27, 'fixed ZKR catalog/allowlist counts')
    return {
        'schema': 'TRNM-W1-ZKR-ARTIFACT-AUDIT1',
        'status': 'FIXED_ZKR_CATALOG_BYTES_AND_CAPACITY_CHECKED',
        'source_provenance': provenance,
        'zip': {'sha256': sha256(blob), 'bytes': len(blob),
                'source_url': 'https://risc0-artifacts.s3.us-west-2.amazonaws.com/zkr/' + ZIP_SHA256 + '.zip'},
        'program_count': len(entries), 'default_named_program_count': len(named),
        'excluded_named_programs': [entry['program'] for entry in entries
                                    if not entry['in_default_named_allowlist']],
        'programs': entries,
        'default_named_summary': {
            'minimum_code_rows': min(entry['code_rows'] for entry in named),
            'maximum_code_rows': max(entry['code_rows'] for entry in named),
            'minimum_unused_code_rows_at_po2_18': min(entry['unused_code_rows_at_evaluated_capacity']
                                                    for entry in named),
            'all_fit_capacity_inequality_at_po2_18': True,
            'all_input_words_canonical': True,
            'all_named_bytecode_streams_nonzero': all(not entry['all_code_words_zero'] for entry in named),
        },
        'qualification': {
            'complete_official_zip_digest_verified': True,
            'all_named_artifact_sha256_and_row_shapes_computed': True,
            'capacity_inequality_at_recorded_outer_po2_checked': True,
            'recursion_source_compilation_reproduced': False,
            'bytecode_to_fri_control_id_recomputed': False,
            'intended_program_semantics_proved': False,
            'all_reachable_traces_certified': False,
            'valid_code_zero_control_digest_excluded': False,
            'every_accepted_recursive_seal_has_po2_18_proved': False,
            'end_to_end_qrom_bound_established': False,
        },
        'scope_notes': [
            'A filename/catalog association is not a recomputation of its FRI code commitment.',
            'A nonzero code stream need not have a provably nonzero digest.',
            'Program::from_encoded capacity checks do not execute the program or certify a satisfying trace.',
            'Minimum po2 here solves a row-capacity inequality only; it is not a verifier acceptance boundary.',
            'The 229 zero-digest allowlist padding leaves still require a separate valid-code exclusion argument.',
            'The artifact parser reads explicit little-endian words; the pinned SDK extraction casts native u32 words.',
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--zkr', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    try:
        result = audit_zip(args.root, args.zkr)
        text = json.dumps(result, sort_keys=True, indent=2) + '\n'
        if args.out:
            with args.out.open('x', encoding='utf-8') as stream:
                stream.write(text)
        else:
            print(text, end='')
        return 0
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile,
            RecursionError) as error:
        print(json.dumps({'schema': 'TRNM-W1-ZKR-ARTIFACT-AUDIT1', 'status': 'invalid_input',
                          'error': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
