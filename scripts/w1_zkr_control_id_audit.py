#!/usr/bin/env python3
"""Reconstruct fixed ZKR FRI code commitments with an independent C kernel.

Run join first, then --all-default only after its bounded result matches.
The driver verifies the official ZIP, all source/archive pins, independent
arithmetic KATs, the exact requested roster and (for all 27) the control root.
It does not execute recursive bytecode or prove compiler/program semantics.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
from types import ModuleType
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SHAPE_PATH = 'scripts/w1_zkr_artifact_audit.py'
SHAPE_SHA256 = '6931e8241fcc63d6531b110fbf7b0e029a39deb676b5fb60746e4e1d47d5e799'
C_PATH = 'scripts/w1_zkr_control_id.c'
C_SHA256 = 'b388eeea5ae14ae2595acb1c6c241141d435fca91f72285e43969554dd3d6813'
P = 2013265921
NATIVE_SOURCE_MEMBERS = (
    'src/core/ntt.rs', 'src/hal/cpu.rs', 'src/prove/poly_group.rs',
    'src/prove/merkle.rs', 'src/core/hash/poseidon2/mod.rs',
)


class ControlIdAuditError(ValueError):
    """An arithmetic/provenance/roster mismatch or incomplete native run."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ControlIdAuditError(message)


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def checked_module(path: Path, expected: str, name: str) -> ModuleType:
    blob = path.read_bytes()
    require(sha256(blob) == expected, f'{path.name}: fixed Python helper SHA-256 mismatch')
    module = ModuleType(name)
    module.__file__ = str(path)
    exec(compile(blob, str(path), 'exec'), module.__dict__)
    return module


def parse_roots(source: str, name: str) -> tuple[int, ...]:
    blocks = re.findall(r'const ' + re.escape(name)
                        + r':\s*&\x27static\s*\[Elem\]\s*=\s*&rou_array!\[(.*?)\];', source, re.S)
    require(len(blocks) == 1, f'{name}: root-of-unity declaration')
    tokens = [token.strip() for token in blocks[0].split(',') if token.strip()]
    require(len(tokens) == 28 and all(re.fullmatch(r'[0-9]+', token) for token in tokens),
            f'{name}: unsupported root-of-unity encoding')
    roots = tuple(map(int, tokens))
    require(roots[0] == 1 and all(0 < value < P for value in roots), f'{name}: root range')
    for bits, value in enumerate(roots[1:], start=1):
        require(pow(value, 1 << bits, P) == 1 and pow(value, 1 << (bits - 1), P) == P - 1,
                f'{name}: root does not have exact order at index {bits}')
    return roots


def naive_dft(values: list[int], root: int, inverse_scale: bool = False) -> list[int]:
    """Tiny O(n^2) reference, independent of the native butterfly algorithm."""
    n = len(values)
    require(0 < n <= 256 and n & (n - 1) == 0, 'reference DFT size')
    require(all(type(value) is int and 0 <= value < P for value in values), 'reference DFT field range')
    scale = pow(n, -1, P) if inverse_scale else 1
    return [sum(value * pow(root, row * col, P) for col, value in enumerate(values)) * scale % P
            for row in range(n)]


def naive_lde(values: list[int], forward: tuple[int, ...], reverse: tuple[int, ...]) -> list[int]:
    bits = len(values).bit_length() - 1
    coefficients = naive_dft(values, reverse[bits], True)
    shifted = [coefficient * pow(3, index, P) % P for index, coefficient in enumerate(coefficients)]
    return naive_dft(shifted + [0] * (3 * len(values)), forward[bits + 2])


def tiny_control_root(engine: object, forward: tuple[int, ...], reverse: tuple[int, ...]) -> tuple[int, ...]:
    columns = [naive_lde([100 * (row + 1) + col for row in range(4)] + [0] * 4,
                         forward, reverse) for col in range(23)]
    layer = [engine.hash_elements([columns[col][row] for col in range(23)]) for row in range(32)]
    while len(layer) > 1:
        layer = [engine.permute((*layer[index], *layer[index + 1], *([0] * 8)))[:8]
                 for index in range(0, len(layer), 2)]
    return layer[0]


def load_context(root: Path) -> tuple[object, ModuleType, object, dict[str, str], set[str], bytes, bytes, dict]:
    shape = checked_module(root / SHAPE_PATH, SHAPE_SHA256, '_w1_native_shape_helper')
    catalog, allowed, provenance = shape.load_context(root)
    helper = checked_module(root / shape.HELPER, shape.HELPER_SHA256, '_w1_native_poseidon_helper')
    snapshot_blob = shape.read_pinned(root / shape.SNAPSHOT, shape.SNAPSHOT_SHA256, 512 * 1024)
    snapshot = json.loads(gzip.decompress(snapshot_blob))
    sources = {row['path']: row['content'] for row in snapshot['files']}
    helper.verify_sources(sources)
    engine = helper.Poseidon2.from_source(sources[helper.CONST_PATH])
    core_source = sources['risc0/core/src/field/baby_bear.rs']
    forward, reverse = parse_roots(core_source, 'ROU_FWD'), parse_roots(core_source, 'ROU_REV')
    require(all(left * right % P == 1 for left, right in zip(forward, reverse)), 'NTT root inverse pairing')
    c_source = shape.read_pinned(root / C_PATH, C_SHA256, 128 * 1024)
    zkp_name = 'risc0-zkp-3.0.5'
    zkp_sha = shape.ARCHIVES[zkp_name][0]
    zkp_blob = shape.read_pinned(root / shape.EVIDENCE / (zkp_name + '.crate'), zkp_sha, 512 * 1024)
    native_sources = []
    with tarfile.open(fileobj=io.BytesIO(zkp_blob), mode='r:gz') as archive:
        for member in NATIVE_SOURCE_MEMBERS:
            data = archive.extractfile(zkp_name + '/' + member).read()
            native_sources.append({'crate': zkp_name, 'archive_sha256': zkp_sha,
                                   'member': member, 'sha256': sha256(data), 'bytes': len(data)})
    arrays = {
        'ROUND_CONSTANTS': engine.constants, 'DIAGONAL': engine.diagonal,
        'ROU_FWD': forward, 'ROU_REV': reverse,
        'KAT_PERM': engine.permute(tuple(range(24))),
        'KAT_HASH23': engine.hash_elements(tuple(range(23))),
        'KAT_PAIR': engine.permute((*range(16), *([0] * 8)))[:8],
        'KAT_NTT8': naive_dft(list(range(1, 9)), forward[3]),
        'KAT_IFFT8': naive_dft(list(range(1, 9)), reverse[3], True),
        'KAT_LDE32': naive_lde(list(range(1, 9)), forward, reverse),
        'KAT_TINY_ROOT': tiny_control_root(engine, forward, reverse),
    }
    lines = ['/* Generated from checksum-pinned RISC Zero sources and independent tiny Python references. */']
    for name, values in arrays.items():
        require(all(type(value) is int and 0 <= value < P for value in values), 'generated C constant range')
        lines.append(f'static const uint32_t {name}[{len(values)}] = {{'
                     + ','.join(str(value) for value in values) + '};')
    header = ('\n'.join(lines) + '\n').encode('ascii')
    provenance.update({
        'artifact_shape_helper': {'path': SHAPE_PATH, 'sha256': SHAPE_SHA256},
        'native_template': {'path': C_PATH, 'sha256': sha256(c_source)},
        'generated_constants_header_sha256': sha256(header),
        'ntt_and_hash_source_members': native_sources,
        'ntt_convention': 'natural coefficients: inverse DFT with ROU_REV/N; multiply coefficient k by 3^k; zero pad to 4N; forward DFT with ROU_FWD',
        'sdk_equivalence': 'SDK bit-reversed coefficients with repeated expansion and skipped butterflies implement the same natural-order LDE; tiny references check the ordering, and catalog comparisons are recorded per requested program',
        'merkle_convention': '23 columns in source order; normal-form internal arithmetic; output raw Montgomery digest words serialized little endian',
        'native_self_test_count': 7,
        'reference_known_answers': {key: list(values) for key, values in arrays.items() if key.startswith('KAT_')},
    })
    return shape, helper, engine, catalog, allowed, c_source, header, provenance


def run_record(command: list[str], directory: Path, label: str, timeout: int,
               environment: dict[str, str] | None = None) -> dict:
    began = time.monotonic()
    timed_out = False
    try:
        process = subprocess.run(command, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=environment, timeout=timeout, check=False)
        stdout, stderr, returncode = process.stdout, process.stderr, process.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, returncode, timed_out = error.stdout or b'', error.stderr or b'', None, True
    (directory / (label + '.stdout')).write_bytes(stdout)
    (directory / (label + '.stderr')).write_bytes(stderr)
    return {
        'command': command, 'timeout_seconds': timeout, 'timed_out': timed_out,
        'exit_code': returncode, 'wall_seconds': time.monotonic() - began,
        'stdout_sha256': sha256(stdout), 'stderr_sha256': sha256(stderr),
        'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
        'stdout': stdout.decode('utf-8', errors='replace'),
        'stderr': stderr.decode('utf-8', errors='replace'),
    }


def validate_native_result(result: dict, rows: int, expected: str, threads: int) -> None:
    require(set(result) == {'control_id', 'code_rows', 'trace_po2', 'domain_rows', 'threads',
                            'root_normal_words', 'lde_samples_normal', 'phase_seconds'},
            'native result field set')
    require(result['control_id'] == expected and re.fullmatch(r'[0-9a-f]{64}', result['control_id']),
            'computed control ID differs from fixed catalog')
    for key, wanted in (('code_rows', rows), ('trace_po2', 18), ('domain_rows', 1 << 20), ('threads', threads)):
        require(type(result[key]) is int and result[key] == wanted, f'native {key} mismatch')
    words = result['root_normal_words']
    require(type(words) is list and len(words) == 8
            and all(type(word) is int and 0 <= word < P for word in words), 'native normal root encoding')
    serialized = struct.pack('<8I', *(word * ((1 << 32) % P) % P for word in words)).hex()
    require(serialized == expected, 'native output Montgomery/byte encoding mismatch')
    samples = result['lde_samples_normal']
    require(type(samples) is list and len(samples) == 16
            and all(type(word) is int and 0 <= word < P for word in samples), 'native LDE sample encoding')
    phases = result['phase_seconds']
    require(set(phases) == {'lde', 'leaves', 'tree'}
            and all(type(value) in (float, int) and math.isfinite(value) and value >= 0
                    for value in phases.values()), 'native phase observations')


def audit(root: Path, zkr: Path, out_dir: Path, requested: list[str], threads: int = 4,
          timeout: int = 120, cc: str = 'cc') -> dict:
    require(type(threads) is int and 1 <= threads <= 4, 'maximum four native worker threads')
    require(type(timeout) is int and 1 <= timeout <= 120, 'maximum 120 seconds per program')
    shape, helper, engine, catalog, allowed, c_source, header, provenance = load_context(root)
    require(requested and len(requested) == len(set(requested))
            and all(name in allowed for name in requested), 'requested program roster')
    require(requested == sorted(requested), 'requested roster must be sorted')
    compiler = shutil.which(cc)
    require(compiler is not None, 'C compiler is unavailable; no native fallback')
    blob = shape.read_pinned(zkr, shape.ZIP_SHA256, 64 * 1024 * 1024)
    require(len(blob) == shape.ZIP_BYTES, 'fixed ZIP length')
    out_dir.mkdir(parents=True, exist_ok=False)
    (out_dir / 'w1_zkr_control_id.c').write_bytes(c_source)
    (out_dir / 'w1_zkr_constants.h').write_bytes(header)
    records = []
    try:
        version = run_record([compiler, '--version'], out_dir, 'compiler-version', 20)
        require(version['exit_code'] == 0, 'compiler identity command failed')
        binary = out_dir / 'w1-zkr-control-id'
        build = run_record([compiler, '-O3', '-std=c11', '-fopenmp', '-Wall', '-Wextra', '-Werror',
                            str(out_dir / 'w1_zkr_control_id.c'), '-o', str(binary)],
                           out_dir, 'compile', 60)
        require(build['exit_code'] == 0 and not build['timed_out'], 'native compilation failed')
        binary_sha = sha256(binary.read_bytes())
        native_environment = os.environ.copy()
        native_environment.update({'OMP_NUM_THREADS': str(threads), 'OMP_THREAD_LIMIT': '4',
                                   'OMP_DYNAMIC': 'FALSE', 'OMP_WAIT_POLICY': 'PASSIVE'})
        kat = run_record([str(binary), '--self-test'], out_dir, 'self-test', 20, native_environment)
        require(kat['exit_code'] == 0 and not kat['timed_out'], 'native self-test failed')
        require(json.loads(kat['stdout']) == {'self_test': 'PASS', 'checks': 7, 'arithmetic': 'normal BabyBear'},
                'native self-test completion record')
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            shape.validate_inventory(archive.namelist(), set(catalog))
            for index, name in enumerate(requested):
                data = archive.read(name)
                geometry = shape.program_shape(data)
                program_path = out_dir / name
                with program_path.open('xb') as stream:
                    stream.write(data)
                run = run_record([str(binary), str(program_path), '18', str(threads)],
                                 out_dir, name + '-control-id', timeout, native_environment)
                event = {'program': name, 'bytecode_sha256': sha256(data), 'geometry': geometry,
                         'declared_control_id': catalog[name], 'native_run': run}
                # Persist every returned/timeout observation before validating it.
                with (out_dir / 'observations.jsonl').open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(event, sort_keys=True) + '\n')
                require(run['exit_code'] == 0 and not run['timed_out'], f'{name}: native run failed or timed out')
                native_result = json.loads(run['stdout'])
                validate_native_result(native_result, geometry['code_rows'], catalog[name], threads)
                event['computed_control_id'] = native_result['control_id']
                event['matches_fixed_catalog'] = True
                records.append(event)
                # Exact input bytes remain reproducible from the retained ZIP.
                # A failing input is retained; only successful scratch copies go.
                program_path.unlink()
                print(json.dumps({'program': name, 'completed': index + 1, 'requested': len(requested),
                                  'control_id': native_result['control_id'], 'matched': True,
                                  'wall_seconds': run['wall_seconds']}), flush=True)
        require([record['program'] for record in records] == requested, 'native completed roster mismatch')
        all_default = requested == sorted(allowed)
        computed_root = None
        if all_default:
            computed_root = helper.build_tree([record['computed_control_id'] for record in records], engine)[-1][0]
            require(computed_root == helper.EXPECTED_ROOT, 'control root from computed bytecode identities mismatch')
        result = {
            'schema': 'TRNM-W1-ZKR-CONTROL-ID-AUDIT1',
            'status': 'RECOMPUTED_CONTROL_IDS_MATCH_FIXED_CATALOG',
            'requested_programs': requested, 'completed_programs': len(records),
            'source_provenance': provenance,
            'official_zip': {'sha256': sha256(blob), 'bytes': len(blob)},
            'native_build': {'compiler_identity': version, 'compilation': build,
                             'binary_sha256': binary_sha, 'self_test': kat},
            'limits': {'threads': threads, 'per_program_timeout_seconds': timeout},
            'programs': records,
            'control_root_from_computed_ids': computed_root,
            'default_named_count': len(allowed), 'zero_digest_padding_leaf_count': 229,
            'qualification': {
                'requested_bytecode_to_fri_control_ids_recomputed': True,
                'all_27_default_named_control_ids_recomputed': all_default,
                'default_control_root_recomputed_from_bytecode': all_default,
                'recursion_source_to_bytecode_compilation_reproduced': False,
                'intended_recursive_program_semantics_proved': False,
                'every_reachable_trace_certified': False,
                'valid_code_zero_control_digest_excluded': False,
                'fresh_receipt_cryptographically_verified': False,
                'end_to_end_qrom_bound_established': False,
                'quantum_work_to_chain_weight_correspondence_proved': False,
            },
        }
        with (out_dir / 'report.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
        return result
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        failure = {'schema': 'TRNM-W1-ZKR-CONTROL-ID-AUDIT1', 'status': 'FAILED_OR_INCOMPLETE',
                   'error': str(error), 'completed_matching_programs': [record['program'] for record in records],
                   'requested_programs': requested, 'all_default_control_ids_verified': False}
        with (out_dir / 'failure.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(failure, indent=2, sort_keys=True) + '\n')
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--zkr', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    select = parser.add_mutually_exclusive_group(required=True)
    select.add_argument('--program', choices=['join.zkr'])
    select.add_argument('--all-default', action='store_true')
    parser.add_argument('--threads', type=int, default=4)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    try:
        shape = checked_module(args.root / SHAPE_PATH, SHAPE_SHA256, '_w1_native_select_helper')
        _, allowed, _ = shape.load_context(args.root)
        requested = sorted(allowed) if args.all_default else [args.program]
        result = audit(args.root.resolve(), args.zkr.resolve(), args.out_dir.resolve(), requested,
                       args.threads, args.timeout, args.cc)
        print(json.dumps({'status': result['status'], 'completed_programs': result['completed_programs'],
                          'control_root': result['control_root_from_computed_ids']}))
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError,
            zipfile.BadZipFile, RecursionError) as error:
        print(json.dumps({'schema': 'TRNM-W1-ZKR-CONTROL-ID-AUDIT1', 'status': 'invalid_or_failed',
                          'error': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
