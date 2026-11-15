#!/usr/bin/env python3
"""Small independent cross-checks, no large program commitments or qualification."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import struct
import subprocess
import sys

ROOT = Path('/workspace/scratch/4a83c49617d8/chain_pq')
OUT = (Path(sys.argv[1]) if len(sys.argv) == 2 else
       Path('/workspace/scratch/4a83c49617d8/zkr-control-id-independent-review'))
SPEC = importlib.util.spec_from_file_location('reviewed_control_audit', ROOT / 'scripts/w1_zkr_control_id_audit.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
P = AUDIT.P


def require(value, message):
    if not value:
        raise RuntimeError(message)


def bitreverse(value, bits):
    result = 0
    for _ in range(bits):
        result = result * 2 + value % 2
        value //= 2
    return result


def sdk_reverse_butterfly(values, roots):
    """Direct mathematical transcription of reviewed Rust rev_butterfly macro."""
    if len(values) == 1:
        return values[:]
    bits = len(values).bit_length() - 1
    half = len(values) // 2
    a, b = values[:half], values[half:]
    left = [(x + y) % P for x, y in zip(a, b)]
    right = [(x - y) * pow(roots[bits], index, P) % P
             for index, (x, y) in enumerate(zip(a, b))]
    return sdk_reverse_butterfly(left, roots) + sdk_reverse_butterfly(right, roots)


def sdk_forward_butterfly(values, roots, expand_bits):
    """Reviewed Rust recursive forward butterfly with its skipped base layers."""
    bits = len(values).bit_length() - 1
    if bits == expand_bits:
        return values[:]
    half = len(values) // 2
    a = sdk_forward_butterfly(values[:half], roots, expand_bits)
    b = sdk_forward_butterfly(values[half:], roots, expand_bits)
    b = [value * pow(roots[bits], index, P) % P for index, value in enumerate(b)]
    return [(x + y) % P for x, y in zip(a, b)] + [(x - y) % P for x, y in zip(a, b)]


def sdk_lde(values, forward, reverse):
    bits = len(values).bit_length() - 1
    scale = pow(len(values), -1, P)
    coefficients = [value * scale % P for value in sdk_reverse_butterfly(values, reverse)]
    shifted = [value * pow(3, bitreverse(index, bits), P) % P
               for index, value in enumerate(coefficients)]
    repeated = [value for value in shifted for _ in range(4)]
    return sdk_forward_butterfly(repeated, forward, 2)


def root_reference(code, bits, engine, forward, reverse):
    n = 1 << bits
    rows = len(code) // 23
    columns = [sdk_lde([code[row * 23 + col] for row in range(rows)] + [0] * (n - rows),
                       forward, reverse) for col in range(23)]
    layer = [engine.hash_elements([column[row] for column in columns]) for row in range(4 * n)]
    while len(layer) > 1:
        layer = [engine.hash_elements(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0], columns[0][:8] + columns[-1][:8]


def main():
    OUT.mkdir()
    shape, helper, engine, catalog, allowed, source, header, provenance = AUDIT.load_context(ROOT)
    (OUT / 'w1_zkr_control_id.c').write_bytes(source)
    (OUT / 'w1_zkr_constants.h').write_bytes(header)
    wrapper = '''#define main reviewed_original_main
#include "w1_zkr_control_id.c"
#undef main
void review_ntt(uint32_t *values, unsigned bits, int inverse) { ntt(values, bits, inverse); }
void review_permute(uint32_t *values) { permutation(values); }
void review_hash23(const uint32_t *values, uint32_t *out) { hash23(values, 1, out); }
int review_root(const uint32_t *code, size_t rows, unsigned bits, uint32_t *root, uint32_t *samples) {
    struct result result;
    if (!control_root(code, rows, bits, 1, &result)) return 0;
    memcpy(root, result.root, sizeof(result.root));
    memcpy(samples, result.samples, sizeof(result.samples));
    return 1;
}
'''
    (OUT / 'wrapper.c').write_text(wrapper)
    command = ['cc', '-O2', '-std=c11', '-fopenmp', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
               str(OUT / 'wrapper.c'), '-o', str(OUT / 'review.so')]
    compiled = subprocess.run(command, capture_output=True, timeout=30)
    (OUT / 'compile.stdout').write_bytes(compiled.stdout)
    (OUT / 'compile.stderr').write_bytes(compiled.stderr)
    require(compiled.returncode == 0, compiled.stderr.decode())
    lib = ctypes.CDLL(str(OUT / 'review.so'))
    pointer = ctypes.POINTER(ctypes.c_uint32)
    lib.review_ntt.argtypes = [pointer, ctypes.c_uint, ctypes.c_int]
    lib.review_permute.argtypes = [pointer]
    lib.review_hash23.argtypes = [pointer, pointer]
    lib.review_root.argtypes = [pointer, ctypes.c_size_t, ctypes.c_uint, pointer, pointer]
    lib.review_root.restype = ctypes.c_int
    import gzip
    sources = {row['path']: row['content'] for row in json.loads(
        gzip.decompress((ROOT / shape.SNAPSHOT).read_bytes()))['files']}
    field = sources['risc0/core/src/field/baby_bear.rs']
    forward, reverse = AUDIT.parse_roots(field, 'ROU_FWD'), AUDIT.parse_roots(field, 'ROU_REV')
    require(all(pow(forward[i], 2, P) == forward[i - 1] for i in range(1, 28)), 'forward root tower')
    require(all(pow(reverse[i], 2, P) == reverse[i - 1] for i in range(1, 28)), 'reverse root tower')
    rng = random.Random(20261107)
    transformations = []
    for bits in range(1, 7):
        n = 1 << bits
        vectors = [[0] * n, [0] * (n - 1) + [1],
                   [(P - 1 - i) % P for i in range(n)], [rng.randrange(P) for _ in range(n)]]
        for index, values in enumerate(vectors):
            for inverse in (0, 1):
                actual = (ctypes.c_uint32 * n)(*values)
                lib.review_ntt(actual, bits, inverse)
                expected = AUDIT.naive_dft(values, reverse[bits] if inverse else forward[bits], bool(inverse))
                require(list(actual) == expected, f'C direct DFT mismatch {bits}/{index}/{inverse}')
            sdk = sdk_lde(values, forward, reverse)
            natural = AUDIT.naive_lde(values, forward, reverse)
            require(sdk == natural, f'SDK/natural LDE mismatch {bits}/{index}')
            transformations.append({'bits': bits, 'vector': index, 'forward_inverse_and_lde_match': True})
    hashes = []
    for index, values in enumerate(([0] * 24, list(range(24)), [P - 1] * 24,
                                    [rng.randrange(P) for _ in range(24)])):
        actual = (ctypes.c_uint32 * 24)(*values)
        lib.review_permute(actual)
        require(tuple(actual) == engine.permute(values), f'permutation {index}')
        leaf = (ctypes.c_uint32 * 8)()
        lib.review_hash23((ctypes.c_uint32 * 23)(*values[:23]), leaf)
        require(tuple(leaf) == engine.hash_elements(values[:23]), f'hash23 {index}')
        hashes.append({'vector': index, 'permutation_and_hash23_match': True})
    roots = []
    for bits, rows in ((2, 1), (3, 7), (4, 15), (5, 31)):
        code = [rng.randrange(P) if index % 3 else P - 1 for index in range(rows * 23)]
        actual_root, samples = (ctypes.c_uint32 * 8)(), (ctypes.c_uint32 * 16)()
        require(lib.review_root((ctypes.c_uint32 * len(code))(*code), rows, bits, actual_root, samples) == 1,
                'native tiny control root completion')
        expected, expected_samples = root_reference(code, bits, engine, forward, reverse)
        require(tuple(actual_root) == expected and list(samples) == expected_samples,
                f'root/column order mismatch {bits}')
        encoded = struct.pack('<8I', *(x * ((1 << 32) % P) % P for x in expected)).hex()
        roots.append({'bits': bits, 'rows': rows, 'root_and_lde_samples_match': True, 'control_id': encoded})
    compiled_cli = subprocess.run(
        ['cc', '-O2', '-std=c11', '-fopenmp', '-Wall', '-Wextra', '-Werror',
         str(OUT / 'w1_zkr_control_id.c'), '-o', str(OUT / 'control-id')],
        capture_output=True, timeout=30)
    require(compiled_cli.returncode == 0, compiled_cli.stderr.decode())
    boundary = OUT / 'capacity-boundary.zkr'
    boundary.write_bytes(bytes(1024 * 23 * 4))
    accepted = subprocess.run([str(OUT / 'control-id'), str(boundary), '11', '1'],
                              capture_output=True, timeout=20)
    require(accepted.returncode == 0, accepted.stderr.decode())
    actual = json.loads(accepted.stdout)
    digest = engine.hash_elements([0] * 23)
    for _ in range(13):
        digest = engine.hash_elements(digest + digest)
    encoded = struct.pack('<8I', *(x * ((1 << 32) % P) % P for x in digest)).hex()
    require(actual['code_rows'] == 1024 and actual['domain_rows'] == 8192
            and actual['root_normal_words'] == list(digest) and actual['control_id'] == encoded,
            'exact N-minus-1024 capacity boundary or analytic zero tree')
    native_inputs = [{'case': 'exact_N_minus_1024_rows', 'exit_code': 0,
                      'root_matches_independent_constant_tree': True}]
    invalid = OUT / 'invalid.zkr'
    negatives = [
        ('one_row_over_capacity', bytes(1025 * 23 * 4), '11', '1'),
        ('extra_word', bytes(23 * 4 + 4), '11', '1'),
        ('partial_byte', bytes(23 * 4 + 1), '11', '1'),
        ('noncanonical_modulus', struct.pack('<I', P) + bytes(88), '11', '1'),
        ('noncanonical_u32_max', struct.pack('<I', (1 << 32) - 1) + bytes(88), '11', '1'),
        ('huge_po2', bytes(92), '9' * 100, '1'),
        ('huge_threads', bytes(92), '11', '9' * 100),
        ('negative_po2', bytes(92), '-11', '1'),
        ('empty_threads', bytes(92), '11', ''),
    ]
    for label, payload, bits, threads in negatives:
        invalid.write_bytes(payload)
        response = subprocess.run([str(OUT / 'control-id'), str(invalid), bits, threads],
                                  capture_output=True, timeout=20)
        require(response.returncode == 2 and not response.stdout, 'native input refusal: ' + label)
        native_inputs.append({'case': label, 'exit_code': response.returncode,
                              'success_stdout_absent': not response.stdout})
    report = {
        'schema': 'TRNM-W1-ZKR-INDEPENDENT-SMALL-REVIEW1',
        'reviewed_sha256': {
            AUDIT.C_PATH: hashlib.sha256(source).hexdigest(),
            'scripts/w1_zkr_control_id_audit.py': hashlib.sha256((ROOT / 'scripts/w1_zkr_control_id_audit.py').read_bytes()).hexdigest(),
            'generated_header': hashlib.sha256(header).hexdigest(),
        },
        'forward_reverse_root_towers_coherent_through_po2': 27,
        'transformation_cases': transformations, 'hash_cases': hashes, 'tiny_control_roots': roots,
        'native_input_boundary_cases': native_inputs,
        'scope': 'actual pinned C functions versus small O(n^2) DFT and separately transcribed SDK bit-reversed recursive butterflies; no large artifact run, compilation-correctness proof or program-semantics proof',
        'all_27_recomputed_here': False, 'security_qualification': False,
    }
    (OUT / 'review.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'report': str(OUT / 'review.json'), 'transformation_cases': len(transformations),
                      'hash_cases': len(hashes), 'tiny_root_cases': len(roots)}))


if __name__ == '__main__':
    main()
