"""Literal SHA-256: arbitrary-IV fixed points are not standard-IV W1 forgeries."""
from __future__ import annotations
import json
import struct

MASK = (1 << 32) - 1
IV = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


def state_words(state: tuple[int, ...]) -> tuple[int, ...]:
    if type(state) is not tuple or len(state) != 8 or any(type(x) is not int or not 0 <= x <= MASK for x in state):
        raise ValueError('state must be eight canonical 32-bit words')
    return state


def rotr(x: int, count: int) -> int:
    return ((x >> count) | (x << (32 - count))) & MASK


def sigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def sigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def choose(e: int, f: int, g: int) -> int:
    return (e & f) ^ (~e & g)


def majority(a: int, b: int, c: int) -> int:
    return (a & b) ^ (a & c) ^ (b & c)


def schedule(block: bytes) -> tuple[int, ...]:
    if type(block) is not bytes or len(block) != 64:
        raise ValueError('compression block must be 64 bytes')
    words = list(struct.unpack('>16I', block))
    for i in range(16, 64):
        first = rotr(words[i - 15], 7) ^ rotr(words[i - 15], 18) ^ (words[i - 15] >> 3)
        second = rotr(words[i - 2], 17) ^ rotr(words[i - 2], 19) ^ (words[i - 2] >> 10)
        words.append((words[i - 16] + first + words[i - 7] + second) & MASK)
    return tuple(words)


def round_forward(state: tuple[int, ...], constant: int, word: int) -> tuple[int, ...]:
    a, b, c, d, e, f, g, h = state
    t1 = (h + sigma1(e) + choose(e, f, g) + constant + word) & MASK
    t2 = (sigma0(a) + majority(a, b, c)) & MASK
    return ((t1 + t2) & MASK, a, b, c, (d + t1) & MASK, e, f, g)


def round_inverse(state: tuple[int, ...], constant: int, word: int) -> tuple[int, ...]:
    new_a, a, b, c, new_e, e, f, g = state
    t2 = (sigma0(a) + majority(a, b, c)) & MASK
    t1 = (new_a - t2) & MASK
    d = (new_e - t1) & MASK
    h = (t1 - sigma1(e) - choose(e, f, g) - constant - word) & MASK
    return (a, b, c, d, e, f, g, h)


def permutation(state: tuple[int, ...], block: bytes, *, inverse: bool = False) -> tuple[int, ...]:
    current = state_words(state)
    words = schedule(block)
    if type(inverse) is not bool:
        raise ValueError('inverse must be a boolean')
    for i in (range(63, -1, -1) if inverse else range(64)):
        current = (round_inverse if inverse else round_forward)(current, K[i], words[i])
    return current


def compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    transformed = permutation(state, block)
    return tuple((x + y) & MASK for x, y in zip(state, transformed))


def blocks(message: bytes) -> tuple[bytes, ...]:
    if type(message) is not bytes or len(message) >= 1 << 61:
        raise ValueError('SHA-256 message must have fewer than 2^64 bits')
    padded = message + b'\x80'
    padded += bytes((56 - len(padded)) % 64) + struct.pack('>Q', len(message) * 8)
    return tuple(padded[i:i + 64] for i in range(0, len(padded), 64))


def sha256(message: bytes) -> bytes:
    current = IV
    for block in blocks(message):
        current = compress(current, block)
    return struct.pack('>8I', *current)


def fixed_point(block: bytes) -> tuple[int, ...]:
    """Arbitrary-IV fixed point, not an inverse of the feed-forward compressor."""
    return permutation((0,) * 8, block, inverse=True)


def observation(block: bytes) -> dict:
    state = fixed_point(block)
    transformed, output = permutation(state, block), compress(state, block)
    return {
        'block_hex': block.hex(),
        'arbitrary_iv_hex': struct.pack('>8I', *state).hex(),
        'round_permutation_output_hex': struct.pack('>8I', *transformed).hex(),
        'compression_output_hex': struct.pack('>8I', *output).hex(),
        'compression_is_fixed_point': output == state,
        'arbitrary_iv_equals_standard_iv': state == IV,
        'construction_inverse_round_steps': 64,
        'standard_iv_reachability_provided': False,
        'canonical_w1_trace_provided': False,
        'sha256_standard_iv_preimage_or_collision_provided': False,
    }


def summary() -> dict:
    return {
        'schema': 'w1-sha256-model-boundary-v1',
        'source': 'FIPS 180-4 sections 4.1.2, 4.2.2, 5.1.1, 5.3.3 and 6.2.2',
        'observations': [observation(block) for block in (bytes(64), bytes(range(64)), b'\xff' * 64)],
        'global_arbitrary_cv_random_compression_bad_bound_instantiates_sha256': False,
        'rooted_canonical_w1_path_bound_established': False,
        'physical_resource_floor_established': False,
        'production_activation': False,
        'benchmark': False,
    }


if __name__ == '__main__':
    print(json.dumps(summary(), sort_keys=True, indent=2))
