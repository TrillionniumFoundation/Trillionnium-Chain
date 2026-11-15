#!/usr/bin/env python3
"""Independently reconstruct the frozen W1 v2 guest memory image and image ID.

This is an executable byte/encoding audit, not a compiler-correctness proof,
receipt verifier, AIR proof, or QROM security reduction.  The ELF loader covers
the fixed little-endian ELF32/RISC-V executable profile.  Its explicit resource
limits and fixed R0BF header are audit restrictions, not SDK rejection claims.

Memory hashing is transcribed from the Apache-2.0 risc0-binfmt 3.0.5 sources
carried in the checksum-verified crates.  Poseidon2 arithmetic is reused from
the separately pinned, independently implemented W1 control-tree helper; its
control-tree digest encoding is deliberately NOT used for memory-tree nodes.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import tarfile
import tomllib
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = 'evidence/pon-w1-qrom-semantics-20261107'
GUEST_PATH = 'evidence/pon-w1-full-v2-20261105/guest.bin'
GUEST_SHA256 = '25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f'
IMAGE_SOURCE = 'formal/pon-nakamoto-v1/w1_v2_verifier/src/image.rs'
IMAGE_SOURCE_SHA256 = 'c972778fe557d3e1a23470423c46c899ade1633ba76cac48268129b2af5d1ddb'
HELPER_PATH = 'scripts/w1_control_tree_audit.py'
HELPER_SHA256 = '0e9b8e2fd9f6905f98b3df1a52b4ac2a46481b101b1d1a6afd29c2f5502f4865'
SNAPSHOT_PATH = 'evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz'
SNAPSHOT_SHA256 = 'f6be3667106df6843f5f29c0954cdce8e2617da36c9c91a7a5198665675e0253'
UPSTREAM = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
CRATES = {
    'risc0-binfmt-3.0.5': {
        'package': 'risc0-binfmt', 'version': '3.0.5',
        'sha256': 'd836c6ad82f4ced7c61d5feedf905a17780312e393aa681d29cc0bbc5131672b',
        'commit': UPSTREAM, 'path_in_vcs': 'risc0/binfmt',
        'members': ('src/lib.rs', 'src/elf.rs', 'src/image.rs', 'src/addr.rs',
                    'src/hash.rs', 'src/sys_state.rs'),
    },
    'risc0-zkos-v1compat-2.2.3': {
        'package': 'risc0-zkos-v1compat', 'version': '2.2.3',
        'sha256': 'b8b0b598ba7946354b10ca5c56e382de801e6c7fce9fccad0396ec436bc5072b',
        'commit': UPSTREAM, 'path_in_vcs': 'risc0/zkos/v1compat',
        'members': ('src/lib.rs', 'src/main.rs', 'src/kernel.s',
                    'elfs/v1compat.elf', 'elfs/v1compat.iid'),
    },
    'risc0-build-3.0.3': {
        'package': 'risc0-build', 'version': '3.0.3',
        'sha256': '1bbb512d728e011d03ce0958ca7954624ee13a215bcafd859623b3c63b2a3f60',
        'commit': 'fba0c0179f0125afe23bd15eb4c34428aacf5705',
        'path_in_vcs': 'risc0/build', 'members': ('src/lib.rs',),
    },
    'risc0-zkp-3.0.5': {
        'package': 'risc0-zkp', 'version': '3.0.5',
        'sha256': '21c0c921e5e2d44197940d387a45e29c6165e318b5a168fdfdbd50f50ba03678',
        'commit': UPSTREAM, 'path_in_vcs': 'risc0/zkp',
        'members': ('src/adapter.rs', 'src/verify/mod.rs', 'src/lib.rs',
                    'src/prove/poly_group.rs', 'src/prove/merkle.rs'),
    },
    'risc0-circuit-recursion-4.0.5': {
        'package': 'risc0-circuit-recursion', 'version': '4.0.5',
        'sha256': '40dd640122abcc67d4d4e4f055c68cbc3ad2efb8589c65c2b23d354632971b60',
        'commit': UPSTREAM, 'path_in_vcs': 'risc0/circuit/recursion',
        'members': ('src/poly_ext.rs', 'src/info.rs', 'src/taps.rs', 'src/lib.rs',
                    'src/prove/program.rs', 'src/prove/zkr.rs', 'build.rs'),
    },
    'risc0-circuit-rv32im-4.0.5': {
        'package': 'risc0-circuit-rv32im', 'version': '4.0.5',
        'sha256': 'cb11231aa4b74bcc0c8d16597893fbd7ea6f6a9ebbc35e16bfd06b467c7ee104',
        'commit': UPSTREAM, 'path_in_vcs': 'risc0/circuit/rv32im',
        'members': ('src/zirgen/poly_ext.rs', 'src/zirgen/info.rs', 'src/zirgen/taps.rs',
                    'src/lib.rs'),
    },
}
LOCK_PATHS = (
    'formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock',
    'formal/pon-nakamoto-v1/w1_zkvm/methods/guest-v2/Cargo.lock',
    'formal/pon-nakamoto-v1/w1_zkvm/Cargo.lock',
)
P = 2013265921
PAGE_BYTES = 1024
TREE_DEPTH = 22
USER_START = 0x10000
KERNEL_START = 0xc0000000
SUSPEND_PC = 0xffff0210
SUSPEND_MODE = 0xffff0214
MAX_BINARY_BYTES = 4 * 1024 * 1024
MAX_LOAD_WORDS = 1 << 20
FIXED_HEADER = bytes.fromhex('0100000008000000000005312e302e30')
EXPECTED_IMAGE_WORDS = (
    1958252411, 3287394615, 1805488136, 1516578702,
    78549041, 790278610, 301018785, 4279049364,
)
ZERO_PAGE_HEX = '242ce034cc4e9326f8b7071124454b2be1a1cd5d21b6483c7ff81d4ba5ac9566'
ZERO_MEMORY_HEX = 'f85c5a32ccc45c22f9686b08d710d4597d7ce256cdcd63146426270d9432c644'
KERNEL_KAT_HEX = '9d41290fa400705127c0240cb646586cc6ea8a23d560aa57cfa86c1369d9d53f'


class SemanticsAuditError(ValueError):
    """Unpinned source, malformed encoding, or failed fixed-artifact check."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SemanticsAuditError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_pinned(root: Path, path: str, expected: str, limit: int) -> bytes:
    with (root / path).open('rb') as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, f'{path}: audit input size limit')
    require(sha256(data) == expected, f'{path}: SHA-256 mismatch')
    return data


def crate_members(blob: bytes, name: str) -> dict[str, bytes]:
    """Read exact members, with no archive extraction or executable build step."""
    spec = CRATES[name]
    require(sha256(blob) == spec['sha256'], f'{name}: Cargo archive checksum mismatch')
    wanted = (*spec['members'], '.cargo_vcs_info.json')
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as archive:
        members = archive.getmembers()
        require(len({m.name for m in members}) == len(members), f'{name}: duplicate archive member')
        result = {}
        for member in wanted:
            info = archive.getmember(f'{name}/{member}')
            require(info.isfile() and info.size <= 16 * 1024 * 1024,
                    f'{name}/{member}: unsupported archive member')
            stream = archive.extractfile(info)
            require(stream is not None, f'{name}/{member}: missing content')
            result[member] = stream.read()
    vcs = json.loads(result['.cargo_vcs_info.json'])
    require(vcs == {'git': {'sha1': spec['commit']}, 'path_in_vcs': spec['path_in_vcs']},
            f'{name}: Cargo VCS provenance mismatch')
    return result


def load_sources(root: Path) -> tuple[ModuleType, object, dict, dict[str, dict[str, bytes]]]:
    """Verify complete small crate archives and compile only pinned helper bytes."""
    archives = {}
    records = []
    for name, spec in CRATES.items():
        blob = read_pinned(root, f'{EVIDENCE}/{name}.crate', spec['sha256'], 8 * 1024 * 1024)
        members = crate_members(blob, name)
        archives[name] = members
        records.append({
            'crate': name, 'archive_sha256': sha256(blob), 'archive_bytes': len(blob),
            'upstream_commit': spec['commit'], 'path_in_vcs': spec['path_in_vcs'],
            'members': [{'path': key, 'sha256': sha256(value), 'bytes': len(value)}
                        for key, value in sorted(members.items())],
        })
    locks = []
    for path in LOCK_PATHS:
        data = (root / path).read_bytes()
        parsed = tomllib.loads(data.decode('utf-8'))
        checked = []
        for name, spec in CRATES.items():
            # risc0-build is a host build dependency, absent from verifier/guest locks.
            if spec['package'] == 'risc0-build' and path != LOCK_PATHS[2]:
                continue
            found = [item for item in parsed['package'] if item['name'] == spec['package']]
            require(len(found) == 1 and found[0].get('version') == spec['version']
                    and found[0].get('checksum') == spec['sha256']
                    and found[0].get('source') == 'registry+https://github.com/rust-lang/crates.io-index',
                    f'{path}: locked {name} provenance mismatch')
            checked.append(name)
        locks.append({'path': path, 'sha256': sha256(data), 'checked_crates': checked})
    helper_data = read_pinned(root, HELPER_PATH, HELPER_SHA256, 128 * 1024)
    helper = ModuleType('_w1_semantics_pinned_poseidon2')
    helper.__file__ = str(root / HELPER_PATH)
    exec(compile(helper_data, helper.__file__, 'exec'), helper.__dict__)
    snapshot_data = read_pinned(root, SNAPSHOT_PATH, SNAPSHOT_SHA256, 512 * 1024)
    with gzip.GzipFile(fileobj=io.BytesIO(snapshot_data)) as stream:
        text = stream.read(8 * 1024 * 1024 + 1)
    require(len(text) <= 8 * 1024 * 1024, 'source snapshot expanded size limit')
    snapshot = json.loads(text)
    require(snapshot['schema'] == 'TRNM-W1-UPSTREAM-SOURCE-SNAPSHOT1'
            and snapshot['commit'] == UPSTREAM, 'source snapshot identity')
    source_records = snapshot['files']
    sources = {row['path']: row['content'] for row in source_records}
    require(len(sources) == len(source_records), 'source snapshot duplicate paths')
    helper.verify_sources(sources)
    engine = helper.Poseidon2.from_source(sources[helper.CONST_PATH])
    provenance = {
        'archives': records, 'lock_checks': locks,
        'poseidon_helper': {'path': HELPER_PATH, 'sha256': sha256(helper_data)},
        'poseidon_source_snapshot': {'path': SNAPSHOT_PATH, 'sha256': sha256(snapshot_data)},
        'whole_cargo_graph_verified': False,
    }
    return helper, engine, provenance, archives


def split_r0bf(binary: bytes) -> tuple[bytes, bytes, dict]:
    require(type(binary) is bytes and 32 <= len(binary) <= MAX_BINARY_BYTES,
            'R0BF: truncated or over audit size limit')
    require(binary[:4] == b'R0BF', 'R0BF: wrong magic; input is a composite binary')
    version, header_len = struct.unpack_from('<II', binary, 4)
    require(version == 1, 'R0BF: unsupported binary version')
    require(header_len == len(FIXED_HEADER) and binary[12:12 + header_len] == FIXED_HEADER,
            'R0BF: audit supports only the fixed V1Compat 1.0.0 header')
    user_len = struct.unpack_from('<I', binary, 12 + header_len)[0]
    user_start = 16 + header_len
    require(0 < user_len < len(binary) - user_start, 'R0BF: empty or truncated user/kernel ELF')
    user = binary[user_start:user_start + user_len]
    kernel = binary[user_start + user_len:]
    return user, kernel, {
        'magic': 'R0BF', 'binary_format_version': version,
        'header_hex': FIXED_HEADER.hex(), 'abi_kind': 'V1Compat', 'abi_version': '1.0.0',
        'user_elf_offset': user_start, 'user_elf_bytes': len(user),
        'user_elf_sha256': sha256(user), 'kernel_elf_offset': user_start + user_len,
        'kernel_elf_bytes': len(kernel), 'kernel_elf_sha256': sha256(kernel),
    }


def load_elf(elf: bytes, max_mem: int) -> tuple[int, dict[int, int], dict]:
    """Implement fixed-profile Program::load_elf word construction.

    PT_LOAD segments are applied in table order, with later words replacing
    earlier ones.  BSS and partial words follow the pinned source's 4-byte loop.
    Section/debug bytes do not enter the loaded image.  General ELF parser
    acceptance equivalence is outside this audit's supported input subset.
    """
    require(type(elf) is bytes and 52 <= len(elf) <= MAX_BINARY_BYTES, 'ELF: invalid size')
    require(elf[:7] == b'\x7fELF\x01\x01\x01', 'ELF: expected little-endian ELF32 version 1')
    fields = struct.unpack_from('<HHIIIIIHHHHHH', elf, 16)
    kind, machine, version, entry, phoff, _, _, ehsize, phsize, phnum, _, _, _ = fields
    require((kind, machine, version, ehsize, phsize) == (2, 243, 1, 52, 32),
            'ELF: unsupported executable header')
    require(type(max_mem) is int and 0 < max_mem <= 0xffffffff, 'ELF: invalid address limit')
    require(entry < max_mem and entry % 4 == 0, 'ELF: entry out of range or unaligned')
    require(0 < phnum <= 256 and phoff + phnum * phsize <= len(elf),
            'ELF: invalid or truncated program-header table')
    image: dict[int, int] = {}
    segments = []
    word_count = 0
    overwritten = 0
    for index in range(phnum):
        ptype, offset, vaddr, paddr, file_size, mem_size, flags, align = struct.unpack_from(
            '<IIIIIIII', elf, phoff + index * phsize)
        if ptype != 1:
            continue
        require(file_size < max_mem and mem_size < max_mem and vaddr % 4 == 0,
                'ELF: load segment size/address restriction')
        count = (mem_size + 3) // 4
        word_count += count
        require(word_count <= MAX_LOAD_WORDS, 'ELF: audit loaded-word limit')
        if count:
            require(vaddr + 4 * (count - 1) < max_mem, 'ELF: load segment address overflow')
        for i in range(0, mem_size, 4):
            if i >= file_size:
                word = 0
            else:
                take = min(file_size - i, 4)
                require(offset + i + take <= len(elf), 'ELF: truncated load segment data')
                word = int.from_bytes(elf[offset + i:offset + i + take], 'little')
            address = vaddr + i
            overwritten += int(address in image)
            image[address] = word
        segments.append({
            'program_header_index': index, 'file_offset': offset, 'virtual_address': vaddr,
            'physical_address_ignored_by_loader': paddr, 'file_bytes': file_size,
            'memory_bytes': mem_size, 'loaded_words': count, 'flags': flags, 'alignment': align,
        })
    require(segments, 'ELF: audit requires at least one load segment')
    return entry, image, {
        'entry': entry, 'program_headers': phnum, 'load_segments': segments,
        'loaded_distinct_words': len(image), 'overwritten_segment_words': overwritten,
    }


def initial_memory(user_entry: int, user: dict[int, int], kernel_entry: int,
                   kernel: dict[int, int]) -> tuple[dict[int, int], dict]:
    """Pinned with_kernel order: user entry; kernel.append(user); suspend slots."""
    user_words = dict(user)
    user_words[USER_START] = user_entry
    memory = dict(kernel)
    overlaps = sorted(set(memory) & set(user_words))
    memory.update(user_words)
    memory[SUSPEND_PC] = kernel_entry
    memory[SUSPEND_MODE] = 1
    return memory, {
        'user_overwrites_kernel_word_count': len(overlaps),
        'user_overwrites_kernel_addresses': overlaps,
        'special_word_writes': [
            {'address': USER_START, 'word': user_entry, 'purpose': 'user entry pointer'},
            {'address': SUSPEND_PC, 'word': kernel_entry, 'purpose': 'initial kernel PC'},
            {'address': SUSPEND_MODE, 'word': 1, 'purpose': 'initial kernel mode'},
        ],
    }


def normal_words(values: tuple[int, ...], count: int, label: str) -> None:
    require(len(values) == count and all(type(v) is int and 0 <= v < P for v in values),
            f'{label}: noncanonical normal-form field words')


def digest_hex(values: tuple[int, ...]) -> str:
    normal_words(values, 8, 'digest')
    return struct.pack('<8I', *values).hex()


def memory_pair(engine: object, left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    normal_words(left, 8, 'left memory digest')
    normal_words(right, 8, 'right memory digest')
    return engine.permute((*right, *left, *((0,) * 8)))[:8]


def page_digest(engine: object, page: bytes) -> tuple[int, ...]:
    require(type(page) is bytes and len(page) == PAGE_BYTES, 'memory page: expected 1024 bytes')
    halfwords = struct.unpack('<512H', page)
    state = (0,) * 24
    for offset in range(0, 512, 16):
        state = engine.permute((*halfwords[offset:offset + 16], *state[16:]))
    return state[:8]


def memory_root(engine: object, memory: dict[int, int]) -> tuple[tuple[int, ...], dict]:
    pages: dict[int, bytearray] = {}
    for address, word in memory.items():
        require(type(address) is int and 0 <= address <= 0xfffffffc and address % 4 == 0,
                'memory: invalid aligned u32 address')
        require(type(word) is int and 0 <= word <= 0xffffffff, 'memory: invalid u32 word')
        page = pages.setdefault(address // PAGE_BYTES, bytearray(PAGE_BYTES))
        struct.pack_into('<I', page, address % PAGE_BYTES, word)
    zero_digests = [page_digest(engine, bytes(PAGE_BYTES))]
    for _ in range(TREE_DEPTH):
        zero_digests.append(memory_pair(engine, zero_digests[-1], zero_digests[-1]))
    require(digest_hex(zero_digests[0]) == ZERO_PAGE_HEX, 'zero-page upstream known-answer mismatch')
    require(digest_hex(zero_digests[TREE_DEPTH]) == ZERO_MEMORY_HEX,
            'zero-memory upstream known-answer mismatch')
    level = {index: page_digest(engine, bytes(page)) for index, page in pages.items()}
    page_records = [{'page_index': index, 'bytes_sha256': sha256(bytes(pages[index])),
                     'poseidon2_normal_digest': digest_hex(value)}
                    for index, value in sorted(level.items())]
    active_pairs = 0
    for height in range(TREE_DEPTH):
        parents = sorted({index // 2 for index in level})
        active_pairs += len(parents)
        level = {index: memory_pair(engine, level.get(index * 2, zero_digests[height]),
                                    level.get(index * 2 + 1, zero_digests[height]))
                 for index in parents}
    root = level.get(0, zero_digests[TREE_DEPTH])
    return root, {
        'memory_address_bits': 32, 'page_bytes': PAGE_BYTES, 'tree_depth': TREE_DEPTH,
        'loaded_pages': len(pages), 'loaded_words': len(memory), 'active_internal_nodes': active_pairs,
        'zero_page_normal_digest': digest_hex(zero_digests[0]),
        'zero_memory_normal_digest': digest_hex(zero_digests[-1]),
        'page_hash_input': '512 little-endian u16 values; overwrite rate 16; retain capacity 8',
        'node_hash_input': 'right normal-form digest words || left normal-form digest words || 0^8',
        'node_hash_output': 'first 8 normal-form field words, serialized little endian',
        'page_records': page_records,
    }


def image_id(root: tuple[int, ...]) -> str:
    encoded = (hashlib.sha256(b'risc0.SystemState').digest()
               + bytes.fromhex(digest_hex(root)) + struct.pack('<I', 0) + struct.pack('<H', 1))
    return hashlib.sha256(encoded).hexdigest()


def recompute_binary(engine: object, binary: bytes) -> dict:
    user_elf, kernel_elf, container = split_r0bf(binary)
    user_entry, user, user_report = load_elf(user_elf, KERNEL_START)
    kernel_entry, kernel, kernel_report = load_elf(kernel_elf, 0xffffffff)
    memory, merge = initial_memory(user_entry, user, kernel_entry, kernel)
    root, tree = memory_root(engine, memory)
    return {
        'binary_bytes': len(binary), 'binary_sha256': sha256(binary), 'container': container,
        'user_elf': user_report, 'kernel_elf': kernel_report, 'initial_memory_writes': merge,
        'memory_tree': tree, 'memory_root': digest_hex(root), 'image_id': image_id(root),
        'image_id_words': list(struct.unpack('<8I', bytes.fromhex(image_id(root)))),
        'image_id_encoding': 'SHA256(SHA256(risc0.SystemState) || memory_root || LE32(0) || LE16(1))',
    }


def shared_permutation_vector(helper: ModuleType, engine: object) -> dict:
    """Exhibit a shared permutation input, not a valid-receipt attack."""
    left, right = tuple(range(1, 9)), tuple(range(9, 17))
    memory_result = memory_pair(engine, left, right)
    encode_mont = lambda words: struct.pack('<8I', *(v * helper.MONTGOMERY_R % P for v in words)).hex()
    control_left, control_right = encode_mont(right), encode_mont(left)
    control_result = engine.hash_pair(control_left, control_right)
    normalized_control = tuple(v * helper.MONTGOMERY_R_INV % P
                               for v in struct.unpack('<8I', bytes.fromhex(control_result)))
    require(memory_result == normalized_control, 'shared permutation encoding vector mismatch')
    return {
        'memory_left_normal_digest': digest_hex(left), 'memory_right_normal_digest': digest_hex(right),
        'control_left_montgomery_digest': control_left,
        'control_right_montgomery_digest': control_right,
        'identical_permutation_input_normal_words': [*right, *left, *([0] * 8)],
        'memory_output_normal_digest': digest_hex(memory_result),
        'control_output_montgomery_digest': control_result,
        'normalized_outputs_equal': True,
        'scope': 'explicit encoding alias across two hash uses; no valid proof or collision attack constructed',
        'independent_oracle_domains_established': False,
    }


def unloaded_byte_counterexample(binary: bytes) -> dict:
    """Change a concrete non-loaded byte and compare the initialized word maps."""
    user, kernel, container = split_r0bf(binary)
    entry, words, info = load_elf(user, KERNEL_START)
    offset = max(segment['file_offset'] + segment['file_bytes']
                 for segment in info['load_segments']) + 16
    require(offset < len(user), 'fixed ELF has no selected uncommitted byte')
    modified_user = bytearray(user)
    modified_user[offset] ^= 1
    modified_entry, modified_words, _ = load_elf(bytes(modified_user), KERNEL_START)
    require(entry == modified_entry and words == modified_words,
            'selected ELF byte unexpectedly changes loaded image')
    binary_offset = container['user_elf_offset'] + offset
    modified_binary = bytearray(binary)
    modified_binary[binary_offset] ^= 1
    _, modified_kernel, _ = split_r0bf(bytes(modified_binary))
    require(modified_kernel == kernel, 'metadata counterexample changed kernel')
    return {
        'user_elf_byte_offset': offset, 'composite_byte_offset': binary_offset,
        'original_byte': binary[binary_offset], 'modified_byte': modified_binary[binary_offset],
        'original_binary_sha256': sha256(binary),
        'modified_binary_sha256': sha256(bytes(modified_binary)),
        'exact_loaded_word_maps_and_entries_equal': True,
        'memory_tree_and_image_id_equal_by_identical_inputs': True,
        'modified_binary_rejected_by_fixed_artifact_digest': sha256(bytes(modified_binary)) != GUEST_SHA256,
        'scope': 'image ID binds the loaded image; separate byte pin binds this complete R0BF file',
    }


def analyze_poly_ext(source: str, tap_count: int, global_sizes: tuple[int, ...]) -> dict:
    """Abstract-interpret the generated PolyExtStep DAG, including MixState.

    The degree variables are trace-tap values over the extension field.  Public
    outputs, transcript challenges and the constraint-mixing challenge are
    fixed coefficients.  A returned bound is not an assertion that a valid
    trace exists, that a quotient is polynomial, or that FRI accepts correctly.
    """
    require(type(source) is str and len(source) <= 16 * 1024 * 1024, 'AIR: source size limit')
    require(type(tap_count) is int and tap_count > 0
            and all(type(size) is int and size >= 0 for size in global_sizes),
            'AIR: invalid input dimensions')
    clean = re.sub(r'//[^\n]*', '', source)
    definitions = list(re.finditer(
        r'pub const DEF:\s*PolyExtStepDef\s*=\s*PolyExtStepDef\s*\{\s*'
        r'block:\s*&\[(.*?)\]\s*,\s*ret:\s*(\d+)\s*,?\s*\};', clean, re.S))
    require(len(definitions) == 1, 'AIR: missing or ambiguous generated DEF')
    block, returned = definitions[0].group(1), int(definitions[0].group(2))
    token = re.compile(r'\s*PolyExtStep::([A-Za-z_][A-Za-z_0-9]*)(?:\(([^()]*)\))?\s*,')
    arities = {'Const': 1, 'ConstExt': 4, 'Get': 1, 'GetGlobal': 2,
               'Add': 2, 'Sub': 2, 'Mul': 2, 'True': 0, 'AndEqz': 2, 'AndCond': 3}
    fp: list[int] = []
    mixes: list[tuple[int, int]] = []
    counts: Counter[str] = Counter()
    used_taps: set[int] = set()
    used_globals: set[tuple[int, int]] = set()
    cursor = 0

    def previous(values: list, index: int, kind: str):
        require(index < len(values), f'AIR: forward/out-of-range {kind} variable {index}')
        return values[index]

    while cursor < len(block):
        match = token.match(block, cursor)
        if match is None and not block[cursor:].strip():
            break
        require(match is not None, 'AIR: unsupported operation syntax')
        cursor = match.end()
        name, arguments = match.groups()
        require(name in arities, f'AIR: unsupported operation {name}')
        if arguments is None:
            args = ()
        else:
            pieces = [item.strip() for item in arguments.split(',')]
            require(all(re.fullmatch(r'[0-9]+', item) is not None for item in pieces),
                    'AIR: nonliteral or negative argument')
            args = tuple(int(item) for item in pieces)
        require(len(args) == arities[name], f'AIR: wrong arity for {name}')
        counts[name] += 1
        if name in ('Const', 'ConstExt'):
            require(all(value <= 0xffffffff for value in args), 'AIR: constant outside u32')
            fp.append(0)
        elif name == 'Get':
            require(args[0] < tap_count, 'AIR: tap outside fixed tap set')
            used_taps.add(args[0])
            fp.append(1)
        elif name == 'GetGlobal':
            require(args[0] < len(global_sizes) and args[1] < global_sizes[args[0]],
                    'AIR: global outside fixed public/challenge vectors')
            used_globals.add(args)
            fp.append(0)
        elif name in ('Add', 'Sub', 'Mul'):
            left, right = (previous(fp, index, 'field') for index in args)
            fp.append(left + right if name == 'Mul' else max(left, right))
        elif name == 'True':
            # The degree-zero bound also safely covers the zero polynomial.
            mixes.append((0, 0))
        elif name == 'AndEqz':
            chain_tot, chain_mul = previous(mixes, args[0], 'mix')
            inner = previous(fp, args[1], 'field')
            # tot = chain.tot + chain.mul * inner; mul = chain.mul * mix.
            mixes.append((max(chain_tot, chain_mul + inner), chain_mul))
        elif name == 'AndCond':
            chain_tot, chain_mul = previous(mixes, args[0], 'mix')
            condition = previous(fp, args[1], 'field')
            inner_tot, inner_mul = previous(mixes, args[2], 'mix')
            # tot = chain.tot + cond * inner.tot * chain.mul.
            mixes.append((max(chain_tot, condition + inner_tot + chain_mul),
                          chain_mul + inner_mul))
    require(mixes and returned < len(mixes), 'AIR: invalid returned mix variable')
    # Match the executor's two register-bank capacity checks, not merely ret < len.
    require(len(mixes) == returned + 1, 'AIR: returned mix is not final executor register')
    require(len(fp) + len(mixes) == sum(counts.values()), 'AIR: register-bank count mismatch')
    result_tot, result_mul = mixes[returned]
    require(all(mul_degree == 0 for _, mul_degree in mixes), 'AIR: mixing multiplier not scalar')
    return {
        'operations': sum(counts.values()), 'opcode_counts': dict(sorted(counts.items())),
        'field_registers': len(fp), 'mix_registers': len(mixes), 'returned_mix_register': returned,
        'return_tot_trace_degree_upper_bound': result_tot,
        'return_mul_trace_degree_upper_bound': result_mul,
        'maximum_field_register_degree_upper_bound': max(fp, default=0),
        'maximum_mix_tot_degree_upper_bound': max(tot for tot, _ in mixes),
        'field_degree_bound_histogram': dict(sorted(Counter(fp).items())),
        'mix_tot_degree_bound_histogram': dict(sorted(Counter(tot for tot, _ in mixes).items())),
        'tap_count': tap_count, 'referenced_taps': len(used_taps),
        'maximum_referenced_tap': max(used_taps, default=None),
        'global_vector_sizes': list(global_sizes), 'referenced_global_values': len(used_globals),
        'global_vectors_are_fixed_coefficients': True,
        'mix_multiplier_is_trace_constant_everywhere': True,
        'division_or_inverse_operations': 0,
        'meaning': 'syntactic upper bound in trace-tap indeterminates over Fp4, for fixed public outputs and challenges',
    }


def air_degree_audit(archives: dict[str, dict[str, bytes]]) -> dict:
    circuits = {}
    for label, crate, prefix in (
        ('recursion', 'risc0-circuit-recursion-4.0.5', 'src/'),
        ('rv32im', 'risc0-circuit-rv32im-4.0.5', 'src/zirgen/'),
    ):
        members = archives[crate]
        poly = members[prefix + 'poly_ext.rs'].decode('utf-8')
        taps = members[prefix + 'taps.rs'].decode('utf-8')
        info = members[prefix + 'info.rs'].decode('utf-8')
        sizes = []
        for name in ('OUTPUT_SIZE', 'MIX_SIZE'):
            declarations = re.findall(r'const ' + name + r': usize = (\d+);', info)
            require(len(declarations) == 1, f'{label}: missing circuit {name}')
            sizes.append(int(declarations[0]))
        tap_count = len(re.findall(r'\bTapData\s*\{', taps))
        result = analyze_poly_ext(poly, tap_count, tuple(sizes))
        require(result['return_tot_trace_degree_upper_bound'] == 5,
                f'{label}: changed generated constraint degree bound')
        circuits[label] = {
            'crate': crate, 'member': prefix + 'poly_ext.rs', 'source_sha256': sha256(poly.encode()),
            **result,
        }
    return {
        'circuits': circuits,
        'abstract_interpreter': {
            'Const_and_ConstExt': 'degree <= 0', 'Get_trace_tap': 'degree <= 1',
            'GetGlobal_public_or_challenge': 'degree <= 0 with those arguments fixed',
            'Add_and_Sub': 'max(input bounds)', 'Mul': 'sum(input bounds)',
            'AndEqz': 'max(chain.tot, chain.mul + inner); retain scalar multiplier',
            'AndCond': 'max(chain.tot, condition + inner.tot + chain.mul); add multiplier degrees',
            'extension_coordinates': 'Fp4 multiplication is bilinear over Fp; expansion does not multiply the degree bound by four',
        },
        'conditional_univariate_consequence': {
            'premise': 'each committed trace polynomial has degree < N; public values/challenges are fixed in X',
            'mixed_numerator_degree_at_most': '5*(N-1)',
            'quotient_additional_premise': 'the mixed numerator is divisible by the degree-N zerofier (3X)^N-1',
            'quotient_degree_at_most_if_premises_hold': '4*N-5',
            'four_way_interleaved_component_degree_if_premises_hold': '< N',
            'actual_trace_divisibility_proved': False,
            'deep_fri_rational_quotient_and_denominator_events_covered': False,
        },
        'qualification': {
            'fixed_generated_constraint_dag_degree_bound_recomputed': True,
            'generator_source_to_constraints_reproduced': False,
            'constraints_encode_intended_vm_or_recursion_semantics_proved': False,
            'rbr_error_bound_instantiated': False,
        },
    }


def audit(root: Path = ROOT) -> dict:
    helper, engine, provenance, archives = load_sources(root)
    binary = read_pinned(root, GUEST_PATH, GUEST_SHA256, MAX_BINARY_BYTES)
    image_source = read_pinned(root, IMAGE_SOURCE, IMAGE_SOURCE_SHA256, 4096).decode('utf-8')
    declarations = re.findall(r'pub const IMAGE_ID: \[u32; 8\] = \[(.*?)\];', image_source, re.S)
    require(len(declarations) == 1, 'fixed verifier image declaration')
    source_words = tuple(int(word.strip()) for word in declarations[0].split(',') if word.strip())
    require(source_words == EXPECTED_IMAGE_WORDS, 'fixed verifier image words changed')
    _, kernel_elf, _ = split_r0bf(binary)
    shipped_kernel = archives['risc0-zkos-v1compat-2.2.3']['elfs/v1compat.elf']
    require(kernel_elf == shipped_kernel, 'embedded kernel differs from locked release archive')
    # This source KAT exercises page hashing, sparse indexing, suspend fields and
    # the right-before-left normal-form node encoding before the real artifact.
    kat_memory = {0x10000: 0x1234b337, SUSPEND_PC: 0x10000, SUSPEND_MODE: 1}
    kat_root, _ = memory_root(engine, kat_memory)
    require(digest_hex(kat_root) == KERNEL_KAT_HEX, 'upstream kernel-memory known-answer mismatch')
    result = recompute_binary(engine, binary)
    require(result['image_id_words'] == list(EXPECTED_IMAGE_WORDS), 'recomputed fixed image ID mismatch')
    return {
        'schema': 'TRNM-W1-QROM-SEMANTICS-AUDIT1',
        'status': 'RECOMPUTED_FIXED_GUEST_IMAGE_AND_ENCODING_BOUNDARIES',
        'provenance': provenance, 'guest_binary': {'path': GUEST_PATH, **result},
        'kernel_release_match': {
            'crate': 'risc0-zkos-v1compat-2.2.3', 'member': 'elfs/v1compat.elf',
            'bytes_equal': True, 'sha256': sha256(shipped_kernel),
            'kernel_source_to_binary_rebuilt': False,
        },
        'known_answers': {
            'zero_page': ZERO_PAGE_HEX, 'zero_memory': ZERO_MEMORY_HEX,
            'upstream_kernel_memory': KERNEL_KAT_HEX, 'all_matched': True,
        },
        'shared_poseidon_permutation_vector': shared_permutation_vector(helper, engine),
        'unloaded_elf_byte_counterexample': unloaded_byte_counterexample(binary),
        'generated_air_degree_audit': air_degree_audit(archives),
        'qualification': {
            'fixed_composite_binary_to_image_id_independently_recomputed': True,
            'embedded_kernel_matches_locked_release_binary': True,
            'fixed_generated_constraint_dag_degree_bound_recomputed': True,
            'guest_source_to_binary_rebuilt': False,
            'compiler_correctness_proved': False,
            'recursive_program_source_to_bytecode_rebuilt': False,
            'named_program_semantics_proved': False,
            'all_reachable_traces_certified': False,
            'valid_code_zero_control_digest_excluded': False,
            'general_sdk_parser_acceptance_equivalence_proved': False,
            'fresh_receipt_cryptographically_verified': False,
            'joint_hash_extraction_theorem_instantiated': False,
            'end_to_end_qrom_bound_established': False,
            'quantum_resource_to_chain_weight_correspondence_proved': False,
        },
        'commitment_scope': {
            'image_id_commits_to': 'initialized loaded memory, including user and kernel entry slots',
            'whole_binary_bytes_binding': 'separate fixed SHA-256 check; ELF section/debug bytes may be uncommitted by image ID',
            'build_source': 'risc0-build 3.0.3 constructs ProgramBinary::new(user_elf, kernel_elf); source reading only',
            'formal_compiler_or_execution_refinement': 'not established by byte reconstruction',
            'padding_zero_digest': 'control-tree padding is not a proof of an executable zero-root program or of its exclusion',
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    try:
        result = audit(args.root)
        encoded = json.dumps(result, indent=2, sort_keys=True) + '\n'
        if args.out:
            with args.out.open('x', encoding='utf-8') as stream:
                stream.write(encoded)
        else:
            print(encoded, end='')
        return 0
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, RecursionError) as error:
        print(json.dumps({'schema': 'TRNM-W1-QROM-SEMANTICS-AUDIT1',
                          'status': 'invalid_input', 'error': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
