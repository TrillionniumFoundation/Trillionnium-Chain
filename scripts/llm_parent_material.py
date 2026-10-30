#!/usr/bin/env python3
"""Preflight explicitly pinned parent LoRA bytes, without model execution.

The caller supplies independently retained contract, adapter and file identities.
This read-only handoff checks actual factor bytes and the existing SmolLM family;
it does not select a parent, authorize installation, train, or update CURRENT.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

import llm_runtime_pilot as runtime


def read_regular(path, maximum):
    """Read a bounded regular file through one descriptor, rejecting symlinks."""
    path = Path(path)
    runtime.require(not path.is_symlink(), 'PARENT_MATERIAL_SYMLINK')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as source:
        observed = os.fstat(source.fileno())
        runtime.require(stat.S_ISREG(observed.st_mode) and 0 < observed.st_size <= maximum,
                        'PARENT_MATERIAL_FILE_LIMIT')
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        runtime.require(len(raw) == observed.st_size and
                        (observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns) ==
                        (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                        'PARENT_MATERIAL_FILE_CHANGED')
    return raw


def factor_bytes(raw, contract):
    """Parse only the bounded, complete F32 safetensors factor set we support."""
    runtime.require(len(raw) >= 10, 'PARENT_MATERIAL_HEADER')
    length = struct.unpack('<Q', raw[:8])[0]
    runtime.require(2 <= length <= 1024 * 1024 and 8 + length <= len(raw),
                    'PARENT_MATERIAL_HEADER')
    header = json.loads(raw[8:8 + length].decode('utf-8'), object_pairs_hook=runtime.unique)
    runtime.require(type(header) is dict, 'PARENT_MATERIAL_HEADER')
    metadata = header.pop('__metadata__', {})
    runtime.require(type(metadata) is dict and all(type(k) is str and type(v) is str
                    for k, v in metadata.items()), 'PARENT_MATERIAL_METADATA')
    shapes = {}
    for target in contract['targets']:
        shapes[target['module'] + '.A'] = [target['rank'], target['in_features']]
        shapes[target['module'] + '.B'] = [target['out_features'], target['rank']]
    runtime.require(set(header) == set(shapes), 'PARENT_MATERIAL_FACTOR_SET')
    payload = raw[8 + length:]
    material, intervals = {}, []
    for name, shape in shapes.items():
        value = header[name]
        runtime.require(type(value) is dict and set(value) == {'dtype', 'shape', 'data_offsets'},
                        'PARENT_MATERIAL_TENSOR_FIELDS')
        runtime.require(value['dtype'] == 'F32' and type(value['shape']) is list and
                        all(type(n) is int for n in value['shape']) and value['shape'] == shape,
                        'PARENT_MATERIAL_TENSOR_PROFILE')
        offsets = value['data_offsets']
        runtime.require(type(offsets) is list and len(offsets) == 2 and
                        all(type(n) is int for n in offsets) and
                        0 <= offsets[0] < offsets[1] <= len(payload) and
                        offsets[1] - offsets[0] == shape[0] * shape[1] * 4,
                        'PARENT_MATERIAL_TENSOR_RANGE')
        start, end = offsets
        intervals.append((start, end))
        material[name] = payload[start:end]
    cursor = 0
    for start, end in sorted(intervals):
        runtime.require(start == cursor, 'PARENT_MATERIAL_OVERLAP_OR_HOLE')
        cursor = end
    runtime.require(cursor == len(payload), 'PARENT_MATERIAL_TRAILING_BYTES')
    return material


def verify_parent(contract_path, adapter_path, artifact_path, *, expected_contract,
                  expected_adapter, expected_file_sha256):
    """Return checked factor bytes and a summary; identities confer no authority."""
    c = runtime.contract_module()
    for digest in (expected_contract, expected_adapter, expected_file_sha256):
        c.digest(digest)
    family = runtime.verify_family(runtime.read_json(runtime.FAMILY_PATH))
    raw_contract = read_regular(contract_path, c.MAX_MANIFEST_BYTES)
    contract = c.verify_target_contract(raw_contract, expected_contract,
        expected_backbone_root=family['material_pins']['fp32_backbone_index_root'],
        expected_tokenizer_root=family['material_pins']['tokenizer_files_root'])
    targets = sorted((dict(module=f'model.layers.{layer}.self_attn.{projection}',
        in_features=576, out_features=576 if projection == 'q_proj' else 192,
        rank=4, alpha=[8, 1]) for layer in range(30) for projection in ('q_proj', 'v_proj')),
        key=lambda target: target['module'])
    runtime.require(contract['architecture'] == family['architecture'] and
        contract['reference'] == runtime.MODEL + '@' + runtime.REVISION + ':derived-cpu-float32' and
        contract['numeric']['storage_dtype'] == 'float32' and
        contract['numeric']['accumulation_dtype'] == 'float32' and
        contract['numeric']['quantization'] == 'none' and contract['targets'] == targets and
        contract['ports']['batch_max'] == 1 and contract['ports']['input_tokens_max'] == 128 and
        contract['ports']['output_tokens_max'] == 16, 'PARENT_MATERIAL_FAMILY')
    raw_adapter = read_regular(adapter_path, c.MAX_MANIFEST_BYTES)
    artifact = read_regular(artifact_path, family['artifact_max_bytes'])
    runtime.require(hashlib.sha256(artifact).hexdigest() == expected_file_sha256,
                    'PARENT_MATERIAL_FILE_IDENTITY')
    material = factor_bytes(artifact, contract)
    c.verify_wrapped_adapter(raw_adapter, expected_adapter, contract, expected_contract, material)
    summary = dict(result='PASS', scope='parent-material-preflight-only-no-training-or-installation',
        contract=expected_contract, adapter=expected_adapter, file_sha256=expected_file_sha256,
        backbone=contract['backbone']['index_root'], tokenizer=contract['tokenizer']['files_root'],
        artifact_bytes=len(artifact), factor_tensors=len(material),
        factor_bytes=sum(map(len, material.values())))
    return material, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('contract', 'adapter', 'artifact', 'expected-contract', 'expected-adapter',
                 'expected-file-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        _, summary = verify_parent(args.contract, args.adapter, args.artifact,
            expected_contract=args.expected_contract, expected_adapter=args.expected_adapter,
            expected_file_sha256=args.expected_file_sha256)
    except (ValueError, KeyError, TypeError, OSError, RecursionError, OverflowError):
        print('{"result":"FAIL","error":"PARENT_MATERIAL_INVALID"}', file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
