#!/usr/bin/env python3
"""Prepare explicit local-research inputs for the native CHB1 executable.

This command reads existing materials and writes one create-only input manifest.
It neither starts a model nor claims independent custody, payment or FinalUse.
The operator must retain and admit the printed manifest SHA-256 before launch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

import llm_cell_sealed_worker_v1 as profile


def capture(path, maximum, expected=None):
    path = Path(path)
    profile.require(path.is_absolute(), 'PREPARATION_ABSOLUTE_INPUT')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as source:
        before = os.fstat(source.fileno())
        profile.require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                        'PREPARATION_INPUT_BOUND')
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    profile.require(len(raw) == before.st_size and
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
        'PREPARATION_INPUT_CHANGED')
    digest = hashlib.sha256(raw).hexdigest()
    profile.require(expected is None or digest == expected, 'PREPARATION_INDEPENDENT_PIN')
    return {'path':str(path), 'sha256':digest}, raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'materials', 'parent', 'parent-sha256', 'python', 'python-sha256',
                 'runtime-snapshot', 'runtime-snapshot-sha256', 'requests', 'requests-sha256',
                 'operation', 'output', 'manifest'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--material-profile', required=True,
                        choices=(profile.CURRENT_MATERIAL, profile.BRIDGED_MATERIAL))
    parser.add_argument('--material-plan')
    parser.add_argument('--material-plan-sha256')
    parser.add_argument('--seconds', type=int, default=300)
    parser.add_argument('--max-snapshot-bytes', type=int, default=512 * 1024**2)
    parser.add_argument('--runtime-rss-bytes', type=int, default=8 * 1024**3)
    parser.add_argument('--threads', type=int, default=4)
    parser.add_argument('--environment-generation', type=int, default=1)
    args = parser.parse_args()
    profile.require(profile.digest(args.operation) and args.operation != '00' * 32
        and 1 <= args.seconds <= 300 and 1 <= args.max_snapshot_bytes <= 512 * 1024**2
        and 1 <= args.runtime_rss_bytes <= 8 * 1024**3 and 1 <= args.threads <= 4
        and 0 < args.environment_generation < 2**63, 'PREPARATION_FINITE_ORIGINAL_ALLOWANCES')
    root, base = Path(args.repo).resolve(strict=True), Path(args.materials).resolve(strict=True)
    output = Path(args.output)
    profile.require(output.is_absolute() and not output.exists()
        and output.parent.resolve(strict=True) == output.parent, 'PREPARATION_CREATE_ONLY_OUTPUT')
    _, raw = capture(args.parent, 128 * 1024, args.parent_sha256)
    parent = profile.decode(raw)
    profile.require(type(parent) is dict and set(parent) == {'schema', 'generation', 'operation_id',
        'directory', 'contract', 'adapter', 'file_sha256'} and
        parent['schema'] == 'hepta-smollm-parent-material-v1' and type(parent['generation']) is int
        and 1 <= parent['generation'] < 2**63 and type(parent['operation_id']) is str
        and 1 <= len(parent['operation_id'].encode()) <= 128
        and all(profile.digest(parent[key]) for key in ('contract','adapter','file_sha256')),
        'PREPARATION_ORIGINAL_PARENT')
    adapter = Path(parent['directory'])
    profile.require(adapter.is_absolute() and adapter.resolve(strict=True) == adapter,
                    'PREPARATION_PARENT_DIRECTORY')
    model, environment, total = {}, {}, 0
    target = None
    for name in sorted(profile.MODEL_FILES):
        scope, relative = name.split('/', 1)
        path = (base if scope == 'base' else adapter) / relative
        expected = parent['file_sha256'] if name == 'adapter/artifact.safetensors' else None
        model[name], raw = capture(path, 512 * 1024**2, expected)
        total += len(raw)
        if name == 'adapter/target-contract.json':
            target = profile.decode(raw)
        del raw
    for name in sorted(profile.ENVIRONMENT - {profile.SNAPSHOT_PATH}):
        environment[name], raw = capture(root / name, 16 * 1024**2)
        total += len(raw)
        del raw
    environment[profile.SNAPSHOT_PATH], raw = capture(
        args.runtime_snapshot, 16 * 1024**2, args.runtime_snapshot_sha256)
    total += len(raw)
    runtime_snapshot = profile.decode(raw)
    del raw
    if args.material_profile == profile.BRIDGED_MATERIAL:
        profile.require(args.material_plan is not None and args.material_plan_sha256 ==
            '01ec1a644f37b9fc7a4c6616f589768df97f8eed7a289b5de86afadaa7ce6165',
            'PREPARATION_EXPLICIT_MATERIAL_BRIDGE')
        environment[profile.MATERIAL_PLAN_PATH], raw = capture(
            args.material_plan, 64 * 1024, args.material_plan_sha256)
        total += len(raw)
        profile.require(model['adapter/target-contract.json']['sha256'] ==
            'ebc8ac84999a91acb823d1bf8959a7dbc61fe20d7ba137f11affe426605d9852'
            and parent['contract'] == 'c9b06f9a029a3257801844f89acb59b5f59f6a39087335af323f274e9152992f'
            and environment[profile.MODULES['llm_runtime_pilot']]['sha256'] ==
            'ac6b1d9058610907a7dd3486c663c1ee6ad40135a34c63770daa5f556e5879cc',
            'PREPARATION_ORIGINAL_CLOSED_BRIDGE_PAIR')
    else:
        profile.require(args.material_plan is None and args.material_plan_sha256 is None,
                        'PREPARATION_UNDECLARED_BRIDGE')
    profile.require(total <= args.max_snapshot_bytes, 'PREPARATION_COMPLETE_SNAPSHOT_ALLOWANCE')
    python, _ = capture(Path(args.python).resolve(strict=True), 512 * 1024**2, args.python_sha256)
    profile.require(runtime_snapshot['python']['executable'] == python['path'] and
        runtime_snapshot['files'][python['path']] == python['sha256'], 'PREPARATION_RUNTIME_INTERPRETER')
    _, raw = capture(args.requests, 16 * 1024, args.requests_sha256)
    requests = profile.decode(raw)
    profile.require(type(requests) is list and len(requests) == 2 and
        all(type(row) is dict and set(row) == {'request_id','prompt'}
            and type(row['request_id']) is str and 1 <= len(row['request_id'].encode()) <= 128
            and type(row['prompt']) is str and 1 <= len(row['prompt'].encode()) <= 2048
            for row in requests) and requests[0]['request_id'] != requests[1]['request_id'],
            'PREPARATION_TWO_ORIGINAL_TASKS')
    _, raw = capture(root / 'config/pon/model-family-smollm2-135m-v1.json', 1024 * 1024,
                    environment['config/pon/model-family-smollm2-135m-v1.json']['sha256'])
    family = profile.decode(raw)
    manifest = dict(schema='trnm.cell-sealed-research-source.v1', operation=args.operation,
        context=dict(family=family['id'], base=target['backbone']['index_root'],
            parent=parent['file_sha256'], tokenizer=target['tokenizer']['files_root'],
            layout=parent['contract'], runtime=environment[profile.WORKER_PATH]['sha256']),
        environment_generation=args.environment_generation, model=model, environment=environment,
        python=python, output=str(output), seconds=args.seconds,
        max_snapshot_bytes=args.max_snapshot_bytes, runtime_rss_bytes=args.runtime_rss_bytes,
        threads=args.threads, material_profile=args.material_profile,
        parent={key:parent[key] for key in ('generation','operation_id','contract','adapter','file_sha256')},
        requests=requests)
    encoded = profile.canonical(manifest) + b'\n'
    profile.require(len(encoded) <= 128 * 1024, 'PREPARATION_MANIFEST_BOUND')
    path = Path(args.manifest)
    profile.require(path.is_absolute(), 'PREPARATION_MANIFEST_PATH')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), 'wb') as out:
        out.write(encoded); out.flush(); os.fsync(out.fileno())
    print(json.dumps(dict(schema='trnm.cell-sealed-research-input-preparation.v1',
        manifest=str(path), sha256=profile.sha(encoded), payload_bytes=total,
        manifest_count=len(model) + len(environment), native_executed=False,
        model_executed=False, authority=profile.NO_AUTHORITY), sort_keys=True))


if __name__ == '__main__':
    main()
