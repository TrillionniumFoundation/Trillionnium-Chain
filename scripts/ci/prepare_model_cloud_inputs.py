#!/usr/bin/env python3
"""Transport only the original pinned public model and hash-locked CPU wheels.

No model execution, evaluation, runtime qualification or installation occurs here.
The existing pilot remains the owner of the seven model hashes and verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import llm_runtime_pilot as runtime

REQUIREMENTS = Path(__file__).resolve().parent / 'model-runtime-cpu-requirements.txt'
MAX_BUNDLE_BYTES = 768 * 1024 * 1024


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        runtime.require(newurl.startswith('https://'), 'MODEL_INPUT_REDIRECT_SCHEME')
        return super().redirect_request(request, response, code, message, headers, newurl)


def copy_exact(source, output, expected_size, expected_hash):
    """A fresh file never becomes accepted after a short, long or corrupt read."""
    digest = hashlib.sha256()
    remaining = expected_size
    created = False
    try:
        with output.open('xb') as target:
            created = True
            while remaining:
                block = source.read(min(1024 * 1024, remaining))
                runtime.require(block, 'MODEL_INPUT_SHORT_READ')
                runtime.require(len(block) <= remaining, 'MODEL_INPUT_EXCESS_BYTES')
                target.write(block)
                digest.update(block)
                remaining -= len(block)
            runtime.require(not source.read(1), 'MODEL_INPUT_EXCESS_BYTES')
        runtime.require(digest.hexdigest() == expected_hash, 'MODEL_INPUT_HASH')
    except BaseException:
        if created:
            output.unlink(missing_ok=True)
        raise


def fetch_model(output):
    output.mkdir()  # Never reuse a cache or an earlier partial material directory.
    opener = urllib.request.build_opener(HttpsOnlyRedirect())
    manifest = dict(model=runtime.MODEL, revision=runtime.REVISION, files={})
    for name, (size, digest) in sorted(runtime.PUBLIC_FILES.items()):
        url = f'https://huggingface.co/{runtime.MODEL}/resolve/{runtime.REVISION}/{name}'
        request = urllib.request.Request(url, headers={'User-Agent': 'hepta-pinned-model-inputs-v1'})
        with opener.open(request, timeout=60) as source:
            runtime.require(source.status == 200, 'MODEL_INPUT_HTTP_STATUS')
            copy_exact(source, output / name, size, digest)
        # Keep the original handoff's exact material-pin schema. Transport
        # provenance belongs to the separate input inventory below.
        manifest['files'][name] = dict(size=size, sha256=digest,
                                      revision=runtime.REVISION)
    (output / 'material-manifest.json').write_bytes(runtime.canonical(manifest) + b'\n')
    runtime.verify_materials(output)


def seal(bundle, source_report):
    runtime.verify_materials(bundle / 'model')
    lock = REQUIREMENTS.read_bytes()
    locked_hashes = set(re.findall(rb'--hash=sha256:([0-9a-f]{64})', lock))
    wheels = sorted((bundle / 'wheels').iterdir())
    runtime.require(0 < len(wheels) <= 64 and all(
        item.is_file() and not item.is_symlink() and item.suffix == '.whl'
        for item in wheels), 'MODEL_INPUT_WHEEL_SET')
    offline = []
    for wheel in wheels:
        digest = runtime.file_sha(wheel)
        runtime.require(digest.encode() in locked_hashes, 'MODEL_INPUT_UNLOCKED_WHEEL')
        runtime.require(re.fullmatch(r'[A-Za-z0-9_.+!-]+\.whl', wheel.name),
                        'MODEL_INPUT_WHEEL_NAME')
        offline.append(f'./wheels/{wheel.name} --hash=sha256:{digest}')
    # Paths keep the original wheel bytes installable with --no-index and no URL
    # lookup. pip check is still required after the complete offline installation.
    (bundle / 'offline-wheel-requirements.txt').write_text('\n'.join(offline) + '\n')
    (bundle / 'model-runtime-cpu-requirements.txt').write_bytes(lock)
    shutil.copyfile(source_report, bundle / 'source.json')
    (bundle / 'SCOPE.txt').write_text(
        'Pinned public input transport only. No model execution, efficacy, '
        'independent evaluation, runtime execution closure, ordinary installation, '
        'FinalUse, public reward or activation qualification is implied.\n'
        'For offline installation, enter this bundle and use a fresh CPython3.12 '
        'Linux x86_64 environment: python -m pip --isolated install --no-index '
        '--no-deps --require-hashes -r offline-wheel-requirements.txt; '
        'then python -m pip check.\n')
    inventory = {}
    total = 0
    for item in sorted(bundle.rglob('*')):
        runtime.require(not item.is_symlink(), 'MODEL_INPUT_SYMLINK')
        if item.is_dir():
            continue
        runtime.require(item.is_file(), 'MODEL_INPUT_FILE_TYPE')
        size = item.stat().st_size
        total += size
        runtime.require(total <= MAX_BUNDLE_BYTES, 'MODEL_INPUT_BUNDLE_BOUND')
        inventory[item.relative_to(bundle).as_posix()] = dict(
            size=size, sha256=runtime.file_sha(item))
    report = dict(schema='hepta-public-model-input-bundle-v1', model=runtime.MODEL,
                  revision=runtime.REVISION, platform='CPython3.12-Linux-x86_64',
                  source=runtime.read_json(source_report),
                  requirements_sha256=hashlib.sha256(lock).hexdigest(),
                  model_sources={name: f'https://huggingface.co/{runtime.MODEL}/resolve/{runtime.REVISION}/{name}'
                                 for name in sorted(runtime.PUBLIC_FILES)},
                  source_files_sha256={
                      'scripts/llm_runtime_pilot.py': runtime.file_sha(Path(runtime.__file__)),
                      'scripts/ci/prepare_model_cloud_inputs.py': runtime.file_sha(Path(__file__))},
                  files=inventory, total_file_bytes=total,
                  model_execution_performed=False, runtime_execution_qualified=False,
                  ordinary_installation_qualified=False, public_reward_eligible=False)
    with (bundle / 'input-manifest.json').open('xb') as handle:
        handle.write(runtime.canonical(report) + b'\n')
    print(json.dumps(dict(files=len(inventory), total_file_bytes=total,
                          model_revision=runtime.REVISION, qualifications=False)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    fetch = commands.add_parser('fetch-model')
    fetch.add_argument('--output', required=True, type=Path)
    finish = commands.add_parser('seal')
    finish.add_argument('--bundle', required=True, type=Path)
    finish.add_argument('--source-report', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'fetch-model':
        fetch_model(args.output)
    else:
        seal(args.bundle, args.source_report)


if __name__ == '__main__':
    main()
