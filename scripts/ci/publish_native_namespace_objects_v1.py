#!/usr/bin/env python3
"""One-use, exact-object transport; never move refs or assert qualification.

This carrier imports a hash-pinned, locally tested public Git pack and uploads
only the nine allowlisted blobs. No candidate source or build script is run.
The carrier and its payload must be absent from the final product tree.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

REPOSITORY = 'TrillionniumFoundation/Trillionnium-Chain'
BRANCH = 'refs/heads/fix/chain-six-class-publish-20260911'
BASE = '8bf4d2caab0289d77478ca8fed3a7ea32d39af06'
TESTED_COMMIT = 'a00cd7db1e92e0a8d310939a137e114272f1cb62'
TESTED_TREE = 'eb2799773b9c243333b5f1290d17d90825b5f4e0'
PACK_SHA256 = '6d0837deaa4da86ee7a77275818503c625a3b263402de969f22d25f47c2cfad2'
PACK_SIZE = 15077
BLOBS = {
    '.github/workflows/trnm-required-baseline.yml': 'f2ea8ec24daa4c1ae40bf138201770d8739c6ada',
    'docs/development/plan-manifest-v1.toml': '4d4aebe14254632b4bd08d612620aae27b2228b2',
    'docs/modules/TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md': '175c37d05ebb881cf829fcbcc3dfbc39aea64151',
    'trillionnium/Cargo.lock': '11fd607718aa960920690dd6b9966b6d7688e684',
    'trillionnium/crates/trnm-native-execution-v0/Cargo.toml': '81c91be77f73047148093b6bcc3812171ac20577',
    'trillionnium/crates/trnm-native-execution-v0/README.md': '48a4152367b62433bd4ecf0326518cf4626e474b',
    'trillionnium/crates/trnm-native-execution-v0/src/durable.rs': 'fb527ae869ad38e64257ea47ed453c39cd3eebb2',
    'trillionnium/crates/trnm-native-execution-v0/src/durable/namespace_v1.rs': 'a1e658b809f61804957386a3684465e9b9042ef1',
    'trillionnium/crates/trnm-native-execution-v0/src/durable/replay_floor_v1.rs': 'ce8b49ae0de4ce800b2c37f0a9b01057cbe2dbf3',
}
DELETED = 'scripts/ci/package_offline_rust_inputs_v1.sh'


def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(['git', *args], input=data, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=60).stdout


def require(condition: bool, explanation: str) -> None:
    if not condition:
        raise ValueError(explanation)


def verify(pack_file: Path) -> dict[str, bytes]:
    require(pack_file.is_file() and not pack_file.is_symlink(), 'pack file policy')
    require(pack_file.stat().st_size <= 21000, 'encoded pack length')
    text = pack_file.read_text(encoding='ascii')
    pack = base64.b64decode(''.join(text.split()), validate=True)
    require(len(pack) == PACK_SIZE, 'decoded pack length')
    require(hashlib.sha256(pack).hexdigest() == PACK_SHA256, 'pack digest')
    git('cat-file', '-e', BASE + '^{commit}')
    git('index-pack', '--strict', '--stdin', '--fix-thin', data=pack)
    require(git('show', '-s', '--format=%P', TESTED_COMMIT).decode().strip() == BASE,
            'tested source parent')
    require(git('rev-parse', TESTED_COMMIT + '^{tree}').decode().strip() == TESTED_TREE,
            'tested source tree')
    changes = set(git('diff-tree', '--no-commit-id', '--name-only', '-r', '-z',
                      BASE, TESTED_COMMIT).decode().strip('\0').split('\0'))
    require(changes == set(BLOBS) | {DELETED}, 'changed path allowlist')
    require(not git('ls-tree', TESTED_COMMIT, '--', DELETED), 'retired helper deletion')
    result = {}
    for path, expected in BLOBS.items():
        entry = git('ls-tree', TESTED_COMMIT, '--', path).decode().strip()
        require(entry == f'100644 blob {expected}\t{path}', 'exact blob entry')
        data = git('cat-file', 'blob', expected)
        require(len(data) <= 400000, 'blob size bound')
        calculated = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        require(calculated == expected, 'local blob identity')
        result[path] = data
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('authenticated API redirect refused')


def publish(blobs: dict[str, bytes]) -> list[dict[str, str]]:
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'repository scope')
    require(os.environ.get('GITHUB_REF') == BRANCH, 'branch scope')
    require(os.environ.get('GITHUB_EVENT_NAME') == 'push', 'push-only scope')
    require(git('rev-parse', 'HEAD').decode().strip() == os.environ.get('GITHUB_SHA'),
            'transport checkout identity')
    token = os.environ.get('GH_TOKEN', '')
    require(bool(token), 'missing Contents-write token')
    # Fixed endpoint, TLS certificate validation and no redirects. No refs,
    # branches, status, review, protection, workflow or release writes exist.
    endpoint = f'https://api.github.com/repos/{REPOSITORY}/git/blobs'
    opener = urllib.request.build_opener(NoRedirect())
    accepted = []
    for path, data in blobs.items():
        body = json.dumps({'content': base64.b64encode(data).decode(),
                           'encoding': 'base64'}).encode()
        request = urllib.request.Request(endpoint, data=body, method='POST', headers={
            'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'trnm-exact-blob-transport',
        })
        with opener.open(request, timeout=45) as response:
            require(response.status == 201, 'blob creation status')
            raw = response.read(65537)
            require(len(raw) <= 65536, 'API response length')
            result = json.loads(raw)
        require(result.get('sha') == BLOBS[path], 'remote blob identity')
        accepted.append({'path': path, 'sha': BLOBS[path]})
        print(json.dumps(accepted[-1]), flush=True)
    return accepted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--pack', type=Path, default=Path(__file__).with_name('native_namespace_objects_v1.pack.b64'))
    args = parser.parse_args()
    before = git('rev-parse', 'HEAD').decode().strip()
    require(not git('status', '--porcelain', '--untracked-files=all'), 'unclean carrier')
    blobs = verify(args.pack)
    accepted = publish(blobs) if args.publish else []
    require(git('rev-parse', 'HEAD').decode().strip() == before, 'carrier ref movement')
    require(not git('status', '--porcelain', '--untracked-files=all'), 'carrier modified')
    report = {
        'scope': 'exact-source-blobs-only-not-acceptance',
        'base': BASE, 'locally_tested_commit': TESTED_COMMIT, 'tree': TESTED_TREE,
        'pack_sha256': PACK_SHA256, 'verified_blobs': BLOBS,
        'uploaded_blobs': accepted, 'ref_updated': False,
        'runtime_executed_by_transport': False, 'production_activation': False,
    }
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        # Do not dump HTTP request objects, headers, credentials or environment.
        print(f'object transport failed closed: {type(exc).__name__}', file=sys.stderr)
        raise SystemExit(1)
