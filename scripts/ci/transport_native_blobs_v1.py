"""Temporary pinned public blob transport; no checkout or product execution."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

REPOSITORY = 'TrillionniumFoundation/Trillionnium-Chain'
PREFIX = 'https://api.github.com/repos/' + REPOSITORY + '/git/'
PACK_BLOB = '656ee221f403f357a77209e0e8f1376bcaa1f421'
PACK_SHA256 = '6d0837deaa4da86ee7a77275818503c625a3b263402de969f22d25f47c2cfad2'
M15_PACK_BLOB = '0aa66806660311bc446079ece9920a63fdc2b53f'
M15_PACK_SHA256 = 'ef047d7eb422a8610ba26366b7e530a23ea585f98db80c6c7374ba94cf6ee777'
BLOB_PACK_SHA256 = '69920ec43462dde822cbf279b5dc901e8d6eedb6da92f6718bf9b6eca012f24c'
SLICES = ((1261, 1305), (1457, 1605), (1670, 2608), (2816, 2879),
          (3117, 3212), (3212, 4330), (4426, 11382), (11474, 14942),
          (14942, 15057))
SEEDS = {'5347b1d06e6f44990fa5d5c8c51e38176e33e0e4': 35899,
 '4fbcbafea05a271a234885f69b54f81c7a12597d': 9571,
 '96edaba4fac1ba70f5b47c5f61b418afe74b4fb5': 86420,
 'c047ba6789655de39c2d768b8e0a0e9db32e9b71': 54402,
 '7ca6b54efd62612f04d758c47c09f1d41be2ddeb': 2171,
 'f4399f0209e372048cc50b950406c5d9c8c49417': 15781,
 'c6d74e1fb69c2723aeaaba63c808577602647451': 311089,
 'fbafeda7918c34a63af912fb67bf74ec9a4933a6': 5105,
 'a0d9f33e05d196dc42f344de38a9315db86b1553': 379159}
OUTPUTS = {'.github/workflows/trnm-required-baseline.yml': 'f2ea8ec24daa4c1ae40bf138201770d8739c6ada',
 'docs/development/plan-manifest-v1.toml': '4d4aebe14254632b4bd08d612620aae27b2228b2',
 'docs/modules/TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md': '175c37d05ebb881cf829fcbcc3dfbc39aea64151',
 'trillionnium/Cargo.lock': '11fd607718aa960920690dd6b9966b6d7688e684',
 'trillionnium/crates/trnm-native-execution-v0/Cargo.toml': '81c91be77f73047148093b6bcc3812171ac20577',
 'trillionnium/crates/trnm-native-execution-v0/README.md': '48a4152367b62433bd4ecf0326518cf4626e474b',
 'trillionnium/crates/trnm-native-execution-v0/src/durable.rs': 'fb527ae869ad38e64257ea47ed453c39cd3eebb2',
 'trillionnium/crates/trnm-native-execution-v0/src/durable/namespace_v1.rs': 'a1e658b809f61804957386a3684465e9b9042ef1',
 'trillionnium/crates/trnm-native-execution-v0/src/durable/replay_floor_v1.rs': 'ce8b49ae0de4ce800b2c37f0a9b01057cbe2dbf3',
 'trillionnium/crates/trnm-poco-lab-validator/src/process_event.rs': '45c35b3eec96927cd836d63ee6b57322f7637eb3'}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('authenticated redirect refused')


def api(suffix, token, value=None):
    allowed = {PACK_BLOB, M15_PACK_BLOB} | set(SEEDS)
    require((value is not None and suffix == 'blobs') or
            (value is None and suffix.startswith('blobs/') and suffix[6:] in allowed),
            'fixed blob endpoint only')
    request = urllib.request.Request(PREFIX + suffix,
        data=None if value is None else json.dumps(value).encode(),
        method='GET' if value is None else 'POST', headers={
            'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'trnm-pinned-public-blob-transport'})
    # Record only a fixed public object path and numeric status, never
    # authorization headers or response bodies. Retrying an identical blob
    # creation is content-addressed and cannot move a branch.
    for attempt in range(3):
        print(json.dumps({'operation': request.get_method(), 'object': suffix,
                          'attempt': attempt + 1}), flush=True)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=45) as response:
                require(response.status == (200 if value is None else 201), 'HTTP status')
                raw = response.read(1500001)
                require(len(raw) <= 1500000, 'HTTP response bound')
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            print(json.dumps({'operation': request.get_method(), 'object': suffix,
                              'http_status': exc.code}), flush=True)
            if exc.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
            time.sleep(2 ** attempt)
    raise ValueError('bounded HTTP attempts exhausted')


def load_blob(sha, token):
    value = api('blobs/' + sha, token)
    require(value.get('sha') == sha and value.get('encoding') == 'base64', 'blob metadata')
    data = base64.b64decode(''.join(value['content'].split()), validate=True)
    require(len(data) <= 400000 and value.get('size') == len(data), 'blob size')
    require(digest(data) == sha, 'blob hash')
    return data


def blob_pack(encoded):
    require(digest(encoded) == PACK_BLOB and len(encoded) <= 21000, 'carrier blob')
    pack = base64.b64decode(''.join(encoded.decode('ascii').split()), validate=True)
    require(len(pack) == 15077 and hashlib.sha256(pack).hexdigest() == PACK_SHA256,
            'immutable full pack digest')
    require(pack[:12] == b'PACK' + struct.pack('>II', 2, 23), 'full pack header')
    require(hashlib.sha1(pack[:-20]).digest() == pack[-20:], 'full pack trailer')
    # Fixed byte spans were independently decoded by native Git locally. The
    # full pack remains hash-bound; only nine blob entries, not commit/tree
    # graphs or runnable code, enter the isolated transport object database.
    out = b'PACK' + struct.pack('>II', 2, 9) + b''.join(pack[a:b] for a, b in SLICES)
    out += hashlib.sha1(out).digest()
    require(len(out) == 12977 and hashlib.sha256(out).hexdigest() == BLOB_PACK_SHA256,
            'derived blob-only pack digest')
    return out


def materialize(load, directory):
    def git(*args, data=None):
        return subprocess.run(['git', '--git-dir=' + str(directory), *args], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=60).stdout
    packed = blob_pack(load(PACK_BLOB))
    encoded_m15 = load(M15_PACK_BLOB)
    require(len(encoded_m15) <= 1200 and digest(encoded_m15) == M15_PACK_BLOB,
            'M15 carrier identity')
    m15 = base64.b64decode(''.join(encoded_m15.decode('ascii').split()), validate=True)
    require(len(m15) == 829 and hashlib.sha256(m15).hexdigest() == M15_PACK_SHA256,
            'M15 blob-only pack identity')
    require(m15[:12] == b'PACK' + struct.pack('>II', 2, 1) and
            hashlib.sha1(m15[:-20]).digest() == m15[-20:], 'M15 pack envelope')
    git('init', '--bare', '--quiet', str(directory))
    for sha, length in SEEDS.items():
        data = load(sha)
        require(len(data) == length and digest(data) == sha, 'exact delta base')
        require(git('hash-object', '-w', '--stdin', data=data).decode().strip() == sha,
                'stored delta base')
    git('index-pack', '--strict', '--stdin', '--fix-thin', data=packed)
    git('index-pack', '--strict', '--stdin', '--fix-thin', data=m15)
    result = {}
    for path, sha in OUTPUTS.items():
        require(git('cat-file', '-t', sha).strip() == b'blob', 'output type')
        data = git('cat-file', 'blob', sha)
        require(len(data) <= 400000 and digest(data) == sha, 'output hash')
        result[path] = data
    require(not git('for-each-ref'), 'transport must not create refs')
    return result


def require_scope():
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'repository scope')
    require(os.environ.get('GITHUB_REF') == 'refs/heads/fix/chain-six-class-publish-20260911',
            'branch scope')
    require(os.environ.get('GITHUB_EVENT_NAME') == 'push', 'push-only scope')
    actor = os.environ.get('GITHUB_ACTOR')
    require(actor in ('ProfAlexQI', 'Franksudoman', 'ProfHepta') and
            os.environ.get('GITHUB_TRIGGERING_ACTOR') == actor, 'actor scope')
    require(re.fullmatch(r'[0-9a-f]{40}', os.environ.get('GITHUB_SHA', '')) is not None,
            'transport source identity')


def main():
    require_scope()
    token = os.environ.get('GH_TOKEN', '')
    require(bool(token), 'missing Contents token')
    with tempfile.TemporaryDirectory(prefix='trnm-pinned-blobs-', dir=os.environ['RUNNER_TEMP']) as temp:
        blobs = materialize(lambda sha: load_blob(sha, token), Path(temp) / 'objects.git')
        uploaded = []
        for path, data in blobs.items():
            require(digest(data) == OUTPUTS[path], 'publication allowlist')
            value = api('blobs', token, {'content': base64.b64encode(data).decode(), 'encoding': 'base64'})
            require(value.get('sha') == OUTPUTS[path], 'remote blob identity')
            uploaded.append({'path': path, 'sha': OUTPUTS[path]})
            print(json.dumps(uploaded[-1]), flush=True)
    print(json.dumps({'transport_head': os.environ['GITHUB_SHA'], 'uploaded_blobs': uploaded,
        'scope': 'source-blob-transport-only', 'runtime_executed': False,
        'refs_updated': False, 'acceptance_granted': False}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Never render HTTP request objects, credentials or the environment.
        print('pinned blob transport failed: ' + type(exc).__name__, flush=True)
        raise SystemExit(1)
