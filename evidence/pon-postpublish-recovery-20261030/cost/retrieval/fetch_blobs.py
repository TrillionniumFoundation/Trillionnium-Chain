from pathlib import Path
import base64
import concurrent.futures
import datetime
import hashlib
import json
import urllib.request


ROOT = Path('/tmp/recovery-cost')
ITEMS = [
    ('native-v5-stdout', '581b49bfef116c952903c6519c9f179c4cdd6214',
     '6781436c5acfc932df0aac3d46ee1f04c9e987158d87d74f107ed542529dbe7d'),
    ('native-v5-binary', '93c4e04b5cbf8c4ae180f2258f26a4af06475f68',
     'b876349e5f5c3dbebeb50f4c791cfaecc72911d59276383136d1b98b46cc2c9e'),
]


def retrieve(item):
    name, oid, expected = item
    url = 'https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/git/blobs/' + oid
    record = {
        'name': name, 'git_blob_oid': oid, 'url': url,
        'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'requested_accept': 'application/vnd.github.raw+json',
        'attempt': 2, 'execution_permission': 'require_escalated',
        'inherited_proxy_and_tls_verification_preserved': True,
    }
    try:
        request = urllib.request.Request(url, headers={
            'Accept': 'application/vnd.github.raw+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'Trillionnium-evidence-recovery',
        })
        with urllib.request.urlopen(request, timeout=40) as response:
            body = response.read(16 * 1024 * 1024 + 1)
            record.update(status=response.status,
                          content_type=response.headers.get('Content-Type'),
                          response_bytes=len(body))
        if len(body) > 16 * 1024 * 1024:
            raise ValueError('response bound exceeded')
        if body.startswith(b'{'):
            obj = json.loads(body)
            if obj['sha'] != oid or obj['encoding'] != 'base64':
                raise ValueError('unexpected Git blob JSON identity or encoding')
            data = base64.b64decode(obj['content'])
            record['transport_shape'] = 'Git blob JSON with base64'
        else:
            data = body
            record['transport_shape'] = 'raw Git blob bytes'
        actual = hashlib.sha256(data).hexdigest()
        git_oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        record.update(bytes=len(data), sha256=actual, computed_git_blob_oid=git_oid,
                      expected_sha256=expected, sha256_matches=actual == expected,
                      git_oid_matches=git_oid == oid)
        if actual != expected or git_oid != oid:
            raise ValueError('download does not match pinned SHA-256 and Git object identity')
        destination = ROOT / (name + '.gz')
        destination.write_bytes(data)
        record.update(saved_path=str(destination), success=True)
    except Exception as exc:
        record.update(success=False, error_type=type(exc).__name__, error=str(exc))
    record['finished_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (ROOT / (name + '-retrieval-attempt2.json')).write_text(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(retrieve, ITEMS))
    for result in results:
        print(json.dumps(result))
    raise SystemExit(0 if all(result['success'] for result in results) else 1)
