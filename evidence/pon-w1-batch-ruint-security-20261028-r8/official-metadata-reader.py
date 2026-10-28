#!/usr/bin/env python3
"""Read bounded public release metadata only; never fetch or run toolchains."""
import hashlib
import json
from pathlib import Path
import resource
import time
import urllib.error
import urllib.request

URL = 'https://api.github.com/repos/risc0/rust/releases?per_page=10'
OUT = Path('/tmp/w1-batch-ruint-security-20261028-r8/official-risc0-rust-releases')
MAX_BYTES = 512 * 1024


def main():
    OUT.mkdir(exist_ok=False)
    start = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_SELF)
    request = urllib.request.Request(URL, headers={
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Trillionnium-W1-read-only-dependency-review',
    })
    status = 'FAILED'
    error = None
    http_status = None
    final_url = None
    raw = b''
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            http_status = response.status
            final_url = response.url
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise RuntimeError('public metadata exceeded declared byte bound')
        value = json.loads(raw)
        if not isinstance(value, list):
            raise RuntimeError('release list JSON expected')
        selected = [
            {key: item.get(key) for key in (
                'tag_name', 'name', 'published_at', 'prerelease', 'draft',
                'html_url', 'target_commitish', 'body')}
            | {'assets': [
                {key: asset.get(key) for key in ('name', 'size', 'digest', 'browser_download_url')}
                for asset in item.get('assets', [])
            ]}
            for item in value
        ]
        (OUT / 'releases-selected.json').write_text(json.dumps(selected, indent=2) + '\n')
        status = 'READ_PUBLIC_METADATA'
    except BaseException as exception:
        error = repr(exception)
        if isinstance(exception, urllib.error.HTTPError):
            http_status = exception.code
    finally:
        if len(raw) <= MAX_BYTES:
            (OUT / 'response.json').write_bytes(raw)
        after = resource.getrusage(resource.RUSAGE_SELF)
        result = {
            'schema': 'TRNM-RISC0-RUST-OFFICIAL-RELEASES-READ1',
            'url': URL, 'final_url': final_url, 'http_status': http_status,
            'status': status, 'error': error, 'maximum_bytes': MAX_BYTES,
            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'socket_timeout_seconds': 15, 'wall_seconds': time.monotonic() - start,
            'process_cpu_seconds': (after.ru_utime + after.ru_stime)
                - (before.ru_utime + before.ru_stime),
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'toolchain_downloaded': False, 'native_or_guest_execution': False,
            'installation_or_mutation_of_toolchains': False,
        }
        (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
    if status != 'READ_PUBLIC_METADATA':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
