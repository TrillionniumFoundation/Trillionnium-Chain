#!/usr/bin/env python3
"""Bounded read-only official tag/target metadata, with no toolchain install."""
import hashlib
import json
from pathlib import Path
import re
import resource
import time
import urllib.request

OUT = Path('/tmp/w1-risc0-official-target-specs-20261028-r8')
MAX_RESPONSE = 128 * 1024
MAX_TOTAL = 768 * 1024
FILE = 'compiler/rustc_target/src/spec/targets/riscv32im_risc0_zkvm_elf.rs'


def main():
    OUT.mkdir(exist_ok=False)
    started = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_SELF)
    rows = []
    total = 0
    status = 'FAILED'
    error = None

    def get(label, url):
        nonlocal total
        if time.monotonic() - started > 42:
            raise RuntimeError('total metadata deadline reached')
        request = urllib.request.Request(url, headers={
            'User-Agent': 'Trillionnium-W1-read-only-target-review',
            'Accept': 'application/vnd.github+json' if url.startswith('https://api.github.com/')
                else 'text/plain',
        })
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read(MAX_RESPONSE + 1)
            code = response.status
            final_url = response.url
        if len(raw) > MAX_RESPONSE or total + len(raw) > MAX_TOTAL:
            raise RuntimeError('public metadata byte bound exceeded')
        total += len(raw)
        (OUT / label).write_bytes(raw)
        rows.append({'path': label, 'url': url, 'final_url': final_url,
                     'http_status': code, 'bytes': len(raw),
                     'sha256': hashlib.sha256(raw).hexdigest()})
        return raw

    try:
        for version in ('1.88.0', '1.91.1'):
            tag = 'r0.' + version
            raw = get(version + '-tag.json',
                      'https://api.github.com/repos/risc0/rust/git/ref/tags/' + tag)
            obj = json.loads(raw)['object']
            if obj['type'] == 'tag':
                if re.fullmatch(r'[0-9a-f]{40}', obj['sha']) is None:
                    raise RuntimeError('invalid annotated tag SHA')
                raw = get(version + '-tag-object.json',
                          'https://api.github.com/repos/risc0/rust/git/tags/' + obj['sha'])
                obj = json.loads(raw)['object']
            if obj['type'] != 'commit' or re.fullmatch(r'[0-9a-f]{40}', obj['sha']) is None:
                raise RuntimeError('official release tag did not resolve to a commit')
            commit = obj['sha']
            get(version + '-riscv32im-risc0-zkvm-elf.rs',
                'https://raw.githubusercontent.com/risc0/rust/' + commit + '/' + FILE)
        status = 'READ_PUBLIC_TARGET_SOURCES'
    except BaseException as exception:
        error = repr(exception)
    finally:
        after = resource.getrusage(resource.RUSAGE_SELF)
        result = {
            'schema': 'TRNM-RISC0-OFFICIAL-TARGET-SOURCE-READ1', 'status': status,
            'error': error, 'records': rows, 'total_bytes': total,
            'max_response_bytes': MAX_RESPONSE, 'max_total_bytes': MAX_TOTAL,
            'wall_seconds': time.monotonic() - started,
            'process_cpu_seconds': (after.ru_utime + after.ru_stime)
                - (before.ru_utime + before.ru_stime),
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'compiler_downloaded': False, 'source_executed': False,
            'compiler_installed_or_executed': False,
        }
        (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
    if status != 'READ_PUBLIC_TARGET_SOURCES':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
