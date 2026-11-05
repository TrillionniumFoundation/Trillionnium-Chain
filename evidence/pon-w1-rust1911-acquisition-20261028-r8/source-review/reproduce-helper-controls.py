#!/usr/bin/env python3
"""Small pure-source controls; does not fetch, install or execute a compiler."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import time

script = Path(sys.argv[1])
output = Path(sys.argv[2])
assert not output.exists(), 'control receipt must be a new file'
started = time.monotonic()
code = script.read_bytes()
ast.parse(code)
spec = importlib.util.spec_from_file_location('w1_official_compiler_acquire', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def member(name, kind=tarfile.REGTYPE, size=0, link=''):
    result = tarfile.TarInfo(name)
    result.type, result.size, result.linkname = kind, size, link
    return result


results = []


def expect(label, callback, accepted):
    try:
        callback()
        actual, detail = True, None
    except (RuntimeError, ValueError) as error:
        actual, detail = False, str(error)
    assert actual == accepted, (label, actual, accepted, detail)
    results.append({'label': label, 'expected': 'ACCEPT' if accepted else 'REJECT',
                    'observed': 'ACCEPT' if actual else 'REJECT', 'reason': detail})


expect('regular-dir-internal-symlink-hardlink', lambda: module.check_members([
    member('.', tarfile.DIRTYPE), member('bin', tarfile.DIRTYPE),
    member('bin/rustc', size=17), member('rustc', tarfile.SYMTYPE, link='bin/rustc'),
    member('bin/rustc-copy', tarfile.LNKTYPE, link='bin/rustc')]), True)
for label, items in [
    ('absolute-member', [member('/tmp/outside')]),
    ('parent-member', [member('../outside')]),
    ('normalized-parent-member', [member('a/../../outside')]),
    ('absolute-symlink', [member('link', tarfile.SYMTYPE, link='/tmp/outside')]),
    ('parent-symlink', [member('dir/link', tarfile.SYMTYPE, link='../../outside')]),
    ('parent-hardlink', [member('link', tarfile.LNKTYPE, link='../outside')]),
    ('special-fifo', [member('fifo', tarfile.FIFOTYPE)]),
    ('normalized-duplicate', [member('./rustc'), member('rustc')]),
    ('archive-size-cap', [member('huge', size=module.MAX_EXTRACTED_BYTES + 1)]),
    ('member-count-cap', [member('f' + str(i)) for i in range(module.MAX_MEMBERS + 1)]),
    ('regular-root', [member('.')]),
    ('nul-member', [member('a\0b')]),
    ('empty-member', [member('')]),
]:
    expect(label, lambda items=items: module.check_members(items), False)
for url in ['https://github.com/risc0/rust/releases/file',
            'https://release-assets.githubusercontent.com/asset']:
    expect('official-https-' + url.split('/')[2],
           lambda url=url: module.require_official_https(url), True)
for url in ['http://github.com/asset', 'https://example.com/asset',
            'https://evil.github.com/asset', 'https://user:pass@github.com/asset',
            'https://github.com:444/asset']:
    expect('redirect-reject-' + url, lambda url=url: module.require_official_https(url), False)
assert module.member_allocated_bound(member('small', size=4097)) == 8192
source_text = code.decode()
assert source_text.index("(out / 'archive-member-inventory.json').write_text") < source_text.index(
    'require(free_bytes() - allocation - reserve >= FLOOR')
assert "filter='data'" in source_text
assert 'member_allocated_bound(member) >= FLOOR + 4 * BLOCK' in source_text
record = {
    'schema': 'TRNM-COMPILER-ACQUISITION-SOURCE-CONTROLS1', 'status': 'PASS',
    'source_sha256': hashlib.sha256(code).hexdigest(),
    'wall_seconds': time.monotonic() - started, 'controls': results,
    'source_order_check_inventory_before_capacity_refusal': True,
    'regular_member_allocation_rounding_check': True,
    'official_archive_downloaded': False, 'compiler_installed_or_executed': False,
    'network_used': False,
    'limits': 'Pure helper/source controls only; not real archive, target ABI or prover compatibility evidence.',
}
with output.open('x') as handle:
    json.dump(record, handle, indent=2)
    handle.write('\n')
print(json.dumps({'status': 'PASS', 'control_count': len(results),
                  'source_sha256': record['source_sha256']}))
