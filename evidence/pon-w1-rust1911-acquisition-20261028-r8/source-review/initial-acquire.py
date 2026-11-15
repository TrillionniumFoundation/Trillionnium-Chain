#!/usr/bin/env python3
"""One-shot official compiler fetch or authenticated complete installation.

Fetch requires the separately scoped network approval. Install is local-only
and must run under the namespace-safe resource supervisor. Neither mode invokes
Cargo, a guest program, a receipt verifier or a prover.
"""
import hashlib
import json
import os
from pathlib import Path
import posixpath
import resource
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request

BASE = Path('/tmp/w1-risc0-1911-resources-r8')
ARCHIVE = BASE / 'rust-1.91.1.tar.gz'
RISC0_HOME = BASE / 'home'
COMPILER = RISC0_HOME / 'toolchains/v1.91.1-rust-x86_64-unknown-linux-gnu'
URL = 'https://github.com/risc0/rust/releases/download/r0.1.91.1/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz'
ARCHIVE_BYTES = 515330687
ARCHIVE_SHA256 = 'e082a1dc44abdef1d95460295a70218eb294ab999b834570ec932d05641cce5d'
FLOOR = 1073741824
PROJECTED_EXTRACTED_BYTES = 1744830464  # 1.625 GiB; estimate, never actual-size evidence.
MAX_EXTRACTED_BYTES = 2147483648
MAX_MEMBERS = 4096
BLOCK = 1024 * 1024


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(BLOCK), b''):
            result.update(chunk)
    return result.hexdigest()


def free_bytes():
    value = os.statvfs(BASE)
    return value.f_bavail * value.f_frsize


def usage():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'self_cpu_seconds': own.ru_utime + own.ru_stime,
            'child_cpu_seconds': children.ru_utime + children.ru_stime,
            'self_peak_rss_bytes': own.ru_maxrss * 1024,
            'child_peak_single_process_rss_bytes': children.ru_maxrss * 1024}


def emit(out, value):
    row = {'unix_ns': time.time_ns(), **value}
    with (out / 'acquisition-events.jsonl').open('a') as handle:
        handle.write(json.dumps(row, sort_keys=True) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    print(json.dumps(row, sort_keys=True), flush=True)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def fetch(out):
    require(not ARCHIVE.exists(), 'already-present archive must be separately adopted, never overwritten')
    partial = BASE / 'rust-1.91.1.tar.gz.partial'
    require(not partial.exists(), 'prior partial download retained; no retry or resume')
    free = free_bytes()
    require(free - ARCHIVE_BYTES - PROJECTED_EXTRACTED_BYTES >= FLOOR,
            'space precheck: projected complete acquisition would violate 1 GiB floor')
    emit(out, {'stage': 'DOWNLOAD', 'state': 'STARTED', 'url': URL,
               'expected_bytes': ARCHIVE_BYTES, 'expected_sha256': ARCHIVE_SHA256,
               'maximum_wall_seconds': 180, 'socket_timeout_seconds': 15,
               'free_before_bytes': free,
               'projected_extracted_bytes_not_measurement': PROJECTED_EXTRACTED_BYTES})
    started = time.monotonic()
    total = 0
    value = hashlib.sha256()
    request = urllib.request.Request(URL, headers={
        'User-Agent': 'Trillionnium-W1-bounded-official-compiler-acquisition',
        'Accept': 'application/octet-stream',
    })
    with urllib.request.urlopen(request, timeout=15) as response, partial.open('xb') as handle:
        final_url = response.url
        while True:
            require(time.monotonic() - started < 180, 'download wall deadline')
            chunk = response.read(min(BLOCK, ARCHIVE_BYTES - total + 1))
            if not chunk:
                break
            require(total + len(chunk) <= ARCHIVE_BYTES, 'archive byte limit exceeded')
            require(free_bytes() - len(chunk) >= FLOOR, 'free-disk floor before download write')
            handle.write(chunk)
            value.update(chunk)
            total += len(chunk)
            if total % (16 * BLOCK) == 0:
                handle.flush()
                emit(out, {'stage': 'DOWNLOAD', 'state': 'PROGRESS', 'bytes': total,
                           'wall_seconds': time.monotonic() - started, 'free_bytes': free_bytes()})
        handle.flush()
        os.fsync(handle.fileno())
    require(total == ARCHIVE_BYTES, 'exact official archive byte length mismatch')
    require(value.hexdigest() == ARCHIVE_SHA256, 'official archive SHA-256 mismatch')
    require(not ARCHIVE.exists(), 'refuse archive overwrite')
    partial.rename(ARCHIVE)
    emit(out, {'stage': 'DOWNLOAD', 'state': 'CHECKSUM_VERIFIED', 'bytes': total,
               'sha256': value.hexdigest(), 'final_url': final_url,
               'wall_seconds': time.monotonic() - started, 'free_after_bytes': free_bytes()})
    return {'outcome': 'OFFICIAL_ARCHIVE_DOWNLOADED_AND_VERIFIED', 'archive_sha256': value.hexdigest(),
            'archive_bytes': total, 'compiler_installed': False, 'compiler_executed': False}


def member_name(member):
    name = posixpath.normpath(member.name)
    require(not posixpath.isabs(name) and name != '..' and not name.startswith('../'),
            'archive member escapes declared root')
    return name


def check_members(members):
    require(len(members) <= MAX_MEMBERS, 'archive member count cap')
    names = set()
    allocation = 0
    logical = 0
    records = []
    for member in members:
        name = member_name(member)
        require(name not in names, 'duplicate archive path')
        names.add(name)
        require(member.isdir() or member.isreg() or member.issym() or member.islnk(),
                'archive special file is not allowed')
        if member.isreg():
            require(0 <= member.size <= MAX_EXTRACTED_BYTES, 'archive member size bound')
            logical += member.size
            allocation += ((member.size + 4095) // 4096) * 4096
        elif member.isdir() or member.issym():
            allocation += 4096
        if member.issym() or member.islnk():
            require(not posixpath.isabs(member.linkname), 'absolute archive link')
            link_base = posixpath.dirname(name) if member.issym() else ''
            target = posixpath.normpath(posixpath.join(link_base, member.linkname))
            require(target != '..' and not target.startswith('../'), 'archive link escapes root')
        records.append({'name': member.name, 'normalized_name': name, 'size': member.size,
                        'type': member.type.decode('ascii', errors='replace'),
                        'linkname': member.linkname})
    require(logical <= MAX_EXTRACTED_BYTES and allocation <= MAX_EXTRACTED_BYTES,
            'complete extraction byte budget exceeded')
    return logical, allocation, records


def run_version(out, label, argv):
    started = time.monotonic()
    emit(out, {'stage': label, 'state': 'STARTED', 'argv': argv})
    with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=15)
    emit(out, {'stage': label, 'state': 'EXIT', 'returncode': result.returncode,
               'wall_seconds': time.monotonic() - started,
               'stdout_sha256': digest(out / (label + '.stdout')),
               'stderr_sha256': digest(out / (label + '.stderr'))})
    require(result.returncode == 0, 'official compiler metadata command failed')
    return (out / (label + '.stdout')).read_text()


def install(out):
    require(ARCHIVE.is_file() and ARCHIVE.stat().st_size == ARCHIVE_BYTES,
            'complete exact archive required')
    require(digest(ARCHIVE) == ARCHIVE_SHA256, 'authenticated archive changed before extraction')
    require(not RISC0_HOME.exists(), 'fresh independent RISC0_HOME required; never overwrite a prior tree')
    started = time.monotonic()
    emit(out, {'stage': 'ARCHIVE_INSPECTION', 'state': 'STARTED', 'archive_sha256': ARCHIVE_SHA256})
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        members = archive.getmembers()
        logical, allocation, records = check_members(members)
    # Filesystem directory/accounting overhead and other activity are kept
    # outside the header sum. The supervisor separately samples actual bytes.
    reserve = 16 * BLOCK
    require(free_bytes() - allocation - reserve >= FLOOR,
            'actual complete archive headers plus overhead would violate free-disk floor')
    (out / 'archive-member-inventory.json').write_text(json.dumps({
        'schema': 'TRNM-RISC0-1911-AUTHENTICATED-TAR-INVENTORY1',
        'archive_sha256': ARCHIVE_SHA256, 'regular_logical_bytes': logical,
        'projected_allocated_bytes_from_headers': allocation, 'overhead_reserve_bytes': reserve,
        'members': records,
    }, indent=2) + '\n')
    emit(out, {'stage': 'ARCHIVE_INSPECTION', 'state': 'PASSED', 'members': len(members),
               'logical_bytes': logical, 'projected_allocated_bytes': allocation,
               'wall_seconds': time.monotonic() - started, 'free_before_extract_bytes': free_bytes()})
    COMPILER.mkdir(parents=True, exist_ok=False)
    extraction_started = time.monotonic()
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        # Use the complete archive, not a selective/minimal compiler. Python's
        # data filter rechecks actual paths and links while extracting.
        for member in archive:
            require(time.monotonic() - extraction_started < 100, 'extraction wall deadline')
            require(free_bytes() >= FLOOR + 4 * BLOCK, 'free-disk floor during extraction')
            archive.extract(member, COMPILER, filter='data')
    tree = []
    seen = set()
    allocated = 0
    for path in sorted(COMPILER.rglob('*')):
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            require(resolved == COMPILER or COMPILER in resolved.parents, 'installed symlink escaped root')
            tree.append({'path': str(path.relative_to(COMPILER)), 'symlink': os.readlink(path)})
        elif path.is_file():
            value = path.stat()
            identity = (value.st_dev, value.st_ino)
            if identity not in seen:
                seen.add(identity)
                allocated += value.st_blocks * 512
            tree.append({'path': str(path.relative_to(COMPILER)), 'bytes': value.st_size,
                         'allocated_bytes': value.st_blocks * 512, 'sha256': digest(path)})
    require(allocated <= MAX_EXTRACTED_BYTES and free_bytes() >= FLOOR,
            'actual installation byte budget or free-disk floor')
    (out / 'installed-tree.json').write_text(json.dumps({
        'schema': 'TRNM-RISC0-1911-INSTALLED-TREE1', 'allocated_unique_regular_bytes': allocated,
        'files': tree,
    }, indent=2) + '\n')
    settings = '[default_versions]\nrust = "1.91.1"\n'
    with (RISC0_HOME / 'settings.toml').open('x') as handle:
        handle.write(settings)
        handle.flush()
        os.fsync(handle.fileno())
    emit(out, {'stage': 'COMPLETE_EXTRACTION', 'state': 'COMPLETE',
               'wall_seconds': time.monotonic() - extraction_started,
               'actual_allocated_unique_regular_bytes': allocated,
               'settings_sha256': digest(RISC0_HOME / 'settings.toml')})
    compiler = str(COMPILER / 'bin/rustc')
    version = run_version(out, 'rustc-version-verbose', [compiler, '--version', '--verbose'])
    require(version.splitlines()[0].startswith('rustc 1.91.1'), 'official compiler version mismatch')
    targets = run_version(out, 'rustc-target-list', [compiler, '--print', 'target-list'])
    require('riscv32im-risc0-zkvm-elf' in targets.splitlines(), 'expected zkVM target is absent')
    cfg = run_version(out, 'rustc-target-cfg', [compiler, '--print', 'cfg', '--target', 'riscv32im-risc0-zkvm-elf'])
    for expected in ('target_arch="riscv32"', 'target_endian="little"',
                     'target_pointer_width="32"', 'target_os="zkvm"', 'target_vendor="risc0"'):
        require(expected in cfg.splitlines(), 'official compiler target cfg mismatch: ' + expected)
    return {'outcome': 'OFFICIAL_COMPILER_INSTALLED_METADATA_CHECKED_NO_BUILD',
            'archive_sha256': ARCHIVE_SHA256, 'archive_bytes': ARCHIVE_BYTES,
            'risc0_home': str(RISC0_HOME), 'compiler_path': compiler,
            'compiler_sha256': digest(COMPILER / 'bin/rustc'),
            'actual_allocated_unique_regular_bytes': allocated,
            'compiler_version_target_metadata_checked': True,
            'cargo_build_executed': False, 'guest_program_executed': False,
            'receipt_verified': False, 'prover_executed': False,
            'actual_sdk_or_prover_compatibility_established': False}


def interrupted(signum, _frame):
    raise RuntimeError('acquisition interrupted by signal ' + str(signum))


def main():
    mode, out_text = sys.argv[1:]
    require(mode in ('fetch', 'install'), 'explicit acquisition mode required')
    out = Path(out_text)
    require(out.is_dir() and not (out / 'acquisition-events.jsonl').exists(),
            'supervisor must create a fresh output directory; no retry')
    require(BASE.is_dir(), 'declared empty resources root must exist')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    started = time.monotonic()
    before = usage()
    result = {}
    emit(out, {'schema': 'TRNM-RISC0-1911-ACQUISITION-DECLARATION1', 'mode': mode,
               'source_sha256': digest(Path(__file__)), 'resources_root': str(BASE),
               'floor_bytes': FLOOR, 'archive_bytes': ARCHIVE_BYTES,
               'archive_sha256': ARCHIVE_SHA256, 'url': URL,
               'new_compiler_home': str(RISC0_HOME), 'no_cargo_guest_receipt_or_prover': True})
    try:
        result = fetch(out) if mode == 'fetch' else install(out)
    except BaseException as error:
        result = {'outcome': 'FAILED_NO_RETRY', 'error': repr(error)}
        raise
    finally:
        after = usage()
        result.update({'schema': 'TRNM-RISC0-1911-ACQUISITION-RESULT1', 'mode': mode,
                       'wall_seconds': time.monotonic() - started,
                       'self_cpu_seconds': after['self_cpu_seconds'] - before['self_cpu_seconds'],
                       'child_cpu_seconds': after['child_cpu_seconds'] - before['child_cpu_seconds'],
                       'self_peak_rss_bytes': after['self_peak_rss_bytes'],
                       'child_peak_single_process_rss_bytes': after['child_peak_single_process_rss_bytes'],
                       'free_after_bytes': free_bytes(), 'automatic_retry': False,
                       'source_sha256': digest(Path(__file__))})
        with (out / 'acquisition-result.json').open('x') as handle:
            json.dump(result, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        emit(out, result)


if __name__ == '__main__':
    main()
