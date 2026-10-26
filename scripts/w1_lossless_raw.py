#!/usr/bin/env python3
"""Lossless post-command evidence compaction; never part of a miner's budget.

Only a fully completed, non-truncated command's stdout is removed, and only after
an exclusive gzip write and a complete bounded round trip against its original
step receipt. Failures leave the original and any partial archive in place.
The old step receipt is not changed. This proves byte preservation, not hardware
attestation. Decompression uses one gzip member, rejects trailers and truncated
members, and never creates an uncompressed file.
"""
from __future__ import annotations
import gzip
import hashlib
import os
from pathlib import Path
import re
import stat
import zlib

CHUNK = 64 * 1024
DEFAULT_LIMIT = 1024 * 1024 * 1024


def require(value, label):
    if not value:
        raise ValueError(label)


def _identity(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _regular(path, limit):
    before = path.lstat()
    require(not path.is_symlink() and stat.S_ISREG(before.st_mode), 'RAW_NOT_REGULAR')
    require(0 <= before.st_size <= limit, 'RAW_STORED_SIZE')
    return before


def _sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()


def verified_raw_stream(path, expected_bytes=None, expected_sha256=None, *,
                        max_output_bytes=DEFAULT_LIMIT):
    """Yield bounded raw byte chunks; fully consume to obtain verification.

    This is an iterator, not a context manager or seekable file. A .gz suffix
    selects a single-member gzip decoder; other paths contain original bytes.
    Optional expected length and SHA refer to the *uncompressed* raw stream.
    All bounds, checksum and file identity checks complete before exhaustion.
    """
    require(type(max_output_bytes) is int and 0 <= max_output_bytes <= DEFAULT_LIMIT,
            'RAW_OUTPUT_LIMIT')
    if expected_bytes is not None:
        require(type(expected_bytes) is int and 0 <= expected_bytes <= max_output_bytes,
                'RAW_EXPECTED_BYTES')
    if expected_sha256 is not None:
        require(type(expected_sha256) is str and re.fullmatch('[0-9a-f]{64}', expected_sha256),
                'RAW_EXPECTED_SHA256')
    path = Path(path).absolute()
    before = _regular(path, 2 * max_output_bytes + 1024 * 1024)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if path.suffix == '.gz' else None
    digest = hashlib.sha256()
    total = 0
    with path.open('rb') as source:
        require(_identity(os.fstat(source.fileno())) == _identity(before), 'RAW_OPEN_REPLACED')
        for stored in iter(lambda: source.read(CHUNK), b''):
            if decoder is None:
                pieces = [stored]
            else:
                require(not decoder.eof, 'GZIP_TRAILING_BYTES_OR_MEMBER')
                pieces = []
                pending = stored
                while pending:
                    try:
                        output = decoder.decompress(pending, min(CHUNK, max_output_bytes - total + 1))
                    except zlib.error as error:
                        raise ValueError('GZIP_INVALID') from error
                    pending = decoder.unconsumed_tail
                    require(not decoder.unused_data, 'GZIP_TRAILING_BYTES_OR_MEMBER')
                    if output:
                        total += len(output)
                        require(total <= max_output_bytes, 'RAW_DECOMPRESSED_LIMIT')
                        digest.update(output)
                        yield output
                continue
            for output in pieces:
                total += len(output)
                require(total <= max_output_bytes, 'RAW_DECOMPRESSED_LIMIT')
                digest.update(output)
                yield output
        require(decoder is None or decoder.eof, 'GZIP_TRUNCATED')
        require(_identity(os.fstat(source.fileno())) == _identity(before), 'RAW_MUTATED_DURING_READ')
    require(not path.is_symlink() and _identity(path.lstat()) == _identity(before), 'RAW_PATH_REPLACED')
    require(expected_bytes is None or total == expected_bytes, 'RAW_LENGTH_MISMATCH')
    require(expected_sha256 is None or digest.hexdigest() == expected_sha256, 'RAW_SHA256_MISMATCH')


def bounded_raw_lines(path, max_output_bytes=DEFAULT_LIMIT, max_line_bytes=2 * 1024 * 1024,
                      *, expected_bytes=None, expected_sha256=None):
    """Yield original lines without materializing the decompressed file."""
    require(type(max_line_bytes) is int and 0 < max_line_bytes <= DEFAULT_LIMIT, 'RAW_LINE_LIMIT')
    pending = bytearray()
    for chunk in verified_raw_stream(path, expected_bytes, expected_sha256,
                                     max_output_bytes=max_output_bytes):
        for piece in chunk.splitlines(keepends=True):
            pending.extend(piece)
            require(len(pending) <= max_line_bytes, 'RAW_LINE_TOO_LONG')
            if pending.endswith(b'\n'):
                yield bytes(pending)
                pending.clear()
    if pending:
        yield bytes(pending)


def compress_completed_stdout(out, step):
    """Return the separate five-field compression receipt; do not mutate step."""
    require(type(step) is dict and step.get('complete_success') is True and
            step.get('stdout_truncated') is False, 'COMPRESSION_REQUIRES_COMPLETE_STDOUT')
    name = step.get('stdout')
    require(type(name) is str and name not in ('', '.', '..') and Path(name).name == name,
            'STDOUT_BASENAME')
    expected_bytes, expected_sha = step.get('stdout_bytes'), step.get('stdout_sha256')
    require(type(expected_bytes) is int and 0 < expected_bytes <= DEFAULT_LIMIT, 'STDOUT_BYTES')
    require(type(expected_sha) is str and re.fullmatch('[0-9a-f]{64}', expected_sha), 'STDOUT_SHA256')
    out = Path(out).resolve()
    source, target = out / name, out / (name + '.gz')
    before = _regular(source, expected_bytes)
    require(before.st_size == expected_bytes, 'STDOUT_SIZE_MISMATCH')
    with target.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', compresslevel=6, mtime=0, fileobj=output) as zipped:
            for chunk in verified_raw_stream(source, expected_bytes, expected_sha,
                                             max_output_bytes=expected_bytes):
                zipped.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    for _ in verified_raw_stream(target, expected_bytes, expected_sha, max_output_bytes=expected_bytes):
        pass
    result = dict(path=target.name, compressed_bytes=target.stat().st_size,
                  compressed_sha256=_sha(target), raw_bytes=expected_bytes, raw_sha256=expected_sha)
    require(not source.is_symlink() and _identity(source.lstat()) == _identity(before),
            'STDOUT_CHANGED_BEFORE_UNLINK')
    source.unlink()
    return result
