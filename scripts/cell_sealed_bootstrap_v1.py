"""Fixed -c bootstrap embedded in the native CHB1 research launcher."""
import array
import fcntl
import hashlib
import json
import os
import socket
import stat
import struct
import sys
import time

if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
    raise RuntimeError('SEALED_BOOTSTRAP_ISOLATION')
if len(sys.argv) != 6:
    raise RuntimeError('SEALED_BOOTSTRAP_ARGUMENTS')
expected_descriptor, expected_worker, mode, endpoint, bootstrap_sha256 = sys.argv[1:]
if mode not in ('supervisor', 'worker'):
    raise RuntimeError('SEALED_BOOTSTRAP_MODE')
stream = socket.socket(fileno=0) if mode == 'supervisor' else socket.socket(socket.AF_UNIX)
stream.settimeout(10)
if mode == 'worker':
    stream.connect(endpoint)

def exact(length):
    result = bytearray()
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise RuntimeError('SEALED_BOOTSTRAP_EOF')
        result.extend(part)
    return bytes(result)

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError('SEALED_BOOTSTRAP_DUPLICATE')
        result[key] = value
    return result

fds = []
try:
    length = struct.unpack('>I', exact(4))[0]
    if not 1 <= length <= 131072:
        raise RuntimeError('SEALED_BOOTSTRAP_HEADER_BOUND')
    header = json.loads(exact(length), object_pairs_hook=unique)
    if (type(header) is not dict or header.get('schema') != 'trnm.cell-sealed-research-fds.v1'
            or header.get('descriptor_sha512') != expected_descriptor
            or len(header.get('descriptor', '')) > 4096
            or type(header.get('deadline_monotonic_ns')) is not int
            or time.monotonic_ns() >= header['deadline_monotonic_ns']):
        raise RuntimeError('SEALED_BOOTSTRAP_HEADER_PIN')
    descriptor = bytes.fromhex(header['descriptor'])
    if hashlib.sha512(b'TRNM/Cell/HostSealedDualContext/v1\0' + descriptor).hexdigest() != expected_descriptor:
        raise RuntimeError('SEALED_BOOTSTRAP_DESCRIPTOR')
    rows, worker = header.get('files'), header.get('worker')
    if (type(rows) is not list or not 1 <= len(rows) <= 64 or type(worker) is not int
            or not 0 <= worker < len(rows)):
        raise RuntimeError('SEALED_BOOTSTRAP_ROSTER')
    for _ in rows:
        if time.monotonic_ns() >= header['deadline_monotonic_ns']:
            raise RuntimeError('SEALED_BOOTSTRAP_ORIGINAL_DEADLINE')
        stream.settimeout(max(0.001, min(10, (header['deadline_monotonic_ns'] - time.monotonic_ns()) / 1e9)))
        marker, ancillary, flags, _ = stream.recvmsg(1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
        received = []
        invalid = False
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                invalid = True
                continue
            values = array.array('i')
            whole = len(data) - len(data) % values.itemsize
            values.frombytes(data[:whole])
            received.extend(values)
            invalid |= whole != len(data)
        fds.extend(received)
        if invalid or marker != b'F' or flags & ~(socket.MSG_CMSG_CLOEXEC) or len(received) != 1:
            raise RuntimeError('SEALED_BOOTSTRAP_DESCRIPTOR_COUNT')
    row = rows[worker]
    if (row.get('scope') != 'environment' or row.get('sha256') != expected_worker
            or type(row.get('bytes')) is not int or not 0 < row['bytes'] <= 2 * 1024**2):
        raise RuntimeError('SEALED_BOOTSTRAP_WORKER_PIN')
    fd = fds[worker]
    before = os.fstat(fd)
    seals = fcntl.fcntl(fd, getattr(fcntl, 'F_GET_SEALS', 1034))
    if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o111
            or before.st_size != row['bytes'] or seals & 0x2f != 0x2f):
        raise RuntimeError('SEALED_BOOTSTRAP_IMMUTABLE_WORKER')
    raw = bytearray()
    while len(raw) < before.st_size:
        block = os.pread(fd, min(65536, before.st_size - len(raw)), len(raw))
        if not block or time.monotonic_ns() >= header['deadline_monotonic_ns']:
            raise RuntimeError('SEALED_BOOTSTRAP_WORKER_READ')
        raw.extend(block)
    raw = bytes(raw)
    if hashlib.sha256(raw).hexdigest() != expected_worker:
        raise RuntimeError('SEALED_BOOTSTRAP_WORKER_BYTES')
    namespace = {'__name__': '__cell_sealed_worker_v1__', '__file__': '/cell-sealed/' + row['path']}
    exec(compile(raw, namespace['__file__'], 'exec'), namespace)
    stream.close()
    namespace['entry'](header, fds, mode, bootstrap_sha256)
finally:
    stream.close()
    for fd in fds:
        os.close(fd)
