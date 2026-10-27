"""Private, bounded loopback byte transport. No function validates a proof."""
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import stat
import struct
import sys
import time

MAX_BYTES = 128 * 1024**2
CHUNK_BYTES = 1024**2
FRAME = struct.Struct('!8sQ32s32s')
MAGIC, ACK = b'PNW1TCP1', b'PNW1ACK1'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def remaining(deadline):
    value = (deadline-time.monotonic_ns()) / 10**9
    require(value > 0, 'loopback-deadline')
    return value


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8192,
            'loopback-config-file')
    return json.loads(path.read_text())


def write_json(path, value):
    partial = path.with_name(path.name+'.partial')
    with partial.open('x') as output:
        os.chmod(partial, 0o600)
        json.dump(value, output, sort_keys=True)
        output.write('\n'); output.flush(); os.fsync(output.fileno())
    # The live receiver readiness record must never be visible half-written.
    os.link(partial,path,follow_symlinks=False)
    partial.unlink()


def file_identity(path, cap=MAX_BYTES, *, allow_empty=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and (0 if allow_empty else 1) <= before.st_size <= cap,
                'loopback-file-bound')
        digest, size = hashlib.sha256(), 0
        while block := stream.read(CHUNK_BYTES):
            size += len(block); require(size <= cap, 'loopback-file-growth')
            digest.update(block)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                and size == before.st_size, 'loopback-file-changed')
    return dict(bytes=size, sha256=digest.hexdigest(), device=before.st_dev,
                inode=before.st_ino, mtime_ns=before.st_mtime_ns)


def receive_exact(connection, length, deadline):
    require(0 <= length <= FRAME.size, 'loopback-small-frame-bound')
    result = bytearray()
    while len(result) < length:
        connection.settimeout(remaining(deadline))
        block = connection.recv(length-len(result))
        require(block, 'loopback-short-frame')
        result.extend(block)
    return bytes(result)


def receive_stream(connection, directory, expected, nonce, deadline, report):
    header = receive_exact(connection, FRAME.size, deadline)
    magic, length, digest, token = FRAME.unpack(header)
    require(magic == MAGIC and token == nonce, 'loopback-frame-identity')
    require(0 < length <= MAX_BYTES, 'loopback-payload-cap')
    require(length == expected['bytes'] and digest.hex() == expected['sha256'],
            'loopback-frame-context')
    report.update(header_bytes_received=FRAME.size, payload_bytes_received=0,
                  payload_sha256=None, file_fsync_completed=False, directory_fsync_completed=False)
    actual = hashlib.sha256(); partial = directory/'received.partial'
    with partial.open('xb') as output:
        os.chmod(partial,0o600)
        while report['payload_bytes_received'] < length:
            connection.settimeout(remaining(deadline))
            block = connection.recv(min(CHUNK_BYTES, length-report['payload_bytes_received']))
            require(block, 'loopback-short-payload')
            require(output.write(block) == len(block), 'loopback-short-write')
            actual.update(block); report['payload_bytes_received'] += len(block)
        connection.settimeout(remaining(deadline))
        require(connection.recv(1) == b'', 'loopback-trailing-bytes')
        report['payload_sha256'] = actual.hexdigest()
        require(actual.digest() == digest, 'loopback-payload-hash')
        remaining(deadline); output.flush(); os.fsync(output.fileno())
        report['file_fsync_completed'] = True
    remaining(deadline)
    # Fresh destination, atomic no-clobber publication; failed partials remain.
    os.link(partial, directory/'received.bin', follow_symlinks=False)
    partial.unlink()
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
    report['directory_fsync_completed'] = True
    connection.settimeout(remaining(deadline))
    connection.sendall(FRAME.pack(ACK, length, digest, nonce))
    report['ack_bytes_sent'] = FRAME.size


def send_stream(connection, source, expected, nonce, deadline, report):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size == expected['bytes']
                and 0 < before.st_size <= MAX_BYTES, 'loopback-source-bound')
        digest = hashlib.sha256()
        connection.settimeout(remaining(deadline))
        connection.sendall(FRAME.pack(MAGIC, before.st_size, bytes.fromhex(expected['sha256']), nonce))
        report.update(header_bytes_sent=FRAME.size, payload_bytes_sendall_completed=0,
                      partial_send_unknown=False)
        while report['payload_bytes_sendall_completed'] < before.st_size:
            block = stream.read(min(CHUNK_BYTES, before.st_size-report['payload_bytes_sendall_completed']))
            require(block, 'loopback-source-short')
            digest.update(block); connection.settimeout(remaining(deadline))
            report['partial_send_unknown'] = True
            connection.sendall(block)
            report['partial_send_unknown'] = False
            report['payload_bytes_sendall_completed'] += len(block)
        require(not stream.read(1) and digest.hexdigest() == expected['sha256'], 'loopback-source-hash')
        after = os.fstat(stream.fileno())
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) ==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns), 'loopback-source-changed')
    connection.shutdown(socket.SHUT_WR)
    reply = receive_exact(connection, FRAME.size, deadline)
    require(reply == FRAME.pack(ACK, expected['bytes'], bytes.fromhex(expected['sha256']), nonce),
            'loopback-ack-context')
    report['ack_bytes_received'] = FRAME.size
    connection.settimeout(remaining(deadline))
    require(connection.recv(1) == b'', 'loopback-trailing-ack')


def worker():
    """Called only by a fixed internal child command; never a proof CLI."""
    config = read_json(Path(sys.argv[1]))
    require(set(config) == {'schema','role','directory','source','expected','nonce','deadline_ns','port'}
            and config['schema'] == 'pon-w1-loopback-worker-v1'
            and config['role'] in ('sender','receiver'), 'loopback-worker-config')
    directory, role = Path(config['directory']), config['role']
    report = dict(schema='pon-w1-loopback-worker-observation-v1', role=role, pid=os.getpid(),
        outcome='failed', cryptographic_proof_verified=False, public_ingress_qualified=False,
        resource_qualification=False, consensus_authority=False, tcp_ip_bytes_measured=False)
    started = time.monotonic_ns()
    try:
        resource.setrlimit(resource.RLIMIT_AS, (MAX_BYTES,MAX_BYTES))
        require(resource.getrlimit(resource.RLIMIT_AS) == (MAX_BYTES,MAX_BYTES), 'loopback-address-space-cap')
        report['address_space_limit_bytes'] = MAX_BYTES
        nonce = bytes.fromhex(config['nonce']); require(len(nonce) == 32, 'loopback-nonce')
        report['nonce_sha256'] = hashlib.sha256(nonce).hexdigest()
        deadline = config['deadline_ns']; require(type(deadline) is int, 'loopback-deadline-type')
        expected = config['expected']
        require(set(expected) == {'bytes','sha256'} and type(expected['bytes']) is int
                and 0 < expected['bytes'] <= MAX_BYTES, 'loopback-payload-cap')
        require(len(bytes.fromhex(expected['sha256'])) == 32, 'loopback-expected-hash')
        if role == 'receiver':
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(('127.0.0.1',0)); listener.listen(1)
                write_json(directory/'ready.json',dict(schema='pon-w1-loopback-ready-v1',
                    address=list(listener.getsockname()), nonce_sha256=report['nonce_sha256'], pid=os.getpid()))
                listener.settimeout(remaining(deadline)); connection, peer = listener.accept()
                with connection:
                    require(peer[0] == '127.0.0.1', 'loopback-peer-address')
                    report.update(local=list(connection.getsockname()),peer=list(peer))
                    receive_stream(connection,directory,expected,nonce,deadline,report)
        else:
            require(type(config['port']) is int and 0 < config['port'] < 65536, 'loopback-port')
            with socket.create_connection(('127.0.0.1',config['port']),timeout=remaining(deadline)) as connection:
                report.update(local=list(connection.getsockname()),peer=list(connection.getpeername()))
                send_stream(connection,Path(config['source']),expected,nonce,deadline,report)
        remaining(deadline); report['outcome'] = 'complete'
    except BaseException as error:
        report.update(error_type=type(error).__name__, error=str(error)[:200])
        raise
    finally:
        report['observed_wall_ns'] = time.monotonic_ns()-started
        write_json(directory/role/'worker.json',report)
