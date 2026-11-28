"""Observe one real provider image in its own disposable process.

The caller runs this observer once for the retained C provider and once for the
HIA provider. Only process-local capabilities and measured clock/PID values are
normalized. Every other return bit, error, typed value, capacity refusal and
resource effect is compared. This file supplies inputs; it implements no
provider operation and never turns a signal or timeout into success.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import time

MAX = (1 << 64) - 1
MARK = 0xA5


def words(*values):
    return struct.pack('<' + 'Q' * len(values), *(v & MAX for v in values))


class Observer:
    def __init__(self, library, output):
        self.library = Path(library).resolve(strict=True)
        self.output = Path(output).absolute()
        assert not self.output.exists()
        self.output.mkdir(parents=True, mode=0o700)
        self.report = {'schema': 'trnm.hia.task-provider.native-observation.v1',
                       'status': 'FAIL', 'finalized': False,
                       'library': str(self.library),
                       'library_sha256': hashlib.sha256(self.library.read_bytes()).hexdigest(),
                       'calls': [], 'resource_checks': [], 'concurrent': []}
        self.lib = C.CDLL(str(self.library))
        for name, args, result in (
            ('new', [], C.c_void_p), ('enter', [C.c_void_p], C.c_int),
            ('leave', [C.c_void_p], C.c_int), ('reset', [C.c_void_p], C.c_uint64),
            ('free', [C.c_void_p], None),
        ):
            fun = getattr(self.lib, 'trnm_task_provider_' + name)
            fun.argtypes, fun.restype = args, result
            setattr(self, name, fun)
        self.invoke = self.lib.trnm_task_provider
        self.invoke.argtypes = [C.c_void_p, C.c_uint64, C.c_void_p,
                               C.c_uint64, C.c_void_p, C.c_uint64]
        self.invoke.restype = C.c_uint64
        self.owners = []
        self.token = 1000
        self.save()

    def save(self):
        (self.output / 'observation.json').write_text(json.dumps(self.report, indent=2) + '\n')

    def owner(self):
        result = self.new()
        assert result
        self.owners.append(result)
        return result

    def call(self, name, owner, op, payload=b'', capacity=4096, *,
             null_input=False, null_output=False, declared_size=None,
             capability=False, normalize=()):
        assert 0 <= capacity <= 65536
        incoming = C.create_string_buffer(payload)
        outgoing = C.create_string_buffer(bytes([MARK]) * (capacity + 64), capacity + 64)
        size = len(payload) if declared_size is None else declared_size
        result = self.invoke(owner, op, None if null_input else incoming, size,
                             None if null_output else outgoing, capacity)
        assert incoming.raw[:len(payload)] == payload, ('input-mutated', name)
        assert outgoing.raw[capacity:] == bytes([MARK]) * 64, ('output-overrun', name)
        if result > capacity or result in (MAX, MAX - 1):
            assert outgoing.raw == bytes([MARK]) * (capacity + 64), ('refusal-wrote', name)
            response = b''
        else:
            assert outgoing.raw[result:capacity] == bytes([MARK]) * (capacity - result), ('tail-wrote', name)
            response = outgoing.raw[:result]
        canonical = bytearray(response)
        if capability and len(response) >= 24:
            pointer = struct.unpack_from('<Q', response, 8)[0]
            if pointer not in (0, MAX):
                self.token += 1
                struct.pack_into('<Q', canonical, 8, self.token)
        for offset, value in normalize:
            if len(canonical) >= offset + 8:
                struct.pack_into('<Q', canonical, offset, value)
        self.report['calls'].append({'name': name, 'op': op,
            'request_hex': payload.hex(), 'capacity': capacity, 'actual_response_hex': response.hex(),
            'normalized': {'return': result, 'response_hex': canonical.hex()}})
        self.save()
        return result, response

    def scalar(self, name, owner, op, payload=b'', **kw):
        result, response = self.call(name, owner, op, payload, **kw)
        assert result == 24, (name, result)
        return struct.unpack('<QQQ', response)

    def open_database(self, name, owner, path=b':memory:', flags=6, code=0):
        actual, handle, last = self.scalar(name, owner, 2, words(flags, len(path)) + path,
                                           capability=True)
        assert actual == code and last == 0, (name, actual, code)
        return handle

    def prepare(self, name, owner, db, sql, code=0):
        actual, statement, tail = self.scalar(name, owner, 5, words(db, len(sql)) + sql,
                                               capability=True)
        assert actual == code and tail <= len(sql), (name, actual, code)
        return statement, tail

    def execute(self, name, owner, db, sql, step=101, final=0):
        statement, _ = self.prepare(name + '/prepare', owner, db, sql)
        assert self.scalar(name + '/step', owner, 7, words(statement))[0] == step
        assert self.scalar(name + '/finalize', owner, 9, words(statement))[0] == final

    def closed(self, name, fd):
        try:
            os.fstat(fd)
        except OSError as error:
            assert error.errno == 9
        else:
            raise AssertionError(('descriptor-still-open', name, fd))
        self.report['resource_checks'].append({'name': name, 'closed': True})

    def run(self):
        os.umask(0o077)
        owner, other = self.owner(), self.owner()
        try:
            self.framing(owner)
            self.identity(owner)
            self.sql(owner, other)
            self.files(owner, other)
            self.lifetime(owner, other)
            self.concurrent(owner)
            assert {r['op'] for r in self.report['calls']} >= set(range(1, 30))
            for live in self.owners:
                assert self.reset(live) == 0
            self.free(None)
            self.report.update(status='PASS', finalized=True,
                               operation_coverage=list(range(1, 30)),
                               actual_calls=len(self.report['calls']))
        except BaseException as error:
            self.report.update(failure=repr(error))
            raise
        finally:
            for live in self.owners:
                self.free(live)
            self.save()
        print(json.dumps({'status': 'PASS', 'calls': len(self.report['calls']),
                          'concurrent_transactions': len(self.report['concurrent']),
                          'resource_checks': len(self.report['resource_checks'])}))

    def framing(self, owner):
        for cap in (0, 1, 7, 23):
            assert self.call('small-cap/' + str(cap), owner, 999, b'x', cap)[0] == 24
        assert self.call('null-owner', None, 1, words(0, 0))[0] == MAX
        assert self.call('null-input', owner, 1, b'', declared_size=1, null_input=True)[0] == MAX
        assert self.call('null-output', owner, 1, words(0, 0), 24, null_output=True)[0] == MAX
        for op in (0, 30, 255, MAX):
            assert self.call('unknown-op/' + str(op), owner, op)[0] == MAX
        randomizer = random.Random(0x54525031)
        for op in range(1, 30):
            for size in (0, 1, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32, 33, 41):
                # Zero handle/invalid selector; filesystem paths contain NUL.
                # No random input is allowed to address a host-selected path.
                raw = bytearray(randomizer.randbytes(size))
                raw[:min(8, size)] = bytes(min(8, size))
                if op in (2, 15, 16, 17, 20, 21):
                    raw[:] = bytes(size)
                normal = ((8, 0), (16, 0)) if op == 22 else ((8, 0),) if op == 23 else ()
                self.call('frame/' + str(op) + '/' + str(size), owner, op, bytes(raw), 24,
                          capability=op in (2, 5, 17), normalize=normal)
        # A correctly framed empty-path open may retain a failing SQLite handle;
        # reset below observes and consumes such real handles, not guessed IDs.
        observed = self.reset(owner)
        self.report['resource_checks'].append({'name': 'frame-reset', 'resources': observed})

    def identity(self, owner):
        for selector in range(6):
            for index in (*range(65), 2147483647):
                self.call('identity/' + str(selector) + '/' + str(index), owner, 1,
                          words(selector, index), 4096)
        for payload in (words(6, 0), words(MAX, 0), words(0, 2147483648), words(0, MAX)):
            assert self.call('identity-bad/' + payload.hex(), owner, 1, payload)[0] == MAX
        for cap in (23, 24, 25, 40, 118, 119, 120):
            self.call('identity-cap/' + str(cap), owner, 1, words(1, 0), cap)
        for errno in (0, 1, 2, 5, 9, 12, 13, 17, 20, 21, 22, 28, 36, 95, 9999, 2147483647):
            self.call('strerror/' + str(errno), owner, 24, words(errno))
        for result in (0, 1, 5, 7, 19, 21, 100, 101, 9999, 2147483647):
            self.call('errstr/' + str(result), owner, 28, words(result))
        before = time.time_ns()
        _, response = self.call('clock', owner, 22, normalize=((8, 0), (16, 0)))
        after = time.time_ns()
        code, seconds, nanos = struct.unpack('<QQQ', response)
        assert code == 0 and nanos < 1_000_000_000 and before <= seconds * 1_000_000_000 + nanos <= after
        code, pid, last = self.scalar('pid', owner, 23, normalize=((8, 0),))
        assert code == last == 0 and pid == os.getpid()

    def sql(self, owner, other):
        db = self.open_database('db-open', owner)
        for op, payload in ((3, words(db)), (4, words(db, 0)), (5, words(db, 0)),
                            (10, words(db)), (11, words(db)), (12, words(db)),
                            (25, words(db)), (27, words(db))):
            assert self.call('cross-db/' + str(op), other, op, payload)[0] == MAX
        self.call('null-errmsg', owner, 11, words(0))
        self.call('null-extended-error', owner, 12, words(0))
        assert self.scalar('busy-timeout', owner, 4, words(db, 0))[0] == 0
        assert self.call('busy-timeout-overflow', owner, 4, words(db, 1 << 31))[0] == MAX
        statement, _ = self.prepare('bind-prepare', owner, db, b'SELECT ?1,?2,?3,?4,?5')
        assert self.scalar('bind-count', owner, 26, words(statement))[1] == 5
        binds = ((1, 1, words(-(1 << 63))), (2, 2, struct.pack('<d', -1.5)),
                 (3, 3, b'a\0z\xff'), (4, 4, b'\0\xffblob'), (5, 5, b''))
        for index, kind, value in binds:
            assert self.scalar('bind/' + str(kind), owner, 6, words(statement, index, kind) + value)[0] == 0
        for index in (0, 6, 2147483647, 2147483648, MAX):
            self.call('bind-index/' + str(index), owner, 6, words(statement, index, 5))
        for kind, payload in ((0, b''), (1, b''), (1, bytes(7)), (1, bytes(9)),
                              (2, b''), (2, bytes(7)), (2, bytes(9)), (5, b'x'), (6, b''), (MAX, b'')):
            assert self.call('bind-shape/' + str(kind) + '/' + str(len(payload)), owner, 6,
                             words(statement, 1, kind) + payload)[0] == MAX
        assert self.scalar('bind-step', owner, 7, words(statement))[0] == 100
        assert self.scalar('column-count', owner, 13, words(statement))[1] == 5
        for index in range(5):
            self.call('column-name/' + str(index), owner, 14, words(statement, index))
            for cap in (23, 24, 25, 31, 32, 64):
                self.call('column-value/' + str(index) + '/' + str(cap), owner, 8,
                          words(statement, index), cap)
        for index in (5, 2147483647, 2147483648, MAX):
            for op in (8, 14):
                assert self.call('column-invalid/' + str(op) + '/' + str(index), owner, op,
                                 words(statement, index))[0] == MAX
        for op, payload in ((6, words(statement, 1, 5)), (7, words(statement)),
                            (8, words(statement, 0)), (9, words(statement)),
                            (13, words(statement)), (14, words(statement, 0)), (26, words(statement))):
            assert self.call('cross-statement/' + str(op), other, op, payload)[0] == MAX
        assert self.scalar('close-busy', owner, 3, words(db))[0] == 5
        assert self.scalar('bind-finalize', owner, 9, words(statement))[0] == 0
        assert self.call('stale-statement', owner, 7, words(statement))[0] == MAX
        for number in (0, 1, (1 << 63) - 1, 1 << 63, MAX):
            st, _ = self.prepare('integer-prepare/' + str(number), owner, db, b'SELECT ?')
            assert self.scalar('integer-bind/' + str(number), owner, 6, words(st, 1, 1, number))[0] == 0
            assert self.scalar('integer-step/' + str(number), owner, 7, words(st))[0] == 100
            _, value = self.call('integer-value/' + str(number), owner, 8, words(st, 0))
            assert value == words(0, 1, 8, number)
            self.scalar('integer-finalize/' + str(number), owner, 9, words(st))
        for bits in (0, 1 << 63, 1, 0x0010000000000000, 0x7fefffffffffffff,
                     0x3ff0000000000000, 0xbff0000000000000, 0x7ff0000000000000,
                     0xfff0000000000000, 0x7ff8000000000000, 0x7ff0000000000001):
            key = hex(bits)
            st, _ = self.prepare('float-prepare/' + key, owner, db, b'SELECT ?')
            assert self.scalar('float-bind/' + key, owner, 6, words(st, 1, 2, bits))[0] == 0
            assert self.scalar('float-step/' + key, owner, 7, words(st))[0] == 100
            self.call('float-value/' + key, owner, 8, words(st, 0))
            self.scalar('float-finalize/' + key, owner, 9, words(st))
        for kind, payload in ((3, b''), (4, b''), (3, b'A\0B'), (4, bytes(range(256)))):
            key = str(kind) + '/' + str(len(payload))
            st, _ = self.prepare('value-prepare/' + key, owner, db, b'SELECT ?')
            self.scalar('value-bind/' + key, owner, 6, words(st, 1, kind) + payload)
            self.scalar('value-step/' + key, owner, 7, words(st))
            _, value = self.call('value-result/' + key, owner, 8, words(st, 0))
            assert value == words(0, kind, len(payload)) + payload
            self.scalar('value-finalize/' + key, owner, 9, words(st))
        for sql in (b'', b'; ; -- empty', b'SELECT 1; SELECT 2', b'SELECT 1\0SELECT 2', b'SELECT 1 -- tail'):
            key = sql.hex()
            st, _ = self.prepare('tail/' + key, owner, db, sql)
            if st:
                self.scalar('tail-finalize/' + key, owner, 9, words(st))
        for sql in (b'SELEC 1', b'SELECT FROM', b'SELECT nonexistent', b'CREATE TABLE (x)'):
            st, _ = self.prepare('bad-sql/' + sql.hex(), owner, db, sql, code=1)
            assert st == 0
            for op in (11, 12, 25, 27):
                self.call('sql-error/' + sql.hex() + '/' + str(op), owner, op, words(db))
        self.execute('create-table', owner, db, b'CREATE TABLE t(x INTEGER PRIMARY KEY)')
        self.execute('insert', owner, db, b'INSERT INTO t VALUES(1),(2)')
        assert self.scalar('changes', owner, 10, words(db))[1] == 2
        self.execute('constraint', owner, db, b'INSERT INTO t VALUES(1)', step=19, final=19)
        st, _ = self.prepare('two-rows', owner, db, b'SELECT x FROM t ORDER BY x')
        self.scalar('two-rows-step', owner, 7, words(st))
        first = self.call('two-rows-column-1', owner, 8, words(st, 0))[1]
        assert self.call('two-rows-column-repeat', owner, 8, words(st, 0))[1] == first
        self.scalar('two-rows-step-2', owner, 7, words(st))
        assert self.call('two-rows-column-2', owner, 8, words(st, 0))[1] != first
        self.scalar('two-rows-finalize', owner, 9, words(st))
        assert self.scalar('db-close', owner, 3, words(db))[0] == 0
        assert self.call('stale-db', owner, 10, words(db))[0] == MAX
        # open_v2 may return an owned SQLite handle on an opening failure.
        path = os.fsencode(self.output / 'absent-parent' / 'database')
        failed = self.open_database('failed-open', owner, path, code=14)
        if failed:
            self.call('failed-open-message', owner, 11, words(failed))
            assert self.scalar('failed-open-close', owner, 3, words(failed))[0] == 0

    def files(self, owner, other):
        root = self.output / 'files'
        path = os.fsencode(root)
        assert self.scalar('mkdir', owner, 16, words(0o700, 0, len(path)) + path)[0] == 0
        assert self.scalar('mkdir-exists', owner, 16, words(0o700, 0, len(path)) + path)[0] == 17
        source = path + b'/source-\xff'
        content = b'abcdefghij\0\xff'
        with open(source, 'wb') as stream:
            stream.write(content)
        alias = path + b'/alias'
        symbolic = path + b'/symbolic'
        os.symlink(b'source-\xff', symbolic)
        for follow in (0, 1):
            for key, name in (('file', source), ('symlink', symbolic), ('missing', path + b'/missing')):
                self.call('stat/' + str(follow) + '/' + key, owner, 15, words(follow, 0, len(name)) + name)
        self.call('stat-bad-follow', owner, 15, words(2, 0, len(source)) + source)
        self.call('mkdir-bad-mode', owner, 16, words(1 << 32, 0, len(path)) + path)
        self.call('open-bad-flags', owner, 17, words(1 << 31, 0, len(source)) + source)
        self.call('open-bad-mode', owner, 17, words(0, 1 << 32, len(source)) + source)
        for op in (15, 16, 17, 20, 21):
            self.call('path-nul/' + str(op), owner, op, words(0, 0, 1) + b'\0')
            self.call('path-length/' + str(op), owner, op, words(0, 0, MAX) + b'x')
        assert self.scalar('link', owner, 20, words(0, 0, len(source)) + source + alias)[0] == 0
        assert os.stat(source).st_ino == os.stat(alias).st_ino
        for key, left, right in (('empty-source', b'', alias), ('empty-target', source, b''), ('both-empty', b'', b'')):
            assert self.scalar('link/' + key, owner, 20, words(0, 0, len(left)) + left + right)[0] == 2
        assert self.scalar('unlink', owner, 21, words(0, 0, len(alias)) + alias)[0] == 0
        assert not os.path.exists(alias)
        assert self.scalar('unlink-missing', owner, 21, words(0, 0, len(alias)) + alias)[0] == 2
        code, fd, _ = self.scalar('open-file', owner, 17, words(os.O_RDONLY, 0, len(source)) + source, capability=True)
        assert code == 0
        for op, payload in ((18, words(fd)), (19, words(fd)), (29, words(fd, 1))):
            assert self.call('cross-fd/' + str(op), other, op, payload)[0] == MAX
        assert self.call('read-short-cap', owner, 29, words(fd, len(content)), 24)[0] == len(content) + 24
        assert self.scalar('read-zero', owner, 29, words(fd, 0))[1] == 0
        assert self.call('read-first', owner, 29, words(fd, 4))[1] == words(0, 4, 0) + content[:4]
        assert self.call('read-short', owner, 29, words(fd, 4096), 4120)[1] == words(0, len(content) - 4, 0) + content[4:]
        assert self.call('read-eof', owner, 29, words(fd, 4))[1] == words(0, 0, 0)
        assert self.call('read-size-overflow', owner, 29, words(fd, MAX))[0] == MAX
        assert self.scalar('fsync', owner, 19, words(fd))[0] == 0
        assert self.scalar('close-file', owner, 18, words(fd))[0] == 0
        self.closed('explicit-close', fd)
        for op, payload in ((18, words(fd)), (19, words(fd)), (29, words(fd, 1))):
            assert self.call('stale-fd/' + str(op), owner, op, payload)[0] == MAX
        external = os.open(source, os.O_RDONLY)
        try:
            for op, payload in ((18, words(external)), (19, words(external)), (29, words(external, 1))):
                assert self.call('unowned-fd/' + str(op), owner, op, payload)[0] == MAX
            assert os.read(external, 1) == content[:1]
        finally:
            os.close(external)
        for op in (15, 16, 17, 20, 21):
            would = path + b'/must-not-exist'
            raw = words(0o700 if op == 16 else os.O_WRONLY | os.O_CREAT, 0o600, len(would)) + would
            if op == 20:
                raw = words(0, 0, len(source)) + source + would
            self.call('path-no-cap/' + str(op), owner, op, raw, 23)
            assert not os.path.exists(would)

    def lifetime(self, owner, other):
        db = self.open_database('lifetime-db', owner)
        self.prepare('lifetime-stmt-1', owner, db, b'SELECT 1')
        self.prepare('lifetime-stmt-2', owner, db, b'SELECT 2')
        path = os.fsencode(self.output / 'files') + b'/source-\xff'
        code, fd, _ = self.scalar('lifetime-fd', owner, 17, words(os.O_RDONLY, 0, len(path)) + path, capability=True)
        assert code == 0
        assert self.reset(owner) == 4
        assert self.reset(owner) == 0 and self.reset(other) == 0
        self.closed('reset-closed-fd', fd)
        assert self.call('reset-stale-db', owner, 10, words(db))[0] == MAX
        dying = self.owner()
        db = self.open_database('free-db', dying)
        self.prepare('free-stmt', dying, db, b'SELECT 1')
        code, fd, _ = self.scalar('free-fd', dying, 17, words(os.O_RDONLY, 0, len(path)) + path, capability=True)
        assert code == 0
        self.free(dying);self.owners.remove(dying)
        self.closed('free-closed-fd', fd)

    def concurrent(self, owner):
        db = self.open_database('thread-db', owner)

        def raw(op, payload):
            incoming = C.create_string_buffer(payload)
            outgoing = C.create_string_buffer(256)
            size = self.invoke(owner, op, incoming, len(payload), outgoing, len(outgoing))
            assert size <= 256
            return outgoing.raw[:size]

        def worker(index):
            results = []
            for iteration in range(8):
                value = index * 100 + iteration
                assert self.enter(owner) == 0
                try:
                    sql = ('SELECT ' + str(value)).encode()
                    code, statement, _ = struct.unpack('<QQQ', raw(5, words(db, len(sql)) + sql))
                    assert code == 0 and statement
                    assert struct.unpack('<QQQ', raw(7, words(statement)))[0] == 100
                    observed = raw(8, words(statement, 0))
                    assert observed == words(0, 1, 8, value)
                    assert struct.unpack('<QQQ', raw(9, words(statement)))[0] == 0
                    results.append({'thread': index, 'iteration': iteration, 'actual': observed.hex()})
                finally:
                    assert self.leave(owner) == 0
            return results

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for values in pool.map(worker, range(8)):
                self.report['concurrent'].extend(values)
        assert self.scalar('thread-db-close', owner, 3, words(db))[0] == 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--library', required=True)
    parser.add_argument('--output', required=True)
    options = parser.parse_args()
    Observer(options.library, options.output).run()
