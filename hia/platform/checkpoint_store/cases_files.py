"""Public path, retained lock, numeric extent and exact CAS boundary cases."""
import hashlib
import os
import struct

from .fixtures import record, set_field
from .qualification_support import need
from .cases_recovery import disk, expect, state, write_private


def pin(count, root):
    body = b"TRNMCPX1\1\0\0\0" + count.to_bytes(8, "big") + root
    return body + hashlib.sha256(
        b"trnm.external-node-checkpoint.journal-export.v1\0"
        + len(body).to_bytes(8, "big") + body).digest()


def run(suite):
    cp0 = record()
    cp1 = record(1, predecessor=cp0[640:])
    p = suite.pair("file-boundaries")
    empty = pin(0, bytes(32))
    p.call(1, empty)
    for n, root in ((0, bytes([1]) * 32), (1, bytes(32)),
                    ((1 << 64) - 1, bytes([2]) * 32)):
        p.call(1, pin(n, root), label="pin-count-shape")
    for path in (b"", b"/", b"relative", b"/.", b"/.."):
        p.call(5, empty + path, label="export-path")
        p.call(30, path, label="client-path")
    for q in (p.na, p.nb):
        write_private(q / "pin", empty)
        (q / "pin").chmod(0o644)  # Public pin import has no private-mode rule.
        os.link(q / "pin", q / "hardlink")
        (q / "symlink").symlink_to(q / "pin")
        (q / "directory").mkdir(mode=0o700)
        os.mkfifo(q / "fifo", mode=0o600)
        write_private(q / "checkpoint", cp0)
        (q / "cp-link").symlink_to(q / "checkpoint")
        write_private(q / "short", bytes(83))
        write_private(q / "long", bytes(85))
    for suffix in ("pin", "hardlink", "symlink", "directory", "fifo", "short", "long", "missing"):
        p.path(4, suffix, label="pin-import")
    for suffix in ("checkpoint", "cp-link", "directory", "missing", "short", "long"):
        p.path(50, suffix, label="checkpoint-input")
    for suffix in ("pin", "hardlink", "symlink", "directory", "fifo", "missing/new"):
        p.path(5, suffix, empty, label="exclusive-export")
    for suffix in (b"/nul\0tail", b"/" + b"x" * 256, b"/invalid-\xff"):
        a, b = bytes(p.na) + suffix, bytes(p.nb) + suffix
        p.call(5, empty + a, empty + b, label="raw-export-path")
        p.call(4, a, b, label="raw-import-path")
        p.call(50, a, b, label="raw-checkpoint-input")
        p.call(11, a, b, label="raw-authority-path")
        value = p.call(40, cp0 + a + b"-ledger", cp0 + b + b"-ledger", label="raw-ledger-path")
        if value[0][0] == 0:
            p.call(45)
    # Parent traversal is not canonical authority admission. Export retains the
    # original Path rules and follows parent symlinks, so compare the operations.
    for q in (p.na, p.nb):
        (q / "child").mkdir(mode=0o700)
        (q / "parent-link").symlink_to(q / "child", target_is_directory=True)
    for suffix in ("parent-link/journal", "child/../journal", "child/./journal"):
        value = p.path(11, suffix, label="authority-components")
        if value[0][0] == 0:
            p.call(19)
    p.close()

    p = suite.pair("pin-length-arithmetic")
    p.path(11, "journal")
    p.call(19)
    maximum = ((1 << 64) - 1) // 1461
    for count in (maximum, maximum + 1, (1 << 64) - 1):
        value = p.path(12, "journal", pin(count, bytes([9]) * 32), label="checked-count-times-record")
        expect(value, 1, "mismatch" if count == maximum else "length overflow")
    p.path(12, "journal", empty)
    p.call(19)
    p.close()

    p = suite.pair("cas-validation")
    p.path(11, "journal")
    def cas(expected, target):
        return p.call(17, struct.pack("<Q", expected is not None)
                      + (expected if expected is not None else bytes(672)) + target)
    # Scope, generation, predecessor and current-value comparisons all refuse
    # before appending; every typed checkpoint is canonical independently.
    for target in (cp1, record((1 << 64) - 1)):
        expect(cas(None, target), 1, "compare-and-advance failed")
    cas(None, cp0)
    wrong_scope = record(scope=bytes([33]) * 32, watermark_scope=bytes([33]) * 32)
    candidates = [(wrong_scope, cp1), (cp0, cp0), (cp0, record(2)),
                  (cp0, record(1)), (record((1 << 64) - 1), cp0),
                  (None, cp0), (cp1, record(2, predecessor=cp1[640:]))]
    original_lengths = [(q / "journal").stat().st_size for q in (p.na, p.nb)]
    for expected, target in candidates:
        expect(cas(expected, target), 1, "compare-and-advance failed")
        need([(q / "journal").stat().st_size for q in (p.na, p.nb)] == original_lengths,
             "Refused CAS appended a journal record")
    cas(cp0, cp1)
    # Independent scopes in one journal share one full-journal count.
    for marker in range(34, 43):
        cp = record(scope=bytes([marker]) * 32, watermark_scope=bytes([marker]) * 32)
        cas(None, cp)
        got = p.call(16, cp[16:48])
        need(got[1] == struct.pack("<Q", 1) + cp, "Cross-scope cache value differs")
    saved = p.call(14)[1]
    need(int.from_bytes(saved[12:20], "big") == 11, "Full journal pin lost another scope")
    p.call(19)
    p.path(12, "journal", saved)
    p.call(16, cp0[16:48])
    p.call(19)
    state(p)
    p.close()

    # A second actual process cannot acquire an owner lock. Release must allow
    # an exact pinned reopen; failures cannot leak descriptor or lock custody.
    for ledger in (False, True):
        p = suite.pair("lock-owner-" + str(ledger))
        other = suite.pair("lock-contender-" + str(ledger))
        p.path(40 if ledger else 11, "state", cp0 if ledger else b"")
        prefix = cp0 + cp1 if ledger else p.call(14)[1]
        method, drop = (41, 45) if ledger else (12, 19)
        before = [len(os.listdir("/proc/" + str(a.p.pid) + "/fd")) for a in (other.a, other.b)]
        for _ in range(3):
            value = other.call(method, prefix + bytes(p.na / "state"),
                               prefix + bytes(p.nb / "state"), label="held-lock")
            expect(value, 1, "lock")
        after = [len(os.listdir("/proc/" + str(a.p.pid) + "/fd")) for a in (other.a, other.b)]
        need(before == after, ("Failed constructors leaked descriptors", before, after))
        p.call(drop)
        other.call(method, prefix + bytes(p.na / "state"), prefix + bytes(p.nb / "state"))
        other.call(drop)
        other.close()
        p.close()
