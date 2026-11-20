"""Finite, explicitly typed test corpus for the staging relation."""
from __future__ import annotations
from dataclasses import dataclass, replace
import itertools
import json
import random
import struct

MAX = (1 << 64) - 1
BLOCK = bytes(range(32))
SLOT = 7

def kv(rows) -> bytes:
    return b"TKVSTR01" + struct.pack("<Q", len(rows)) + b"".join(
        struct.pack("<QQ", len(key), len(value)) + key + value for key, value in rows)

def delta(rows) -> bytes:
    return b"NDLT0001" + struct.pack("<Q", len(rows)) + BLOCK + struct.pack("<Q", SLOT) + b"".join(
        struct.pack("<QQQ", len(key), MAX if before is None else len(before),
                    MAX if after is None else len(after)) + key +
        (b"" if before is None else before) + (b"" if after is None else after)
        for key, before, after in rows)

@dataclass(frozen=True)
class Case:
    name: str
    before: tuple
    changes: tuple
    result: tuple
    code: int = 0
    fail_delta: int | None = None
    fail_row: int | None = None
    detach: bool = False
    root: bool = True
    profile: int = 0
    cancel: int | None = None
    cancel_class: int = 2
    token: int = 0x12345678

    def corpus(self) -> dict:
        return {"name": self.name, "base_hex": kv(self.before).hex(),
            "delta_hex": delta(self.changes).hex(), "detach": self.detach, "root": self.root,
            "profile": self.profile, "cancel": self.cancel, "cancel_class": self.cancel_class,
            "token": self.token}

    def progress(self):
        events = [(1, 0), (2, 0)]
        n = len(self.changes)
        events.extend((3, count) for count in range(256, n + 1, 256))
        events.append((3, n))
        for index in range(n):
            events.append((4, index))
            if index == self.fail_delta:
                break
        else:
            events.append((5, 0))
            for index in range(len(self.result)):
                if index % 256 == 0:
                    events.append((6, index))
                if index == self.fail_row:
                    break
            else:
                events.append((7, len(self.result)))
        if self.cancel is not None:
            if not 1 <= self.cancel <= len(events):
                raise ValueError("Cancellation outside actual progress relation")
            events = events[:self.cancel]
        return [[index + 1, kind, row] for index, (kind, row) in enumerate(events)]

def cases() -> list[Case]:
    result = [
        Case("empty", (), (), ()),
        Case("identity", ((b"a", b"1"),), (), ((b"a", b"1"),)),
        Case("insert", (), ((b"a", None, b"1"),), ((b"a", b"1"),)),
        Case("replace", ((b"a", b"1"),), ((b"a", b"1", b"2"),), ((b"a", b"2"),)),
        Case("delete", ((b"a", b"1"),), ((b"a", b"1", None),), ()),
        Case("mixed", ((b"a", b"1"), (b"c", b"3"), (b"z", b"9")),
            ((b"a", b"1", b"2"), (b"b", None, b"4"), (b"c", b"3", None)),
            ((b"a", b"2"), (b"b", b"4"), (b"z", b"9"))),
    ]
    for index, (actual, before, after, detach) in enumerate(itertools.product(
            (None, b"", b"0", b"1", b"false", b"{}"),
            (None, b"", b"0", b"1"), (None, b"", b"0", b"2"), (False, True))):
        expected, new = (after, before) if detach else (before, after)
        base = () if actual is None else ((b"k", actual),)
        rows = () if new is None else ((b"k", new),)
        code, fail_delta, fail_row = 0, None, None
        if actual != expected:
            code, fail_delta = 81, 0
        elif new is None and actual is None:
            code, fail_delta = 82, 0
        elif new == b"":
            code, fail_row = 83, 0
        result.append(Case(f"options-{index:03}", base, ((b"k", before, after),),
            rows, code, fail_delta, fail_row, detach))
    valid = [b"null", b"true", b"false", b"0", b"-1", b"-9223372036854775808",
        b"18446744073709551615", b'""', b'"a"', b'"\\n\\t\\r\\b\\f\\\\\\""',
        b'"\\u0000"', b'"\\u001f"', b'"\x7f"', b"[]", b"{}", b'[null,true,-1,"a"]',
        b'{"a":1,"b":[false,{"c":"x"}]}']
    for index, value in enumerate(valid):
        rows = ((b"v", value),)
        result.append(Case(f"canonical-{index:02}", rows, (), rows))
    for index, value in enumerate((b" 1", b"1 ", b'{"b":1,"a":2}', b'{"a":1,"a":2}',
            b'"\\u0061"', b'"\\/"', b"1e0", b"1.00", b"-0", b"18446744073709551616",
            b"0.000000", b'["a", 1]')):
        rows = ((b"v", value),)
        result.append(Case(f"roundtrip-{index:02}", rows, (), rows, 84, fail_row=0))
    malformed = (b"", b"nul", b"truefalse", b"01", b"+1", b".1", b"1.", b"1e",
        b"1e400", b"[", b"{}", b"[1,]", b'{"a":}', b'"\\q"', b'"\\ud800"',
        b'"\xff"', b"\xff", b'"\n"', b"nullx")
    for index, value in enumerate(malformed):
        if value == b"{}":
            continue
        rows = ((b"v", value),)
        result.append(Case(f"serde-refusal-{index:02}", rows, (), rows, 83, fail_row=0))
    for index, value in enumerate((b"1.0", b"-0.0", b"1.25", b'{"a":[1.0]}')):
        rows = ((b"v", value),)
        result.extend((Case(f"float-stored-{index}", rows, (), rows, root=False),
            Case(f"float-root-{index}", rows, (), rows, 85)))
    for index, value in enumerate(('"é"'.encode(), '{"é":1}'.encode(), '["😀"]'.encode())):
        rows = ((b"v", value),)
        result.extend((Case(f"unicode-stored-{index}", rows, (), rows, root=False),
            Case(f"unicode-root-{index}", rows, (), rows, 86)))
    for label, value, code in (
            ("nested-float-first", '[1.0,"é"]'.encode(), 85),
            ("nested-unicode-first", '["é",1.0]'.encode(), 86),
            ("object-key-before-float", '{"é":1.0}'.encode(), 86)):
        rows = ((b"v", value),)
        result.append(Case(label, rows, (), rows, code))
    for key in (b"", b"x" * 159, b"x" * 160, "é".encode() * 80, b"\0", "😀".encode()):
        rows = ((key, b"null"),)
        result.append(Case("key-" + key.hex()[:20] + "-" + str(len(key)), rows, (), rows,
            83 if not key else 0, fail_row=0 if not key else None))
    projection = [
        Case("projection-both-empty", ((b"", b""),), (), ((b"", b""),), 83, fail_row=0),
        Case("projection-empty-key-before-json", ((b"", b"bad"),), (), ((b"", b"bad"),), 83, fail_row=0),
        Case("projection-empty-key-before-m06", ((b"", b"1.0"),), (), ((b"", b"1.0"),), 83, fail_row=0),
        Case("projection-empty-value", ((b"k", b""),), (), ((b"k", b""),), 83, fail_row=0),
        Case("projection-value-dimension-before-key-null", ((b"", b"x" * 4097),), (), ((b"", b"x" * 4097),), 84, fail_row=0),
        Case("projection-key-dimension-before-value-null", ((b"k" * 161, b""),), (), ((b"k" * 161, b""),), 84, fail_row=0),
        Case("projection-truncated-utf8-key-dimension-first", ((b"k" * 160 + "é".encode(), b""),), (),
            ((b"k" * 160 + "é".encode(), b""),), 84, fail_row=0),
        Case("projection-empty-key-insert", (), ((b"", None, b"null"),), ((b"", b"null"),), 83, fail_row=0),
        Case("projection-empty-key-delete", ((b"", b"null"),), ((b"", b"null", None),), ()),
        Case("projection-empty-key-detach-delete", ((b"", b"null"),), ((b"", None, b"null"),), (), detach=True),
        Case("projection-empty-value-repair", ((b"k", b""),), ((b"k", b"", b"null"),), ((b"k", b"null"),)),
        Case("projection-empty-value-delete", ((b"k", b""),), ((b"k", b"", None),), ()),
        Case("projection-empty-key-before-mismatch", ((b"", b"null"),), ((b"", b"false", b"1"),),
            ((b"", b"1"),), 81, fail_delta=0),
        Case("projection-empty-key-absent-delete", (), ((b"", None, None),), (), 82, fail_delta=0),
        Case("projection-empty-key-after-unrelated-mismatch", ((b"", b"null"), (b"z", b"1")),
            ((b"z", b"2", b"3"),), ((b"", b"null"), (b"z", b"3")), 81, fail_delta=0),
        Case("projection-empty-key-deleted-before-next-serde", ((b"", b"null"), (b"z", b"bad")),
            ((b"", b"null", None),), ((b"z", b"bad"),), 83, fail_row=0),
    ]
    result.extend(projection)
    for point in (4, 5):
        result.append(replace(projection[1], name=f"projection-cancel-before-key-null-{point}",
            code=80, cancel=point))
    for length in (1, 2, 31, 32, 55, 56, 63, 64, 65, 127, 255, 256, 4095, 4096):
        value = b"0" if length == 1 else b'"' + b"x" * (length - 2) + b'"'
        rows = ((b"v", value),)
        result.append(Case(f"stored-extent-{length}", rows, (), rows))
    for key, value, label in ((b"k" * 161, b"bad", "key-plus-one"),
            (b"k", b"x" * 4097, "value-plus-one"),
            (b"k" * 161, b"x" * 4097, "both-plus-one")):
        rows = ((key, value),)
        result.append(Case(label, rows, (), rows, 84, fail_row=0))
        result.append(Case(label + "-removed", rows, ((key, value, None),), ()))
    wide_key = b"a" * 32767 + "😀".encode() + b"z" * 12
    for name, key in (("chunk-key", b"k" * 32769), ("split-utf8-key", wide_key)):
        rows = ((key, b"not-json"),)
        result.append(Case(name + "-removed", rows, ((key, b"not-json", None),), ()))
        result.append(Case(name + "-survives", rows, (), rows, 84, fail_row=0))
    huge = b"x" * ((2 << 20) + 17)
    result.append(Case("value-over-two-mib-replaced", ((b"k", huge),),
        ((b"k", huge, b"1"),), ((b"k", b"1"),)))
    changed = huge[:-1] + b"y"
    result.append(Case("value-over-two-mib-last-byte-mismatch", ((b"k", huge),),
        ((b"k", changed, b"1"),), ((b"k", b"1"),), 81, fail_delta=0))
    result.append(Case("before-json-does-not-preempt-delta", ((b"a", b"bad"), (b"z", b"1")),
        ((b"z", b"2", b"3"),), ((b"a", b"bad"), (b"z", b"3")), 81, fail_delta=0))
    result.append(Case("late-serde-after-all-deltas", ((b"a", b"1"), (b"z", b"bad")),
        ((b"a", b"1", b"2"),), ((b"a", b"2"), (b"z", b"bad")), 83, fail_row=1))
    for count in (255, 256, 257, 511, 512, 513):
        rows = tuple((f"k{index:06}".encode(), b"1") for index in range(count))
        changes = tuple((key, None, value) for key, value in rows)
        result.append(Case(f"progress-boundary-{count}", (), changes, rows, root=False))
    rng = random.Random(0x545354414745)
    for index in range(24):
        before = {}
        after = {}
        for key_index in range(17):
            key = f"k{key_index:03}".encode()
            if rng.randrange(3):
                before[key] = str(rng.randrange(100)).encode()
            if rng.randrange(3):
                after[key] = str(rng.randrange(100)).encode()
        changes = tuple((key, before.get(key), after.get(key))
            for key in sorted(before.keys() | after.keys()) if before.get(key) != after.get(key))
        left, right = tuple(sorted(before.items())), tuple(sorted(after.items()))
        result.append(Case(f"random-attach-{index}", left, changes, right))
        result.append(Case(f"random-detach-{index}", right, changes, left, detach=True))
    seeds = [result[0], result[5], next(row for row in result if row.name == "progress-boundary-257")]
    for seed in seeds:
        positions = range(1, len(seed.progress()) + 1) if len(seed.progress()) <= 12 else (1, 2, 3, 4, 5, 130, 260, 262, 263, 264)
        for position in positions:
            if position <= len(seed.progress()):
                result.append(replace(seed, name=f"cancel-{seed.name}-{position}", code=80, cancel=position))
    names = [row.name for row in result]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate semantic case name")
    return result
