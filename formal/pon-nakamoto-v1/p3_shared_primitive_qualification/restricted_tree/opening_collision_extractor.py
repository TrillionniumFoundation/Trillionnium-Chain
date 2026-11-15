#!/usr/bin/env python3
"""Deterministic, oracle-independent two-opening -> full-hash collision checker.

This is a mathematical harness for one ordinary fixed-shape binary Merkle path,
not an adapter for P3 MMCS, a hash attack, or a quantum knowledge extractor.
Tags are local test tags, not an authorized protocol profile identifier.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable

GOLDILOCKS = 18446744069414584321
LEAF_TAG = b"TRNM-P3-BINARY-EXTRACTION-CHECK/V1\0LEAF\0"
BRANCH_TAG = b"TRNM-P3-BINARY-EXTRACTION-CHECK/V1\0BRANCH\0"
Hash = Callable[[bytes], bytes]


def _uint(value: int, bits: int, name: str) -> bytes:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"{name} must be a canonical unsigned {bits}-bit integer")
    return value.to_bytes(bits // 8, "little")


@dataclass(frozen=True)
class Context:
    profile: bytes
    height: int
    index: int
    leaf_width: int
    digest_bytes: int

    def validate(self) -> None:
        if not isinstance(self.profile, bytes) or not self.profile:
            raise ValueError("profile must be nonempty bytes")
        _uint(len(self.profile), 32, "profile length")
        if type(self.height) is not int or not 0 <= self.height <= 64:
            raise ValueError("this harness supports heights 0..64")
        if type(self.index) is not int or not 0 <= self.index < (1 << self.height):
            raise ValueError("index outside the fixed tree")
        _uint(self.leaf_width, 32, "leaf width")
        if type(self.digest_bytes) is not int or self.digest_bytes <= 0:
            raise ValueError("digest_bytes must be positive")

    def prefix(self, tag: bytes) -> bytes:
        # The fixed profile and length framing make tag/profile parsing unique.
        return tag + _uint(len(self.profile), 32, "profile length") + self.profile

    def leaf_input(self, row: tuple[int, ...]) -> bytes:
        if len(row) != self.leaf_width:
            raise ValueError("leaf width differs from verifier context")
        for x in row:
            if type(x) is not int or not 0 <= x < GOLDILOCKS:
                raise ValueError("field element is not canonical Goldilocks")
        return self.prefix(LEAF_TAG) + _uint(len(row), 32, "row width") + b"".join(
            _uint(x, 64, "field element") for x in row
        )

    def branch_input(self, left: bytes, right: bytes) -> bytes:
        if not isinstance(left, bytes) or not isinstance(right, bytes):
            raise ValueError("digests must be bytes")
        if len(left) != self.digest_bytes or len(right) != self.digest_bytes:
            raise ValueError("digest has the wrong full-output length")
        return self.prefix(BRANCH_TAG) + left + right


@dataclass(frozen=True)
class Opening:
    row: tuple[int, ...]
    siblings: tuple[bytes, ...]


@dataclass(frozen=True)
class Query:
    level: int
    role: str
    message: bytes
    digest: bytes


@dataclass(frozen=True)
class Collision:
    level: int
    role: str
    message0: bytes
    message1: bytes
    digest: bytes
    hash_calls: int


class Recorder:
    """Check output length and observed determinism; do not assume an ideal hash."""
    def __init__(self, function: Hash, digest_bytes: int):
        self.function = function
        self.digest_bytes = digest_bytes
        self.calls = 0
        self.seen: dict[bytes, bytes] = {}

    def __call__(self, message: bytes) -> bytes:
        digest = self.function(message)
        self.calls += 1
        if not isinstance(digest, bytes) or len(digest) != self.digest_bytes:
            raise ValueError("hash did not return its complete declared output")
        if message in self.seen and self.seen[message] != digest:
            raise ValueError("the supplied callable is not deterministic")
        self.seen[message] = digest
        return digest


def evaluate(context: Context, opening: Opening, function: Hash) -> tuple[Query, ...]:
    context.validate()
    if len(opening.siblings) != context.height:
        raise ValueError("path length differs from the fixed tree height")
    message = context.leaf_input(opening.row)
    digest = function(message)
    queries = [Query(0, "leaf", message, digest)]
    for level, sibling in enumerate(opening.siblings):
        if (context.index >> level) & 1:
            message = context.branch_input(sibling, digest)
        else:
            message = context.branch_input(digest, sibling)
        digest = function(message)
        queries.append(Query(level + 1, "branch", message, digest))
    return tuple(queries)


def extract_collision(
    context: Context, root: bytes, opening0: Opening, opening1: Opening, function: Hash
) -> Collision:
    """Require two accepted conflicting rows; return a collision in full function.

    Siblings are arbitrary bytes of the correct digest length. No reachability
    or preimage witness is requested for them. All appended hash calls are
    counted, including duplicate queries. Neither input path is mutated.
    """
    context.validate()
    if not isinstance(root, bytes) or len(root) != context.digest_bytes:
        raise ValueError("root has the wrong complete digest length")
    if opening0.row == opening1.row:
        raise ValueError("conflicting openings require distinct rows")
    recorder = Recorder(function, context.digest_bytes)
    queries0 = evaluate(context, opening0, recorder)
    queries1 = evaluate(context, opening1, recorder)
    if queries0[-1].digest != root or queries1[-1].digest != root:
        raise ValueError("both openings must be accepted against the same root")
    for level, (query0, query1) in enumerate(zip(queries0, queries1, strict=True)):
        if query0.digest == query1.digest:
            # This is the first merge. At level zero, canonical row encoding
            # makes the messages distinct; later, the different running child
            # occupies the same fixed slot in both injective branch encodings.
            if query0.message == query1.message:
                raise AssertionError("injective encoding / first-merge invariant failed")
            return Collision(level, query0.role, query0.message, query1.message,
                             query0.digest, recorder.calls)
    raise AssertionError("equal accepted roots must contain a first merge")


def verify_collision(collision: Collision, function: Hash) -> bool:
    """Two additional hash calls, if a caller independently rechecks the result."""
    return collision.message0 != collision.message1 and (
        function(collision.message0) == collision.digest == function(collision.message1)
    )
