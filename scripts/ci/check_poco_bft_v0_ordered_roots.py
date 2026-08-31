#!/usr/bin/env python3
"""Reconstruct PoCO-BFT v0 deterministic ordered-root golden vectors.

This checker intentionally uses only the Python standard library and does not
call the Rust consensus crates.  It freezes the CEV0 preimages for ordered
payload, receipt, and evidence roots, including odd-node duplicate-right
handling and the outer item-count commitment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


HASH_PREFIX = b"trnm.cev0.hash.v0"
LEAF_DOMAIN = b"trnm.poco-bft.ordered-leaf.v0"
NODE_DOMAIN = b"trnm.poco-bft.ordered-node.v0"
ROOT_DOMAIN = b"trnm.poco-bft.ordered-root.v0"
DOMAINS = {LEAF_DOMAIN, NODE_DOMAIN, ROOT_DOMAIN}

SCHEMA_VERSION = 0
KINDS = {
    "payload": 0,
    "receipts": 1,
    "evidence": 2,
}
EXPECTED_EMPTY_ROOTS = {
    "payload": "0165aeb0b26dc305d5d2a639f4d8ad56abd03fcf165af902d856ecf58eebced2",
    "receipts": "b455563b0b1e6ce49c079d2ef14e20dbccb1168af66d245d7295c45fa0895156",
    "evidence": "df2f0138177d79d16f277d2c45d5a9fdbe492daa75c2b28fb901f3450022b047",
}

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR = (
    REPO_ROOT / "docs/protocol/poco-bft-v0/vectors/ordered-roots-v0.json"
)

# The same byte sequence is used for every kind so kind-domain separation is
# directly visible.  Prefix counts 0..4 select the conformance cases.
FIXTURE_ITEMS = (
    b"",
    b"\x00",
    b"\x00\xff",
    b"cev0",
)


class VectorError(ValueError):
    """The ordered-root input, vector, or claimed relationship is invalid."""


def uint(value: object, bits: int, label: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VectorError(f"{label} must be an unsigned u{bits} integer")
    if value < 0 or value >= 1 << bits:
        raise VectorError(f"{label} is outside u{bits}")
    return value.to_bytes(bits // 8, "big")


def fixed_hash(value: object, label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise VectorError(f"{label} must contain exactly 32 bytes")
    return value


def cev0_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise VectorError(f"{label} must be bytes")
    return uint(len(value), 32, f"{label} length") + value


def optional_hash(value: bytes | None) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + fixed_hash(value, "optional inner hash")


def frame(value: bytes) -> bytes:
    return uint(len(value), 32, "digest frame length") + value


def digest(domain: bytes, encoded: bytes) -> bytes:
    if domain not in DOMAINS:
        raise VectorError(f"unfrozen ordered-root domain: {domain!r}")
    return hashlib.sha256(
        frame(HASH_PREFIX) + frame(domain) + frame(encoded)
    ).digest()


def validate_kind(kind: object) -> int:
    if isinstance(kind, bool) or not isinstance(kind, int):
        raise VectorError("ordered-root kind must be an integer")
    if kind not in KINDS.values():
        raise VectorError(f"unknown ordered-root kind: {kind}")
    return kind


def encode_leaf(kind: int, index: int, item: bytes) -> bytes:
    """Encode (schema_version, kind, index, Bytes item) in exact CEV0 order."""

    return b"".join(
        (
            uint(SCHEMA_VERSION, 16, "leaf schema_version"),
            uint(validate_kind(kind), 8, "leaf kind"),
            uint(index, 32, "leaf index"),
            cev0_bytes(item, "leaf item"),
        )
    )


def encode_node(
    kind: int,
    level: int,
    left: bytes,
    right: bytes,
) -> bytes:
    """Encode (schema_version, kind, level, left, right) in CEV0 order."""

    return b"".join(
        (
            uint(SCHEMA_VERSION, 16, "node schema_version"),
            uint(validate_kind(kind), 8, "node kind"),
            uint(level, 32, "node level"),
            fixed_hash(left, "left child hash"),
            fixed_hash(right, "right child hash"),
        )
    )


def encode_root(kind: int, item_count: int, inner: bytes | None) -> bytes:
    """Encode (schema_version, kind, item_count, Optional<Hash32> inner)."""

    return b"".join(
        (
            uint(SCHEMA_VERSION, 16, "root schema_version"),
            uint(validate_kind(kind), 8, "root kind"),
            uint(item_count, 32, "root item_count"),
            optional_hash(inner),
        )
    )


def ordered_root_trace(kind: int, values: Iterable[bytes]) -> dict[str, object]:
    """Build an ordered root and retain every canonical preimage for vectors."""

    kind = validate_kind(kind)
    items = tuple(values)
    uint(len(items), 32, "ordered-root item count")

    leaf_preimages = tuple(
        encode_leaf(kind, index, item) for index, item in enumerate(items)
    )
    leaf_hashes = tuple(digest(LEAF_DOMAIN, encoded) for encoded in leaf_preimages)

    current = leaf_hashes
    node_levels: list[dict[str, object]] = []
    level = 0
    while len(current) > 1:
        parents: list[bytes] = []
        pairs: list[dict[str, object]] = []
        for offset in range(0, len(current), 2):
            left = current[offset]
            duplicated_right = offset + 1 == len(current)
            right = left if duplicated_right else current[offset + 1]
            encoded = encode_node(kind, level, left, right)
            parent = digest(NODE_DOMAIN, encoded)
            parents.append(parent)
            pairs.append(
                {
                    "pair_index": offset // 2,
                    "duplicate_right": duplicated_right,
                    "left_hash": left,
                    "right_hash": right,
                    "node_preimage": encoded,
                    "node_hash": parent,
                }
            )
        node_levels.append({"level": level, "pairs": tuple(pairs)})
        current = tuple(parents)
        level += 1

    inner = None if not current else current[0]
    root_preimage = encode_root(kind, len(items), inner)
    root = digest(ROOT_DOMAIN, root_preimage)
    return {
        "items": items,
        "leaf_preimages": leaf_preimages,
        "leaf_hashes": leaf_hashes,
        "node_levels": tuple(node_levels),
        "inner": inner,
        "root_preimage": root_preimage,
        "root": root,
    }


def ordered_root(kind: int, values: Iterable[bytes]) -> bytes:
    root = ordered_root_trace(kind, values)["root"]
    assert isinstance(root, bytes)
    return root


def validate_claim(
    kind: int,
    values: Iterable[bytes],
    claimed_item_count: int,
    claimed_root: bytes,
) -> None:
    """Validate a claimed root without normalizing a mismatched item count."""

    items = tuple(values)
    uint(claimed_item_count, 32, "claimed item_count")
    if claimed_item_count != len(items):
        raise VectorError("claimed item_count does not equal the ordered item count")
    if fixed_hash(claimed_root, "claimed root") != ordered_root(kind, items):
        raise VectorError("claimed ordered root does not match the ordered items")


def hex_trace(trace: dict[str, object]) -> dict[str, object]:
    items = trace["items"]
    leaf_preimages = trace["leaf_preimages"]
    leaf_hashes = trace["leaf_hashes"]
    node_levels = trace["node_levels"]
    inner = trace["inner"]
    root_preimage = trace["root_preimage"]
    root = trace["root"]
    assert isinstance(items, tuple)
    assert isinstance(leaf_preimages, tuple)
    assert isinstance(leaf_hashes, tuple)
    assert isinstance(node_levels, tuple)
    assert inner is None or isinstance(inner, bytes)
    assert isinstance(root_preimage, bytes)
    assert isinstance(root, bytes)

    encoded_levels: list[dict[str, object]] = []
    for node_level in node_levels:
        assert isinstance(node_level, dict)
        pairs = node_level["pairs"]
        assert isinstance(pairs, tuple)
        encoded_pairs: list[dict[str, object]] = []
        for pair in pairs:
            assert isinstance(pair, dict)
            encoded_pairs.append(
                {
                    "pair_index": pair["pair_index"],
                    "duplicate_right": pair["duplicate_right"],
                    "left_hash_hex": pair["left_hash"].hex(),
                    "right_hash_hex": pair["right_hash"].hex(),
                    "node_preimage_hex": pair["node_preimage"].hex(),
                    "node_hash_hex": pair["node_hash"].hex(),
                }
            )
        encoded_levels.append(
            {"level": node_level["level"], "pairs": encoded_pairs}
        )

    return {
        "item_count": len(items),
        "items_hex": [item.hex() for item in items],
        "leaf_preimages_hex": [item.hex() for item in leaf_preimages],
        "leaf_hashes_hex": [item.hex() for item in leaf_hashes],
        "node_levels": encoded_levels,
        "inner_hash_hex": None if inner is None else inner.hex(),
        "root_preimage_hex": root_preimage.hex(),
        "root_hex": root.hex(),
    }


def root_case(trace: dict[str, object]) -> dict[str, object]:
    """Keep the 0..4 cross-kind matrix compact; detailed traces live below."""

    items = trace["items"]
    inner = trace["inner"]
    root_preimage = trace["root_preimage"]
    root = trace["root"]
    assert isinstance(items, tuple)
    assert inner is None or isinstance(inner, bytes)
    assert isinstance(root_preimage, bytes)
    assert isinstance(root, bytes)
    return {
        "item_count": len(items),
        "items_hex": [item.hex() for item in items],
        "inner_hash_hex": None if inner is None else inner.hex(),
        "root_preimage_hex": root_preimage.hex(),
        "root_hex": root.hex(),
    }


def rejected_mutation(
    kind: int,
    items: tuple[bytes, ...],
    claimed_count: int,
    claimed_root: bytes,
) -> str:
    try:
        validate_claim(kind, items, claimed_count, claimed_root)
    except VectorError as error:
        return str(error)
    raise VectorError("leaf-count mutation was unexpectedly accepted")


def build_vectors() -> dict[str, object]:
    cases = {
        name: [
            root_case(ordered_root_trace(kind, FIXTURE_ITEMS[:count]))
            for count in range(5)
        ]
        for name, kind in KINDS.items()
    }

    empty_roots = {
        name: cases[name][0]["root_hex"] for name in KINDS
    }
    if empty_roots != EXPECTED_EMPTY_ROOTS:
        raise VectorError(
            "computed empty roots do not match the frozen PoCO-BFT v0 constants"
        )

    order_original = (b"alpha", b"beta", b"gamma")
    order_reversed = tuple(reversed(order_original))
    order_root = ordered_root(KINDS["payload"], order_original)
    reversed_root = ordered_root(KINDS["payload"], order_reversed)
    if order_root == reversed_root:
        raise VectorError("ordered root did not bind item order")

    framing_left = (b"a", b"bc")
    framing_right = (b"ab", b"c")
    if b"".join(framing_left) != b"".join(framing_right):
        raise VectorError("framing fixtures do not have equal raw concatenations")
    framing_left_trace = ordered_root_trace(KINDS["payload"], framing_left)
    framing_right_trace = ordered_root_trace(KINDS["payload"], framing_right)
    framing_left_root = framing_left_trace["root"]
    framing_right_root = framing_right_trace["root"]
    assert isinstance(framing_left_root, bytes)
    assert isinstance(framing_right_root, bytes)
    if framing_left_root == framing_right_root:
        raise VectorError("ordered root did not bind Bytes framing")

    three_items = FIXTURE_ITEMS[:3]
    three_trace = ordered_root_trace(KINDS["payload"], three_items)
    three_inner = three_trace["inner"]
    three_root = three_trace["root"]
    assert isinstance(three_inner, bytes)
    assert isinstance(three_root, bytes)
    mutated_count_preimage = encode_root(KINDS["payload"], 4, three_inner)
    mutated_count_root = digest(ROOT_DOMAIN, mutated_count_preimage)
    if mutated_count_root == three_root:
        raise VectorError("outer ordered root did not bind item_count")
    mutation_error = rejected_mutation(
        KINDS["payload"], three_items, 4, mutated_count_root
    )

    same_items = (b"same-item",)
    kind_roots = {
        name: ordered_root(kind, same_items).hex() for name, kind in KINDS.items()
    }
    if len(set(kind_roots.values())) != len(KINDS):
        raise VectorError("ordered roots did not bind the root kind")

    left_leaves = framing_left_trace["leaf_preimages"]
    right_leaves = framing_right_trace["leaf_preimages"]
    assert isinstance(left_leaves, tuple)
    assert isinstance(right_leaves, tuple)

    public_leaf_preimage = encode_leaf(KINDS["payload"], 0, b"a")
    public_leaf_digest = digest(LEAF_DOMAIN, public_leaf_preimage)

    return {
        "schema": "trnm_poco_bft_ordered_roots_vectors_v0",
        "protocol_version": 0,
        "public_leaf_helper": {
            "kind": "payload",
            "index": 0,
            "item_hex": "61",
            "leaf_preimage_hex": public_leaf_preimage.hex(),
            "leaf_digest_hex": public_leaf_digest.hex(),
        },
        "canonical_codec": "CEV0",
        "hash_algorithm": "sha256",
        "hash_prefix_ascii": HASH_PREFIX.decode("ascii"),
        "domains": {
            "leaf": LEAF_DOMAIN.decode("ascii"),
            "node": NODE_DOMAIN.decode("ascii"),
            "root": ROOT_DOMAIN.decode("ascii"),
        },
        "kind_codes": KINDS,
        "algorithm": {
            "leaf_preimage": "u16(schema=0) || u8(kind) || u32(index) || Bytes(item)",
            "node_preimage": "u16(schema=0) || u8(kind) || u32(level) || Hash32(left) || Hash32(right)",
            "root_preimage": "u16(schema=0) || u8(kind) || u32(item_count) || Optional<Hash32>(inner)",
            "first_parent_level": 0,
            "odd_node_rule": "duplicate-right at every level",
            "empty_inner": "Optional::Absent",
            "outer_root_always_hashed": True,
        },
        "fixture_items_hex": [item.hex() for item in FIXTURE_ITEMS],
        "frozen_empty_roots_hex": empty_roots,
        "cases": cases,
        "detailed_tree_traces": {
            "payload_count_3_duplicate_right": hex_trace(three_trace),
            "payload_count_4_balanced": hex_trace(
                ordered_root_trace(KINDS["payload"], FIXTURE_ITEMS)
            ),
        },
        "relational_checks": {
            "item_order": {
                "kind": "payload",
                "original_items_hex": [item.hex() for item in order_original],
                "reversed_items_hex": [item.hex() for item in order_reversed],
                "original_root_hex": order_root.hex(),
                "reversed_root_hex": reversed_root.hex(),
                "roots_differ": True,
            },
            "bytes_framing": {
                "kind": "payload",
                "left_items_hex": [item.hex() for item in framing_left],
                "right_items_hex": [item.hex() for item in framing_right],
                "equal_unframed_concatenation_hex": b"".join(framing_left).hex(),
                "left_leaf_preimages_hex": [item.hex() for item in left_leaves],
                "right_leaf_preimages_hex": [item.hex() for item in right_leaves],
                "left_root_hex": framing_left_root.hex(),
                "right_root_hex": framing_right_root.hex(),
                "roots_differ": True,
            },
            "duplicate_right_leaf_count_mutation": {
                "kind": "payload",
                "actual_items_hex": [item.hex() for item in three_items],
                "actual_item_count": 3,
                "inner_hash_hex": three_inner.hex(),
                "actual_root_hex": three_root.hex(),
                "mutated_item_count": 4,
                "mutated_root_preimage_hex": mutated_count_preimage.hex(),
                "mutated_root_hex": mutated_count_root.hex(),
                "roots_differ": True,
                "accepted_by_reference_validator": False,
                "expected_error": mutation_error,
            },
            "kind_domain_separation": {
                "items_hex": [item.hex() for item in same_items],
                "roots_hex": kind_roots,
                "all_roots_distinct": True,
            },
        },
        "scope": (
            "Independent ordered-root CEV0, SHA-256, kind, order, framing, "
            "duplicate-right, and item-count conformance vectors for payload, "
            "receipt, and evidence items."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument(
        "--print-expected",
        action="store_true",
        help="print the independently reconstructed JSON",
    )
    args = parser.parse_args()

    try:
        expected = build_vectors()
    except (AssertionError, TypeError, VectorError) as error:
        print(f"ordered-root reference check failed: {error}", file=sys.stderr)
        return 1

    if args.print_expected:
        print(json.dumps(expected, indent=2, sort_keys=True))
        return 0

    try:
        with args.vector.open("r", encoding="utf-8") as source:
            committed = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        print(f"ordered-root vector could not be loaded: {error}", file=sys.stderr)
        return 1

    if committed != expected:
        print(
            "committed ordered-root vector differs from independent "
            "reconstruction; run with --print-expected and review the "
            "protocol change",
            file=sys.stderr,
        )
        return 1

    print(
        "[ok] PoCO-BFT v0 ordered-root vectors: "
        f"15 roots, empty-payload={EXPECTED_EMPTY_ROOTS['payload']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
