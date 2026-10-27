#!/usr/bin/env python3
"""Fail-closed exact-byte checker for a RESEARCH-only PQ merge.

This checks source identity and false activation flags. It does not execute
cryptography, verify PoN security, or establish production qualification.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import sys

REL_MANIFEST = "config/pon/pq-cross-branch-corpus-v1.json"
REQUIRED_UPSTREAM = frozenset(("base", "cell", "migration", "witness", "roster", "parity"))
REQUIRED_FALSE = frozenset((
    "production_activation", "independent_accepted", "native_pq_node_integrated",
    "quantum_pon_hardness_qualified", "physical_rollback_resistant",
    "hepta_final_use_integrated", "public_wan_accepted", "allow_legacy_fallback",
))

# Enumerate research implementation entrypoints, not just manually listed pins.
# This prevents a new PQ verifier from being silently omitted from the
# source-integrity manifest. This is NOT proof of cryptographic acceptance.
PQ_SOURCE_DIRS = (
    "formal/pon-nakamoto-v1",
    "trillionnium/crates/trnm-protocol/src",
    "trillionnium/crates/trnm-crypto-primitives/src",
)

class IntegrityError(ValueError):
    pass


def _safe_regular(root: Path, relative: str, ceiling: int = 4 * 1024 * 1024) -> bytes:
    if (type(relative) is not str or not relative or "\\" in relative
            or relative.startswith("/") or relative.split("/") != list(Path(relative).parts)
            or any(p in ("", ".", "..") for p in relative.split("/"))):
        raise IntegrityError("unsafe path")
    path = root
    for part in relative.split("/"):
        path = path / part
        if path.is_symlink():
            raise IntegrityError("symlink source refused: " + relative)
    try:
        st = path.stat()
    except OSError as exc:
        raise IntegrityError("missing source: " + relative) from exc
    if not stat.S_ISREG(st.st_mode) or st.st_size > ceiling:
        raise IntegrityError("nonregular/oversize source: " + relative)
    data = path.read_bytes()
    if len(data) != st.st_size:
        raise IntegrityError("changing source: " + relative)
    return data


def _json(root: Path, relative: str) -> dict:
    def unique_pairs(pairs):
        result = {}
        for key, val in pairs:
            if key in result:
                raise IntegrityError("duplicate JSON key")
            result[key] = val
        return result
    try:
        value = json.loads(_safe_regular(root, relative), object_pairs_hook=unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("noncanonical JSON document: " + relative) from exc
    if not isinstance(value, dict):
        raise IntegrityError("expected JSON object: " + relative)
    return value


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _check_pq_source_coverage(root: Path, pins: dict[str, str]) -> None:
    """Fail closed when a newly added PQ implementation evades the blob manifest."""
    for directory in PQ_SOURCE_DIRS:
        parent = root / directory
        if parent.is_symlink() or not parent.is_dir():
            raise IntegrityError("missing or symlink PQ source directory: " + directory)
        # Every descendant matters: a future verifier in experiments/ or an
        # owner submodule must not evade the fixed-source manifest.
        pending = [parent]
        visited = 0
        while pending:
            current = pending.pop()
            for source in current.iterdir():
                visited += 1
                if visited > 10000:
                    raise IntegrityError("PQ source traversal budget exhausted")
                relative = source.relative_to(root).as_posix()
                if source.is_symlink():
                    raise IntegrityError("symlink PQ source entry refused: " + relative)
                if source.is_dir():
                    pending.append(source)
                    continue
                # Nested Rust/C/Python files inside a PQ-named module are
                # implementations too, even when called native.rs or mod.rs.
                parts = source.relative_to(parent).parts
                is_pq_source = any(part.startswith(("pq_", "pqg_", "pql"))
                                   for part in parts)
                if source.suffix not in (".py", ".c", ".rs") or not is_pq_source:
                    continue
                if relative not in pins:
                    raise IntegrityError("unpinned PQ source: " + relative)
                # A pinned path is already byte-checked by check(); never
                # treat source enumeration as cryptographic authority.

def check(root: Path) -> dict:
    root = Path(root).resolve(strict=True)
    m = _json(root, REL_MANIFEST)
    if m.get("schema") != "trnm-pq-cross-branch-corpus-v1" or m.get("status") != "research-only-hold-no-go":
        raise IntegrityError("corpus must remain research/HOLD")
    if m.get("parent_profile") != "pon-nakamoto-v1":
        raise IntegrityError("wrong profile")
    heads = m.get("upstream_heads")
    if not isinstance(heads, dict) or set(heads) != REQUIRED_UPSTREAM:
        raise IntegrityError("missing provenance parent")
    if not all(type(v) is str and re.fullmatch("[0-9a-f]{40}", v) for v in heads.values()):
        raise IntegrityError("malformed provenance commit")
    assertions = m.get("assertions")
    if not isinstance(assertions, dict) or set(assertions) != REQUIRED_FALSE:
        raise IntegrityError("missing acceptance gate")
    if any(value is not False for value in assertions.values()):
        raise IntegrityError("unaccepted capability claimed true")
    pins = m.get("pinned_blobs")
    required = m.get("required_paths")
    if (not isinstance(pins, dict) or not isinstance(required, list)
            or not required or len(required) != len(set(required))
            or any(type(p) is not str or p not in pins for p in required)):
        raise IntegrityError("incomplete source pins")
    for relative, sha in pins.items():
        if type(sha) is not str or not re.fullmatch("[0-9a-f]{40}", sha):
            raise IntegrityError("invalid pinned blob")
        if _git_blob(_safe_regular(root, relative)) != sha:
            raise IntegrityError("changed source: " + relative)
    _check_pq_source_coverage(root, pins)
    overwrites = m.get("overwrites")
    expected_overwrites = {
        "formal/pon-nakamoto-v1/pq_cell_custody.py": "cell",
        "formal/pon-nakamoto-v1/pq_account_migration.py": "migration",
        "formal/pon-nakamoto-v1/pq_pql5_quorum.py": "witness",
        "formal/pon-nakamoto-v1/test_pq_pql5_quorum.py": "witness",
    }
    if overwrites != expected_overwrites:
        raise IntegrityError("unreviewed source substitution")
    actual_consensus = _json(root, "config/consensus-mainline.json")
    actual_devnet = _json(root, "config/pon/devnet-v1.json")
    pq = _json(root, "config/pon/post-quantum-transition-v1.json")
    if (actual_consensus.get("production_consensus_activation") is not False
            or actual_consensus.get("runtime_implemented") is not False
            or actual_consensus.get("active_consensus_implementation") is not None
            or actual_devnet.get("production_activation") is not False
            or actual_devnet.get("max_transaction_bytes") != 2048
            or pq.get("production_activation") is not False
            or pq.get("allow_classical_fallback") is not False
            or pq.get("reference_signature", {}).get("signature_bytes") != 3309
            or pq.get("existing_devnet_limits", {}).get("post_quantum_transaction_wire_compatible") is not False):
        raise IntegrityError("installed consensus or PQ gate changed")
    return {
        "schema": "trnm-pq-cross-branch-check-v1", "status": "HOLD_NO_GO",
        "exact_source_blobs": len(pins), "upstream_heads": len(heads),
        "cryptographic_acceptance": False, "node_activated": False,
    }


if __name__ == "__main__":
    try:
        print(json.dumps(check(Path(__file__).resolve().parents[2]), sort_keys=True))
    except (IntegrityError, OSError, ValueError) as exc:
        print("HOLD_NO_GO: " + str(exc), file=sys.stderr)
        sys.exit(1)
