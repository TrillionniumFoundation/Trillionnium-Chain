"""Candidate staged state-sync verifier and swap model.

The canonical Rust node does not yet expose a whole-node state-sync import
contract.  This module keeps the missing boundary executable without changing
that truth: it authenticates a bounded manifest/chunk set, recomputes the
application sparse root, and models a staged (never in-place) swap guarded by
an external monotonic anchor.  It is intentionally stdlib-only and
candidate-non-normative.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import threading
from typing import Any, Mapping, Sequence


DEPTH = 256
TREE_VERSION = 0
MAX_MANIFEST_BYTES = 256 * 1024
MAX_CHUNK_BYTES = 1024 * 1024
MAX_CHUNKS = 64
MAX_RECORDS_PER_CHUNK = 1024
ZERO32 = b"\x00" * 32


class StateSyncError(ValueError):
    """Stable fail-closed state-sync rejection."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise StateSyncError("non-canonical JSON") from exc


def _digest(domain: str, payload: bytes) -> bytes:
    encoded = domain.encode("utf-8")
    return hashlib.sha256(len(encoded).to_bytes(4, "little") + encoded + payload).digest()


# Candidate fixture profile commitments.  They deliberately model the
# protocol-09 identity-compression/greedy-chunk profile and make downgrade or
# alternate-profile mutants fail before any bytes are staged.
CHUNKING_PROFILE_HASH = _digest(
    "trnm.poco-ai.state-sync-chunking-profile.v1",
    b"schema=1;algorithm=0;target=65536;max=1048576;split=1",
).hex()
COMPRESSION_PROFILE_HASH = _digest(
    "trnm.poco-ai.state-sync-compression-profile.v1",
    b"schema=1;algorithm=0",
).hex()


def _hash_hex(value: Any, label: str, *, allow_zero: bool = False) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise StateSyncError(f"{label} shape")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise StateSyncError(f"{label} encoding") from exc
    if decoded.hex() != value or (not allow_zero and decoded == ZERO32):
        raise StateSyncError(f"{label} value")
    return decoded


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise StateSyncError(f"{label} fields")
    return value


def _u64(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value < 2**64:
        raise StateSyncError(f"{label} range")
    return value


def _context_digest(context: Mapping[str, Any]) -> bytes:
    # Bind every immutable context fact, not only genesis/stack.  Otherwise a
    # caller could pair a valid checkpoint with a different validator/DA/fee
    # descriptor while retaining the same context digest.  This preimage is
    # intentionally identical to the binary carrier's ProtocolContextV1
    # candidate encoding.
    _validate_context(context)
    chain = context["chain_id"].encode("ascii")
    fields = b"".join(
        _hash_hex(context.get(name), f"context {name}")
        for name in _CONTEXT_HASH_FIELDS
    )
    epoch = _u64(context.get("epoch"), "context epoch")
    return _digest(
        "trnm.poco-ai.protocol-context.v1",
        len(chain).to_bytes(2, "little") + chain + fields + epoch.to_bytes(8, "little"),
    )


_CONTEXT_HASH_FIELDS = (
    "genesis_hash",
    "stack_profile_hash",
    "validator_set_hash",
    "state_schema_hash",
    "da_policy_hash",
    "verification_registry_hash",
    "fee_schedule_hash",
)
_CONTEXT_KEYS = frozenset(("chain_id", "epoch", *_CONTEXT_HASH_FIELDS))


def _canonical_header_id(context_hash: bytes, height: int, state_root: bytes) -> bytes:
    """Derive the candidate header identifier from the complete context cut.

    This is intentionally kept local rather than importing the fixture/wire
    encoder.  State-sync verification must recompute the binding itself so a
    caller cannot make an arbitrary ``expected_block_id`` authoritative.
    """

    if len(context_hash) != 32 or len(state_root) != 32:
        raise StateSyncError("header binding shape")
    return _digest(
        "trnm.poco-ai.block-header.v1",
        context_hash + height.to_bytes(8, "little") + state_root + TREE_VERSION.to_bytes(2, "little"),
    )


def _checkpoint_id(block_id: bytes, state_root: bytes) -> bytes:
    if len(block_id) != 32 or len(state_root) != 32:
        raise StateSyncError("checkpoint binding shape")
    return _digest("trnm.poco-ai.epoch-checkpoint-id.candidate.v1", block_id + state_root)


def _validate_context(context: Mapping[str, Any]) -> tuple[str, int]:
    """Validate the fixed candidate context shape before any allocation."""

    if not isinstance(context, Mapping):
        raise StateSyncError("context type")
    try:
        if frozenset(context.keys()) != _CONTEXT_KEYS:
            raise StateSyncError("context fields")
    except (TypeError, ValueError, OverflowError) as exc:
        raise StateSyncError("context fields") from exc
    chain = context.get("chain_id")
    if not isinstance(chain, str) or not chain or any(ord(char) > 127 for char in chain):
        raise StateSyncError("context chain")
    if len(chain.encode("ascii")) > 128:
        raise StateSyncError("context chain bound")
    for name in _CONTEXT_HASH_FIELDS:
        _hash_hex(context.get(name), f"context {name}")
    epoch = _u64(context.get("epoch"), "context epoch")
    return chain, epoch


def _decode_records(payload: bytes) -> list[tuple[int, bytes, int, bytes, bytes]]:
    """Decode the bounded binary state-record chunk without local imports."""

    if len(payload) < 2 or len(payload) > MAX_CHUNK_BYTES:
        raise StateSyncError("chunk size")
    count = int.from_bytes(payload[:2], "little")
    if count == 0 or count > MAX_RECORDS_PER_CHUNK:
        raise StateSyncError("chunk record count")
    offset = 2
    output: list[tuple[int, bytes, int, bytes, bytes]] = []
    previous_key: bytes | None = None
    for _ in range(count):
        if offset + 2 + 32 + 8 + 4 > len(payload):
            raise StateSyncError("chunk truncated")
        kind = int.from_bytes(payload[offset : offset + 2], "little")
        offset += 2
        if kind == 0:
            raise StateSyncError("chunk object kind")
        object_id = payload[offset : offset + 32]
        offset += 32
        version = int.from_bytes(payload[offset : offset + 8], "little")
        offset += 8
        value_len = int.from_bytes(payload[offset : offset + 4], "little")
        offset += 4
        if value_len > 4 * 1024 * 1024 or offset + value_len > len(payload):
            raise StateSyncError("chunk value bound")
        value = payload[offset : offset + value_len]
        offset += value_len
        key = _digest("trnm.poco-ai.state-key.v1", kind.to_bytes(2, "little") + object_id)
        if previous_key is not None and key <= previous_key:
            raise StateSyncError("chunk key order")
        previous_key = key
        output.append((kind, object_id, version, value, key))
    if offset != len(payload):
        raise StateSyncError("chunk trailing bytes")
    return output


def _empty_hashes() -> tuple[bytes, ...]:
    values = [_digest("trnm.poco-ai.state-empty-leaf.v1", (0).to_bytes(2, "little"))]
    for level in range(DEPTH):
        values.append(
            _digest(
                "trnm.poco-ai.state-node.v1",
                level.to_bytes(2, "little") + values[level] + values[level],
            )
        )
    return tuple(values)


def _state_root(records: Sequence[tuple[int, bytes, int, bytes, bytes]]) -> bytes:
    empty = _empty_hashes()
    current: dict[int, bytes] = {}
    for kind, object_id, version, value, key in records:
        leaf = _digest(
            "trnm.poco-ai.state-leaf.v1",
            key + kind.to_bytes(2, "little") + version.to_bytes(8, "little") + len(value).to_bytes(4, "little") + value,
        )
        number = int.from_bytes(key, "big")
        if number in current:
            raise StateSyncError("duplicate state key")
        current[number] = leaf
    if not current:
        return empty[DEPTH]
    for level in range(DEPTH):
        parent_values: dict[int, bytes] = {}
        for parent in {index >> 1 for index in current}:
            left = current.get(parent << 1, empty[level])
            right = current.get((parent << 1) | 1, empty[level])
            parent_values[parent] = _digest(
                "trnm.poco-ai.state-node.v1",
                level.to_bytes(2, "little") + left + right,
            )
        current = parent_values
    return current.get(0, empty[DEPTH])


def _manifest_material(manifest: Mapping[str, Any]) -> bytes:
    # The fixture has no self-referential manifest id.  Keep this helper
    # explicit so callers cannot accidentally hash an unauthenticated subset.
    return _canonical_json(
        {
            key: manifest[key]
            for key in (
                "schema_version",
                "context_digest",
                "height",
                "block_id",
                "epoch_checkpoint_id",
                "state_root",
                "state_schema_hash",
                "chunking_profile_hash",
                "compression_profile_hash",
                "chunk_count",
                "total_uncompressed_bytes",
                "chunk_manifest_root",
                "chunk_entries",
                "epoch",
                "validator_set_hash",
                "da_policy_hash",
                "verification_registry_hash",
                "fee_schedule_hash",
                "history_start_height",
                "catch_up_start_height",
                "max_chunk_uncompressed_bytes",
                "max_chunk_count",
            )
        }
    )


@dataclass(frozen=True)
class ManifestView:
    digest: bytes
    height: int
    state_root: bytes
    block_id: bytes
    epoch: int
    chunk_count: int
    records: tuple[tuple[int, bytes, int, bytes, bytes], ...]
    # These fields are retained in the verified view so the staged swap and
    # external anchor can enforce the same context/checkpoint cut that was
    # authenticated by the manifest.  They are appended to preserve the
    # earlier positional constructor shape for candidate callers.
    context_digest: bytes = ZERO32
    validator_set_hash: bytes = ZERO32
    checkpoint_digest: bytes = ZERO32


def verify_manifest(
    manifest: Mapping[str, Any],
    chunks: Sequence[bytes],
    context: Mapping[str, Any],
    *,
    expected_block_id: bytes,
    expected_root: bytes,
    expected_height: int | None = None,
) -> ManifestView:
    """Authenticate manifest metadata, chunks, and exact application root."""

    _validate_context(context)
    if (
        not isinstance(expected_block_id, (bytes, bytearray))
        or len(expected_block_id) != 32
        or not isinstance(expected_root, (bytes, bytearray))
        or len(expected_root) != 32
    ):
        raise StateSyncError("expected binding shape")
    expected_block_id = bytes(expected_block_id)
    expected_root = bytes(expected_root)
    if not isinstance(manifest, Mapping):
        raise StateSyncError("manifest type")
    if not isinstance(chunks, Sequence) or isinstance(chunks, (str, bytes, bytearray)):
        raise StateSyncError("chunk sequence type")
    required = {
        "schema_version", "context_digest", "height", "block_id", "epoch_checkpoint_id",
        "state_root", "state_schema_hash", "chunking_profile_hash", "compression_profile_hash",
        "chunk_count", "total_uncompressed_bytes", "chunk_manifest_root", "chunk_entries",
        "epoch", "validator_set_hash", "da_policy_hash", "verification_registry_hash",
        "fee_schedule_hash", "history_start_height", "catch_up_start_height",
        "max_chunk_uncompressed_bytes", "max_chunk_count",
    }
    # Bound the container before canonicalizing it.  In particular, do not
    # serialize an attacker-controlled list of millions of descriptors merely
    # to discover that its field set is invalid.
    try:
        manifest_size = len(manifest)
    except (TypeError, ValueError, OverflowError) as exc:
        raise StateSyncError("manifest size") from exc
    if manifest_size > len(required) + 4:
        raise StateSyncError("manifest size")
    value = _exact(dict(manifest), required, "manifest")
    if not isinstance(value["chunk_entries"], list) or len(value["chunk_entries"]) > MAX_CHUNKS:
        raise StateSyncError("manifest chunk entries bound")
    if len(_canonical_json(value)) > MAX_MANIFEST_BYTES:
        raise StateSyncError("manifest size")
    if isinstance(value["schema_version"], bool) or value["schema_version"] != 1:
        raise StateSyncError("manifest schema")
    context_hash = _context_digest(context)
    if _hash_hex(value["context_digest"], "manifest context digest") != context_hash:
        raise StateSyncError("manifest context binding")
    height = _u64(value["height"], "manifest height", minimum=1)
    if expected_height is None:
        raise StateSyncError("expected height required")
    expected_height = _u64(expected_height, "expected height", minimum=1)
    if height != expected_height:
        raise StateSyncError("manifest height binding")
    epoch = _u64(value["epoch"], "manifest epoch")
    if epoch != _u64(context.get("epoch"), "context epoch"):
        raise StateSyncError("manifest epoch binding")
    block_id = _hash_hex(value["block_id"], "manifest block id")
    root = _hash_hex(value["state_root"], "manifest state root")
    if block_id != expected_block_id or root != expected_root:
        raise StateSyncError("manifest order binding")
    # The external expected block id is an additional predecessor binding,
    # not a substitute for deriving the candidate header from the complete
    # context/height/application root.  Without this recomputation a caller
    # could supply a self-consistent but forged height or block id.
    if block_id != _canonical_header_id(context_hash, height, root):
        raise StateSyncError("manifest header binding")
    checkpoint_digest = _hash_hex(value["epoch_checkpoint_id"], "manifest checkpoint")
    if checkpoint_digest != _checkpoint_id(block_id, root):
        raise StateSyncError("manifest checkpoint binding")
    for name in (
        "state_schema_hash", "chunking_profile_hash", "compression_profile_hash",
        "chunk_manifest_root", "validator_set_hash", "da_policy_hash",
        "verification_registry_hash", "fee_schedule_hash",
    ):
        _hash_hex(value[name], f"manifest {name}")
    if value["chunking_profile_hash"] != CHUNKING_PROFILE_HASH:
        raise StateSyncError("chunking profile mismatch")
    if value["compression_profile_hash"] != COMPRESSION_PROFILE_HASH:
        raise StateSyncError("compression profile mismatch")
    for name in ("state_schema_hash", "validator_set_hash", "da_policy_hash", "verification_registry_hash", "fee_schedule_hash"):
        context_value = context.get(name)
        if not isinstance(context_value, str) or value[name] != context_value:
            raise StateSyncError(f"manifest {name} binding")
    history_start = _u64(value["history_start_height"], "manifest history start")
    catch_up_start = _u64(value["catch_up_start_height"], "manifest catch-up start")
    if history_start > height or catch_up_start != height + 1:
        raise StateSyncError("manifest catch-up range")
    chunk_count = _u64(value["chunk_count"], "manifest chunk count", minimum=1)
    if not isinstance(value["chunk_entries"], list):
        raise StateSyncError("manifest chunk entries type")
    if chunk_count > MAX_CHUNKS or chunk_count != len(chunks) or chunk_count != len(value["chunk_entries"]):
        raise StateSyncError("manifest chunk count")
    max_chunk = _u64(value["max_chunk_uncompressed_bytes"], "manifest max chunk", minimum=1)
    # The profile commitment includes these exact ceilings.  Accepting a
    # smaller caller-supplied limit would be a downgrade/equivocation: a
    # later implementation could silently apply different chunking rules
    # while reusing the same profile hash.
    if max_chunk != MAX_CHUNK_BYTES:
        raise StateSyncError("manifest max chunk profile mismatch")
    max_chunks = _u64(value["max_chunk_count"], "manifest max chunks", minimum=1)
    if max_chunks != MAX_CHUNKS or chunk_count > max_chunks:
        raise StateSyncError("manifest max chunk count profile mismatch")
    total_declared = _u64(value["total_uncompressed_bytes"], "manifest total bytes")
    if total_declared > max_chunk * max_chunks:
        raise StateSyncError("manifest total bytes bound")
    descriptors: list[dict[str, Any]] = []
    all_records: list[tuple[int, bytes, int, bytes, bytes]] = []
    total = 0
    for index, (descriptor_raw, chunk) in enumerate(zip(value["chunk_entries"], chunks)):
        descriptor = _exact(
            descriptor_raw,
            {"chunk_index", "first_state_key", "last_state_key", "uncompressed_bytes", "compressed_bytes", "uncompressed_hash", "compressed_hash"},
            "chunk descriptor",
        )
        if descriptor["chunk_index"] != index:
            raise StateSyncError("chunk index")
        for number_name in ("chunk_index", "uncompressed_bytes", "compressed_bytes"):
            number = descriptor[number_name]
            if isinstance(number, bool) or not isinstance(number, int) or number < 0 or number >= 2**64:
                raise StateSyncError("chunk descriptor number")
        if not isinstance(chunk, (bytes, bytearray)) or not 0 < len(chunk) <= max_chunk or len(chunk) > MAX_CHUNK_BYTES:
            raise StateSyncError("chunk bound")
        raw_chunk = bytes(chunk)
        records = _decode_records(raw_chunk)
        first_key = _hash_hex(descriptor["first_state_key"], "chunk first key")
        last_key = _hash_hex(descriptor["last_state_key"], "chunk last key")
        first, last = records[0][4], records[-1][4]
        if first_key != first or last_key != last:
            raise StateSyncError("chunk key range")
        if descriptor["uncompressed_bytes"] != len(raw_chunk) or descriptor["compressed_bytes"] != len(raw_chunk):
            raise StateSyncError("chunk length")
        chunk_hash = _digest("trnm.poco-ai.state-sync-chunk-bytes.v1", raw_chunk).hex()
        uncompressed_hash = _hash_hex(descriptor["uncompressed_hash"], "chunk uncompressed hash")
        compressed_hash = _hash_hex(descriptor["compressed_hash"], "chunk compressed hash")
        if uncompressed_hash.hex() != chunk_hash or compressed_hash.hex() != chunk_hash:
            raise StateSyncError("chunk digest")
        descriptors.append(descriptor)
        total += len(raw_chunk)
        all_records.extend(records)
    if total_declared != total:
        raise StateSyncError("manifest total bytes")
    descriptor_bytes = b"".join(_canonical_json(item) for item in descriptors)
    expected_manifest_root = _digest("trnm.poco-ai.state-sync-chunk-manifest-root.v1", descriptor_bytes).hex()
    if value["chunk_manifest_root"] != expected_manifest_root:
        raise StateSyncError("manifest chunk root")
    # Global ordering matters across chunk boundaries; duplicate/torn chunks
    # must fail before a staged target can become active.
    ordered = sorted(all_records, key=lambda record: record[4])
    if [record[4] for record in all_records] != [record[4] for record in ordered] or len({record[4] for record in all_records}) != len(all_records):
        raise StateSyncError("global state key order")
    if _state_root(all_records) != root:
        raise StateSyncError("application root mismatch")
    return ManifestView(
        digest=_digest("trnm.poco-ai.state-sync-manifest.v1", _manifest_material(value)),
        height=height,
        state_root=root,
        block_id=block_id,
        epoch=epoch,
        chunk_count=chunk_count,
        records=tuple(all_records),
        context_digest=context_hash,
        validator_set_hash=_hash_hex(value["validator_set_hash"], "manifest validator set"),
        checkpoint_digest=checkpoint_digest,
    )


@dataclass(frozen=True)
class ExternalAnchor:
    chain_id: str
    generation: int
    height: int
    state_root: bytes
    manifest_digest: bytes
    namespace_id: str
    # The initial candidate anchor uses zero sentinels.  A committed anchor
    # must carry every field below; keeping them on the predecessor prevents a
    # same-height fork or an epoch/context substitution from being treated as
    # a monotonic successor.
    block_id: bytes = ZERO32
    context_digest: bytes = ZERO32
    epoch: int = 0
    validator_set_hash: bytes = ZERO32
    checkpoint_digest: bytes = ZERO32

    def __post_init__(self) -> None:
        # Freeze byte buffers at the public boundary.  A frozen dataclass alone
        # is shallow: accepting a caller-owned bytearray would let the anchor
        # digest change after validation and turn a retry into an ABA token.
        if (
            not isinstance(self.chain_id, str)
            or not self.chain_id
            or any(ord(char) > 127 for char in self.chain_id)
            or len(self.chain_id.encode("ascii")) > 128
            or not isinstance(self.namespace_id, str)
            or not self.namespace_id
            or any(ord(char) > 127 for char in self.namespace_id)
            or len(self.namespace_id.encode("ascii")) > 256
        ):
            raise StateSyncError("external anchor identity")
        _u64(self.generation, "external anchor generation")
        _u64(self.height, "external anchor height")
        _u64(self.epoch, "external anchor epoch")
        for value, label in (
            (self.state_root, "external anchor root"),
            (self.manifest_digest, "external anchor manifest"),
            (self.block_id, "external anchor block"),
            (self.context_digest, "external anchor context"),
            (self.validator_set_hash, "external anchor validator set"),
            (self.checkpoint_digest, "external anchor checkpoint"),
        ):
            if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
                raise StateSyncError(label)
        object.__setattr__(self, "state_root", bytes(self.state_root))
        object.__setattr__(self, "manifest_digest", bytes(self.manifest_digest))
        object.__setattr__(self, "block_id", bytes(self.block_id))
        object.__setattr__(self, "context_digest", bytes(self.context_digest))
        object.__setattr__(self, "validator_set_hash", bytes(self.validator_set_hash))
        object.__setattr__(self, "checkpoint_digest", bytes(self.checkpoint_digest))

    def digest(self) -> bytes:
        """Stable digest of the complete external record (candidate evidence)."""

        material = (
            self.chain_id.encode("utf-8")
            + self.generation.to_bytes(8, "little")
            + self.height.to_bytes(8, "little")
            + self.state_root
            + self.manifest_digest
            + self.block_id
            + self.context_digest
            + self.epoch.to_bytes(8, "little")
            + self.validator_set_hash
            + self.checkpoint_digest
            + self.namespace_id.encode("utf-8")
        )
        return _digest("trnm.poco-ai.external-anchor-record.candidate.v1", material)


def _validate_anchor(
    anchor: ExternalAnchor,
    *,
    chain_id: str,
    namespace_id: str,
) -> None:
    """Validate an externally supplied predecessor before comparing it."""

    if not isinstance(anchor, ExternalAnchor):
        raise StateSyncError("external anchor type")
    if anchor.chain_id != chain_id or anchor.namespace_id != namespace_id:
        raise StateSyncError("external anchor identity")
    _u64(anchor.generation, "external anchor generation")
    _u64(anchor.height, "external anchor height")
    _u64(anchor.epoch, "external anchor epoch")
    for value, label in (
        (anchor.state_root, "external anchor root"),
        (anchor.manifest_digest, "external anchor manifest"),
        (anchor.block_id, "external anchor block"),
        (anchor.context_digest, "external anchor context"),
        (anchor.validator_set_hash, "external anchor validator set"),
        (anchor.checkpoint_digest, "external anchor checkpoint"),
    ):
        if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
            raise StateSyncError(label)
    if anchor.generation == 0:
        if (
            anchor.height != 0
            or anchor.epoch != 0
            or bytes(anchor.state_root) != ZERO32
            or bytes(anchor.manifest_digest) != ZERO32
            or bytes(anchor.block_id) != ZERO32
            or bytes(anchor.context_digest) != ZERO32
            or bytes(anchor.validator_set_hash) != ZERO32
            or bytes(anchor.checkpoint_digest) != ZERO32
        ):
            raise StateSyncError("external anchor zero state")
    elif anchor.height < 1:
        raise StateSyncError("external anchor height")
    elif any(
        bytes(value) == ZERO32
        for value in (
            anchor.state_root,
            anchor.manifest_digest,
            anchor.block_id,
            anchor.context_digest,
            anchor.validator_set_hash,
            anchor.checkpoint_digest,
        )
    ):
        raise StateSyncError("external anchor empty state")
    elif bytes(anchor.checkpoint_digest) != _checkpoint_id(
        bytes(anchor.block_id), bytes(anchor.state_root)
    ):
        raise StateSyncError("external anchor checkpoint binding")
    elif bytes(anchor.block_id) != _canonical_header_id(
        bytes(anchor.context_digest), anchor.height, bytes(anchor.state_root)
    ):
        raise StateSyncError("external anchor header binding")


@dataclass(frozen=True)
class StageToken:
    instance_id: str
    stage_id: str
    namespace_id: str
    generation: int
    view: ManifestView
    chunks: tuple[bytes, ...]
    stage_digest: bytes


class StagedStateSync:
    """Candidate staged/swap state machine with explicit rollback fences."""

    def __init__(self, chain_id: str, *, namespace_id: str = "whole-node-active-v1") -> None:
        if (
            not isinstance(chain_id, str)
            or not isinstance(namespace_id, str)
            or not chain_id
            or not namespace_id
            or any(ord(char) > 127 for char in chain_id + namespace_id)
            or len(chain_id.encode("ascii")) > 128
            or len(namespace_id.encode("ascii")) > 256
        ):
            raise StateSyncError("invalid namespace")
        self._instance_id = os.urandom(16).hex()
        self._namespace_id = namespace_id
        self._chain_id = chain_id
        self._anchor = ExternalAnchor(chain_id, 0, 0, ZERO32, ZERO32, namespace_id)
        self._active: StageToken | None = None
        self._stages: dict[str, StageToken] = {}
        self._sidecars: set[str] = set()
        self._intent: StageToken | None = None
        # The lock only serializes this in-memory candidate owner.  A real
        # node still needs an independently administered compare-and-advance
        # backend; this lock is not presented as that authority.
        self._lock = threading.RLock()

    @property
    def anchor(self) -> ExternalAnchor:
        return self._anchor

    @property
    def active(self) -> StageToken | None:
        return self._active

    def mark_sidecar(self, suffix: str) -> None:
        """Test-only fault injection; any sidecar fences authority."""

        self._sidecars.add(suffix)

    def mark_wal(self) -> None:
        self.mark_sidecar("-wal")

    def _check_health(self) -> None:
        if self._sidecars:
            raise StateSyncError("sidecar present")
        if self._intent is not None:
            raise StateSyncError("incomplete swap intent")

    def stage(
        self,
        manifest: Mapping[str, Any],
        chunks: Sequence[bytes],
        context: Mapping[str, Any],
        *,
        expected_block_id: bytes,
        expected_root: bytes,
        generation: int,
        expected_height: int | None = None,
        fault: str | None = None,
    ) -> StageToken:
        with self._lock:
            self._check_health()
            _validate_anchor(
                self._anchor,
                chain_id=self._chain_id,
                namespace_id=self._namespace_id,
            )
            generation = _u64(generation, "stage generation", minimum=1)
            if fault not in {None, "torn", "sidecar", "wal"}:
                raise StateSyncError("unknown stage fault")
            if fault in {"torn", "sidecar", "wal"}:
                # Retain any partial staging residue and fence this namespace
                # until explicit operator reconciliation.  A torn write must
                # never be treated as a clean stage that can later authorize.
                self.mark_sidecar(f"-{fault}")
                raise StateSyncError(f"injected {fault} fault")
            if (
                self._anchor.generation >= 2**64 - 1
                or generation != self._anchor.generation + 1
            ):
                raise StateSyncError("stale generation")
            view = verify_manifest(
                manifest,
                chunks,
                context,
                expected_block_id=expected_block_id,
                expected_root=expected_root,
                expected_height=expected_height,
            )
            context_chain, _ = _validate_context(context)
            if context_chain != self._chain_id:
                raise StateSyncError("chain namespace mismatch")
            stage_id = os.urandom(16).hex()
            token = StageToken(
                self._instance_id,
                stage_id,
                self._namespace_id,
                generation,
                view,
                tuple(bytes(chunk) for chunk in chunks),
                _digest("trnm.poco-ai.state-sync-stage.v1", view.digest + generation.to_bytes(8, "little")),
            )
            self._stages[stage_id] = token
            return token

    def commit(
        self,
        token: StageToken,
        *,
        generation: int,
        expected_anchor: ExternalAnchor | None = None,
        simulate_crash: str | None = None,
    ) -> ExternalAnchor:
        with self._lock:
            self._check_health()
            generation = _u64(generation, "commit generation", minimum=1)
            if expected_anchor is None:
                # A local staged token is never sufficient authority.  The
                # caller must present the exact externally observed
                # predecessor for compare-and-advance.
                raise StateSyncError("external anchor CAS required")
            _validate_anchor(
                self._anchor,
                chain_id=self._chain_id,
                namespace_id=self._namespace_id,
            )
            _validate_anchor(
                expected_anchor,
                chain_id=self._chain_id,
                namespace_id=self._namespace_id,
            )
            if not isinstance(token, StageToken) or token.instance_id != self._instance_id:
                raise StateSyncError("copied stage token")
            stored = self._stages.get(token.stage_id)
            if stored != token or token.namespace_id != self._namespace_id:
                raise StateSyncError("unknown or mutated stage")
            if expected_anchor is not None and expected_anchor != self._anchor:
                raise StateSyncError("external anchor CAS mismatch")
            if generation != token.generation:
                raise StateSyncError("stage generation mismatch")
            if (
                self._anchor.generation >= 2**64 - 1
                or generation != self._anchor.generation + 1
                or token.view.height < self._anchor.height
            ):
                raise StateSyncError("external anchor rollback")
            # A monotonic generation is not enough to authorize a new fork at
            # an already-finalized height.  At equal height every immutable
            # checkpoint/context identity must be byte-for-byte identical;
            # otherwise quarantine before changing the active target.
            if token.view.height == self._anchor.height and self._anchor.generation != 0:
                if (
                    token.view.block_id != self._anchor.block_id
                    or token.view.state_root != self._anchor.state_root
                    or token.view.digest != self._anchor.manifest_digest
                    or token.view.context_digest != self._anchor.context_digest
                    or token.view.epoch != self._anchor.epoch
                    or token.view.validator_set_hash != self._anchor.validator_set_hash
                    or token.view.checkpoint_digest != self._anchor.checkpoint_digest
                ):
                    raise StateSyncError("external anchor equivocation")
            elif self._anchor.generation != 0:
                if token.view.epoch < self._anchor.epoch:
                    raise StateSyncError("external anchor epoch rollback")
                if token.view.epoch == self._anchor.epoch:
                    if token.view.validator_set_hash != self._anchor.validator_set_hash:
                        raise StateSyncError("external anchor validator-set drift")
                    if token.view.context_digest != self._anchor.context_digest:
                        raise StateSyncError("external anchor context drift")
            if simulate_crash not in {None, "before_active", "after_active"}:
                raise StateSyncError("unknown crash simulation")
            next_anchor = ExternalAnchor(
                self._chain_id,
                generation,
                token.view.height,
                token.view.state_root,
                token.view.digest,
                self._namespace_id,
                token.view.block_id,
                token.view.context_digest,
                token.view.epoch,
                token.view.validator_set_hash,
                token.view.checkpoint_digest,
            )
            # Intent is visible until both active target and external anchor
            # are updated.  A simulated crash leaves a permanent fence on
            # reopen and retains the failed token for review.
            self._intent = token
            if simulate_crash in {"before_active", "after_active"}:
                if simulate_crash == "after_active":
                    self._active = token
                raise StateSyncError(f"simulated crash {simulate_crash}")
            self._active = token
            self._anchor = next_anchor
            self._intent = None
            del self._stages[token.stage_id]
            return self._anchor

    def reopen(self) -> ExternalAnchor:
        with self._lock:
            self._check_health()
            _validate_anchor(
                self._anchor,
                chain_id=self._chain_id,
                namespace_id=self._namespace_id,
            )
            if self._active is None:
                if self._anchor.generation != 0:
                    raise StateSyncError("active target missing")
                return self._anchor
            if (
                self._active.instance_id != self._instance_id
                or self._active.namespace_id != self._namespace_id
            ):
                raise StateSyncError("renamed namespace")
            if (
                self._anchor.generation == 0
                or self._active.generation != self._anchor.generation
                or self._active.view.height != self._anchor.height
                or self._active.view.state_root != self._anchor.state_root
                or self._active.view.block_id != self._anchor.block_id
                or self._active.view.context_digest != self._anchor.context_digest
                or self._active.view.epoch != self._anchor.epoch
                or self._active.view.validator_set_hash != self._anchor.validator_set_hash
                or self._active.view.checkpoint_digest != self._anchor.checkpoint_digest
            ):
                raise StateSyncError("active/anchor mismatch")
            if self._active.view.digest != self._anchor.manifest_digest:
                raise StateSyncError("full-store rollback")
            return self._anchor

    def clone_namespace(self, namespace_id: str) -> "StagedStateSync":
        """Create a copied namespace; old tokens must not cross the boundary."""

        if not isinstance(namespace_id, str) or not namespace_id:
            raise StateSyncError("invalid namespace")
        clone = StagedStateSync(self._chain_id, namespace_id=namespace_id)
        clone._anchor = self._anchor
        clone._active = self._active
        clone._stages = dict(self._stages)
        return clone


__all__ = [
    "ExternalAnchor",
    "ManifestView",
    "StageToken",
    "StateSyncError",
    "StagedStateSync",
    "verify_manifest",
]
