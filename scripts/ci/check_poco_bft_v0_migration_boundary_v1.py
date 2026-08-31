#!/usr/bin/env python3
"""Independent, standard-library checker for the candidate migration boundary.

This checker intentionally does not import the Rust crate or any authoring
helper.  It re-implements the bounded big-endian framing, domain-separated
commitments, source/target descriptor bindings, and the three explicit
legacy-storage rejection tags.  It is a deterministic evidence gate only;
all production/cutover bits must remain false.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = ROOT / "docs/protocol/poco-bft-v0/vectors/migration-boundary-v1.json"


class GateError(Exception):
    pass


def fail(message: str) -> NoReturn:
    raise GateError(message)


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            fail(f"duplicate JSON object key: {key}")
        value[key] = child
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} keys differ: got={sorted(value)} expected={sorted(expected)}")


def hex_bytes(value: Any, label: str, length: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) % 2 or any(c not in "0123456789abcdef" for c in value):
        fail(f"{label} is not lowercase hexadecimal")
    output = bytes.fromhex(value)
    if length is not None and len(output) != length:
        fail(f"{label} length {len(output)} != {length}")
    return output


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def hash_len_framed(domain: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"trnm.domain.hash.v1")
    h.update(u64(len(domain)))
    h.update(domain)
    for part in parts:
        h.update(u64(len(part)))
        h.update(part)
    return h.digest()


class Cursor:
    def __init__(self, value: bytes, label: str = "bytes") -> None:
        self.value = value
        self.offset = 0
        self.label = label

    def take(self, count: int, field: str) -> bytes:
        end = self.offset + count
        if end > len(self.value):
            fail(f"{self.label}: truncated {field}")
        start = self.offset
        self.offset = end
        return self.value[start:end]

    def number(self, width: int, field: str) -> int:
        raw = self.take(width, field)
        return int.from_bytes(raw, "big")

    def framed_u32(self, field: str) -> bytes:
        length = self.number(4, f"{field}.length")
        if length > 1 << 20:
            fail(f"{field} exceeds bounded frame")
        return self.take(length, field)

    def consensus_string(self, field: str) -> bytes:
        length = self.number(2, f"{field}.length")
        if length == 0 or length > 128:
            fail(f"{field} has invalid length")
        value = self.take(length, field)
        if not (48 <= value[0] <= 57 or 97 <= value[0] <= 122):
            fail(f"{field} has invalid first byte")
        allowed = b"abcdefghijklmnopqrstuvwxyz0123456789._:-"
        if any(byte not in allowed for byte in value[1:]):
            fail(f"{field} has invalid character")
        return value

    def finish(self) -> None:
        if self.offset != len(self.value):
            fail(f"{self.label}: trailing bytes at {self.offset}")


def parse_manifest(raw: bytes, fixture: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    c = Cursor(raw, "target manifest")
    if c.number(2, "schema") != 1:
        fail("target manifest schema mismatch")
    if c.framed_u32("profile") != b"trnm.poco-bft.migration.target-genesis-manifest.v1":
        fail("target manifest profile mismatch")
    chain = c.consensus_string("target_chain_id")
    genesis = c.take(32, "target_genesis_hash")
    validator_set = c.take(32, "target_validator_set_digest")
    protocol = c.number(4, "target_protocol_version")
    application_schema = c.take(32, "application_schema_digest")
    runtime_profile = c.take(32, "runtime_profile_digest")
    root = c.take(32, "initial_state_root")
    c.finish()
    if chain != fixture["target_chain_id"].encode() or genesis != hex_bytes(fixture["target_genesis_hash_hex"], "target genesis", 32):
        fail("target manifest identity mismatch")
    if root != hex_bytes(fixture["target_state_root_hex"], "target state root", 32):
        fail("target manifest root mismatch")
    if protocol != 0 or any(value == bytes(32) for value in (validator_set, application_schema, runtime_profile)):
        fail("target manifest contains invalid zero/context fields")
    digest = hash_len_framed(
        b"trnm.poco-bft.migration.target-genesis-manifest-commitment.v1", raw
    )
    return digest, {
        "chain": chain,
        "genesis": genesis,
        "validator_set": validator_set,
        "protocol": protocol,
        "root": root,
    }


def parse_rejection(raw: bytes, fixture: dict[str, Any]) -> tuple[bytes, dict[str, int]]:
    c = Cursor(raw, "legacy storage rejection")
    if c.number(2, "schema") != 1:
        fail("legacy rejection schema mismatch")
    if c.framed_u32("profile") != b"trnm.poco-bft.migration.legacy-storage-rejection.v1":
        fail("legacy rejection profile mismatch")
    ids = [c.take(32, name) for name in ("data_directory_id", "wal_id", "validator_key_set_id")]
    expected = [
        hex_bytes(fixture["source_data_directory_id_hex"], "source data directory", 32),
        hex_bytes(fixture["source_wal_id_hex"], "source wal", 32),
        hex_bytes(fixture["source_validator_key_set_id_hex"], "source key set", 32),
    ]
    if ids != expected or len(set(ids)) != 3 or any(value == bytes(32) for value in ids):
        fail("legacy rejection identities mismatch")
    tags = [c.number(1, name) for name in ("data_directory_disposition", "wal_disposition", "key_disposition")]
    if tags != [0, 0, 0]:
        fail("legacy storage import disposition is not rejected")
    c.finish()
    digest = hash_len_framed(b"trnm.poco-bft.migration.legacy-storage-rejection.v1", raw)
    return digest, {"tag_start": len(raw) - 3}


def parse_fresh_directory(raw: bytes, fixture: dict[str, Any]) -> tuple[bytes, dict[str, int]]:
    c = Cursor(raw, "fresh data directory")
    if c.number(2, "schema") != 1:
        fail("fresh directory schema mismatch")
    if c.framed_u32("profile") != b"trnm.poco-bft.migration.fresh-data-directory.v1":
        fail("fresh directory profile mismatch")
    chain = c.consensus_string("target_chain_id")
    genesis = c.take(32, "target_genesis_hash")
    directory_id = c.take(32, "target_data_directory_id")
    marker_offset = c.offset
    marker = c.number(1, "fresh_marker")
    c.finish()
    if chain != fixture["target_chain_id"].encode() or genesis != hex_bytes(fixture["target_genesis_hash_hex"], "target genesis", 32):
        fail("fresh directory target identity mismatch")
    if directory_id != hex_bytes(fixture["target_data_directory_id_hex"], "target data directory", 32):
        fail("fresh directory identity mismatch")
    if marker != 1:
        fail("fresh directory marker is not set")
    digest = hash_len_framed(b"trnm.poco-bft.migration.fresh-data-directory.v1", raw)
    return digest, {"marker_offset": marker_offset}


def parse_block_identity(c: Cursor) -> bytes:
    start = c.offset
    if c.number(2, "block.schema") != 1:
        fail("Comet BlockID schema mismatch")
    if c.framed_u32("block.profile") != b"trnm.poco-bft.migration.comet-block-id.v1":
        fail("Comet BlockID profile mismatch")
    block_hash = c.take(32, "block.hash")
    total = c.number(4, "block.part_set_total")
    part_hash = c.take(32, "block.part_set_hash")
    if block_hash == bytes(32) or part_hash == bytes(32) or total == 0:
        fail("invalid Comet BlockID")
    return c.value[start:c.offset]


def parse_descriptor(raw: bytes, fixture: dict[str, Any], manifest_digest: bytes) -> tuple[bytes, dict[str, Any]]:
    c = Cursor(raw, "genesis descriptor")
    if c.number(2, "schema") != 1:
        fail("descriptor schema mismatch")
    if c.framed_u32("profile") != b"trnm.poco-bft.migration.genesis.v1":
        fail("descriptor profile mismatch")
    source_chain = c.consensus_string("source_chain_id")
    source_genesis = c.take(32, "source_genesis")
    source_application = c.take(32, "source_application_id")
    source_store = c.take(32, "source_store_id")
    height = c.number(8, "source_height")
    block = parse_block_identity(c)
    finality = c.take(32, "source_finality")
    app_hash = c.take(32, "legacy_app_hash")
    export_digest = c.take(32, "export_manifest_digest")
    mapping = c.take(32, "mapping_profile_digest")
    target_chain = c.consensus_string("target_chain_id")
    target_genesis = c.take(32, "target_genesis")
    target_manifest = c.take(32, "target_manifest_digest")
    root = c.take(32, "native_state_root")
    target_set = c.take(32, "target_validator_set_digest")
    protocol = c.number(4, "target_protocol_version")
    source_namespace = c.take(32, "source_namespace")
    migration_instance = c.take(32, "migration_instance")
    c.finish()
    if source_chain != fixture["source_chain_id"].encode() or target_chain != fixture["target_chain_id"].encode():
        fail("descriptor chain identity mismatch")
    if source_chain == target_chain or height == 0 or protocol != 0:
        fail("descriptor one-way/protocol invariant failed")
    if target_genesis != hex_bytes(fixture["target_genesis_hash_hex"], "target genesis", 32):
        fail("descriptor target genesis mismatch")
    if root != hex_bytes(fixture["target_state_root_hex"], "target root", 32):
        fail("descriptor target root mismatch")
    if any(value == bytes(32) for value in (source_genesis, source_application, source_store, finality, app_hash, export_digest, mapping, target_manifest, root, target_set, source_namespace, migration_instance)):
        fail("descriptor contains zero commitment")
    if target_manifest != manifest_digest:
        fail("descriptor target manifest digest mismatch")
    namespace = hash_len_framed(
        b"trnm.poco-bft.migration.source-namespace.v1",
        source_chain,
        source_genesis,
        source_application,
        source_store,
    )
    if source_namespace != namespace:
        fail("descriptor source namespace mismatch")
    expected_instance = hash_len_framed(
        b"trnm.poco-bft.migration.instance.v1",
        namespace,
        u64(height),
        block,
        finality,
        app_hash,
        export_digest,
        mapping,
        target_chain,
        target_genesis,
        target_manifest,
        root,
        target_set,
        u32(protocol),
    )
    if migration_instance != expected_instance:
        fail("descriptor migration instance mismatch")
    digest = hash_len_framed(b"trnm.poco-bft.migration.genesis-commitment.v1", raw)
    return digest, {
        "target_manifest": target_manifest,
        "root": root,
        "migration_instance": migration_instance,
    }


def parse_envelope(raw: bytes, vector: dict[str, Any], *, expected: bool = True) -> dict[str, Any]:
    fixture = vector["fixture"]
    c = Cursor(raw, "fresh genesis import envelope")
    if c.number(2, "schema") != 1:
        fail("import envelope schema mismatch")
    if c.framed_u32("profile") != b"trnm.poco-bft.migration.fresh-genesis-import.v1":
        fail("import envelope profile mismatch")
    descriptor = c.framed_u32("descriptor")
    manifest = c.framed_u32("target_manifest")
    projection_commitment = c.take(32, "projection_commitment")
    descriptor_commitment = c.take(32, "descriptor_commitment")
    target_manifest_commitment = c.take(32, "target_manifest_commitment")
    migration_instance = c.take(32, "migration_instance")
    rejection = c.framed_u32("legacy_storage_rejection")
    directory = c.framed_u32("fresh_data_directory")
    policy_offset = c.offset
    policy = [c.number(1, name) for name in ("in_place", "old_wal", "old_keys")]
    c.finish()
    manifest_digest, manifest_info = parse_manifest(manifest, fixture)
    descriptor_digest, descriptor_info = parse_descriptor(descriptor, fixture, manifest_digest)
    rejection_digest, rejection_info = parse_rejection(rejection, fixture)
    directory_digest, directory_info = parse_fresh_directory(directory, fixture)
    valid = vector["valid"]
    if descriptor != hex_bytes(valid["descriptor_canonical_hex"], "descriptor vector"):
        fail("descriptor bytes differ from vector")
    if manifest != hex_bytes(valid["target_manifest_canonical_hex"], "manifest vector"):
        fail("manifest bytes differ from vector")
    if rejection != hex_bytes(valid["legacy_storage_rejection_canonical_hex"], "rejection vector"):
        fail("rejection bytes differ from vector")
    if directory != hex_bytes(valid["fresh_data_directory_canonical_hex"], "directory vector"):
        fail("directory bytes differ from vector")
    expected_hashes = {
        "projection": hex_bytes(valid["projection_commitment_hex"], "projection commitment", 32),
        "descriptor": hex_bytes(valid["descriptor_commitment_hex"], "descriptor commitment", 32),
        "manifest": hex_bytes(valid["target_manifest_commitment_hex"], "manifest commitment", 32),
        "instance": hex_bytes(valid["migration_instance_hex"], "migration instance", 32),
    }
    if projection_commitment != expected_hashes["projection"]:
        fail("projection commitment mismatch")
    if descriptor_commitment != descriptor_digest or descriptor_commitment != expected_hashes["descriptor"]:
        fail("descriptor commitment mismatch")
    if target_manifest_commitment != manifest_digest or target_manifest_commitment != expected_hashes["manifest"]:
        fail("target manifest commitment mismatch")
    if migration_instance != descriptor_info["migration_instance"] or migration_instance != expected_hashes["instance"]:
        fail("migration instance mismatch")
    if policy != [0, 0, 0]:
        fail("fresh-genesis policy permits legacy reuse")
    if directory_info["marker_offset"] != len(directory) - 1:
        fail("fresh directory marker offset drift")
    if expected and not vector["valid"].get("envelope_reassembles_from_components", False):
        fail("envelope vector does not declare deterministic component reassembly")
    return {
        "policy_offset": policy_offset,
        "rejection": rejection,
        "directory": directory,
        "rejection_tag_start": rejection_info["tag_start"],
        "directory_marker_offset": directory_info["marker_offset"],
        "envelope_commitment": hash_len_framed(
            b"trnm.poco-bft.migration.fresh-genesis-import-commitment.v1", raw
        ),
    }


def mutate_and_reject(raw: bytes, vector: dict[str, Any], info: dict[str, Any], mutation_id: str) -> None:
    mutated = bytearray(raw)
    if mutation_id == "trailing_byte":
        mutated.append(0)
    elif mutation_id == "in_place_import":
        mutated[info["policy_offset"]] = 1
    elif mutation_id == "old_wal_import":
        mutated[info["policy_offset"] + 1] = 1
    elif mutation_id == "old_validator_key_import":
        mutated[info["policy_offset"] + 2] = 1
    elif mutation_id == "old_data_directory_import":
        mutated[info["rejection_tag_start"]] = 1
    elif mutation_id == "fresh_marker_cleared":
        # The directory is the final framed object before the three policy
        # bytes. Locate its marker from the parsed nested bytes.
        directory = bytearray(info["directory"])
        directory[info["directory_marker_offset"]] = 0
        # Replace the final framed directory body in the envelope.
        c = Cursor(bytes(mutated), "mutation")
        c.number(2, "schema"); c.framed_u32("profile"); c.framed_u32("descriptor"); c.framed_u32("manifest")
        c.take(32, "projection"); c.take(32, "descriptor commitment"); c.take(32, "manifest commitment"); c.take(32, "instance")
        c.framed_u32("rejection")
        directory_length_offset = c.offset
        old_length = c.number(4, "directory length")
        directory_offset = c.offset
        if old_length != len(directory):
            fail("directory mutation framing drift")
        mutated[directory_offset : directory_offset + old_length] = directory
        del directory_length_offset
    elif mutation_id == "descriptor_commitment_mutation":
        # Commitments start after schema/profile and the two nested frames.
        c = Cursor(bytes(mutated), "mutation")
        c.number(2, "schema"); c.framed_u32("profile"); c.framed_u32("descriptor"); c.framed_u32("manifest"); c.take(32, "projection")
        mutated[c.offset] ^= 1
    elif mutation_id == "target_root_substitution":
        # Mutate a target-manifest byte, leaving the envelope commitments
        # untouched; canonical nested equality must reject it.
        c = Cursor(bytes(mutated), "mutation")
        c.number(2, "schema"); c.framed_u32("profile"); c.framed_u32("descriptor")
        manifest_length = c.number(4, "manifest length")
        manifest_offset = c.offset
        manifest = bytearray(c.take(manifest_length, "manifest"))
        # The initial root is the final 32 bytes of the typed manifest.
        manifest[-1] ^= 1
        mutated[manifest_offset : manifest_offset + manifest_length] = manifest
    else:
        fail(f"unknown mutation id {mutation_id}")
    try:
        parse_envelope(bytes(mutated), vector, expected=False)
    except GateError:
        return
    fail(f"mutation accepted: {mutation_id}")


def main() -> int:
    try:
        raw_json = VECTOR_PATH.read_bytes()
        vector = json.loads(raw_json.decode("utf-8"), object_pairs_hook=no_duplicates)
        if not isinstance(vector, dict):
            fail("vector root is not an object")
        exact_keys(
            vector,
            {
                "schema", "candidate_only", "production_activation",
                "source_export_verification_required", "target_jmt_root_recomputation_required",
                "cross_peer_genesis_qc_activation", "fixture", "import_policy", "valid",
                "negative_mutations",
            },
            "vector",
        )
        if vector["schema"] != "trnm_poco_bft_migration_boundary_vectors_v1":
            fail("vector schema mismatch")
        if vector["candidate_only"] is not True or vector["production_activation"] is not False:
            fail("candidate/activation truth drift")
        if vector["source_export_verification_required"] is not True or vector["target_jmt_root_recomputation_required"] is not True:
            fail("verification requirements were weakened")
        if vector["cross_peer_genesis_qc_activation"] is not False:
            fail("cross-peer activation must remain false")
        fixture = vector["fixture"]
        exact_keys(
            fixture,
            {
                "source_chain_id", "target_chain_id", "target_genesis_hash_hex", "target_state_root_hex",
                "source_data_directory_id_hex", "source_wal_id_hex", "source_validator_key_set_id_hex",
                "target_data_directory_id_hex",
            },
            "fixture",
        )
        for key in (
            "target_genesis_hash_hex", "target_state_root_hex", "source_data_directory_id_hex",
            "source_wal_id_hex", "source_validator_key_set_id_hex", "target_data_directory_id_hex",
        ):
            hex_bytes(fixture[key], f"fixture.{key}", 32)
        exact_keys(
            vector["import_policy"],
            {
                "in_place_import_allowed", "old_data_directory_imported", "old_wal_imported",
                "old_validator_keys_imported", "fresh_target_directory_required", "legacy_storage_disposition",
            },
            "import_policy",
        )
        policy = vector["import_policy"]
        if any(policy[key] is not False for key in ("in_place_import_allowed", "old_data_directory_imported", "old_wal_imported", "old_validator_keys_imported")):
            fail("import policy contains an enabled legacy path")
        if policy["fresh_target_directory_required"] is not True or policy["legacy_storage_disposition"] != "rejected-not-imported":
            fail("fresh directory/rejection policy drift")
        valid = vector["valid"]
        exact_keys(
            valid,
            {
                "descriptor_canonical_hex", "target_manifest_canonical_hex", "legacy_storage_rejection_canonical_hex",
                "fresh_data_directory_canonical_hex", "projection_commitment_hex", "descriptor_commitment_hex",
                "target_manifest_commitment_hex", "migration_instance_hex",
                "envelope_reassembles_from_components", "envelope_commitment_hex",
            },
            "valid",
        )
        if valid["envelope_reassembles_from_components"] is not True:
            fail("envelope component-reassembly claim is false")
        profile = b"trnm.poco-bft.migration.fresh-genesis-import.v1"
        def frame(value: bytes) -> bytes:
            return u32(len(value)) + value
        envelope = (
            u16(1)
            + frame(profile)
            + frame(hex_bytes(valid["descriptor_canonical_hex"], "descriptor vector"))
            + frame(hex_bytes(valid["target_manifest_canonical_hex"], "manifest vector"))
            + hex_bytes(valid["projection_commitment_hex"], "projection commitment", 32)
            + hex_bytes(valid["descriptor_commitment_hex"], "descriptor commitment", 32)
            + hex_bytes(valid["target_manifest_commitment_hex"], "manifest commitment", 32)
            + hex_bytes(valid["migration_instance_hex"], "migration instance", 32)
            + frame(hex_bytes(valid["legacy_storage_rejection_canonical_hex"], "rejection vector"))
            + frame(hex_bytes(valid["fresh_data_directory_canonical_hex"], "directory vector"))
            + bytes(3)
        )
        info = parse_envelope(envelope, vector)
        if info["envelope_commitment"] != hex_bytes(valid["envelope_commitment_hex"], "envelope commitment", 32):
            fail("envelope commitment mismatch")
        negatives = vector["negative_mutations"]
        if not isinstance(negatives, list) or len(negatives) != 8:
            fail("negative mutation count drift")
        seen: set[str] = set()
        for item in negatives:
            if not isinstance(item, dict) or set(item) != {"id", "field", "operation", "expected"}:
                fail("malformed negative mutation record")
            mutation_id = item["id"]
            if mutation_id in seen or item["expected"] != "reject":
                fail("negative mutation metadata drift")
            seen.add(mutation_id)
            mutate_and_reject(envelope, vector, info, mutation_id)
        expected_ids = {
            "trailing_byte", "in_place_import", "old_wal_import", "old_validator_key_import",
            "old_data_directory_import", "fresh_marker_cleared", "descriptor_commitment_mutation",
            "target_root_substitution",
        }
        if seen != expected_ids:
            fail(f"negative mutation ids differ: {sorted(seen)}")
        print(
            "poco_migration_boundary_v1=passed "
            "candidate_only=true source_token=true target_root_recompute=true "
            "legacy_wal_rejected=true legacy_keys_rejected=true legacy_data_dir_rejected=true "
            "in_place_import=false deterministic_vectors=true exact_nested_replay=true "
            "production_activation=false cross_peer_cutover=false"
        )
        return 0
    except (GateError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"poco_migration_boundary_v1=failed error={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
