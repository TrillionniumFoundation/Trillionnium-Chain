"""Independent canonical test data; never imported by the native runtime."""
import hashlib
import struct

MAX_U64 = (1 << 64) - 1
RECORD_SIZE = 672
PREFIX_SIZE = 640
MAGIC = b"TRNMCP02"
SCHEMA = 2
DOMAIN = b"trnm.external-node-checkpoint.value.v2"
FRAME_PREFIX = b"trnm.domain.hash.v1" + struct.pack(">Q", len(DOMAIN)) + DOMAIN + struct.pack(">Q", PREFIX_SIZE)
SCRATCH_MIN = 132256
SCRATCH = b"\xc7" * (SCRATCH_MIN + 31)
OUTPUT = b"\xa5" * (RECORD_SIZE + 19)

# Canonical record layout, independently represented as named fields.
LAYOUT = {
    "scope": (16, 32), "generation": (48, 8), "predecessor": (56, 32),
    "authority_journal": (88, 32), "authority_profile": (120, 32),
    "authority_revision": (152, 8), "authority_state": (160, 32),
    "authority_chain": (192, 32), "host_config": (224, 32),
    "projection_profile": (256, 32), "binding_manifest": (288, 32),
    "committed_head": (320, 32), "recovery_closure": (352, 32),
    "block_id": (384, 32), "height": (416, 8), "state_root": (424, 32),
    "application_generation": (456, 8), "timestamp_ms": (464, 8),
    "effect_journal": (472, 32), "effect_profile": (504, 32),
    "watermark_scope": (536, 32), "watermark_journal": (568, 32),
    "watermark_sequence": (600, 8), "watermark_checksum": (608, 32),
}

def digest(prefix):
    assert len(prefix) == PREFIX_SIZE
    return hashlib.sha256(FRAME_PREFIX + prefix).digest()


def set_field(record, name, value, *, rehash=True):
    offset, size = LAYOUT[name]
    data = bytearray(record)
    data[offset:offset + size] = struct.pack(">Q", value) if size == 8 else value
    if rehash:
        data[640:672] = digest(data[:640])
    return bytes(data)


def record(generation=0, predecessor=None, **overrides):
    """Encode named fields without applying any admission or successor policy."""
    values = {
        "scope": b"\x01" * 32, "generation": generation,
        "predecessor": bytes(32) if generation == 0 else b"\x21" * 32,
        "authority_journal": b"\x02" * 32, "authority_profile": b"\x03" * 32,
        "authority_revision": 1, "authority_state": b"\x04" * 32,
        "authority_chain": b"\x05" * 32, "host_config": b"\x06" * 32,
        "projection_profile": b"\x07" * 32, "binding_manifest": b"\x08" * 32,
        "committed_head": b"\x09" * 32, "recovery_closure": b"\x0a" * 32,
        "block_id": b"\x0b" * 32, "height": 1, "state_root": b"\x0c" * 32,
        "application_generation": 1, "timestamp_ms": 100,
        "effect_journal": b"\x0d" * 32, "effect_profile": b"\x0e" * 32,
        "watermark_scope": b"\x01" * 32, "watermark_journal": b"\x0d" * 32,
        "watermark_sequence": 0, "watermark_checksum": b"\x0f" * 32,
    }
    if predecessor is not None:
        values["predecessor"] = predecessor
    values.update(overrides)
    prefix = bytearray(MAGIC + struct.pack(">Q", SCHEMA) + bytes(624))
    for name, value in values.items():
        offset, size = LAYOUT[name]
        encoded = struct.pack(">Q", value) if size == 8 else value
        assert len(encoded) == size
        prefix[offset:offset + size] = encoded
    return bytes(prefix) + digest(prefix)
