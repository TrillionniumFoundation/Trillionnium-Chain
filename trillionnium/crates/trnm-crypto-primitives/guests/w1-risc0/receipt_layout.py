"""Bounded, independent bincode-1.3 / RISC Zero-3.0.6 receipt layout reader.

This reproduces the host's structural allowlist, not the SDK, STARK verifier,
or W1 relation. It authenticates no seal words or verifier-parameter digests.
No allocation or iteration is sized by an unchecked serialized length.
"""
import struct

from check_observations import require


class Cursor:
    def __init__(self, raw):
        self.raw = memoryview(raw)
        self.offset = 0

    def take(self, size):
        require(size <= len(self.raw) - self.offset, "receipt layout: truncated field")
        start = self.offset
        self.offset += size
        return self.raw[start:self.offset]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def length(self, cap, label):
        value = self.u64()
        require(value <= cap, "receipt layout: " + label)
        return value

    def state(self):
        variant = self.u32()
        require(variant in (0, 1), "receipt layout: unknown state variant")
        self.take(36 if variant == 0 else 32)

    def input(self):
        variant = self.u32()
        require(variant in (0, 1), "receipt layout: unknown input variant")
        if variant == 0:
            require(self.take(1) == b"\0", "receipt layout: unsupported claim input")
        else:
            self.take(32)

    def journal(self, cap):
        length = self.length(cap, "journal byte budget")
        require(length == 228, "receipt layout: journal is not the fixed PWJ1 size")
        start = self.offset
        self.take(length)
        return start

    def output(self, journal_cap):
        variant = self.u32()
        require(variant in (0, 1), "receipt layout: unknown output variant")
        if variant == 1:
            self.take(32)
            return
        option = self.take(1)
        require(option in (b"\0", b"\1"), "receipt layout: invalid output option")
        if option == b"\0":
            return
        variant = self.u32()
        require(variant in (0, 1), "receipt layout: unknown journal variant")
        if variant == 0:
            self.journal(journal_cap)
        else:
            self.take(32)
        variant = self.u32()
        require(variant in (0, 1), "receipt layout: unknown assumptions variant")
        if variant == 0:
            self.length(0, "nonempty claim assumptions are unsupported")
        else:
            require(self.take(32) == bytes(32), "receipt layout: unresolved claim assumptions")

    def claim(self, journal_cap):
        self.state()
        self.state()
        variant = self.u32()
        require(variant in (0, 1, 2, 3), "receipt layout: unknown exit-code variant")
        if variant in (0, 1):
            self.u32()
        self.input()
        self.output(journal_cap)


def parse_receipt_layout(raw, caps):
    """Return byte positions and declared dimensions; never a proof verdict.

    The caller supplies the already checked, original resource caps. Seal word
    100 and the last word are the exact SDK mutation sites in audit_one.rs.
    A short first seal can be structurally allowed without supporting word 100.
    """
    require(len(raw) <= caps["receipt_bytes"], "receipt layout: total certificate byte budget")
    cursor = Cursor(raw)
    require(cursor.u32() == 0, "receipt layout: only Composite receipts are supported")
    count = cursor.length(caps["segments"], "segment count budget")
    require(count > 0, "receipt layout: empty segment list")
    padded_cycles, maximum_po2 = 0, 0
    first_word_100 = first_parameters = last_word = None
    for index in range(count):
        words = cursor.length(caps["seal_words"], "segment seal word budget")
        require(words >= 92, "receipt layout: incomplete seal header")
        seal_start = cursor.offset
        seal = cursor.take(words * 4)
        version = struct.unpack_from("<I", seal, 0)[0]
        po2 = struct.unpack_from("<I", seal, 91 * 4)[0]
        require(version == 2, "receipt layout: unsupported RV32IM seal version")
        require(13 <= po2 <= 20, "receipt layout: segment proof dimension budget")
        padded_cycles += 1 << po2
        require(padded_cycles <= caps["padded_cycles"], "receipt layout: total padded proof-cycle budget")
        maximum_po2 = max(maximum_po2, po2)
        if index == 0 and words > 100:
            first_word_100 = seal_start + 100 * 4
        last_word = seal_start + (words - 1) * 4
        require(cursor.u32() == index, "receipt layout: noncanonical segment index")
        name_bytes = cursor.length(9, "hash-name string budget")
        require(cursor.take(name_bytes) == b"poseidon2", "receipt layout: unsupported commitment hash")
        if index == 0:
            first_parameters = cursor.offset
        cursor.take(32)
        cursor.claim(caps["journal_bytes"])
    cursor.length(0, "nested assumption receipts are unsupported")
    cursor.take(32)
    journal_start = cursor.journal(caps["journal_bytes"])
    cursor.take(32)
    require(cursor.offset == len(raw), "receipt layout: trailing certificate bytes")
    return {"shape": {"segments": count, "padded_cycles": padded_cycles, "maximum_po2": maximum_po2},
            "first_seal_word_100_offset": first_word_100, "last_seal_word_offset": last_word,
            "first_segment_parameters_offset": first_parameters, "journal_offset": journal_start}
