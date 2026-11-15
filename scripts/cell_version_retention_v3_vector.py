#!/usr/bin/env python3
"""Independent TCA3 envelope/pins/events over the published TCV1 fixture.

Canonical bytes do not prove funding, custody, rollback resistance or execution.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "formal/pon-nakamoto-v1/vectors"
OUTPUT = VECTORS / "cell-version-retention-v3.json"


def number(value, size):
    return value.to_bytes(size, "big")


def frame(value):
    return number(len(value), 4) + value


class Reader:
    def __init__(self, value):
        self.value = value
        self.position = 0

    def take(self, size):
        end = self.position + size
        if end > len(self.value):
            raise ValueError("truncated fixture")
        result = self.value[self.position:end]
        self.position = end
        return result

    def integer(self, size):
        return int.from_bytes(self.take(size), "big")

    def framed(self):
        return self.take(self.integer(4))


def pin(closure, role):
    reader = Reader(closure)
    assert reader.take(4) == b"TCD1"
    generation = reader.take(8)
    profile = reader.take(32)
    release = Reader(reader.framed())
    assert release.take(4) == b"TCR1"
    family = release.take(release.integer(1))
    context = number(len(family), 1) + family + release.take(5 * 32)
    closure_id = hashlib.sha256(b"trnm.cell-dependency-closure.v1\0" + closure).digest()
    return closure_id + context + generation + profile + bytes([1, role]) + number(1_000_000, 8) + number(64, 8)


def generate():
    source = json.loads((VECTORS / "cell-complete-version-v1.json").read_text())
    version = bytes.fromhex(source["wire_hex"])
    assert hashlib.sha512(b"TRNM/Cell/CompleteVersion/v1\0" + version).hexdigest() == source["commitment_sha512"]
    reader = Reader(version)
    assert reader.take(4) == b"TCV1"
    model = Reader(reader.framed())
    assert model.take(4) == b"TMR1"
    model_closure = model.framed()
    environment = reader.framed()
    manifests = [reader.framed() for _ in range(reader.integer(2))]
    assert reader.position == len(version) and len(manifests) == 4
    ids = [bytes([value]) * 32 for value in (101, 102, 103, 104)]
    wire = b"TCA3" + b"".join(ids) + number(0, 2) + number(2, 2)
    wire += b"".join(number(value, 8) for value in (10, 100, 90)) + frame(version)
    wire += pin(model_closure, 1) + pin(environment, 6) + bytes([0, 0])
    wire += number(len(manifests), 2)
    for index, manifest in enumerate(manifests):
        item = Reader(manifest)
        assert item.take(4) == b"TCM1"
        item.take(item.integer(1) + 5 * 32)
        payload = item.integer(8)
        wire += bytes([110 + index]) * 32 + bytes([120 + index]) * 32
        wire += b"".join(number(value, 8) for value in (10, 120, payload * 2))
        wire += b"\0" + frame(manifest)
    store = bytes([73]) * 32
    contract = hashlib.sha256(b"trnm.cell-version-retention-contract.v3\0" + store + wire).digest()
    tip = hashlib.sha256(b"trnm.cell-version-retention-genesis.v3\0" + store + number(64 * 4096, 8) + number(64, 4) + number(32, 4) + number(64 << 20, 8)).digest()
    anchors = [{"generation": 0, "commitment": tip.hex(), "wire_hex": (b"CVA3" + number(0, 8) + tip).hex()}]
    for status in range(3):
        generation = status + 1
        tip = hashlib.sha256(b"trnm.cell-version-retention-event.v3\0" + store + number(generation, 8) + ids[0] + contract + bytes([status]) + tip).digest()
        anchors.append({"generation": generation, "commitment": tip.hex(), "wire_hex": (b"CVA3" + number(generation, 8) + tip).hex()})
    return {"schema": "trnm-cell-version-retention-vector-v3", "scope": "canonical envelope and catalog-event framing only", "source_tcv1_commitment": source["commitment_sha512"], "wire_bytes": len(wire), "wire_hex": wire.hex(), "contract_sha256": contract.hex(), "anchors": anchors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = json.dumps(generate(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if OUTPUT.read_text() != text:
            raise SystemExit("TCA3 independent vector differs")
        print("TCA3 independent vector PASS")
    else:
        OUTPUT.write_text(text)
        print(f"wrote {OUTPUT.name}")


if __name__ == "__main__":
    main()
