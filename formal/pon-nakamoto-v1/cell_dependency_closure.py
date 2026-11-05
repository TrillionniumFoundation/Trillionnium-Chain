"""Independent TCD1 codec/graph oracle; no storage, network or model authority.

The vector uses tiny public synthetic byte strings. It is not a model-load or
ordinary Hepta installation receipt. TCM1/TCR1 identities remain unchanged.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

MAX_WIRE = 1_048_576
MAX_FILES = 256
MAX_DEPTH = 16
MAX_CELL = 64 * 1024**3
DOMAIN = b"trnm.cell-dependency-closure.v1\0"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(value: str) -> bytes:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "canonical digest")
    result = bytes.fromhex(value)
    require(any(result), "zero digest")
    return result


def context_bytes(context: dict) -> bytes:
    require(set(context) == {"family", "base", "parent", "tokenizer", "layout", "runtime"},
            "context fields")
    family = context["family"]
    require(type(family) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", family) is not None,
            "family")
    return bytes([len(family)]) + family.encode("ascii") + b"".join(
        digest(context[key]) for key in ("base", "parent", "tokenizer", "layout", "runtime")
    )


def release_bytes(context: dict, manifests: list[str]) -> bytes:
    ids = sorted(digest(value) for value in manifests)
    require(ids and len(ids) == len(set(ids)) and len(ids) <= MAX_FILES, "release members")
    return b"TCR1" + context_bytes(context) + struct.pack(">I", len(ids)) + b"".join(ids)


def portable_path(path: str) -> None:
    require(type(path) is str and 1 <= len(path) <= 255 and
            re.fullmatch(r"[A-Za-z0-9._/-]+", path) is not None, "portable path")
    parts = path.split("/")
    require(len(parts) <= 8, "path depth")
    for part in parts:
        require(1 <= len(part) <= 64 and not part.startswith(".") and not part.endswith("."),
                "path component")
        stem = part.split(".", 1)[0].lower()
        require(stem not in {"con", "prn", "aux", "nul"} and
                re.fullmatch(r"(?:com|lpt)[1-9]", stem) is None, "reserved path")


def indices(values: list[int], count: int) -> None:
    require(type(values) is list and len(values) <= MAX_FILES and
            all(type(index) is int and 0 <= index < count for index in values) and
            values == sorted(set(values)), "canonical indices")


def validate(value: dict) -> None:
    require(set(value) == {"context", "selected_generation", "loader_profile", "roots", "files"},
            "closure fields")
    context_bytes(value["context"])
    require(type(value["selected_generation"]) is int and
            0 < value["selected_generation"] < 2**64, "generation")
    digest(value["loader_profile"])
    files = value["files"]
    require(type(files) is list and 1 <= len(files) <= MAX_FILES, "file count")
    indices(value["roots"], len(files))
    require(value["roots"], "roots")
    paths = [file["path"] for file in files]
    require(paths == sorted(set(paths)), "canonical paths")
    folded_paths = {path.lower() for path in paths}
    require(len(folded_paths) == len(paths), "case-fold path alias")
    for index, file in enumerate(files):
        require(set(file) == {"path", "role", "manifest", "payload_sha256", "payload_bytes", "dependencies"},
                "file fields")
        portable_path(file["path"])
        parts = file["path"].lower().split("/")
        require(all("/".join(parts[:end]) not in folded_paths for end in range(1, len(parts))),
                "file/directory alias")
        require(type(file["role"]) is int and 1 <= file["role"] <= 6, "role")
        digest(file["manifest"])
        digest(file["payload_sha256"])
        require(type(file["payload_bytes"]) is int and 1 <= file["payload_bytes"] <= MAX_CELL,
                "payload bytes")
        indices(file["dependencies"], len(files))
        require(index not in file["dependencies"], "self dependency")
    release_bytes(value["context"], [file["manifest"] for file in files])
    # Independent topological elimination proves acyclicity and longest path.
    remaining = set(range(len(files)))
    heights = {}
    while remaining:
        ready = {index for index in remaining if all(child in heights for child in files[index]["dependencies"])}
        require(ready, "dependency cycle")
        for index in ready:
            heights[index] = 1 + max((heights[child] for child in files[index]["dependencies"]), default=0)
            require(heights[index] <= MAX_DEPTH, "graph depth")
        remaining -= ready
    reached = set()
    pending = list(value["roots"])
    while pending:
        index = pending.pop()
        if index not in reached:
            reached.add(index)
            pending.extend(files[index]["dependencies"])
    require(len(reached) == len(files), "unreachable file")


def encode(value: dict) -> bytes:
    validate(value)
    release = release_bytes(value["context"], [file["manifest"] for file in value["files"]])
    out = bytearray(b"TCD1")
    out += struct.pack(">Q", value["selected_generation"])
    out += digest(value["loader_profile"])
    out += struct.pack(">I", len(release)) + release
    out += struct.pack(">H", len(value["roots"]))
    out += b"".join(struct.pack(">H", index) for index in value["roots"])
    out += struct.pack(">H", len(value["files"]))
    for file in value["files"]:
        path = file["path"].encode("ascii")
        out += struct.pack(">H", len(path)) + path + bytes([file["role"]])
        out += digest(file["manifest"]) + digest(file["payload_sha256"])
        out += struct.pack(">QH", file["payload_bytes"], len(file["dependencies"]))
        out += b"".join(struct.pack(">H", index) for index in file["dependencies"])
    require(len(out) <= MAX_WIRE, "wire bound")
    return bytes(out)


class Reader:
    def __init__(self, data: bytes):
        self.data, self.offset = data, 0

    def take(self, size: int) -> bytes:
        require(size <= len(self.data) - self.offset, "truncated")
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def integer(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def indices(self) -> list[int]:
        count = self.integer(2)
        require(count <= MAX_FILES, "index count")
        return [self.integer(2) for _ in range(count)]


def decode(wire: bytes) -> dict:
    require(type(wire) is bytes and len(wire) <= MAX_WIRE, "wire bound")
    reader = Reader(wire)
    require(reader.take(4) == b"TCD1", "version")
    generation, loader = reader.integer(8), reader.take(32).hex()
    release_size = reader.integer(4)
    require(release_size <= MAX_WIRE, "release bound")
    release = reader.take(release_size)
    member = Reader(release)
    require(member.take(4) == b"TCR1", "release version")
    family_size = member.integer(1)
    require(1 <= family_size <= 64, "family bound")
    context = {"family": member.take(family_size).decode("ascii")}
    for name in ("base", "parent", "tokenizer", "layout", "runtime"):
        context[name] = member.take(32).hex()
    count = member.integer(4)
    require(1 <= count <= MAX_FILES, "release count")
    members = [member.take(32).hex() for _ in range(count)]
    require(member.offset == len(release), "release suffix")
    require(release_bytes(context, members) == release, "release canonical")
    roots = reader.indices()
    count = reader.integer(2)
    require(1 <= count <= MAX_FILES, "file count")
    files = []
    for _ in range(count):
        size = reader.integer(2)
        require(1 <= size <= 255, "path bound")
        files.append({"path": reader.take(size).decode("ascii"), "role": reader.integer(1),
                      "manifest": reader.take(32).hex(), "payload_sha256": reader.take(32).hex(),
                      "payload_bytes": reader.integer(8), "dependencies": reader.indices()})
    require(reader.offset == len(wire), "trailing bytes")
    value = {"context": context, "selected_generation": generation, "loader_profile": loader,
             "roots": roots, "files": files}
    require(encode(value) == wire, "noncanonical bytes or release membership")
    return value


def fixture() -> dict:
    context = {"family": "closure-v1", **{name: bytes([i]).hex() * 32 for i, name in
               enumerate(("base", "parent", "tokenizer", "layout", "runtime"), 1)}}
    files, manifests = [], []
    for name, role, payload, dependencies in (
        ("base/model.safetensors", 1, b"base-fixture", []),
        ("tokenizer/tokenizer.json", 2, b"{}", []),
        ("z-model.json", 6, b'{"kind":"fixture"}', [0, 1]),
    ):
        checksum = hashlib.sha256(payload).digest()
        manifest = (b"TCM1" + context_bytes(context) + struct.pack(">Q", len(payload)) + checksum
                    + struct.pack(">II", 16384, 1) + struct.pack(">I", len(payload)) + checksum)
        identity = hashlib.sha256(b"trnm.cell-manifest.v1\0" + manifest).hexdigest()
        files.append({"path": name, "role": role, "manifest": identity,
                      "payload_sha256": checksum.hex(), "payload_bytes": len(payload),
                      "dependencies": dependencies})
        manifests.append({"wire_hex": manifest.hex(), "payload_hex": payload.hex()})
    value = {"context": context, "selected_generation": 7, "loader_profile": "06" * 32,
             "roots": [2], "files": files}
    wire = encode(value)
    return {"scope": "synthetic-codec-and-graph-vector-not-a-model", "closure": value,
            "wire_hex": wire.hex(), "closure_id": hashlib.sha256(DOMAIN + wire).hexdigest(),
            "manifests": manifests}


if __name__ == "__main__":
    destination = Path(__file__).with_name("vectors") / "cell-dependency-closure-v1.json"
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(fixture(), indent=2, sort_keys=True) + "\n")
