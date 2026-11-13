"""Independent TMR1 identity oracle; does not authenticate or authorize a model."""
import hashlib
import struct

import cell_dependency_closure as closure

DOMAIN = b"trnm.cell-model-release-root.v1\0"


def encode(value, parents):
    wire = closure.encode(value)
    closure.require(type(parents) is list and len(parents) <= 16, "lineage count")
    ids = [closure.digest(item) for item in parents]
    closure.require(ids == sorted(set(ids)), "canonical lineage")
    routers = [file for file in value["files"] if file["role"] == 5]
    router = bytearray(b"trnm.cell-model-router-roster.v1\0" + struct.pack(">H", len(routers)))
    for file in routers:
        path = file["path"].encode("ascii")
        router += struct.pack(">H", len(path)) + path
        router += closure.digest(file["manifest"]) + closure.digest(file["payload_sha256"])
        router += struct.pack(">Q", file["payload_bytes"])
    return (b"TMR1" + struct.pack(">I", len(wire)) + wire
            + hashlib.sha256(router).digest() + bytes([len(ids)]) + b"".join(ids))


def fixture():
    value = closure.fixture()["closure"]
    value["files"][2]["role"] = 5
    parents = ["21" * 32, "22" * 32]
    wire = encode(value, parents)
    return {"scope": "synthetic-identity-vector-not-model-authorization", "closure": value,
            "lineage": parents, "wire_hex": wire.hex(),
            "model_root": hashlib.sha256(DOMAIN + wire).hexdigest()}


if __name__ == "__main__":
    import json
    from pathlib import Path
    print(json.dumps(fixture(), indent=2, sort_keys=True))
