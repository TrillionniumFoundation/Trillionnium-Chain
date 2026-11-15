#!/usr/bin/env python3
"""Independent byte specification and hashlib vectors for the research profile.

This reference deliberately does not import or parse the Rust implementation.
Its constants are a reviewed copy of the normative profile specification.
It is a correctness oracle for finite vectors, never a collision-resistance test.
"""
from __future__ import annotations

import hashlib
import json
import struct

FIELD = 18446744069414584321
PROFILE = b"TRNM-W1-P3-SHA3-512-TAGGED-R1"
MAGIC = b"TRNM-W1-SHARED-HASH\0"
DESCRIPTOR = b"p3=0.8.0;sha3=512;r=576;c=1024;F=18446744069414584321;E=X^2-7;binary;cap=0;log_blowup=2;log_final_poly=0;max_log_arity=1;queries=64;pow=0;zk=0;sha=d13,w7728,p27,q2,next1;carry=d14,w370,p180,q1,next0"
ROLES = {"leaf": 1, "branch": 2, "transcript": 3, "statement_context": 4}


def frame(component: int, role: str, context: bytes, payload: bytes) -> bytes:
    if type(component) is not int or component not in (0, 1, 4):
        raise ValueError("unknown reference component")
    if type(context) is not bytes or len(context) != 64:
        raise ValueError("context must contain 64 bytes")
    if role not in ROLES or (component == 0) != (role == "statement_context"):
        raise ValueError("invalid component/role combination")
    if type(payload) is not bytes:
        raise ValueError("payload must be bytes")
    return b"".join((
        MAGIC,
        struct.pack("<HH", 1, len(PROFILE)), PROFILE,
        struct.pack("<H", len(DESCRIPTOR)), DESCRIPTOR,
        struct.pack("<IB", component, ROLES[role]), context,
        payload, struct.pack("<Q", len(payload)),
    ))


def context_payload(public: bytes, header: bytes, artifacts: bytes) -> bytes:
    output = bytearray(struct.pack("<I", 3))
    for number, value in enumerate((public, header, artifacts), 1):
        output.extend(struct.pack("<BQ", number, len(value)))
        output.extend(value)
    return bytes(output)


def vectors() -> dict:
    cases = []
    context = bytes(range(64))
    for component in (1, 4):
        for values in ((), (0,), (1,), (1, 0), (0, 1, FIELD - 1)):
            payload = b"".join(struct.pack("<Q", value) for value in values)
            cases.append({
                "name": f"component_{component}_leaf_" + "_".join(map(str, values)),
                "component": component, "role": "leaf", "context_hex": context.hex(),
                "payload_hex": payload.hex(),
            })
        children = (
            bytes(64) + bytes([255]) * 64,
            b"".join(struct.pack("<Q", value) for value in (FIELD, (1 << 64) - 1, 0, 1, 2, 3, 4, 5))
            + bytes(reversed(range(64))),
        )
        for index, payload in enumerate(children):
            cases.append({
                "name": f"component_{component}_branch_{index}",
                "component": component, "role": "branch", "context_hex": context.hex(),
                "payload_hex": payload.hex(),
            })
        for count in (0, 1, 71, 72, 73, 144, 201):
            cases.append({
                "name": f"component_{component}_transcript_{count}",
                "component": component, "role": "transcript", "context_hex": context.hex(),
                "payload_hex": bytes(index % 256 for index in range(count)).hex(),
            })
    for index, triple in enumerate(((b"a", b"bc", b"d"), (b"ab", b"c", b"d"), (b"", b"", b""))):
        cases.append({
            "name": f"statement_context_{index}", "component": 0,
            "role": "statement_context", "context_hex": bytes(64).hex(),
            "payload_hex": context_payload(*triple).hex(),
            "public_hex": triple[0].hex(), "expected_header_hex": triple[1].hex(),
            "expected_artifacts_hex": triple[2].hex(),
        })
    for case in cases:
        message = frame(case["component"], case["role"], bytes.fromhex(case["context_hex"]),
                        bytes.fromhex(case["payload_hex"]))
        case["framed_message_bytes"] = len(message)
        case["sha3_512_hex"] = hashlib.sha3_512(message).hexdigest()
    return {
        "schema": "p3.tagged_sha3.independent_vectors.v1",
        "profile_id": PROFILE.decode("ascii"), "descriptor": DESCRIPTOR.decode("ascii"),
        "reference": "Python standard-library hashlib.sha3_512; independent struct byte encoding",
        "security_claim": False, "cases": cases,
    }


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=2, sort_keys=True))
