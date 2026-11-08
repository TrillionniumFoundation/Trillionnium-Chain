#!/usr/bin/env python3
"""Independent CCH1/SHA-512 framing vectors; no Rust imports or PQ claims."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/cpq1-content-v1/vectors.json"

def check():
    data = json.loads(FIXTURE.read_text())
    assert data["schema"] == "trnm-cch1-framing-vectors-v1"
    assert data["profile_ids_are_synthetic_test_labels"] is True
    for vector in data["vectors"]:
        profile = bytes.fromhex(vector["profile_id_hex"])
        instance = bytes.fromhex(vector["instance_hex"])
        payload = bytes.fromhex(vector["payload_hex"])
        assert len(profile) == len(instance) == 64
        assert 1 <= vector["kind"] <= 5
        header = (b"CCH1" + profile + bytes([vector["kind"]]) + instance
                  + struct.pack(">QQ", vector["generation"], len(payload)))
        digest = hashlib.sha512(b"TRNM/CPQ1/FullContent/SHA512/v1\0" + header + payload).digest()
        assert (header + digest).hex() == vector["claim_hex"], vector["name"]
        assert len(header + digest) == 213
    return len(data["vectors"])

if __name__ == "__main__":
    print(json.dumps({"result": "PASS", "vectors": check(), "native_execution": False}))
