#!/usr/bin/env python3
"""Independently verify the candidate first-new-epoch signature vector.

This checker reproduces only the RFC 8032 Ed25519 key/signature relation with
the standard-library implementation used by the QC/TC reference lane.  The
signing-root bytes remain a fixture supplied by the epoch test and therefore
do not constitute an independent reconstruction of the complete CEV0 proof.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "docs/protocol/poco-bft-v0/vectors/epoch-first-proposal-signing-v0.json"
REFERENCE = Path(__file__).with_name("check_poco_bft_v0_qc_tc_vectors.py")


def load_reference():
    spec = importlib.util.spec_from_file_location("trnm_qc_tc_reference", REFERENCE)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the standard-library Ed25519 reference")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    reference = load_reference()
    vector = json.loads(VECTOR.read_text(encoding="utf-8"))
    root = bytes.fromhex(vector["expected_signing_root_hex"])
    signature = bytes.fromhex(vector["expected_signature_hex"])
    expected_public = bytes.fromhex(vector["expected_public_key_hex"])
    seed = hashlib.sha256(
        b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:validator-a"
    ).digest()
    if reference.ed25519_public_key(seed) != expected_public:
        raise SystemExit("candidate vector public key does not match the fixture seed")
    if reference.ed25519_sign(seed, root) != signature:
        raise SystemExit("candidate vector signature does not match independent Ed25519")
    if not reference.ed25519_verify(expected_public, root, signature):
        raise SystemExit("candidate vector signature failed independent verification")
    mutated = bytearray(signature)
    mutated[0] ^= 1
    if reference.ed25519_verify(expected_public, root, bytes(mutated)):
        raise SystemExit("mutated candidate signature was accepted")
    print("PoCO-BFT v0 candidate epoch-first-proposal Ed25519 vector verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
