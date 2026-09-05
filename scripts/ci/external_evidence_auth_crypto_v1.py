"""Bounded OpenSSL Ed25519 verification for external evidence v1."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile

from external_evidence_auth_common_v1 import (
    AuthenticationError, ED25519_SPKI, require,
)

def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> None:
    require(len(public_key) == 32 and len(signature) == 64 and 0 < len(message) <= 512,
            "invalid Ed25519 input bounds")
    require(public_key not in {bytes(32), b"\x01" + bytes(31)}, "degenerate public key")
    with tempfile.TemporaryDirectory(prefix="trnm-evidence-verify-") as directory:
        root = pathlib.Path(directory)
        (root / "public.der").write_bytes(ED25519_SPKI + public_key)
        (root / "signature").write_bytes(signature)
        (root / "message").write_bytes(message)
        try:
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                 "-inkey", str(root / "public.der"), "-rawin", "-in", str(root / "message"),
                 "-sigfile", str(root / "signature")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AuthenticationError("Ed25519 verifier unavailable") from error
    require(result.returncode == 0, "Ed25519 signature verification failed")
