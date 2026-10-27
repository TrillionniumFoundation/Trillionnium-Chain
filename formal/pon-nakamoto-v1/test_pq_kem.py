"""OpenSSL 3.5+ ML-KEM-768 primitive conformance; NOT a TLS handshake."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


def run(*args):
    try:
        result = subprocess.run(["openssl", *args], check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("OpenSSL KEM provider not available") from exc
    if result.returncode:
        raise RuntimeError("OpenSSL KEM operation failed: " + result.stderr.decode(errors="replace")[:300])


class RealMLKEM768Tests(unittest.TestCase):
    def test_real_encapsulation_decapsulation_corruption_and_wrong_key(self):
        if not shutil.which("openssl"):
            raise RuntimeError("ML-KEM conformance requires OpenSSL 3.5+")
        with tempfile.TemporaryDirectory(prefix="trnm-pq-kem-") as d:
            p = Path(d)
            for name in ("one", "two"):
                run("genpkey", "-algorithm", "ML-KEM-768", "-out", str(p / f"{name}.priv"))
                run("pkey", "-in", str(p / f"{name}.priv"), "-pubout", "-out", str(p / f"{name}.pub"))
            run("pkeyutl", "-encap", "-pubin", "-inkey", str(p / "one.pub"),
                "-out", str(p / "ct"), "-secret", str(p / "key_a"))
            run("pkeyutl", "-decap", "-inkey", str(p / "one.priv"),
                "-in", str(p / "ct"), "-secret", str(p / "key_b"))
            self.assertEqual((p / "key_a").read_bytes(), (p / "key_b").read_bytes())
            self.assertEqual(len((p / "ct").read_bytes()), 1088)
            self.assertEqual(len((p / "key_a").read_bytes()), 32)
            run("pkeyutl", "-decap", "-inkey", str(p / "two.priv"),
                "-in", str(p / "ct"), "-secret", str(p / "wrong_key"))
            self.assertNotEqual((p / "key_a").read_bytes(), (p / "wrong_key").read_bytes())
            ct = bytearray((p / "ct").read_bytes())
            ct[-1] ^= 0x01
            (p / "bad_ct").write_bytes(ct)
            run("pkeyutl", "-decap", "-inkey", str(p / "one.priv"),
                "-in", str(p / "bad_ct"), "-secret", str(p / "bad_key"))
            # ML-KEM implicit rejection: corrupted ciphertext can still produce a key.
            self.assertNotEqual((p / "key_a").read_bytes(), (p / "bad_key").read_bytes())


if __name__ == "__main__":
    unittest.main()
