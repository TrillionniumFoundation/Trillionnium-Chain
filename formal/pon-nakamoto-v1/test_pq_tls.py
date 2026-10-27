"""Real loopback TLS 1.3 hybrid-KEM + ML-DSA-65 certificate; no Chain/P2P host integration."""
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest


def command(args, **kwargs):
    result = subprocess.run(["openssl", *args], check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=15, **kwargs)
    if result.returncode:
        raise RuntimeError("offline TLS setup failed: " + result.stderr.decode(errors="replace")[:350])


class RealHybridTLSTests(unittest.TestCase):
    def test_loopback_authenticated_pq_tls_and_strict_downgrade_refusals(self):
        if not shutil.which("openssl"):
            raise RuntimeError("OpenSSL 3.5+ with ML-DSA / X25519MLKEM768 is required")
        with tempfile.TemporaryDirectory(prefix="trnm-pq-tls-") as d:
            p = Path(d)
            key, cert = p / "key.pem", p / "cert.pem"
            command(["genpkey", "-algorithm", "ML-DSA-65", "-out", str(key)])
            command(["req", "-new", "-x509", "-key", str(key),
                     "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"])
            probe = socket.socket()
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
            with (p / "server.log").open("wb") as server_log:
                server = subprocess.Popen([
                    "openssl", "s_server", "-accept", f"127.0.0.1:{port}",
                    "-cert", str(cert), "-key", str(key), "-tls1_3",
                    "-groups", "X25519MLKEM768", "-www",
                ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=server_log)
                try:
                    for _ in range(80):
                        if server.poll() is not None:
                            self.fail("TLS test server failed to start")
                        try:
                            sock = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                            sock.close()
                            break
                        except OSError:
                            time.sleep(0.05)
                    else:
                        self.fail("TLS test server not ready")

                    def client(groups="X25519MLKEM768", host="localhost"):
                        return subprocess.run([
                            "openssl", "s_client", "-connect", f"127.0.0.1:{port}",
                            "-tls1_3", "-groups", groups, "-CAfile", str(cert),
                            "-verify_hostname", host, "-verify_return_error", "-brief",
                        ], input=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)

                    good = client()
                    self.assertEqual(good.returncode, 0, good.stderr.decode(errors="replace"))
                    report = good.stderr.decode(errors="replace")
                    self.assertIn("Protocol version: TLSv1.3", report)
                    self.assertIn("Signature type: mldsa65", report)
                    self.assertIn("Negotiated TLS1.3 group: X25519MLKEM768", report)
                    self.assertIn("Verification: OK", report)
                    self.assertIn("Verified peername: localhost", report)

                    # An opportunistic TLS fallback or a nonmatching identity is NOT accepted.
                    wrong_name = client(host="attacker.invalid")
                    self.assertNotEqual(wrong_name.returncode, 0)
                    classical_only = client(groups="X25519")
                    self.assertNotEqual(classical_only.returncode, 0)
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
