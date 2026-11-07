"""Real loopback TLS observations, using the explicitly pinned OpenSSL backend.

RFC 10024's other groups are primitive interoperability controls, not additions
to the separate PPH1 probe's fixed X25519MLKEM768 identity/profile policy.
No Chain/P2P host integration or business authority is established here.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from pq_openssl_backend import BackendError, binding


class PinnedTLSProbeBackend:
    """Test-only CLI selection; shares the cryptographic oracle's exact binding.

    TLS listeners are deliberately separate from the production-shaped crypto
    wrapper. This helper neither expands that wrapper's commands nor changes
    the provider's trust boundary.
    """
    def __init__(self):
        self.declared = binding()
        self.environment = dict(os.environ, OPENSSL_CONF=os.devnull,
                                OPENSSL_MODULES=str(self.declared.modules))
        result = subprocess.run([str(self.declared.executable), "version"],
                                capture_output=True, timeout=5,
                                env=self.environment, check=False)
        if (result.returncode or len(result.stdout) > 512 or
                not result.stdout.startswith(
                    ("OpenSSL " + self.declared.version + " ").encode())):
            raise BackendError("TLS probe backend version differs from its declaration")
        reported = result.stdout.decode().strip()
        cli_version, separator, library_version = reported.partition(" (Library: ")
        if separator and library_version != cli_version + ")":
            raise BackendError("TLS probe CLI and loaded library versions differ")
        self.version_text = cli_version

    def command(self, args):
        if (not args or args[0] not in
                ("genpkey", "req", "pkey", "s_server", "s_client") or
                any(type(arg) is not str or "\x00" in arg for arg in args)):
            raise BackendError("TLS probe command shape")
        if any(arg.startswith("-") and arg.lstrip("-").split("=", 1)[0]
               in ("provider", "provider-path", "engine", "config") for arg in args):
            raise BackendError("TLS probe cannot replace the declared provider/configuration")
        return [str(self.declared.executable), args[0], "-provider", "default", *args[1:]]

    def run(self, args, *, input_data=None, timeout=15, check=False):
        return subprocess.run(self.command(args), input=input_data,
                              capture_output=True, timeout=timeout,
                              env=self.environment, check=check)


class RealHybridTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = PinnedTLSProbeBackend()
        cls.temp = tempfile.TemporaryDirectory(prefix="trnm-pq-tls-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.key, cls.cert = cls.root / "key.pem", cls.root / "cert.pem"
        cls.backend.run(["genpkey", "-algorithm", "ML-DSA-65", "-out", str(cls.key)],
                        check=True)
        cls.backend.run(["req", "-new", "-x509", "-key", str(cls.key),
                         "-out", str(cls.cert), "-days", "1", "-subj", "/CN=localhost",
                         "-addext", "subjectAltName=DNS:localhost"], check=True)

    @contextmanager
    def server(self, group="X25519MLKEM768"):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with tempfile.TemporaryFile() as server_log:
            server = subprocess.Popen(self.backend.command([
                "s_server", "-accept", f"127.0.0.1:{port}",
                "-cert", str(self.cert), "-key", str(self.key), "-tls1_3",
                "-groups", group, "-www",
            ]), env=self.backend.environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=server_log)
            try:
                for _ in range(80):
                    if server.poll() is not None:
                        self.fail("TLS test server failed to start")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    self.fail("TLS test server not ready")
                yield port
            finally:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)

    def client(self, port, *, group="X25519MLKEM768", host="localhost",
               protocol="-tls1_3"):
        return self.backend.run([
            "s_client", "-connect", f"127.0.0.1:{port}", protocol,
            "-groups", group, "-CAfile", str(self.cert), "-verify_hostname", host,
            "-verify_return_error", "-brief", "-ign_eof",
        ], input_data=b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", timeout=12)

    def assert_authenticated_response(self, result, group):
        report = result.stderr.decode(errors="replace")
        self.assertEqual(result.returncode, 0, report)
        self.assertIn("Protocol version: TLSv1.3", report)
        self.assertIn("Signature type: mldsa65", report)
        self.assertIn("Negotiated TLS1.3 group: " + group, report)
        self.assertIn("Verification: OK", report)
        self.assertIn("Verified peername: localhost", report)
        # A CLI handshake exit alone does not demonstrate accepted application data.
        self.assertIn(b"HTTP/1.0 200 ok", result.stdout)

    def test_loopback_authenticated_pq_tls_and_strict_downgrade_refusals(self):
        with self.server() as port:
            self.assert_authenticated_response(self.client(port), "X25519MLKEM768")
            for change in (dict(host="attacker.invalid"), dict(group="X25519"),
                           dict(group="SecP384r1MLKEM1024"),
                           dict(group="X25519", protocol="-tls1_2")):
                with self.subTest(change=change):
                    refused = self.client(port, **change)
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertNotIn(b"HTTP/1.0 200 ok", refused.stdout)

    def test_rfc10024_other_standard_groups_have_real_authenticated_handshakes(self):
        for group in ("SecP256r1MLKEM768", "SecP384r1MLKEM1024"):
            with self.subTest(group=group), self.server(group) as port:
                self.assert_authenticated_response(self.client(port, group=group), group)

    def test_declared_backend_ignores_path_openssl_and_inherited_configuration(self):
        # A failing decoy only detects a wrong executable selection. It cannot
        # produce a successful signature, certificate or handshake.
        with tempfile.TemporaryDirectory(prefix="pq-tls-path-control-") as d:
            root = Path(d)
            marker, decoy = root / "called", root / "openssl"
            decoy.write_text(f"#!{sys.executable}\nfrom pathlib import Path\n"
                             f"Path({str(marker)!r}).touch()\nraise SystemExit(29)\n")
            decoy.chmod(0o700)
            bad_config = root / "invalid.cnf"
            bad_config.write_text("this is not an OpenSSL configuration\n")
            with patch.dict(os.environ, {
                "PATH": str(root) + os.pathsep + os.environ.get("PATH", ""),
                "OPENSSL_CONF": str(bad_config), "OPENSSL_MODULES": str(root / "absent"),
            }):
                backend = PinnedTLSProbeBackend()
                backend.run(["genpkey", "-algorithm", "ML-DSA-65",
                             "-out", str(root / "test-only.key")], check=True)
            self.assertFalse(marker.exists())
            self.assertEqual(backend.declared, self.backend.declared)
            self.assertEqual(backend.version_text, self.backend.version_text)


if __name__ == "__main__":
    unittest.main()
