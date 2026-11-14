"""Actual independent OpenSSL-native C mutual PQ TLS + hybrid group experiments.

This is localhost and never a product listener or ledger verifier. Each positive
asserts BOTH peers sent authenticated application bytes, not s_client's misleading
handshake exit code. Every negative has no accepted application exchange.
"""
from __future__ import annotations
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import unittest

from pq_envelope import public_key_id, Reject, parse_signed, sign_reference, verify_reference
from pq_peer_session import PeerHello,parse_hello, sign_hello,verify_hello,FRAME_BYTES
from test_pq_tls import PinnedTLSProbeBackend

ROOT = Path(__file__).resolve().parent
NETWORK = bytes(range(32))
GENESIS = bytes(range(32,64))
PROFILE = bytes(range(64,96))


def cmd(args, *, env):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30, check=True, env=env)


class PQMutualTLSProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = PinnedTLSProbeBackend()
        cls.t = tempfile.TemporaryDirectory(prefix="trnm-pq-mtls-")
        cls.addClassCleanup(cls.t.cleanup)
        cls.dir = Path(cls.t.name)
        cls.exe = cls.dir / "pq_mtls_probe"
        cls.keys = {}
        for name, algorithm in (("server", "ML-DSA-65"), ("client", "ML-DSA-65"),
                                ("attacker", "ML-DSA-65"), ("classical", "ED25519"),
                                ("other_parameter", "ML-DSA-44")):
            k, c, pub = (cls.dir / f"{name}.key", cls.dir / f"{name}.cert",
                         cls.dir / f"{name}.public")
            cls.backend.run(["req", "-new", "-x509", "-newkey", algorithm,
                             "-keyout", str(k), "-out", str(c), "-nodes", "-days", "1",
                             "-subj", f"/CN={name}.local",
                             "-addext", f"subjectAltName=DNS:{name}.local"], check=True)
            cls.backend.run(["pkey", "-in", str(k), "-pubout", "-out", str(pub)], check=True)
            if algorithm == "ML-DSA-65":
                key_id = public_key_id(pub.read_bytes())
            else:
                # Supply an exact matching pin for a trusted but wrong-algorithm
                # certificate, so the negative must reach the algorithm policy.
                der = cls.backend.run(["pkey", "-in", str(k), "-pubout",
                                       "-outform", "DER"], check=True).stdout
                key_id = hashlib.sha256(b"TRNM/PoN/PQKey/v1\0" + der).digest()
            cls.keys[name] = (k, c, key_id)
        prefix = cls.backend.declared.executable.parent.parent
        archives = [prefix / "lib" / name for name in ("libssl.a", "libcrypto.a")]
        for archive in archives:
            if (not archive.is_file() or archive.is_symlink() or
                    archive.resolve(strict=True) != archive):
                raise RuntimeError("TLS probe requires the declared provider's static archives")
        cmd(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
             "-I", str(prefix / "include"), str(ROOT / "pq_mtls_probe.c"),
             "-o", str(cls.exe), *map(str, archives), "-ldl", "-pthread"],
            env=cls.backend.environment)
        reported = cmd([str(cls.exe), "--backend-version"],
                       env=cls.backend.environment).stdout.decode().splitlines()
        if reported != [cls.backend.version_text, cls.backend.version_text]:
            raise RuntimeError("TLS probe headers, linked library and pinned CLI differ")

    def pair(self, *, client="client", server="server", server_group="X25519MLKEM768",
             client_group="X25519MLKEM768", client_cert=True,
             cli_client=False,
             client_trust="server", server_trust="client", hostname="server.local",
             expected_client_key=None, expected_server_key=None,
             client_network=NETWORK, server_network=NETWORK,
             client_genesis=GENESIS, server_genesis=GENESIS,
             client_profile=PROFILE, server_profile=PROFILE):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        sk, sc, sid = self.keys[server]
        ck, cc, cid = self.keys[client]
        server_ca = self.keys[server_trust][1]
        client_ca = self.keys[client_trust][1]
        def args(mode, key, cert, ca, expected, host, network, genesis, profile, group):
            return [str(self.exe), mode, str(port), str(cert), str(key), str(ca),
                    (expected if expected is not None else (cid if mode=="server" else sid)).hex(),
                    host, network.hex(), genesis.hex(), profile.hex(), group]
        srv = subprocess.Popen(args("server",sk,sc,server_ca,expected_client_key,"client.local",
                                    server_network,server_genesis,server_profile,server_group),
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                               env=self.backend.environment)
        try:
            self.assertTrue(select.select([srv.stdout], [], [], 5)[0],
                            "native server startup timed out")
            ready = srv.stdout.readline().strip()
            self.assertEqual(ready, "READY", "native server startup failed")
            if not client_cert or cli_client:
                # The CLI can finish transport authentication without the C
                # client's profile check. This isolates the server-side refusal.
                certificate_args = ["-cert",str(cc),"-key",str(ck)] if client_cert else []
                cli = self.backend.run(["s_client","-tls1_3", "-groups",client_group,
                                        "-connect",f"127.0.0.1:{port}","-CAfile",str(client_ca),
                                        "-verify_hostname",hostname,"-verify_return_error","-brief",
                                        "-ign_eof",*certificate_args],
                                       input_data=b"PING", timeout=8)
                client_rc = cli.returncode
                client_out = cli.stdout.decode(errors="replace")
                client_err = cli.stderr.decode(errors="replace")
            else:
                cli = subprocess.run(args("client",ck,cc,client_ca,expected_server_key,hostname,
                                          client_network,client_genesis,client_profile,client_group),
                                     capture_output=True,text=True,timeout=8,
                                     env=self.backend.environment)
                client_rc,client_out,client_err=cli.returncode,cli.stdout,cli.stderr
            out,err=srv.communicate(timeout=8)
        finally:
            if srv.poll() is None:
                srv.kill();srv.communicate(timeout=4)
        def parsed(raw):
            for line in raw.splitlines():
                if line.startswith('{'):
                    return json.loads(line)
            if "PONG" in raw:
                return {"application_exchange": True}
            return None
        return client_rc, srv.returncode, parsed(client_out), parsed(out),client_err,err

    def test_real_mutual_tls_hybrid_and_same_secret_exporter(self):
        c,s,co,so,ce,se=self.pair()
        self.assertEqual((c,s),(0,0),(ce,se))
        self.assertEqual(co["peer_key_id"], self.keys["server"][2].hex())
        self.assertEqual(so["peer_key_id"], self.keys["client"][2].hex())
        self.assertEqual(co["group"],"X25519MLKEM768")
        self.assertEqual(so["group"],"X25519MLKEM768")
        self.assertEqual(co["channel_tag"],so["channel_tag"])

    def test_missing_client_certificate_refused_by_server(self):
        c,s,co,so,ce,se=self.pair(client_cert=False)
        self.assertNotEqual(s,0,(ce,se))
        self.assertIsNone(so)

    def test_untrusted_client_certificate_refused_before_application(self):
        c,s,co,so,ce,se=self.pair(client="attacker")
        self.assertNotEqual(s,0,(ce,se))
        self.assertIsNone(so)

    def test_key_pinned_identity_rejects_even_valid_tls_trust(self):
        bad=bytes(32)
        c,s,co,so,ce,se=self.pair(expected_client_key=bad)
        self.assertNotEqual(s,0,(ce,se))
        self.assertIsNone(so)
        c,s,co,so,ce,se=self.pair(expected_server_key=bad)
        self.assertNotEqual(c,0,(ce,se))
        self.assertIsNone(co)

    def test_x25519_only_and_no_shared_hybrid_group_refused(self):
        for g1,g2 in (("X25519","X25519"),("X25519MLKEM768","X25519"),
                      ("X25519","X25519MLKEM768:X25519"),
                      ("X25519MLKEM768:X25519","X25519")):
            with self.subTest(groups=(g1,g2)):
                c,s,co,so,ce,se=self.pair(server_group=g1,client_group=g2)
                self.assertFalse(c==0 and s==0,(ce,se))
                self.assertIsNone(co)
                self.assertIsNone(so)
                if ":" in g1 or ":" in g2:
                    self.assertIn("REFUSED group_outside_profile",ce)

    def test_rfc10024_alternate_group_does_not_silently_change_pph1_profile(self):
        # The primitive TLS tests exercise both other standard groups. This
        # PPH1 v1 probe deliberately admits only its original X25519 profile.
        for group in ("SecP256r1MLKEM768", "SecP384r1MLKEM1024"):
            with self.subTest(group=group):
                c,s,co,so,ce,se=self.pair(server_group=group,client_group=group)
                self.assertNotEqual(c,0,(ce,se))
                self.assertNotEqual(s,0,(ce,se))
                self.assertIsNone(co)
                self.assertIsNone(so)
                self.assertIn("REFUSED group_outside_profile",ce)
                # The client may close before SSL_accept finishes on the server.
                # A separate CLI peer reaches the server's own policy check.
                c,s,co,so,ce,se=self.pair(server_group=group,client_group=group,
                                         cli_client=True)
                self.assertNotEqual(s,0,(ce,se))
                self.assertIsNone(co)
                self.assertIsNone(so)
                self.assertIn("REFUSED group_outside_profile",se)

    def test_trusted_classical_and_wrong_parameter_identity_refused_after_handshake(self):
        for name in ("classical", "other_parameter"):
            with self.subTest(peer=name,side="server"):
                c,s,co,so,ce,se=self.pair(client=name,server_trust=name)
                self.assertNotEqual(s,0,(ce,se))
                self.assertIsNone(so)
                self.assertIsNone(co)
                self.assertIn("REFUSED peer_not_mldsa65",se)
            with self.subTest(peer=name,side="client"):
                c,s,co,so,ce,se=self.pair(server=name,client_trust=name,
                                         hostname=name+".local")
                self.assertNotEqual(c,0,(ce,se))
                self.assertIsNone(co)
                self.assertIsNone(so)
                self.assertIn("REFUSED peer_not_mldsa65",ce)

    def test_hybrid_key_exchange_does_not_authorize_a_classical_peer_identity(self):
        # The TLS chain is trusted and the configured group is hybrid. Only
        # the independent PQ identity gate must refuse this classical key.
        # Reuse the declared backend's certificate and exact DER pin prepared
        # by setUpClass; do not regenerate or mutate another test's fixture.
        c, s, co, so, ce, se = self.pair(client="classical", server_trust="classical")
        self.assertNotEqual(s, 0, (ce, se))
        self.assertIsNone(co)
        self.assertIsNone(so)
        self.assertIn("REFUSED peer_not_mldsa65", se)

    def test_hostname_and_trustroot_refused(self):
        c,s,co,so,ce,se=self.pair(hostname="malicious.invalid")
        self.assertNotEqual(c,0,(ce,se));self.assertIsNone(co)
        c,s,co,so,ce,se=self.pair(client_trust="attacker")
        self.assertNotEqual(c,0,(ce,se));self.assertIsNone(co)

    def test_network_parameter_change_changes_exporter_binding(self):
        for field in ("client_network", "client_genesis", "client_profile"):
            with self.subTest(field=field):
                c,s,co,so,ce,se=self.pair(**{field:bytes([99])*32})
                self.assertEqual((c,s),(0,0),(ce,se))
                self.assertNotEqual(co["channel_tag"],so["channel_tag"])


    def sign_client_hello(self,channel_tag, **changes):
        hello=PeerHello(NETWORK,GENESIS,PROFILE,self.keys["client"][2],
                        self.keys["server"][2],bytes.fromhex(channel_tag),9,13,1020,
                        bytes(range(96,128)))
        return sign_hello(replace(hello,**changes),private_key_path=self.keys["client"][0])

    def inspect_hello(self,frame,channel_tag, **changes):
        kwargs=dict(remote_public_pem=self.client_public(),expected_network=NETWORK,
                    expected_genesis=GENESIS,expected_profile=PROFILE,
                    expected_remote_key_id=self.keys["client"][2],
                    expected_local_key_id=self.keys["server"][2],
                    independently_verified_tls_channel_tag=bytes.fromhex(channel_tag),
                    expected_generation=9,expected_sequence=13,now=1000)
        kwargs.update(changes)
        return verify_hello(frame,**kwargs)

    def client_public(self):
        return self.backend.run(["pkey","-in",str(self.keys["client"][0]),"-pubout"],
                                check=True).stdout

    def test_signed_hello_real_mtls_exporter_cannot_replay_into_another_session(self):
        c,s,co,so,_,_=self.pair()
        self.assertEqual((c,s),(0,0))
        frame=self.sign_client_hello(co["channel_tag"])
        obs=self.inspect_hello(frame,so["channel_tag"])
        self.assertEqual(obs.channel_tag,bytes.fromhex(co["channel_tag"]))
        _,_,co2,so2,_,_=self.pair()
        self.assertNotEqual(co["channel_tag"],co2["channel_tag"])
        with self.assertRaises(Reject):
            self.inspect_hello(frame,so2["channel_tag"])

    def test_signed_hello_wrong_network_role_generation_expiry_and_signature_reject(self):
        _,_,co,so,_,_=self.pair()
        frame=self.sign_client_hello(co["channel_tag"])
        for change in (dict(expected_network=bytes([9])*32),
                       dict(expected_profile=bytes([8])*32),
                       dict(expected_local_key_id=bytes([7])*32),
                       dict(expected_generation=10),dict(expected_sequence=14),
                       dict(now=1021),dict(now=900),dict(now=True),
                       dict(remote_public_pem=self.backend.run(
                           ["pkey","-in",str(self.keys["attacker"][0]),"-pubout"],
                           check=True).stdout)):
            with self.subTest(change=list(change)),self.assertRaises(Reject):
                self.inspect_hello(frame,so["channel_tag"],**change)
        corrupted=bytearray(frame);corrupted[-1]^=1
        with self.assertRaises(Reject):self.inspect_hello(bytes(corrupted),so["channel_tag"])
        for i in range(FRAME_BYTES):
            bad=bytearray(frame);bad[i]^=1
            with self.subTest(offset=i),self.assertRaises(Reject):
                self.inspect_hello(bytes(bad),so["channel_tag"])

    def test_signed_hello_no_default_acceptance_of_peer_chosen_channel(self):
        _,_,co,so,_,_=self.pair(client_network=bytes([99])*32)
        signed=self.sign_client_hello(co["channel_tag"])
        with self.assertRaises(Reject):self.inspect_hello(signed,so["channel_tag"])
        with self.assertRaises(Reject):
            self.sign_client_hello(co["channel_tag"],nonce=bytes(32))
        with self.assertRaises(Reject):parse_hello(signed[:FRAME_BYTES-1])

    def test_authenticated_transport_and_peer_proof_are_not_other_purposes(self):
        c,s,co,so,ce,se=self.pair()
        self.assertEqual((c,s),(0,0),(ce,se))
        frame=self.sign_client_hello(co["channel_tag"])
        self.inspect_hello(frame,so["channel_tag"])
        statement,_=parse_signed(frame[FRAME_BYTES:])
        verification=dict(payload=frame[:FRAME_BYTES], public_pem=self.client_public(),
                          expected_network=NETWORK, expected_context=statement.context,
                          expected_generation=9, expected_sequence=13, now=1000)
        verify_reference(frame[FRAME_BYTES:], expected_purpose=6, **verification)
        for purpose in range(1,6):
            with self.subTest(purpose=purpose):
                # A valid peer proof cannot be replayed as transaction, artifact,
                # evaluation, release or custody authority.
                with self.assertRaises(Reject):
                    verify_reference(frame[FRAME_BYTES:], expected_purpose=purpose,
                                     **verification)
                different=sign_reference(replace(statement,purpose=purpose),
                                         private_key_path=self.keys["client"][0])
                verify_reference(different,expected_purpose=purpose,**verification)
                with self.assertRaises(Reject):
                    self.inspect_hello(frame[:FRAME_BYTES]+different,so["channel_tag"])

    def test_noncanonical_pinned_peer_identity_rejects_before_connect(self):
        # 64 lower-case hex is required, not prefix-matched or silently truncated.
        q=subprocess.run([str(self.exe),"client","12345","x","y","z","Z"*64,
                           "server.local",NETWORK.hex(),GENESIS.hex(),PROFILE.hex(),
                           "X25519MLKEM768"],capture_output=True,text=True,timeout=5,
                          env=self.backend.environment)
        self.assertNotEqual(q.returncode,0)
        self.assertIn("REFUSED canonical identity",q.stderr)

if __name__=="__main__":unittest.main()
