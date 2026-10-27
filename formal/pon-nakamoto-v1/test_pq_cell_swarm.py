"""PCS1: 3 real localhost peer processes, real ML-DSA and hostile controls."""
from __future__ import annotations
from dataclasses import replace
import multiprocessing as mp
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest

from pq_envelope import Reject, public_key_id
from pq_cell_custody import (
    Challenge, catalog_from_chunks, catalog_id, chunk_proof,
    sign_response_fixture, verify_response_research,
)
from pq_cell_swarm import (
    Peer, FetchObservation, _request, _read_authenticated_chunk,
    content_id, fetch_to_immutable_file, serve_fixture,
)


class PQCellSwarmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="trnm-pcs1-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.pairs = []
        for i in range(3):
            secret = cls.root / f"peer-{i}.secret.pem"
            public = cls.root / f"peer-{i}.public.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65",
                            "-out", str(secret)], capture_output=True, check=True, timeout=15)
            subprocess.run(["openssl", "pkey", "-in", str(secret), "-pubout", "-out", str(public)],
                           capture_output=True, check=True, timeout=15)
            cls.pairs.append((secret, public.read_bytes()))
        cls.network = bytes(range(1, 33))
        cls.release = bytes(range(1, 49))
        cls.chunks = (b"a"*72, b"b"*72, b"c"*72, b"d"*72, b"e"*13)
        cls.whole = b"".join(cls.chunks)
        cls.catalog = catalog_from_chunks(cls.network, cls.release, 9, cls.chunks, 72)
        cls.ctx = mp.get_context("spawn")

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="pcs1-output-", dir=self.root)
        self.addCleanup(self.scratch.cleanup)
        self.output = Path(self.scratch.name) / "weights.bin"
        self.children = []
        self.addCleanup(self._cleanup_children)

    def _cleanup_children(self):
        for p in reversed(self.children):
            p.terminate()
            p.join(3)
            if p.is_alive():
                p.kill(); p.join(3)

    def start_peer(self, i, failure=None, *, chunks=None, catalog=None):
        parent, child = self.ctx.Pipe(duplex=False)
        c = self.catalog if catalog is None else catalog
        p = self.ctx.Process(target=serve_fixture,
                             args=(self.chunks if chunks is None else chunks, c.encode(),
                                   self.pairs[i][0], self.pairs[i][1], child),
                             kwargs=dict(failure=failure), daemon=True)
        p.start(); self.children.append(p); child.close()
        self.assertTrue(parent.poll(5), "provider process did not bind")
        port = parent.recv(); parent.close()
        self.assertTrue(port > 0, "provider process failed")
        return Peer("127.0.0.1", port, self.pairs[i][1], public_key_id(self.pairs[i][1]))

    def fetch(self, peers, **kwargs):
        args=dict(catalog_bytes=self.catalog.encode(),
                  expected_catalog_digest=catalog_id(self.catalog),
                  expected_release=self.release,
                  expected_content_id=content_id(self.whole),
                  requester_id=bytes([0x72])*32,
                  peers=peers, destination=self.output,
                  max_parallel=4, max_attempts_per_chunk=8)
        args.update(kwargs)
        return fetch_to_immutable_file(**args)

    def test_three_actual_processes_corrupt_supplier_fallback(self):
        honest_a=self.start_peer(0)
        corrupted=self.start_peer(1, failure="tamper")
        honest_b=self.start_peer(2)
        observed=self.fetch((honest_a, corrupted, honest_b))
        self.assertIsInstance(observed, FetchObservation)
        self.assertEqual(observed.catalog_digest, catalog_id(self.catalog))
        self.assertEqual(observed.content_digest, content_id(self.whole))
        self.assertEqual(observed.object_bytes, len(self.whole))
        self.assertEqual(observed.chunks_verified, len(self.chunks))
        self.assertEqual(observed.failed_attempts, 2)
        self.assertEqual(set(observed.provider_ids), {honest_a.expected_key_id, honest_b.expected_key_id})
        self.assertEqual(self.output.read_bytes(), self.whole)
        self.assertFalse(hasattr(observed,"custody_reward_authorized"))
        self.assertFalse(hasattr(observed,"model_adoption_authorized"))
        self.assertFalse(hasattr(observed,"final_use"))

    def test_two_honest_processes_sparse_download_reconstruction(self):
        a,b=self.start_peer(0), self.start_peer(1)
        observed=self.fetch((a,b), max_parallel=2)
        self.assertEqual(self.output.read_bytes(), self.whole)
        self.assertEqual(observed.failed_attempts, 0)
        self.assertEqual(len(observed.provider_ids), 2)

    def test_all_bad_providers_fail_closed_no_published_object(self):
        bad1=self.start_peer(0, failure="tamper")
        bad2=self.start_peer(1, failure="truncate")
        with self.assertRaises(Reject):
            self.fetch((bad1,bad2), max_attempts_per_chunk=2)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.output.parent.glob(".pcs1-incomplete-*")), [])

    def test_empty_provider_reply_fails_without_partial_publish(self):
        p=self.start_peer(0, failure="close")
        with self.assertRaises(Reject):
            self.fetch((p,), max_attempts_per_chunk=1)
        self.assertFalse(self.output.exists())

    def test_an_authentically_signed_alternate_model_is_not_our_model(self):
        fake_chunks=(b"z"*72, b"y"*72, b"x"*72, b"w"*72, b"q"*13)
        fake_catalog=catalog_from_chunks(self.network,self.release,9,fake_chunks,72)
        evil=self.start_peer(0,chunks=fake_chunks,catalog=fake_catalog)
        # Attacker's internally consistent signed alternate PCC1 is a different
        # release catalog, never the caller's authenticated expected catalog.
        with self.assertRaises(Reject):
            self.fetch((evil,), max_attempts_per_chunk=1)
        self.assertFalse(self.output.exists())
        with self.assertRaises(Reject):
            self.fetch((evil,), catalog_bytes=fake_catalog.encode())

    def test_signed_real_chunks_refused_against_wrong_authenticated_content_id(self):
        good=self.start_peer(0)
        with self.assertRaises(Reject):
            self.fetch((good,),expected_content_id=bytes([0xff])*48)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.output.parent.glob(".pcs1-incomplete-*")), [])

    def test_existing_immutable_destination_is_never_replaced(self):
        good=self.start_peer(0)
        self.output.write_bytes(b"existing authorized bytes")
        with self.assertRaises(Reject):
            self.fetch((good,))
        self.assertEqual(self.output.read_bytes(),b"existing authorized bytes")

    def test_symlink_destination_refuses_without_touching_target(self):
        good=self.start_peer(0)
        target=self.output.parent/"real.bin"
        target.write_bytes(b"sealed")
        self.output.symlink_to(target)
        with self.assertRaises(Reject):
            self.fetch((good,))
        self.assertEqual(target.read_bytes(),b"sealed")
        self.assertTrue(self.output.is_symlink())

    def test_pinned_public_key_and_loopback_literal_required(self):
        actual=self.start_peer(0)
        attacker_pub=self.pairs[1][1]
        with self.assertRaises(Reject):
            self.fetch((replace(actual, public_pem=attacker_pub),))
        for host in ("localhost","0.0.0.0","::1","192.168.1.2",""):
            with self.subTest(host=host), self.assertRaises(Reject):
                self.fetch((replace(actual, host=host),))
        for port in (0,65536,True,-1):
            with self.subTest(port=port), self.assertRaises(Reject):
                self.fetch((replace(actual, port=port),))
        self.assertFalse(self.output.exists())

    def test_replay_valid_signature_for_old_challenge_rejected(self):
        peer=self.start_peer(0)
        now=int(time.time()); me=bytes([4])*32
        q=Challenge(self.network,catalog_id(self.catalog),bytes([2])*32,me,
                    peer.expected_key_id,9,7,1,now,now+60)
        old=_request(peer,q)
        self.assertEqual(_read_authenticated_chunk(old,self.catalog,q,peer,now,me),self.chunks[1])
        new=replace(q,nonce=bytes([3])*32,sequence=8)
        with self.assertRaises(Reject):
            _read_authenticated_chunk(old,self.catalog,new,peer,now,me)

    def test_expired_signed_provider_reply_not_accepted(self):
        peer=self.start_peer(0)
        now=int(time.time()); me=bytes([4])*32
        q=Challenge(self.network,catalog_id(self.catalog),bytes([2])*32,me,
                    peer.expected_key_id,9,7,1,now-60,now)
        response=_request(peer,q)
        with self.assertRaises(Reject):
            _read_authenticated_chunk(response,self.catalog,q,peer,now+1,me)

    def test_catalog_release_network_identity_mismatches_rejected_before_download(self):
        peer=self.start_peer(0)
        for diff in (dict(expected_catalog_digest=bytes(48)),
                     dict(expected_release=bytes(48)),
                     dict(expected_content_id=bytes(12)),
                     dict(requester_id=bytes(32)),
                     dict(requester_id=b"noncanonical")):
            with self.subTest(diff=diff),self.assertRaises(Reject):
                self.fetch((peer,),**diff)
        self.assertFalse(self.output.exists())

    def test_strict_resource_limits_and_bool_types(self):
        peer=self.start_peer(0)
        tests=[dict(max_parallel=0),dict(max_parallel=5),dict(max_parallel=True),
               dict(max_attempts_per_chunk=0),dict(max_attempts_per_chunk=9),
               dict(max_attempts_per_chunk=True),
               dict(max_wall_seconds=0),dict(max_wall_seconds=301),dict(max_wall_seconds=True)]
        for opts in tests:
            with self.subTest(opts=opts),self.assertRaises(Reject):
                self.fetch((peer,),**opts)
        with self.assertRaises(Reject):
            self.fetch((peer,peer))
        with self.assertRaises(Reject):
            self.fetch(())
        with self.assertRaises(Reject):
            self.fetch(None)
        self.assertFalse(self.output.exists())

    def test_malformed_wire_prefix_refused_before_big_allocation(self):
        # Explicit attack fixture answers a real inbound challenge with absurd
        # framing, without receiving any model bytes or invoking PQ signing.
        listener=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1",0));listener.listen(1)
        port=listener.getsockname()[1]
        def one_server():
            try:
                conn,_=listener.accept()
                with conn:
                    conn.settimeout(2)
                    conn.recv(4096)
                    conn.sendall(struct.pack(">I", 0xffffffff))
            finally:
                listener.close()
        from threading import Thread
        t=Thread(target=one_server,daemon=True);t.start()
        pub=self.pairs[0][1]
        p=Peer("127.0.0.1",port,pub,public_key_id(pub))
        now=int(time.time());me=bytes([6])*32
        q=Challenge(self.network,catalog_id(self.catalog),bytes([1])*32,me,
                    p.expected_key_id,9,7,1,now,now+60)
        with self.assertRaises(Reject):
            _request(p,q)
        t.join(timeout=3)

    def test_caller_output_must_be_immutable_even_under_parallel_peer_processes(self):
        peer=self.start_peer(0)
        first=self.fetch((peer,))
        old=self.output.read_bytes()
        with self.assertRaises(Reject):
            self.fetch((peer,))
        self.assertEqual(self.output.read_bytes(),old)
        self.assertEqual(first.chunks_verified,5)


if __name__ == "__main__":
    unittest.main()
