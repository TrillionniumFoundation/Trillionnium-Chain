"""PCQ1/PCR1 real OpenSSL ML-DSA-65 retrieval byte and replay negatives."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import tempfile
import unittest

from pq_envelope import Reject, public_key_id, make_unsigned, sign_reference
from pq_cell_custody import (
    Catalog, Challenge, OfflineOneUseJournal, RetrievalObservation, _layers,
    catalog_from_chunks, catalog_id, chunk_proof, parse_catalog,
    parse_challenge, sign_response_fixture, verify_chunk, verify_response_research,
    MAX_CHALLENGE_TTL, MAX_CHUNK_BYTES, CatalogPinObservation, release_frame_id,
    sign_catalog_binding_fixture, verify_catalog_binding_research,
)


class PQCellCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="trnm-pq-custody-")
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        cls.key = root / "custodian.secret"
        cls.pub = root / "custodian.public"
        cls.wrong_key = root / "other.secret"
        cls.wrong_pub = root / "other.public"
        for sk, pk in ((cls.key, cls.pub), (cls.wrong_key, cls.wrong_pub)):
            subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65",
                            "-out", str(sk)], check=True, capture_output=True, timeout=15)
            subprocess.run(["openssl", "pkey", "-in", str(sk), "-pubout",
                            "-out", str(pk)], check=True, capture_output=True, timeout=15)
        cls.pub_pem = cls.pub.read_bytes()
        cls.provider = public_key_id(cls.pub_pem)
        cls.network = bytes(range(1, 33))
        cls.release = bytes(range(50, 98))
        cls.chunks = (b"a" * 32, b"b" * 32, b"c" * 17)
        cls.catalog = catalog_from_chunks(cls.network, cls.release, 9, cls.chunks, 32)
        cls.index = 2  # odd width's duplicated final leaf
        cls.path = chunk_proof(cls.chunks, cls.index)
        cls.challenge = Challenge(cls.network, catalog_id(cls.catalog), bytes([1])*32,
                                  bytes([2])*32, cls.provider, 9, 7, cls.index, 100, 200)
        cls.packet = sign_response_fixture(cls.catalog, cls.challenge, chunk=cls.chunks[cls.index],
                                           path=cls.path, public_pem=cls.pub_pem,
                                           private_key_path=cls.key, now=150)

    def check(self, packet=None, **override):
        opts = dict(catalog_bytes=self.catalog.encode(), challenge_bytes=self.challenge.encode(),
                    provider_public_pem=self.pub_pem, expected_release=self.release,
                    expected_catalog_digest=catalog_id(self.catalog),
                    expected_requester=self.challenge.requester_id,
                    expected_nonce=self.challenge.nonce, expected_provider_key_id=self.provider,
                    now=150)
        opts.update(override)
        return verify_response_research(self.packet if packet is None else packet, **opts)

    def test_real_ml_dsa_signed_valid_response_and_exact_merkle_path(self):
        result = self.check()
        self.assertIsInstance(result, RetrievalObservation)
        self.assertEqual(result.provider_key_id, self.provider)
        self.assertEqual(len(result.response_digest), 48)
        self.assertEqual(len(result.chunk_leaf), 48)
        self.assertEqual(parse_catalog(self.catalog.encode()), self.catalog)
        self.assertEqual(parse_challenge(self.challenge.encode()), self.challenge)
        self.assertEqual(verify_chunk(self.catalog, self.index, self.chunks[self.index], self.path), result.chunk_leaf)
        self.assertFalse(hasattr(result, "storage_reward_authorized"))
        self.assertFalse(hasattr(result, "final_use_authorized"))

    def test_every_challenge_byte_change_is_refused(self):
        original = self.challenge.encode()
        for i in range(len(original)):
            mutated = bytearray(original)
            mutated[i] ^= 1
            with self.subTest(position=i), self.assertRaises(Reject):
                self.check(challenge_bytes=bytes(mutated))

    def test_signed_response_changed_chunk_merkle_and_signature_reject(self):
        for i in range(len(self.chunks[self.index])):
            altered = bytearray(self.packet)
            altered[12+i] ^= 1
            with self.subTest(chunk_offset=i), self.assertRaises(Reject):
                self.check(bytes(altered))
        # Path starts immediately after chunk, depth and proof start after one byte.
        merkle_off = 12+len(self.chunks[self.index])+1
        altered = bytearray(self.packet)
        altered[merkle_off] ^= 1
        with self.assertRaises(Reject):
            self.check(bytes(altered))
        altered = bytearray(self.packet)
        altered[-1] ^= 1
        with self.assertRaises(Reject):
            self.check(bytes(altered))

    def test_missing_trailing_and_framing_reject(self):
        for raw in (self.packet[:20], self.packet[:-1], self.packet+b"x",
                    b"PXR1"+self.packet[4:],
                    self.packet[:8] + b"\xff\xff\xff\xff" + self.packet[12:],
                    self.packet[:8] + b"\x00\x00\x00\x00" + self.packet[12:],
                    self.packet[:12+len(self.chunks[self.index])] + b"\x00" + self.packet[13+len(self.chunks[self.index]):]):
            with self.subTest(size=len(raw)), self.assertRaises(Reject):
                self.check(raw)

    def test_odd_merkle_duplicate_last_cannot_be_fake_sibling(self):
        self.assertEqual(self.path[0], _layers(self.chunks)[0][2])
        fake = (bytes(48), *self.path[1:])
        with self.assertRaises(Reject):
            verify_chunk(self.catalog, self.index, self.chunks[self.index], fake)
        with self.assertRaises(Reject):
            verify_chunk(self.catalog, self.index, self.chunks[self.index], self.path[:-1])
        with self.assertRaises(Reject):
            verify_chunk(self.catalog, self.index, self.chunks[self.index], self.path+(self.path[0],))

    def test_different_network_release_generation_requester_provider_and_nonce_reject(self):
        changes = (
            {"expected_release": bytes([4])*48},
            {"expected_requester": bytes([4])*32},
            {"expected_nonce": bytes([4])*32},
            {"expected_provider_key_id": bytes([4])*32},
            {"provider_public_pem": self.wrong_pub.read_bytes()},
            {"now": 99}, {"now": 201},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(Reject):
                self.check(**change)
        changed_generation = replace(self.catalog, generation=10).encode()
        with self.assertRaises(Reject):
            self.check(catalog_bytes=changed_generation)
        changed_release = replace(self.catalog, release_manifest=bytes([4])*48).encode()
        with self.assertRaises(Reject):
            self.check(catalog_bytes=changed_release)
        with self.assertRaises(Reject):
            self.check(expected_catalog_digest=bytes([5])*48)

    def test_self_consistent_alternate_catalog_not_accepted_under_original_release(self):
        # A provider may sign an entirely different valid Merkle tree with the
        # same public release ID. The caller MUST pin the separate catalog root.
        chunks = (b"d"*32, b"e"*32, b"f"*17)
        swapped = catalog_from_chunks(self.network, self.release, 9, chunks, 32)
        changed_q = replace(self.challenge, catalog_digest=catalog_id(swapped))
        signed = sign_response_fixture(swapped, changed_q, chunk=chunks[2],
                                       path=chunk_proof(chunks,2), public_pem=self.pub_pem,
                                       private_key_path=self.key, now=150)
        with self.assertRaises(Reject):
            self.check(signed, catalog_bytes=swapped.encode(), challenge_bytes=changed_q.encode())

    def test_wrong_purpose_and_wrong_actual_signing_key_reject(self):
        # A real ML-DSA signature from another key is not accepted for advertised key.
        with self.assertRaises(Reject):
            sign_response_fixture(self.catalog, self.challenge, chunk=self.chunks[self.index],
                                  path=self.path, public_pem=self.wrong_pub.read_bytes(),
                                  private_key_path=self.wrong_key, now=150)
        packet = sign_response_fixture(self.catalog, self.challenge,
                                       chunk=self.chunks[self.index], path=self.path,
                                       public_pem=self.pub_pem, private_key_path=self.wrong_key, now=150)
        with self.assertRaises(Reject):
            self.check(packet)

    def test_malformed_types_dimensions_and_oversized_chunk_reject(self):
        for change in ({"chunk_count": 0}, {"chunk_count": True},
                       {"chunk_size": MAX_CHUNK_BYTES+1}, {"total_bytes": 0},
                       {"generation": False}, {"root": bytes(48)},
                       {"total_bytes": 500}):
            with self.subTest(change=change), self.assertRaises(Reject):
                replace(self.catalog, **change).encode()
        with self.assertRaises(Reject):
            catalog_from_chunks(self.network, self.release, 9, (bytes(33),), 32)
        with self.assertRaises(Reject):
            catalog_from_chunks(self.network, self.release, 9, (bytes(32), bytes(17), bytes(32)), 32)
        with self.assertRaises(Reject):
            replace(self.challenge, expires_at=100+MAX_CHALLENGE_TTL+1).encode()
        with self.assertRaises(Reject):
            replace(self.challenge, chunk_index=True).encode()
        with self.assertRaises(Reject):
            replace(self.challenge, nonce=bytes(32)).encode()
        with self.assertRaises(Reject):
            self.check(now=True)

    def test_even_four_and_single_chunk_complete_paths(self):
        for data in ((b"x"*16,), (b"x"*16,b"y"*16),
                     (b"x"*16,b"y"*16,b"z"*16,b"w"*5)):
            cat = catalog_from_chunks(self.network, self.release, 9, data, 16)
            for i, chunk in enumerate(data):
                with self.subTest(total=len(data), index=i):
                    self.assertEqual(verify_chunk(cat,i,chunk,chunk_proof(data,i)), _layers(data)[0][i])

    def test_release_key_signed_catalog_pin_chains_into_retrieval(self):
        # Caller accepts this release frame identity ONLY after independent PCB1
        # release/reviewer validation. Local fixture verifies the separate signer.
        unsigned = make_unsigned(purpose=4, network=self.network,
                                 context=bytes([7])*32, signer_key_id=self.provider,
                                 owner_generation=9, operation_sequence=7,
                                 expires_at=200, payload=b"already-reviewed-PCB1-release-fixture")
        release_frame = sign_reference(unsigned, private_key_path=self.key)
        prev = bytes(48)
        binding = sign_catalog_binding_fixture(self.catalog, release_frame=release_frame,
                                               previous_head=prev, signer_public_pem=self.pub_pem,
                                               signer_private_path=self.key, sequence=7,
                                               expires_at=200)
        args = dict(release_frame=release_frame, binding_frame=binding,
                    signer_public_pem=self.pub_pem,
                    expected_release_frame_id=release_frame_id(release_frame),
                    expected_signer_key_id=self.provider,
                    expected_previous_head=prev, expected_network=self.network,
                    expected_release_manifest=self.release,
                    expected_generation=9, expected_sequence=7, now=150)
        obs = verify_catalog_binding_research(self.catalog.encode(), **args)
        self.assertIsInstance(obs, CatalogPinObservation)
        self.assertEqual(obs.catalog_digest, catalog_id(self.catalog))
        self.assertEqual(self.check(expected_catalog_digest=obs.catalog_digest).provider_key_id, self.provider)
        self.assertFalse(hasattr(obs, "adoption_authorized"))
        for change in (dict(expected_release_frame_id=bytes([9])*48),
                       dict(expected_signer_key_id=bytes([8])*32),
                       dict(expected_previous_head=bytes([8])*48),
                       dict(expected_generation=8), dict(expected_sequence=8),
                       dict(now=201), dict(signer_public_pem=self.wrong_pub.read_bytes())):
            with self.subTest(change=change), self.assertRaises(Reject):
                verify_catalog_binding_research(self.catalog.encode(), **(args | change))
        altered = bytearray(binding)
        altered[-1] ^= 1
        with self.assertRaises(Reject):
            verify_catalog_binding_research(self.catalog.encode(), **(args | {"binding_frame": bytes(altered)}))
        # Even a signer-originated different catalog needs its OWN attestation,
        # and cannot replace this signed original merely by sharing release ID.
        different = catalog_from_chunks(self.network,self.release,9,(b"f"*32,b"g"*32,b"h"*17),32)
        with self.assertRaises(Reject):
            verify_catalog_binding_research(different.encode(), **args)

    def test_catalog_binding_requires_real_release_purpose(self):
        other = make_unsigned(purpose=1, network=self.network, context=bytes(32),
                              signer_key_id=self.provider, owner_generation=9,
                              operation_sequence=7, expires_at=200, payload=b"not release")
        fake_release = sign_reference(other, private_key_path=self.key)
        with self.assertRaises(Reject):
            release_frame_id(fake_release)
        with self.assertRaises(Reject):
            sign_catalog_binding_fixture(self.catalog, release_frame=fake_release,
                                         previous_head=bytes(48), signer_public_pem=self.pub_pem,
                                         signer_private_path=self.key, sequence=7, expires_at=200)

    def test_journal_first_exact_retry_and_cold_reopen(self):
        db_path = Path(self.temp.name)/"one-use.db"
        with_journal = OfflineOneUseJournal(db_path)
        args = dict(catalog_bytes=self.catalog.encode(), challenge_bytes=self.challenge.encode(),
                    provider_public_pem=self.pub_pem, expected_release=self.release,
                    expected_catalog_digest=catalog_id(self.catalog),
                    expected_requester=self.challenge.requester_id,
                    expected_nonce=self.challenge.nonce, expected_provider_key_id=self.provider,
                    now=150)
        try:
            self.assertEqual(with_journal.record(self.packet,**args)[0], "FIRST_RECORD")
            self.assertEqual(with_journal.record(self.packet,**args)[0], "ALREADY_RECORDED")
        finally:
            with_journal.close()
        with_journal = OfflineOneUseJournal(db_path)
        try:
            self.assertEqual(with_journal.record(self.packet,**args)[0], "ALREADY_RECORDED")
        finally:
            with_journal.close()

    def test_journal_foreign_schema_trigger_and_downgrade_reject(self):
        import sqlite3
        for kind in ("foreign", "trigger", "weakened"):
            db = Path(self.temp.name)/(kind + ".db")
            init = OfflineOneUseJournal(db)
            init.close()
            conn = sqlite3.connect(str(db))
            if kind == "foreign":
                conn.execute("CREATE TABLE attacker (id INT)")
            elif kind == "trigger":
                conn.execute("CREATE TRIGGER trnm_forged AFTER INSERT ON pq_custody_observation BEGIN DELETE FROM pq_custody_observation; END")
            else:
                conn.execute("DROP TABLE pq_custody_observation")
                conn.execute("CREATE TABLE pq_custody_observation (challenge_id BLOB PRIMARY KEY, response_digest BLOB, provider_key_id BLOB)")
            conn.commit()
            conn.close()
            with self.subTest(kind=kind), self.assertRaises(Reject):
                OfflineOneUseJournal(db)

    def test_journal_concurrent_distinct_sqlite_connections_one_first_only(self):
        db = Path(self.temp.name)/"concurrent.db"
        initializer = OfflineOneUseJournal(db)
        initializer.close()
        args = dict(catalog_bytes=self.catalog.encode(), challenge_bytes=self.challenge.encode(),
                    provider_public_pem=self.pub_pem, expected_release=self.release,
                    expected_catalog_digest=catalog_id(self.catalog),
                    expected_requester=self.challenge.requester_id,
                    expected_nonce=self.challenge.nonce, expected_provider_key_id=self.provider,
                    now=150)
        def work(_):
            j = OfflineOneUseJournal(db)
            try:
                return j.record(self.packet,**args)[0]
            finally:
                j.close()
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(work, range(8)))
        self.assertEqual(outcomes.count("FIRST_RECORD"), 1)
        self.assertEqual(outcomes.count("ALREADY_RECORDED"), 7)


if __name__ == "__main__":
    unittest.main()
