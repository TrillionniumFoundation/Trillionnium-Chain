"""Finite PUBLIC-fixture relation tests, not proof or migration qualification.

RFC public keys calibrate the independent integer reference. A mandatory
cryptography backend cross-checks all nineteen fixtures. Mutants distinguish
the original seed relation from scalar/expanded-key substitution and bind hx to
the complete existing research statement. No user key, proof or ledger is used.
"""
import builtins
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import io
import json
import unittest
from unittest.mock import patch

import pq_seed_recovery_v1 as recovery
import pq_seed_relation_vectors_v1 as relation


class PublicSeedRelationVectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This is deliberately mandatory: no skip if cryptography is absent.
        cls.vectors = relation.reproduce_public_vectors()
        cls.by_name = {vector.name: vector for vector in cls.vectors}

    def test_finite_public_catalogue_and_exact_label_derivation(self):
        names = relation.vector_names()
        self.assertEqual(names[:3], (
            "rfc8032-test-1", "rfc8032-test-2", "rfc8032-test-3",
        ))
        self.assertEqual(names[3:], tuple(f"synthetic-{index:02d}" for index in range(16)))
        self.assertEqual(len(set(vector.public_key for vector in self.vectors)), 19)
        self.assertEqual(len(set(vector.hx for vector in self.vectors)), 19)
        for name in names[3:]:
            with self.subTest(name=name):
                seed = hashlib.sha512(
                    b"TRNM/PoN/PublicSyntheticSeed/v1\x00" + name.encode("ascii"),
                ).digest()[:32]
                self.assertEqual(relation._fixture(name).seed, seed)
                self.assertEqual(
                    relation._reference_public_key(seed), self.by_name[name].public_key,
                )

    def test_published_rfc8032_public_keys_calibrate_both_implementations(self):
        expected = (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        )
        for index, key in enumerate(expected, start=1):
            name = f"rfc8032-test-{index}"
            fixture, vector = relation._fixture(name), self.by_name[name]
            with self.subTest(name=name):
                self.assertEqual(vector.public_key.hex(), key)
                backend_key, digest, hx = relation._backend_material(
                    fixture.seed, vector.public_message,
                )
                self.assertEqual(backend_key.hex(), key)
                self.assertEqual(digest, hashlib.sha512(fixture.seed).digest())
                self.assertEqual(hx, vector.hx)

    def test_first_rfc_expansion_pruning_and_bound_message_are_fixed(self):
        seed = relation._fixture("rfc8032-test-1").seed
        expansion, scalar = relation._expand_seed(seed)
        self.assertEqual(expansion.hex(),
                         "357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f"
                         "9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f")
        self.assertEqual(scalar.hex(),
                         "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f")
        vector = self.by_name["rfc8032-test-1"]
        self.assertEqual(vector.public_message.hex(),
                         "6f337afd41358b6e0e956bd690a9451ba0fbd2572af5ff296fd7328760e9203c")
        self.assertEqual(vector.hx.hex(),
                         "0a32d17ef8737a4990f5a0417d3f697646584ae1f0dbf42fbc3b3bb66c380934"
                         "2fc1d0f15e522b1ee3cfad75900975384e42e6ae0993a5f67922d5e063b38268")
        self.assertEqual(vector.statement_sha256.hex(),
                         "9e4d350330564f78faa92bc1d01a27895515e1f083c6589a0ff9cfd2a65fe636")

    def test_reference_group_calibration_and_subgroup_order(self):
        self.assertEqual(
            relation._encode_point(relation._multiply_base(1)).hex(), "58" + "66" * 31,
        )
        identity = b"\x01" + bytes(31)
        for scalar in (0, relation._L, relation._L * 2, relation._L * 7):
            with self.subTest(scalar=scalar):
                self.assertEqual(
                    relation._encode_point(relation._multiply_base(scalar)), identity,
                )
        for vector in self.vectors:
            seed = relation._fixture(vector.name).seed
            _, scalar = relation._expand_seed(seed)
            point = relation._multiply_base(int.from_bytes(scalar, "little"))
            x, y, z, t = point
            with self.subTest(name=vector.name):
                self.assertEqual((x * y - z * t) % relation._P, 0)
                self.assertEqual(
                    ((y * y - x * x) * z * z - z ** 4 - relation._D * x * x * y * y)
                    % relation._P, 0,
                )

    def test_all_mutable_statement_bindings_change_message_and_hx(self):
        name = "synthetic-00"
        original = relation.public_statement(name)
        baseline = self.by_name[name]
        changes = {
            "network": b"N" * 32, "genesis": b"G" * 32,
            "crypto_profile_id": b"P" * 32, "account_id": b"A" * 32,
            "source_snapshot_root": b"S" * 32, "migration_root": b"M" * 32,
            "new_pq_public_key": b"K" * 1952,
            "circuit_artifact_sha256": b"C" * 32,
            "verifier_artifact_sha256": b"V" * 32,
            "account_generation": 8, "operation_nonce": 12,
            "not_before": 101, "expires_at": 201, "recovery_state": "frozen",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = replace(original, **{field: value})
                vector = relation.reproduce_public_vector(name, statement=changed)
                self.assertEqual(vector.public_key, baseline.public_key)
                self.assertNotEqual(vector.public_message, baseline.public_message)
                self.assertNotEqual(vector.hx, baseline.hx)
                self.assertNotEqual(vector.statement_sha256, baseline.statement_sha256)
        # old_public_key also affects the V1 message, but must satisfy the seed
        # relation, unlike a context field that can be independently varied.
        changed = replace(original, old_public_key=self.by_name["synthetic-01"].public_key)
        self.assertNotEqual(
            hashlib.sha256(recovery.MESSAGE_DOMAIN + changed.encode()).digest(),
            baseline.public_message,
        )
        with self.assertRaisesRegex(relation.ReproductionError, "declared old key"):
            relation.reproduce_public_vector(name, statement=changed)

    def test_unqualified_profiles_and_source_pins_are_not_silently_replaced(self):
        name = "synthetic-00"
        original = relation.public_statement(name)
        for field in ("purpose", "message_hash_profile", "proof_profile", "derivation_profile",
                      "pq_algorithm", "source_commit"):
            with self.subTest(field=field), self.assertRaises(recovery.Reject):
                relation.reproduce_public_vector(name, statement=replace(
                    original, **{field: "unsupported"},
                ))
        for field in ("circuit_source_sha256", "verifier_source_sha256",
                      "parameter_source_sha256", "parameter_profile_sha256"):
            with self.subTest(field=field), self.assertRaises(recovery.Reject):
                relation.reproduce_public_vector(name, statement=replace(
                    original, **{field: b"z" * 32},
                ))
        self.assertEqual(original.derivation_profile, "rfc8032-ed25519-seed32-v1")
        self.assertEqual(original.source_commit, "598cdff516c3086487a173d7d9f9af2830e04a32")

    def test_wrong_hash_half_and_scalar_endianness_fail_the_known_relation(self):
        for vector in self.vectors:
            seed = relation._fixture(vector.name).seed
            digest, correct_scalar = relation._expand_seed(seed)
            second_half = bytearray(digest[32:])
            second_half[0] &= 248
            second_half[31] &= 127
            second_half[31] |= 64
            mutants = {
                "second-hash-half": int.from_bytes(second_half, "little"),
                "big-endian-scalar": int.from_bytes(correct_scalar, "big"),
            }
            for mutation, scalar in mutants.items():
                with self.subTest(name=vector.name, mutation=mutation):
                    self.assertNotEqual(
                        relation._encode_point(relation._multiply_base(scalar)),
                        vector.public_key,
                    )

    def test_omitted_pruning_has_effective_mutants_and_explicit_no_op_controls(self):
        unchanged, changed = [], []
        for vector in self.vectors:
            digest, scalar = relation._expand_seed(relation._fixture(vector.name).seed)
            unpruned_key = relation._encode_point(
                relation._multiply_base(int.from_bytes(digest[:32], "little")),
            )
            with self.subTest(name=vector.name):
                if digest[:32] == scalar:
                    # Pruning is a no-op for these public fixtures. Requiring a
                    # different key would be an invalid negative-control claim.
                    unchanged.append(vector.name)
                    self.assertEqual(unpruned_key, vector.public_key)
                else:
                    changed.append(vector.name)
                    self.assertNotEqual(unpruned_key, vector.public_key)
        self.assertEqual(unchanged, ["synthetic-02", "synthetic-14"])
        self.assertEqual(len(changed), 17)

    def test_each_required_pruning_bit_and_point_encoding_has_a_negative_control(self):
        positive_x, negative_x = 0, 0
        for vector in self.vectors:
            seed = relation._fixture(vector.name).seed
            _, scalar_bytes = relation._expand_seed(seed)
            scalar = int.from_bytes(scalar_bytes, "little")
            mutants = (
                scalar | 1, scalar | 2, scalar | 4,
                scalar | (1 << 255), scalar & ~(1 << 254),
            )
            for index, mutant in enumerate(mutants):
                with self.subTest(name=vector.name, pruning_bit=index):
                    self.assertNotEqual(
                        relation._encode_point(relation._multiply_base(mutant)),
                        vector.public_key,
                    )
            # Independently form incorrect point encodings from affine coords.
            x, y, z, _ = relation._multiply_base(scalar)
            inverse = pow(z, relation._P - 2, relation._P)
            x, y = x * inverse % relation._P, y * inverse % relation._P
            with self.subTest(name=vector.name, encoding=True):
                self.assertNotEqual(
                    (y | ((x & 1) << 255)).to_bytes(32, "big"), vector.public_key,
                )
                if x & 1:
                    negative_x += 1
                    self.assertNotEqual(y.to_bytes(32, "little"), vector.public_key)
                else:
                    positive_x += 1
                    self.assertEqual(y.to_bytes(32, "little"), vector.public_key)
        self.assertGreater(positive_x, 0)
        self.assertGreater(negative_x, 0)

    def test_recovered_residue_lifts_to_the_unique_clamped_scalar_on_every_fixture(self):
        self.assertEqual(relation.CLAMPED_SCALAR_FREE_BITS, 251)
        self.assertEqual(
            (relation._CLAMPED_MAX - relation._CLAMPED_MIN) // 8 + 1, 1 << 251,
        )
        self.assertLess(1 << 251, relation._L)
        self.assertEqual(relation._L % 2, 1)
        for vector in self.vectors:
            _, encoded = relation._expand_seed(relation._fixture(vector.name).seed)
            scalar = int.from_bytes(encoded, "little")
            residue = scalar % relation._L
            with self.subTest(name=vector.name):
                self.assertEqual(relation._recover_clamped_scalar(residue), scalar)
                representatives = [
                    residue + index * relation._L for index in range(8)
                    if relation._CLAMPED_MIN <= residue + index * relation._L
                    <= relation._CLAMPED_MAX
                    and (residue + index * relation._L) % 8 == 0
                ]
                self.assertEqual(representatives, [scalar])
                self.assertEqual(
                    relation._encode_point(relation._multiply_base(residue)), vector.public_key,
                )

    def test_clamped_scalar_boundary_and_absent_representatives(self):
        for scalar in (1 << 254, (1 << 254) + 8, (1 << 255) - 16, (1 << 255) - 8):
            with self.subTest(scalar=scalar):
                self.assertEqual(relation._recover_clamped_scalar(scalar % relation._L), scalar)
        # Enumerate both ends of the canonical residue space independently.
        absent = present = 0
        for residue in tuple(range(64)) + tuple(range(relation._L - 64, relation._L)):
            candidates = [
                residue + multiple * relation._L for multiple in range(8)
                if (1 << 254) <= residue + multiple * relation._L < (1 << 255)
                and (residue + multiple * relation._L) % 8 == 0
            ]
            self.assertLessEqual(len(candidates), 1)
            expected = candidates[0] if candidates else None
            self.assertEqual(relation._recover_clamped_scalar(residue), expected)
            absent += not candidates
            present += bool(candidates)
        self.assertGreater(absent, 0)
        self.assertGreater(present, 0)
        self.assertIsNone(relation._recover_clamped_scalar(0))
        for invalid in (-1, relation._L, relation._L + 1, 1 << 256,
                        True, False, 0.0, "0", bytes(32), None):
            with self.subTest(type=type(invalid).__name__), self.assertRaisesRegex(
                relation.ReproductionError, "canonical public scalar residue",
            ):
                relation._recover_clamped_scalar(invalid)

    def test_scalar_only_substitution_does_not_reproduce_the_seed_relation(self):
        for vector in self.vectors:
            seed = relation._fixture(vector.name).seed
            _, scalar_bytes = relation._expand_seed(seed)
            residue = int.from_bytes(scalar_bytes, "little") % relation._L
            for replacement in (scalar_bytes, residue.to_bytes(32, "little")):
                with self.subTest(name=vector.name):
                    self.assertNotEqual(replacement, seed)
                    self.assertNotEqual(relation._reference_public_key(replacement), vector.public_key)
                    self.assertNotEqual(
                        relation._reference_hx(replacement, vector.public_message), vector.hx,
                    )
        # This finite test distinguishes formats; it is not a seed-preimage
        # hardness proof or a demonstration that scalar theft can be repaired.

    def test_expanded_secret_and_wallet64_are_rejected_without_auto_truncation(self):
        for vector in self.vectors:
            seed = relation._fixture(vector.name).seed
            expansion, scalar = relation._expand_seed(seed)
            for value in (expansion, scalar + expansion[32:], seed + vector.public_key):
                with self.subTest(name=vector.name, length=len(value)):
                    with self.assertRaisesRegex(relation.ReproductionError, "no format conversion"):
                        relation._reference_public_key(value)
                    with self.assertRaisesRegex(relation.ReproductionError, "no format conversion"):
                        relation._reference_hx(value, vector.public_message)
            # Selecting either 32-byte expanded half also changes the relation.
            for half in (expansion[:32], expansion[32:]):
                with self.subTest(name=vector.name, expanded_half=True):
                    self.assertNotEqual(relation._reference_public_key(half), vector.public_key)
                    self.assertNotEqual(relation._reference_hx(half, vector.public_message), vector.hx)

    def test_hx_order_and_seed_material_are_exact_not_an_independent_owner_constraint(self):
        for vector in self.vectors:
            seed = relation._fixture(vector.name).seed
            expansion, scalar = relation._expand_seed(seed)
            message = vector.public_message
            variants = (
                seed + message, message + scalar, message + expansion,
                message + expansion[32:], message + vector.public_key,
            )
            for value in variants:
                with self.subTest(name=vector.name):
                    self.assertNotEqual(hashlib.sha512(value).digest(), vector.hx)
            # Anyone knowing this PUBLIC fixture can select hx for any new
            # message. Matching an untrusted hx alone supplies no ownership.
            new_message = bytes([message[0] ^ 1]) + message[1:]
            chosen_hx = hashlib.sha512(new_message + seed).digest()
            self.assertEqual(relation._reference_hx(seed, new_message), chosen_hx)
            self.assertNotEqual(chosen_hx, vector.hx)

    def test_byte_shapes_are_strict_and_diagnostics_do_not_echo_input(self):
        seed = relation._fixture("rfc8032-test-1").seed
        message = self.by_name["rfc8032-test-1"].public_message
        marker = "not-a-wallet-secret-test-sentinel"
        for value in (b"", seed[:-1], seed + b"\x00", bytearray(seed),
                      memoryview(seed), marker, None):
            with self.subTest(type=type(value).__name__):
                with self.assertRaises(relation.ReproductionError) as raised:
                    relation._reference_public_key(value)
                self.assertNotIn(marker, str(raised.exception))
        for invalid in (b"", message[:-1], message + b"\x00", bytearray(message), None):
            with self.subTest(type=type(invalid).__name__), self.assertRaises(
                relation.ReproductionError,
            ):
                relation._reference_hx(seed, invalid)
        for invalid in (True, -1, 1 << 256, 1.0):
            with self.subTest(scalar_type=type(invalid).__name__), self.assertRaises(
                relation.ReproductionError,
            ):
                relation._multiply_base(invalid)

    def test_public_entry_points_never_accept_seed_bytes_or_open_label_space(self):
        marker = "not-a-wallet-secret-test-sentinel"
        seed = relation._fixture("rfc8032-test-1").seed
        for value in (seed, seed.hex(), seed + self.vectors[0].public_key, bytearray(seed),
                      "synthetic-16", "synthetic-999999", marker, {"seed": marker}, None, True):
            for function in (relation.public_statement, relation.reproduce_public_vector):
                with self.subTest(function=function.__name__, type=type(value).__name__):
                    with self.assertRaises(relation.ReproductionError) as raised:
                        function(value)
                    self.assertNotIn(marker, str(raised.exception))

    def test_backend_missing_or_unsupported_is_an_explicit_failure(self):
        real_import = builtins.__import__

        def without_backend(name, *args, **kwargs):
            if name.startswith("cryptography"):
                raise ImportError("simulated unavailable dependency")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=without_backend):
            with self.assertRaisesRegex(relation.ReproductionError, "backend required"):
                relation.reproduce_public_vector("synthetic-00")
        from cryptography.exceptions import UnsupportedAlgorithm
        with patch(
            "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes",
            side_effect=UnsupportedAlgorithm("test backend failure"),
        ):
            with self.assertRaisesRegex(relation.ReproductionError, "cannot reproduce"):
                relation.reproduce_public_vector("synthetic-00")

    def test_each_backend_disagreement_fails_without_a_reference_only_result(self):
        name = "synthetic-00"
        seed = relation._fixture(name).seed
        vector = self.by_name[name]
        material = relation._backend_material(seed, vector.public_message)
        for index in range(3):
            changed = list(material)
            changed[index] = bytes([changed[index][0] ^ 1]) + changed[index][1:]
            with self.subTest(component=index), patch.object(
                relation, "_backend_material", return_value=tuple(changed),
            ), self.assertRaisesRegex(relation.ReproductionError, "reference/backend mismatch"):
                relation.reproduce_public_vector(name)

    def test_vector_remains_a_non_authoritative_immutable_observation(self):
        for vector in self.vectors:
            self.assertEqual(vector.status, "PUBLIC_FIXTURE_RELATION_ONLY_NO_PROOF_OR_AUTHORITY")
            self.assertNotIn("seed", {item.name for item in fields(vector)})
            self.assertFalse(any(hasattr(vector, name) for name in (
                "verified", "authorized", "proof", "signature", "consume_nonce",
            )))
            with self.assertRaises(TypeError):
                bool(vector)
            with self.assertRaises(FrozenInstanceError):
                vector.status = "VERIFIED"
            with self.assertRaises(ValueError):
                replace(vector, status="VERIFIED")

    def test_cli_accepts_no_arguments_or_stdin_and_emits_only_public_vectors(self):
        class UnreadableStdin:
            def read(self, *_args, **_kwargs):
                raise AssertionError("stdin must not be read")

            def readline(self, *_args, **_kwargs):
                raise AssertionError("stdin must not be read")

        out, err = io.StringIO(), io.StringIO()
        with patch("sys.stdin", UnreadableStdin()), redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(relation.main([]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(report["profile"], "trnm-public-seed-relation-vectors-v1")
        self.assertEqual(report["status"], relation.RESEARCH_STATUS)
        self.assertEqual((report["rfc8032_vectors"], report["synthetic_vectors"]), (3, 16))
        self.assertEqual(report["clamped_scalar_free_bits"], 251)
        self.assertEqual(len(report["vectors"]), 19)
        for fixture in relation._FIXTURES:
            self.assertNotIn(fixture.seed.hex(), out.getvalue())
        marker = "not-a-wallet-secret-test-sentinel"
        out, err = io.StringIO(), io.StringIO()
        with patch.object(relation, "reproduce_public_vectors") as run, \
                redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(relation.main(["--seed", marker]), 2)
        run.assert_not_called()
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn(marker, err.getvalue())

    def test_cli_fails_closed_when_required_reproduction_fails(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(
            relation, "reproduce_public_vectors", side_effect=relation.ReproductionError("test"),
        ), redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(relation.main([]), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("reproduction failed", err.getvalue())


if __name__ == "__main__":
    unittest.main()
