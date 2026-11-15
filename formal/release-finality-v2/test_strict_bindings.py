"""Strict signed-byte regression controls using only public synthetic fixture keys.

The readers remain independent code paths. No production key, service, installation,
network finality or model-efficacy assertion is introduced by these controls.
"""
import copy
import unittest

import protocol as P
import verify_certificate as V
from test_protocol import Fixture, ordered


class StrictBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = Fixture()
        cls.bundle, cls.prepare_qc, cls.precommit_qc = cls.fixture.run()
        cls.keys = {P.key_id(key): key for key in cls.fixture.keys}

    @classmethod
    def tearDownClass(cls):
        cls.fixture.close()

    def both(self, bundle, accepted=False, committee=None, context=None):
        committee = self.fixture.m if committee is None else committee
        context = self.fixture.ctx if context is None else context
        readers = (
            ("protocol", lambda: P.verify_decision(bundle, context, committee)),
            ("separate", lambda: V.verify(P.canonical(bundle), P.canonical(committee),
                                         P.canonical(context))),
        )
        for name, reader in readers:
            with self.subTest(reader=name):
                if accepted:
                    result = reader()
                    self.assertTrue(result["finality_certificate_valid"])
                    for flag in ("model_quality_accepted", "long_term_availability_accepted",
                                 "hepta_final_use", "production_activation"):
                        self.assertIs(result[flag], False)
                else:
                    with self.assertRaises(ValueError):
                        reader()

    def resign(self, vote):
        return P.signature(self.keys[vote["signer"]], vote["body"])

    def test_valid_certificates_preserve_original_bytes_and_authority(self):
        before = P.canonical(self.bundle)
        self.both(self.bundle, accepted=True)
        self.assertEqual(before, P.canonical(self.bundle))

    def test_original_eight_vote_alias_counterexamples(self):
        for phase, aliases in (("commit", (True, 1.0)),
                               ("availability", (False, 0.0))):
            for alias in aliases:
                for resign in (False, True):
                    with self.subTest(phase=phase, alias=repr(alias), resigned=resign):
                        bundle = copy.deepcopy(self.bundle)
                        vote = bundle[phase]["votes"][0]
                        vote["body"]["view"] = alias
                        if resign:
                            bundle[phase]["votes"][0] = self.resign(vote)
                        self.both(bundle)

    def test_each_signer_rejects_signed_and_unsigned_type_aliases(self):
        for phase, alias in (("commit", True), ("availability", False)):
            for index in range(len(self.bundle[phase]["votes"])):
                for resign in (False, True):
                    with self.subTest(phase=phase, index=index, resigned=resign):
                        bundle = copy.deepcopy(self.bundle)
                        vote = bundle[phase]["votes"][index]
                        vote["body"]["view"] = alias
                        if resign:
                            bundle[phase]["votes"][index] = self.resign(vote)
                        self.both(bundle)

    def test_outer_certificate_view_types_cannot_replace_integer(self):
        for phase, aliases in (("commit", (True, 1.0, "1", None, -1, 2**63)),
                               ("availability", (False, 0.0, "0", None, -1, 2**63))):
            for alias in aliases:
                with self.subTest(phase=phase, alias=repr(alias)):
                    bundle = copy.deepcopy(self.bundle)
                    bundle[phase]["body"]["view"] = alias
                    self.both(bundle)

    def test_bundle_context_type_aliases_refuse(self):
        for field, aliases in (("epoch", (False, 0.0)), ("height", (True, 1.0))):
            for alias in aliases:
                with self.subTest(field=field, alias=repr(alias)):
                    bundle = copy.deepcopy(self.bundle)
                    bundle["context"][field] = alias
                    self.both(bundle)

    def test_context_validator_rejects_epoch_and_height_aliases(self):
        for field, aliases in (("epoch", (False, 0.0)), ("height", (True, 1.0))):
            for alias in aliases:
                with self.subTest(field=field, alias=repr(alias)):
                    ctx = copy.deepcopy(self.fixture.ctx)
                    ctx[field] = alias
                    with self.assertRaises(ValueError):
                        P.check_context(ctx, self.fixture.m)

    def test_manifest_numeric_fields_are_strict_even_with_valid_members(self):
        for field in ("epoch", "fault_bound", "quorum"):
            original = self.fixture.m[field]
            for alias in (bool(original), float(original)):
                with self.subTest(field=field, alias=repr(alias)):
                    members = copy.deepcopy(self.fixture.m)
                    members[field] = alias
                    self.both(self.bundle, committee=members)

    def test_signed_vote_shape_and_context_cannot_be_substituted(self):
        mutations = (("context", "f"*64), ("phase", "prepare"),
                     ("value", "f"*64), ("view", 2), ("extra", 1))
        for phase in ("availability", "commit"):
            for field, value in mutations:
                for resign in (False, True):
                    with self.subTest(phase=phase, field=field, resigned=resign):
                        bundle = copy.deepcopy(self.bundle)
                        vote = bundle[phase]["votes"][0]
                        vote["body"][field] = value
                        if resign:
                            bundle[phase]["votes"][0] = self.resign(vote)
                        self.both(bundle)

    def test_duplicate_signer_and_invalid_signature_remain_refused(self):
        for phase in ("availability", "commit"):
            bundle = copy.deepcopy(self.bundle)
            bundle[phase]["votes"][1] = copy.deepcopy(bundle[phase]["votes"][0])
            self.both(bundle)
            bundle = copy.deepcopy(self.bundle)
            bundle[phase]["votes"][0]["signature"] = "00"*64
            self.both(bundle)

    def test_new_view_report_types_refuse_even_when_resigned(self):
        with_fixture = Fixture()
        try:
            reports = ordered([node.new_view(1) for node in with_fixture.nodes])
            keys = {P.key_id(key): key for key in with_fixture.keys}
            for alias in (True, 1.0):
                changed = copy.deepcopy(reports)
                changed[0]["body"]["view"] = alias
                changed[0] = P.signature(keys[changed[0]["signer"]], changed[0]["body"])
                with self.subTest(alias=repr(alias)), self.assertRaises(ValueError):
                    P.high_qc(changed, with_fixture.ctx, with_fixture.m, 1)
        finally:
            with_fixture.close()

    def test_all_consensus_phases_reject_resigned_vote_aliases(self):
        for qc in (self.prepare_qc, self.precommit_qc, self.bundle["commit"],
                   self.bundle["availability"]):
            for alias in (bool(qc["body"]["view"]), float(qc["body"]["view"])):
                changed = copy.deepcopy(qc)
                changed["votes"][0]["body"]["view"] = alias
                changed["votes"][0] = self.resign(changed["votes"][0])
                with self.subTest(phase=qc["body"]["phase"], alias=repr(alias)):
                    with self.assertRaises(ValueError):
                        P.check_qc(changed, self.fixture.ctx, self.fixture.m)

    def test_signed_outbox_retry_uses_byte_identity(self):
        f = Fixture()
        try:
            f.run(decide=False)
            node = f.nodes[0]
            original = node.new_view(2)
            stored = node.db.execute("SELECT slot,value FROM outbox ORDER BY slot").fetchall()
            for alias in (True, 1.0):
                changed = copy.deepcopy(original["body"])
                changed["high"]["body"]["view"] = alias
                with self.subTest(alias=repr(alias)), self.assertRaises(ValueError):
                    node._write(node.state(), changed)
                self.assertEqual(stored, node.db.execute("SELECT slot,value FROM outbox ORDER BY slot").fetchall())
            self.assertEqual(P.canonical(original), P.canonical(node.new_view(2)))
        finally:
            f.close()

    def test_signed_statement_retention_and_committee_types_refuse(self):
        for alias in (True, 101.0, "101", -1, 2**63):
            bundle = copy.deepcopy(self.bundle)
            bundle["statement"]["retention_height"] = alias
            self.both(bundle)

    def test_decoders_reject_duplicate_keys_and_noncanonical_bytes(self):
        for raw in (b'{"view":1,"view":1}', b'{ "view":1}', b'{"view":NaN}'):
            for decoder in (P.decode, V.load):
                with self.subTest(raw=raw, decoder=decoder.__module__):
                    with self.assertRaises(ValueError):
                        decoder(raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
