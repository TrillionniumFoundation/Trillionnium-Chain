#!/usr/bin/env python3
"""Real signatures and real SQLite crash/replay/reorg controls; no live effects.

All signing roles here share one test machine. The complete owner+anchor rollback
counterexample is deliberately retained: local separation cannot prove custody
or independently retained currentness. No native crypto test is skipped.
"""
import copy
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest

import pq_openssl_backend as backend
from pq_operation_budget import OperationBudget
import pq_root_recovery_policy_v1 as model
import pq_root_recovery_signatures_v2 as signatures
import pq_root_recovery_journal_v2 as journal
import pq_root_effect_readback_v2 as readback
from test_pq_root_recovery_signatures_native_v2 import NativeFixture


def budget():
    return OperationBudget(time.monotonic() + 120)


class NativeAnchor:
    """Separate durable file, real writer and response signatures, no WAN claim."""
    def __init__(self, path, fixture, anchor_policy, writer_policy, writer_keys):
        self.path, self.fixture, self.policy = path, fixture, anchor_policy
        self.writer_policy, self.writer_keys = writer_policy, writer_keys
        self.fault = None
        self.saved_response = None
        self.cas_count = 0
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE heads(scope TEXT PRIMARY KEY, version INTEGER NOT NULL, root TEXT NOT NULL)")

    def enroll(self, scope, head):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO heads VALUES(?,?,?)", (scope, int(head["version"]), head["root"]))

    def __call__(self, envelope, operation_budget):
        request = journal.verify_anchor_request(self.writer_policy, self.writer_keys, envelope, operation_budget)
        if self.fault == "replay-response":
            return copy.deepcopy(self.saved_response)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT version,root FROM heads WHERE scope=?", (request["scope"],)).fetchone()
            if row is None:
                raise journal.JournalError("fixture:unenrolled-scope")
            head = journal.head_of(row)
            result = "current"
            if request["action"] == "cas":
                if self.fault == "before-cas":
                    raise OSError("fixture:transport failed before CAS")
                if head == request["expected"]:
                    head = request["target"]
                    db.execute("UPDATE heads SET version=?,root=? WHERE scope=?", (int(head["version"]), head["root"], request["scope"]))
                    result = "advanced"
                    self.cas_count += 1
                else:
                    result = "mismatch"
        if request["action"] == "cas" and self.fault == "after-cas":
            raise OSError("fixture:CAS committed; reply lost")
        receipt = journal.receipt_for(request, head, result)
        response = {"receipt": receipt, "approvals": self.fixture.sign_quorum(journal.anchor_message(receipt), policy=self.policy, budget=operation_budget)}
        self.saved_response = copy.deepcopy(response)
        return response


class DurableRootNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = NativeFixture()
        cls.addClassCleanup(cls.crypto.close)
        cls.anchor_policy, cls.anchor_keys = cls.crypto._roster("journal-anchor", budget())
        cls.writer_policy, cls.writer_keys = cls.crypto._roster("journal-writer", budget())
        cls.provider_policy, cls.provider_keys = cls.crypto._roster("journal-provider", budget())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-root-journal-v2-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.anchor = NativeAnchor(self.directory / "anchor.db", self.crypto, self.anchor_policy,
                                   self.writer_policy, self.writer_keys)
        self.owner = self.create_owner(self.directory / "owner.db", "33" * 32)
        self.outcome, self.reconciliation, self.saved_provider = "applied", None, None

    def writer_sign(self, message, operation_budget):
        return self.crypto.sign_quorum(message, policy=self.writer_policy, budget=operation_budget)

    def create_owner(self, path, owner_id):
        owner = journal.RootJournal.create(path, policy=self.crypto.policy, public_keys=self.crypto.public_keys,
            network="11" * 32, genesis="22" * 32, owner_id=owner_id,
            anchor_policy=self.anchor_policy, anchor_keys=self.anchor_keys, transport=self.anchor,
            writer_policy=self.writer_policy, writer_keys=self.writer_keys, writer_signer=self.writer_sign,
            provider_pins={"fixture-provider": {"policy": self.provider_policy, "public_keys": self.provider_keys}})
        self.anchor.enroll(owner.scope, owner.snapshot()["head"])
        return owner

    def reopen(self, path=None, expected_scope=None):
        return journal.RootJournal(path or self.owner.path, self.anchor_policy, self.anchor_keys, self.anchor,
            expected_scope=expected_scope or self.owner.scope, writer_policy=self.writer_policy,
            writer_keys=self.writer_keys, writer_signer=self.writer_sign)

    def proposal(self, action="normal", *, next_policy=None, payload=None, nonce=None):
        snapshot = self.owner.snapshot()
        state = snapshot["state"]
        context = self.owner.context(10)
        statement = model.example(action)["statement"]
        for field in model.SCOPE_FIELDS:
            statement[field] = context[field]
        statement.update(policy_sha512=model.policy_id(state["policy"]), sequence=str(int(state["last_sequence"]) + 1),
                         nonce=nonce or secrets.token_hex(32), valid_from="0", valid_until="100")
        if payload is None:
            payload = {"schema": journal.EFFECT_SCHEMA, "kind": "api", "provider": "fixture-provider",
                       "chain_block": "44" * 32, "request_hex": b"fixture request; never a live API".hex()}
        statement["payload_hex"] = model.canonical(payload).hex()
        statement["next_policy"] = copy.deepcopy(next_policy or self.crypto.next_policy) if action in model.SUCCESSOR_ACTIONS else None
        pairs = tuple(tuple(i for i, key in enumerate(state["policy"]["rosters"][suite]) if key not in state["revoked_signers"])[:2] for suite in model.SUITES)
        approvals = self.crypto.approvals(statement, policy=state["policy"], pairs=pairs)
        kwargs = {}
        if action in model.SUCCESSOR_ACTIONS:
            available = {**self.crypto.public_keys, **self.crypto.next_public_keys}
            kwargs = {"successor_public_keys": {key: available[key] for keys in statement["next_policy"]["rosters"].values() for key in keys},
                      "successor_possessions": self.crypto.possessions(statement)}
        return statement, approvals, kwargs

    def apply(self, proposal):
        statement, approvals, kwargs = proposal
        return self.owner.apply(statement, approvals, now_height=10, budget=budget(), **kwargs)

    def provider(self, request, operation_budget):
        receipt = readback.receipt_for(request, receipt_id="fixture-readback", outcome=self.outcome,
                                      reconciliation=self.reconciliation)
        response = {"receipt": receipt, "approvals": self.crypto.sign_quorum(readback.receipt_message(receipt), policy=self.provider_policy, budget=operation_budget)}
        self.saved_provider = copy.deepcopy(response)
        return response

    def test_all_five_actions_change_durable_state_preserve_history_and_revocations(self):
        original = self.proposal()
        self.apply(original)
        self.apply(self.proposal("rotate"))
        state = self.owner.snapshot()["state"]
        revoked = state["policy"]["rosters"][model.SUITES[0]][0]
        self.apply(self.proposal("revoke", payload={"schema": journal.REVOKE_SCHEMA, "signer_ids": [revoked]}))
        bad = self.proposal("normal")
        bad = (bad[0], self.crypto.approvals(bad[0], policy=self.crypto.next_policy), bad[2])
        with self.assertRaisesRegex(model.Reject, "revoked"):
            self.apply(bad)
        with self.assertRaisesRegex(journal.JournalError, "revoked-successor"):
            self.apply(self.proposal("policy-change", next_policy=self.crypto.next_policy))
        self.apply(self.proposal("policy-change", next_policy=self.crypto.policy))
        self.apply(self.proposal("recover", next_policy=self.crypto.policy))
        reopened = self.reopen()
        state = reopened.snapshot()["state"]
        self.assertEqual(state["owner_generation"], "2")
        self.assertEqual(state["key_epoch"], "4")
        self.assertEqual(len(state["history"]), 5)
        self.assertIn(revoked, state["revoked_signers"])
        reused = self.proposal(nonce=original[0]["nonce"])
        with self.assertRaisesRegex(model.Reject, "nonce-reuse"):
            self.apply(reused)
        self.assertFalse(reopened.qualification()["production_qualified"])

    def test_full_local_database_and_journal_rollback_detected_by_retained_anchor(self):
        saved = self.directory / "before.db"
        shutil.copyfile(self.owner.path, saved)
        operation = self.proposal()
        self.apply(operation)
        shutil.copyfile(saved, self.owner.path)
        self.owner = self.reopen()
        with self.assertRaisesRegex(journal.JournalError, "stale-or-rollback"):
            self.apply(operation)
        self.assertFalse(self.owner.snapshot()["pending"])
        self.assertEqual(self.anchor.cas_count, 1)

    def test_full_owner_and_anchor_rollback_counterexample_stays_unqualified(self):
        # This explicit counterexample must never be reported as resistance to
        # rollback of EVERY retained authority. The fresh response is genuinely
        # signed, but both histories have been restored to identical states.
        before_owner, before_anchor = self.directory / "owner-before.db", self.directory / "anchor-before.db"
        shutil.copyfile(self.owner.path, before_owner)
        shutil.copyfile(self.anchor.path, before_anchor)
        operation = self.proposal()
        self.apply(operation)
        shutil.copyfile(before_owner, self.owner.path)
        shutil.copyfile(before_anchor, self.anchor.path)
        self.owner = self.reopen()
        self.apply(operation)
        self.assertEqual(self.anchor.cas_count, 2)
        q = self.owner.qualification()
        self.assertEqual(q["status"], "HOLD")
        self.assertFalse(q["anchor_independence_verified"])
        self.assertFalse(q["whole_chain_pq_qualified"])
        self.assertIsNone(q["actual_lifetime_failure_bound"])

    def test_lost_cas_reply_fences_restart_and_resumes_only_exact_committed_target(self):
        operation = self.proposal()
        self.anchor.fault = "after-cas"
        with self.assertRaises(OSError):
            self.apply(operation)
        self.assertTrue(self.owner.snapshot()["pending"])
        self.owner = self.reopen()
        with self.assertRaisesRegex(journal.JournalError, "pending-fenced"):
            self.owner.context(10)
        self.anchor.fault = None
        result = self.owner.resume_pending(budget())
        self.assertFalse(result["pending"])
        self.assertEqual(len(result["state"]["history"]), 1)
        self.assertEqual(self.anchor.cas_count, 1)
        with self.assertRaises(model.Reject):
            self.apply(operation)

    def test_pre_cas_failure_keeps_pending_and_cannot_claim_external_completion(self):
        self.anchor.fault = "before-cas"
        with self.assertRaises(OSError):
            self.apply(self.proposal())
        self.anchor.fault = None
        with self.assertRaisesRegex(journal.JournalError, "pending-not-independently-complete"):
            self.owner.resume_pending(budget())
        self.assertTrue(self.reopen().snapshot()["pending"])
        self.assertEqual(self.anchor.cas_count, 0)

    def test_same_head_state_tampering_and_cross_owner_database_are_refused(self):
        before = self.directory / "clean.db"
        shutil.copyfile(self.owner.path, before)
        for column in ("policy", "history", "effects", "revoked_signers"):
            with self.subTest(field=column):
                shutil.copyfile(before, self.owner.path)
                import json
                with sqlite3.connect(self.owner.path) as db:
                    raw = db.execute("SELECT state FROM current").fetchone()[0]
                    value = json.loads(raw)
                    value[column] = {"forged": True}
                    db.execute("UPDATE current SET state=?", (model.canonical(value).decode(),))
                with self.assertRaisesRegex(journal.JournalError, "current-integrity"):
                    self.reopen()
        shutil.copyfile(before, self.owner.path)
        other = self.create_owner(self.directory / "other.db", "77" * 32)
        with self.assertRaisesRegex(journal.JournalError, "scope"):
            self.reopen(other.path, expected_scope=self.owner.scope)

    def test_fresh_challenge_and_writer_authentication_cannot_be_replayed(self):
        self.apply(self.proposal())
        self.anchor.fault = "replay-response"
        with self.assertRaisesRegex(journal.JournalError, "request-binding"):
            self.apply(self.proposal())
        self.anchor.fault = None
        snap = self.owner.snapshot()
        request = journal.anchor_request(self.owner.scope, "current")
        approvals = self.writer_sign(journal.anchor_request_message(request), budget())
        changed = copy.deepcopy(request)
        changed["challenge"] = secrets.token_hex(32)
        with self.assertRaises(backend.BackendError):
            self.anchor({"request": changed, "writer_approvals": approvals}, budget())
        with self.assertRaises(model.Reject):
            self.anchor({"request": request, "writer_approvals": approvals[:2]}, budget())
        self.assertEqual(self.owner.snapshot()["head"], snap["head"])

    def test_reorg_and_unknown_require_fresh_pinned_provider_reconciliation_without_redispatch(self):
        operation = self.proposal()
        self.apply(operation)
        oid = signatures.operation_id(operation[0])
        token = self.owner.enter_effect(oid, budget(), now_height=10)
        self.assertEqual(token["request_hex"], b"fixture request; never a live API".hex())
        with self.assertRaisesRegex(journal.JournalError, "already-entered"):
            self.owner.enter_effect(oid, budget(), now_height=10)
        self.outcome = "unknown"
        self.owner.observe_effect(oid, self.provider, budget())
        with self.assertRaisesRegex(journal.JournalError, "unreconciled-external-effects"):
            self.apply(self.proposal("recover"))
        self.outcome = "applied"
        self.owner.observe_effect(oid, self.provider, budget())
        prior = copy.deepcopy(self.saved_provider)
        self.owner.observe_reorg(["44" * 32], "55" * 32, budget())
        state = self.owner.snapshot()["state"]
        self.assertEqual(state["effects"][oid]["reconciliation"], "required")
        self.assertEqual(len(state["history"]), 1)
        with self.assertRaises(model.Reject):
            self.owner.observe_effect(oid, lambda _request, _budget: prior, budget())
        # A freshly signed known result alone still cannot settle orphan liability.
        self.owner.observe_effect(oid, self.provider, budget())
        self.assertEqual(self.owner.snapshot()["state"]["effects"][oid]["reconciliation"], "required")
        self.reconciliation = "liability-retained"
        self.owner.observe_effect(oid, self.provider, budget())
        self.apply(self.proposal("recover"))
        self.owner = self.reopen()
        with self.assertRaisesRegex(journal.JournalError, "already-entered"):
            self.owner.enter_effect(oid, budget(), now_height=10)
        self.assertEqual(self.owner.snapshot()["state"]["effects"][oid]["phase"], "applied")
        self.assertFalse(self.owner.qualification()["actual_external_effects_verified"])

    def test_reserved_effect_refuses_expiry_rotation_and_signer_revocation_at_last_use(self):
        for case in ("expiry", "rotation", "revocation"):
            with self.subTest(case=case):
                self.owner = self.create_owner(self.directory / (case + ".db"), secrets.token_hex(32))
                proposal = self.proposal()
                self.apply(proposal)
                oid = signatures.operation_id(proposal[0])
                if case == "rotation":
                    self.apply(self.proposal("rotate"))
                elif case == "revocation":
                    signer = proposal[1][0]["signer_id"]
                    self.apply(self.proposal("revoke", payload={"schema": journal.REVOKE_SCHEMA, "signer_ids": [signer]}))
                with self.assertRaisesRegex(journal.JournalError, "authorization-"):
                    self.owner.enter_effect(oid, budget(), now_height=101 if case == "expiry" else 10)
                self.assertEqual(self.owner.snapshot()["state"]["effects"][oid]["phase"], "reserved")

    def test_cross_role_key_aliasing_is_refused_before_database_creation(self):
        path = self.directory / "aliased.db"
        with self.assertRaisesRegex(journal.JournalError, "cross-role-key-alias"):
            journal.RootJournal.create(path, policy=self.crypto.policy, public_keys=self.crypto.public_keys,
                network="11" * 32, genesis="22" * 32, owner_id="66" * 32,
                anchor_policy=self.anchor_policy, anchor_keys=self.anchor_keys, transport=self.anchor,
                writer_policy=self.crypto.policy, writer_keys=self.crypto.public_keys,
                writer_signer=self.writer_sign)
        self.assertFalse(path.exists())

    def test_noncanonical_pending_and_changed_event_are_never_promoted_or_replayed(self):
        self.anchor.fault = "after-cas"
        with self.assertRaises(OSError):
            self.apply(self.proposal())
        self.anchor.fault = None
        with sqlite3.connect(self.owner.path) as db:
            original = db.execute("SELECT state FROM pending").fetchone()[0]
            db.execute("UPDATE pending SET state=?", (" " + original,))
        with self.assertRaisesRegex(journal.JournalError, "pending-noncanonical"):
            self.owner.resume_pending(budget())
        self.assertTrue(self.owner.snapshot()["pending"])
        with sqlite3.connect(self.owner.path) as db:
            db.execute("UPDATE pending SET state=?", (original,))
        self.owner.resume_pending(budget())
        with sqlite3.connect(self.owner.path) as db:
            event = db.execute("SELECT event FROM events WHERE version=1").fetchone()[0]
            db.execute("UPDATE events SET event=? WHERE version=1", (" " + event,))
        with self.assertRaisesRegex(journal.JournalError, "noncanonical-json"):
            self.reopen()

    def test_two_original_state_contenders_cannot_both_consume_or_advance(self):
        first, second = self.proposal(), self.proposal()
        entered, release = threading.Event(), threading.Event()
        original_transport = self.owner.transport
        errors = []
        def blocked(envelope, operation_budget):
            if envelope["request"]["action"] == "current":
                entered.set()
                if not release.wait(10):
                    raise RuntimeError("test contender did not release")
            return original_transport(envelope, operation_budget)
        self.owner.transport = blocked
        def run():
            try:
                self.apply(first)
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(entered.wait(10))
        try:
            with self.assertRaises(sqlite3.OperationalError):
                self.apply(second)
        finally:
            release.set()
            worker.join(120)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(self.owner.snapshot()["state"]["history"]), 1)
        self.assertEqual(self.anchor.cas_count, 1)

    def test_caller_statement_mutation_during_anchor_call_cannot_change_authorized_effect(self):
        proposal = self.proposal()
        original_payload = proposal[0]["payload_hex"]
        transport = self.owner.transport
        def change_caller(envelope, operation_budget):
            proposal[0]["payload_hex"] = model.canonical({"malicious": "post-signature replacement"}).hex()
            return transport(envelope, operation_budget)
        self.owner.transport = change_caller
        result = self.apply(proposal)
        effect = next(iter(result["state"]["effects"].values()))
        self.assertEqual(model.canonical(effect["intent"]).hex(), original_payload)

    def test_missing_database_never_creates_or_enrolls_and_missing_anchor_never_recovers(self):
        absent = self.directory / "absent.db"
        with self.assertRaisesRegex(journal.JournalError, "missing"):
            self.reopen(absent)
        self.assertFalse(absent.exists())
        with sqlite3.connect(self.anchor.path) as db:
            db.execute("DELETE FROM heads")
        with self.assertRaisesRegex(journal.JournalError, "unenrolled-scope"):
            self.apply(self.proposal())
        self.assertFalse(self.owner.snapshot()["pending"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
