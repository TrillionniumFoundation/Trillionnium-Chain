"""Durable research root transitions; never an M15 capability or deployment.

The cryptographic adapter verifies real dual-family signatures. This journal
owns its expected state, reserves nonces durably, and fences uncertain external
CAS. An independently administered anchor and actual provider observations are
explicit trust obligations; a local fixture cannot establish them.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3

import pq_root_recovery_policy_v1 as model
import pq_root_recovery_signatures_v2 as signatures
import pq_root_effect_readback_v2 as providers

SCHEMA = "trnm.root-recovery-journal.v2"
ANCHOR_SCHEMA = "trnm.root-recovery-anchor.v2"
EFFECT_SCHEMA = "trnm.root-effect-intent.v2"
REVOKE_SCHEMA = "trnm.root-revoke-intent.v2"
DOMAIN = b"TRNM/RootRecoveryJournal/State/v2\x00"
ANCHOR_DOMAIN = b"TRNM/RootRecoveryJournal/Anchor/v2\x00"
REQUEST_DOMAIN = b"TRNM/RootRecoveryJournal/AnchorRequest/v2\x00"
WRITER_DOMAIN = b"TRNM/RootRecoveryJournal/AnchorWriter/v2\x00"
SCOPE_DOMAIN = b"TRNM/RootRecoveryJournal/Scope/v2\x00"
INTENT_DOMAIN = b"TRNM/RootRecoveryJournal/Effect/v2\x00"
MAX_EVENTS = 2048
MAX_STATE_BYTES = 2 * 1024 * 1024


class JournalError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise JournalError(code)


def digest(domain, value):
    data = model.canonical(value)
    return hashlib.sha512(domain + len(data).to_bytes(8, "big") + data).hexdigest()


def head_of(row):
    return {"version": str(row[0]), "root": row[1]}


def anchor_message(receipt):
    model.fields(receipt, ("schema", "scope", "challenge", "request_sha512", "head", "result"), "anchor")
    require(receipt["schema"] == ANCHOR_SCHEMA, "anchor:schema")
    for key in ("scope", "request_sha512"):
        model.hex_bytes(receipt[key], 64, key)
    model.hex_bytes(receipt["challenge"], 32, "anchor-challenge")
    validate_head(receipt["head"])
    require(receipt["result"] in ("current", "advanced", "mismatch"), "anchor:result")
    return ANCHOR_DOMAIN + model.canonical(receipt)


def validate_head(head):
    model.fields(head, ("version", "root"), "head")
    model.uint(head["version"], "head-version")
    model.hex_bytes(head["root"], 64, "head-root")


def anchor_request(scope, action, expected=None, target=None):
    require(action in ("current", "cas"), "anchor:action")
    if action == "cas":
        validate_head(expected)
        validate_head(target)
        require(int(target["version"]) == int(expected["version"]) + 1, "anchor:advance")
    else:
        require(expected is None and target is None, "anchor:read-shape")
    return {"schema": ANCHOR_SCHEMA, "scope": scope, "action": action,
            "challenge": secrets.token_hex(32), "expected": expected, "target": target}


def anchor_request_message(request):
    model.fields(request, ("schema", "scope", "action", "challenge", "expected", "target"), "anchor-request")
    require(request["schema"] == ANCHOR_SCHEMA and request["action"] in ("current", "cas"), "anchor-request:schema-action")
    model.hex_bytes(request["scope"], 64, "anchor-request:scope")
    model.hex_bytes(request["challenge"], 32, "anchor-request:challenge")
    if request["action"] == "current":
        require(request["expected"] is None and request["target"] is None, "anchor-request:read-shape")
    else:
        validate_head(request["expected"])
        validate_head(request["target"])
        require(int(request["target"]["version"]) == int(request["expected"]["version"]) + 1, "anchor-request:advance")
    return WRITER_DOMAIN + model.canonical(request)


def verify_anchor_request(writer_policy, writer_keys, envelope, budget):
    """Anchor-side request authentication; enrollment pins are not client input."""
    model.fields(envelope, ("request", "writer_approvals"), "anchor-envelope")
    request = copy.deepcopy(envelope["request"])
    signatures.verify_quorum(writer_policy, writer_keys, anchor_request_message(request),
                             envelope["writer_approvals"], budget=budget)
    return request


def receipt_for(request, head, result):
    """Public fixture/server serialization; the returned dict is NOT signed."""
    return {"schema": ANCHOR_SCHEMA, "scope": request["scope"],
            "challenge": request["challenge"],
            "request_sha512": digest(REQUEST_DOMAIN, request),
            "head": copy.deepcopy(head), "result": result}


@contextmanager
def _database(path, create=False):
    path = Path(path).absolute()
    require(path.parent.resolve() == path.parent and not path.is_symlink(), "database:canonical-path")
    if create:
        # No implicit registration or destructive replacement of existing state.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    else:
        require(path.is_file(), "database:missing")
    connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=0)
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        with connection:
            yield connection
    finally:
        connection.close()


def _encoded_keys(keys):
    return {key: value.hex() for key, value in sorted(keys.items())}


def _decoded_keys(keys):
    return {key: bytes.fromhex(value) for key, value in keys.items()}


class RootJournal:
    """Candidate local owner. The anchor transport is a trust-pinned adapter.

    Transport accepts a request and returns {receipt, approvals}. Every response
    is independently verified under the enrollment pins. Supplying a transport
    object does not supply trust: its public roster cannot come from that object.
    No method starts a process, sends a payment or changes a deployed root.
    """

    def __init__(self, path, anchor_policy, anchor_keys, transport, *, expected_scope,
                 writer_policy, writer_keys, writer_signer):
        signatures.validate_roster(anchor_policy, anchor_keys)
        signatures.validate_roster(writer_policy, writer_keys)
        self.writer_policy = copy.deepcopy(writer_policy)
        self.writer_keys = dict(writer_keys)
        self.writer_signer = writer_signer
        self.path = Path(path).absolute()
        self.anchor_policy = copy.deepcopy(anchor_policy)
        self.anchor_keys = dict(anchor_keys)
        self.transport = transport
        model.hex_bytes(expected_scope, 64, "expected-scope")
        self.scope = expected_scope
        with _database(self.path) as db:
            require(db.execute("PRAGMA user_version").fetchone()[0] == 2, "database:version")
            _, state = self._verified_current(db)
            require(state["schema"] == SCHEMA and state["scope"] == expected_scope, "database:scope-or-schema")
            require(state["anchor_policy"] == self.anchor_policy
                    and state["anchor_keys"] == _encoded_keys(self.anchor_keys), "anchor:pin-change")

    @classmethod
    def create(cls, path, *, policy, public_keys, network, genesis, owner_id,
               anchor_policy, anchor_keys, transport, writer_policy, writer_keys,
               writer_signer, provider_pins=None):
        signatures.validate_roster(policy, public_keys)
        signatures.validate_roster(anchor_policy, anchor_keys)
        signatures.validate_roster(writer_policy, writer_keys)
        model.hex_bytes(network, 32, "network")
        model.hex_bytes(genesis, 32, "genesis")
        model.hex_bytes(owner_id, 32, "owner-id")
        provider_pins = {} if provider_pins is None else provider_pins
        require(type(provider_pins) is dict and len(provider_pins) <= 8, "providers:count")
        enrolled_providers = {}
        for name, pins in provider_pins.items():
            providers._identity(name, "provider-enrollment")
            model.fields(pins, ("policy", "public_keys"), "provider-pins")
            signatures.validate_roster(pins["policy"], pins["public_keys"])
            enrolled_providers[name] = {"policy": copy.deepcopy(pins["policy"]), "public_keys": _encoded_keys(pins["public_keys"])}
        service_groups = [set(writer_keys), set(anchor_keys)] + [set(pins["public_keys"]) for pins in provider_pins.values()]
        service_ids = set().union(*service_groups)
        require(len(service_ids) == sum(len(group) for group in service_groups)
                and not service_ids.intersection(public_keys), "enrollment:cross-role-key-alias")
        scope = digest(SCOPE_DOMAIN, {"network": network, "genesis": genesis, "owner_id": owner_id})
        state = {"schema": SCHEMA, "scope": scope, "network": network, "genesis": genesis,
                 "owner_generation": "1", "key_epoch": "1", "last_sequence": "0",
                 "policy": copy.deepcopy(policy), "public_keys": _encoded_keys(public_keys),
                 "anchor_policy": copy.deepcopy(anchor_policy), "anchor_keys": _encoded_keys(anchor_keys),
                 "writer_policy": copy.deepcopy(writer_policy), "writer_keys": _encoded_keys(writer_keys),
                 "history": [], "revoked_signers": [], "effects": {}, "chain_tip": None, "providers": enrolled_providers}
        initial_root = digest(DOMAIN, {"version": "0", "previous": None, "event": "enrollment", "state": state})
        # Registration at the external anchor is a separate, explicit operation.
        # create() never overwrites or silently enrolls the external authority.
        with _database(path, create=True) as db:
            db.executescript("""
                PRAGMA user_version=2;
                CREATE TABLE current(singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, root TEXT NOT NULL, state TEXT NOT NULL);
                CREATE TABLE pending(singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, root TEXT NOT NULL, state TEXT NOT NULL, event TEXT NOT NULL, previous_root TEXT NOT NULL);
                CREATE TABLE events(version INTEGER PRIMARY KEY, root TEXT NOT NULL, event TEXT NOT NULL, state TEXT NOT NULL, previous_root TEXT NOT NULL);
            """)
            db.execute("CREATE TABLE enrollment(singleton INTEGER PRIMARY KEY CHECK(singleton=1), root TEXT NOT NULL, state TEXT NOT NULL)")
            db.execute("INSERT INTO enrollment VALUES(1,?,?)", (initial_root, model.canonical(state).decode()))
            db.execute("INSERT INTO current VALUES(1,0,?,?)", (initial_root, model.canonical(state).decode()))
        return cls(path, anchor_policy, anchor_keys, transport, expected_scope=scope,
                   writer_policy=writer_policy, writer_keys=writer_keys, writer_signer=writer_signer)

    def _verified_current(self, db, budget=None):
        # A stored root next to mutable state does not authenticate that state.
        # Replay every bounded event from enrollment before using any row.
        def check_raw(raw):
            require(type(raw) is str and len(raw.encode()) <= MAX_STATE_BYTES, "database:row-size")
            value = json.loads(raw)
            require(model.canonical(value).decode() == raw, "database:noncanonical-json")
            return value
        sizes = db.execute("SELECT (SELECT COUNT(*) FROM enrollment),(SELECT COUNT(*) FROM current),(SELECT COUNT(*) FROM pending),(SELECT COUNT(*) FROM events)").fetchone()
        require(sizes[0] == 1 and sizes[1] == 1 and sizes[2] <= 1 and sizes[3] <= MAX_EVENTS, "database:row-count")
        for table, columns in (("enrollment", ("state",)), ("current", ("state",)), ("pending", ("state", "event")), ("events", ("state", "event"))):
            for column in columns:
                largest = db.execute(f"SELECT MAX(length(CAST({column} AS BLOB))) FROM {table}").fetchone()[0]
                require(largest is None or largest <= MAX_STATE_BYTES, "database:row-size")
        initial = db.execute("SELECT root,state FROM enrollment WHERE singleton=1").fetchone()
        require(initial is not None, "database:enrollment")
        state = check_raw(initial[1])
        require(state["scope"] == self.scope, "database:scope")
        require(digest(DOMAIN, {"version": "0", "previous": None, "event": "enrollment", "state": state}) == initial[0], "database:enrollment-integrity")
        head = {"version": "0", "root": initial[0]}
        for row in db.execute("SELECT version,root,state,event,previous_root FROM events ORDER BY version"):
            if budget is not None:
                budget.check()
            require(row[0] == int(head["version"]) + 1 and row[4] == head["root"], "database:event-chain")
            state, event = check_raw(row[2]), check_raw(row[3])
            require(digest(DOMAIN, {"version": str(row[0]), "previous": row[4], "event": event, "state": state}) == row[1], "database:event-integrity")
            head = head_of(row)
        current = db.execute("SELECT version,root,state FROM current WHERE singleton=1").fetchone()
        require(current is not None and head_of(current) == head and current[2] == model.canonical(state).decode(), "database:current-integrity")
        require(state["scope"] == self.scope and state["anchor_policy"] == self.anchor_policy
                and state["anchor_keys"] == _encoded_keys(self.anchor_keys)
                and state["writer_policy"] == self.writer_policy and state["writer_keys"] == _encoded_keys(self.writer_keys), "database:pinned-identity")
        return head, state

    def snapshot(self):
        with _database(self.path) as db:
            db.execute("BEGIN")
            head, state = self._verified_current(db)
            return {"head": head, "state": state,
                    "pending": db.execute("SELECT COUNT(*) FROM pending").fetchone()[0] != 0}

    def _anchor(self, request, budget):
        budget.check()
        message = anchor_request_message(request)
        writer_approvals = self.writer_signer(message, budget)
        signatures.verify_quorum(self.writer_policy, self.writer_keys, message, writer_approvals, budget=budget)
        result = self.transport({"request": copy.deepcopy(request), "writer_approvals": copy.deepcopy(writer_approvals)}, budget)
        budget.check()
        model.fields(result, ("receipt", "approvals"), "anchor-response")
        receipt = copy.deepcopy(result["receipt"])
        message = anchor_message(receipt)
        require(receipt["scope"] == self.scope and receipt["challenge"] == request["challenge"]
                and receipt["request_sha512"] == digest(REQUEST_DOMAIN, request), "anchor:request-binding")
        signatures.verify_quorum(self.anchor_policy, self.anchor_keys, message, result["approvals"], budget=budget)
        budget.check()
        return receipt

    def _fresh_head(self, expected, budget):
        receipt = self._anchor(anchor_request(self.scope, "current"), budget)
        require(receipt["result"] == "current" and receipt["head"] == expected, "anchor:stale-or-rollback")

    def _load_locked(self, db, budget):
        require(db.execute("SELECT COUNT(*) FROM pending").fetchone()[0] == 0, "owner:pending-fenced")
        head, state = self._verified_current(db, budget)
        require(int(head["version"]) < MAX_EVENTS, "owner:event-capacity")
        return head, state

    def context(self, now_height):
        snap = self.snapshot()
        require(not snap["pending"], "owner:pending-fenced")
        return self._context(snap["head"], snap["state"], now_height)

    def _context(self, head, state, now_height):
        model.uint(str(now_height), "now-height")
        scope = {key: state[key] for key in ("network", "genesis", "owner_generation", "key_epoch")}
        scope["previous_state"] = head["root"]
        return {**scope, "last_sequence": state["last_sequence"], "now_height": str(now_height),
                "anchor": {**scope, "last_sequence": state["last_sequence"], "policy_sha512": model.policy_id(state["policy"])},
                "history": copy.deepcopy(state["history"]), "revoked_signers": list(state["revoked_signers"]),
                "observations": {key: "unknown" for key in model.OBSERVATIONS}}

    def _stage(self, db, old_head, state, event):
        require(len(state["history"]) <= model.MAX_HISTORY, "owner:nonce-capacity")
        require(len(state["revoked_signers"]) <= model.MAX_HISTORY, "owner:revocation-capacity")
        raw = model.canonical(state)
        require(len(raw) <= MAX_STATE_BYTES, "owner:state-capacity")
        version = int(old_head["version"]) + 1
        root = digest(DOMAIN, {"version": str(version), "previous": old_head["root"], "event": event, "state": state})
        db.execute("INSERT INTO pending VALUES(1,?,?,?,?,?)", (version, root, raw.decode(), model.canonical(event).decode(), old_head["root"]))
        db.commit()
        return {"version": str(version), "root": root}

    def _finish(self, expected, target, budget):
        with _database(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            verified_head, _ = self._verified_current(db, budget)
            current = db.execute("SELECT version,root FROM current WHERE singleton=1").fetchone()
            require(verified_head == expected, "owner:current-integrity")
            pending = db.execute("SELECT version,root,state,event,previous_root FROM pending WHERE singleton=1").fetchone()
            require(current is not None and head_of(current) == expected, "owner:concurrent-current")
            require(pending is not None and head_of(pending) == target and pending[4] == expected["root"], "owner:concurrent-pending")
            # Recompute before promoting persisted pending bytes after any crash.
            state, event = json.loads(pending[2]), json.loads(pending[3])
            require(model.canonical(state).decode() == pending[2] and model.canonical(event).decode() == pending[3], "owner:pending-noncanonical")
            require(digest(DOMAIN, {"version": str(pending[0]), "previous": pending[4], "event": event, "state": state}) == pending[1], "owner:pending-corrupt")
            db.execute("INSERT INTO events(version,root,state,event,previous_root) VALUES(?,?,?,?,?)", pending)
            db.execute("UPDATE current SET version=?,root=?,state=? WHERE singleton=1", pending[:3])
            db.execute("DELETE FROM pending WHERE singleton=1")
        return {"head": dict(target), "state": state, "pending": False}

    def _publish(self, expected, target, budget):
        # Any exception leaves the already committed pending row intact. There
        # is no rollback-to-retry, refund or creation of a fresh operation nonce.
        receipt = self._anchor(anchor_request(self.scope, "cas", expected, target), budget)
        require(receipt["result"] == "advanced" and receipt["head"] == target, "anchor:cas-refused")
        result = self._finish(expected, target, budget)
        budget.check()
        return result

    def resume_pending(self, budget):
        """Only exact independently observed completion can finish uncertainty."""
        with _database(self.path) as db:
            current = db.execute("SELECT version,root FROM current WHERE singleton=1").fetchone()
            pending = db.execute("SELECT version,root FROM pending WHERE singleton=1").fetchone()
            require(pending is not None, "owner:no-pending")
        receipt = self._anchor(anchor_request(self.scope, "current"), budget)
        require(receipt["result"] == "current" and receipt["head"] == head_of(pending), "owner:pending-not-independently-complete")
        result = self._finish(head_of(current), head_of(pending), budget)
        budget.check()
        return result

    def apply(self, statement, approvals, *, now_height, budget,
              successor_public_keys=None, successor_possessions=None):
        statement = signatures._statement_snapshot(statement)
        approvals = copy.deepcopy(approvals)
        successor_possessions = copy.deepcopy(successor_possessions)
        if successor_public_keys is not None:
            successor_public_keys = dict(successor_public_keys)
        with _database(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            expected, state = self._load_locked(db, budget)
            self._fresh_head(expected, budget)
            require(len(state["history"]) < model.MAX_HISTORY, "owner:nonce-capacity")
            context = self._context(expected, state, now_height)
            verification = signatures.verified_statement(
                state["policy"], context, statement, _decoded_keys(state["public_keys"]), approvals,
                successor_public_keys=successor_public_keys, successor_possessions=successor_possessions,
                budget=budget)
            require(verification["signatures_verified"] is True, "owner:signature-verification")
            action = statement["action"]
            oid = verification["operation_id"]
            # All state changes derive from the originally signed expected state.
            # Locking never updates a request to a newer unsigned predecessor.
            if action in model.SUCCESSOR_ACTIONS:
                service_ids = set(state["writer_keys"]) | set(state["anchor_keys"]) | {key for provider in state["providers"].values() for key in provider["public_keys"]}
                require(not service_ids.intersection(successor_public_keys), "owner:cross-role-successor")
                require(not any(key in state["revoked_signers"] for roster in statement["next_policy"]["rosters"].values() for key in roster), "owner:revoked-successor")
                if action == "recover":
                    require(not any(value["phase"] in ("entered", "unknown") or value["reconciliation"] == "required" for value in state["effects"].values()), "owner:unreconciled-external-effects")
                    state["owner_generation"] = str(model.uint(state["owner_generation"], "generation") + 1)
                state["key_epoch"] = str(model.uint(state["key_epoch"], "epoch") + 1)
                model.uint(state["key_epoch"], "epoch-overflow")
                model.uint(state["owner_generation"], "generation-overflow")
                state["policy"] = copy.deepcopy(statement["next_policy"])
                state["public_keys"] = _encoded_keys(successor_public_keys)
            elif action == "revoke":
                payload = model.strict_json(bytes.fromhex(statement["payload_hex"]))
                model.fields(payload, ("schema", "signer_ids"), "revoke-intent")
                require(payload["schema"] == REVOKE_SCHEMA, "revoke:schema")
                targets = payload["signer_ids"]
                require(type(targets) is list and 1 <= len(targets) <= 6, "revoke:targets")
                for key in targets:
                    model.hex_bytes(key, 64, "revoke-target")
                require(targets == sorted(set(targets)), "revoke:duplicate-or-order")
                roster = {key for keys in state["policy"]["rosters"].values() for key in keys}
                require(all(key in roster and key not in state["revoked_signers"] for key in targets), "revoke:unknown-or-repeated")
                state["revoked_signers"] = sorted(set(state["revoked_signers"]) | set(targets))
            else:
                payload = model.strict_json(bytes.fromhex(statement["payload_hex"]))
                model.fields(payload, ("schema", "kind", "provider", "chain_block", "request_hex"), "effect-intent")
                require(payload["schema"] == EFFECT_SCHEMA and payload["kind"] in ("api", "payment", "resource"), "effect:intent-kind")
                providers._identity(payload["provider"], "effect-provider")
                require(payload["provider"] in state["providers"], "effect:unenrolled-provider")
                model.hex_bytes(payload["chain_block"], 32, "effect-block")
                require(type(payload["request_hex"]) is str and len(payload["request_hex"]) % 2 == 0, "effect:request-encoding")
                try:
                    request = bytes.fromhex(payload["request_hex"])
                except ValueError as error:
                    raise JournalError("effect:request-encoding") from error
                require(request.hex() == payload["request_hex"], "effect:request-canonical")
                state["effects"][oid] = {"phase": "reserved", "intent": payload,
                    "intent_sha512": digest(INTENT_DOMAIN, payload), "observations": [],
                    "orphaned": False, "orphaned_at": None, "reconciliation": "none",
                    "authorization": {key: statement[key] for key in ("valid_from", "valid_until", "owner_generation", "key_epoch", "policy_sha512")},
                    "approving_signers": sorted(row["signer_id"] for row in approvals)}
            state["last_sequence"] = statement["sequence"]
            state["history"].append({"nonce": statement["nonce"], "operation_id": oid})
            state["history"].sort(key=lambda item: item["nonce"])
            event = {"kind": "authorized-root-operation", "statement": statement, "operation_id": oid,
                     "signature_verification": "dual-family-native", "action": action,
                     "approvals": approvals, "successor_possessions": successor_possessions}
            target = self._stage(db, expected, state, event)
        return self._publish(expected, target, budget)

    def _observation(self, change, event, budget):
        with _database(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            expected, state = self._load_locked(db, budget)
            self._fresh_head(expected, budget)
            change(state, str(int(expected["version"]) + 1))
            target = self._stage(db, expected, state, event)
        return self._publish(expected, target, budget)

    def enter_effect(self, operation_id, budget, *, now_height):
        """Reserve the one dispatch before returning its stable idempotency key.

        A crash before return may lose availability. Reopen cannot dispatch
        again; it requires provider readback using this exact operation ID.
        """
        def change(state, _version):
            effect = state["effects"].get(operation_id)
            require(effect is not None and effect["phase"] == "reserved", "effect:already-entered-or-unknown")
            require(not effect["orphaned"], "effect:orphaned-before-dispatch")
            authorization = effect["authorization"]
            now = model.uint(str(now_height), "effect-now-height")
            require(int(authorization["valid_from"]) <= now <= int(authorization["valid_until"]), "effect:authorization-expired-or-future")
            require(authorization["owner_generation"] == state["owner_generation"]
                    and authorization["key_epoch"] == state["key_epoch"]
                    and authorization["policy_sha512"] == model.policy_id(state["policy"]), "effect:authorization-no-longer-current")
            require(not set(effect["approving_signers"]) & set(state["revoked_signers"]), "effect:authorization-revoked")
            effect["phase"] = "entered"
        committed = self._observation(change, {"kind": "effect-entered", "operation_id": operation_id}, budget)
        effect = committed["state"]["effects"][operation_id]
        return {"operation_id": operation_id, "intent_sha512": effect["intent_sha512"],
                "request_hex": effect["intent"]["request_hex"]}

    def observe_effect(self, operation_id, provider_transport, budget):
        """Read a fresh native-signed provider declaration under enrolled keys.

        The signature authenticates a provider statement, not the truth of a
        real external payment. Reconciliation names the exact orphan epoch;
        neither Unknown nor an old signed successful receipt permits replay.
        """
        with _database(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            expected, state = self._load_locked(db, budget)
            self._fresh_head(expected, budget)
            effect = state["effects"].get(operation_id)
            require(effect is not None and effect["phase"] in ("entered", "unknown", "applied", "compensated", "not-applied"), "effect:observation-phase")
            provider = effect["intent"]["provider"]
            pins = state["providers"][provider]
            request = providers.request_for(self.scope, operation_id, effect["intent_sha512"],
                                            provider, effect["orphaned_at"])
            budget.check()
            response = copy.deepcopy(provider_transport(copy.deepcopy(request), budget))
            budget.check()
            result = providers.verify_readback(pins["policy"], _decoded_keys(pins["public_keys"]),
                                               request, response, budget)
            receipt = result["receipt"]
            outcome = receipt["outcome"]
            if effect["phase"] in ("applied", "compensated", "not-applied"):
                allowed = {"applied": ("applied", "compensated"), "compensated": ("compensated",), "not-applied": ("not-applied",)}
                require(outcome in allowed[effect["phase"]], "effect:contradictory-observation")
            if outcome == "compensated":
                require(effect["phase"] in ("applied", "compensated"), "effect:compensation-without-applied")
            effect["phase"] = outcome
            effect["observations"].append(copy.deepcopy(receipt))
            require(len(effect["observations"]) <= 128, "effect:observation-capacity")
            if effect["orphaned"] and result["reorg_reconciliation_verified"]:
                effect["reconciliation"] = "provider-observed"
            event = {"kind": "provider-observation", "operation_id": operation_id,
                     "request": request, "receipt": receipt,
                     "approvals": copy.deepcopy(response["approvals"])}
            target = self._stage(db, expected, state, event)
        return self._publish(expected, target, budget)

    def observe_reorg(self, orphaned_blocks, new_tip, budget):
        require(type(orphaned_blocks) is list and len(orphaned_blocks) <= 128, "reorg:block-set")
        for block in orphaned_blocks + [new_tip]:
            model.hex_bytes(block, 32, "reorg-block")
        require(orphaned_blocks == sorted(set(orphaned_blocks)), "reorg:duplicate-or-order")
        orphaned_blocks = list(orphaned_blocks)
        def change(state, reorg_version):
            state["chain_tip"] = new_tip
            for effect in state["effects"].values():
                if effect["intent"]["chain_block"] in orphaned_blocks:
                    effect["orphaned"] = True
                    effect["orphaned_at"] = reorg_version
                    effect["reconciliation"] = "required" if effect["phase"] != "reserved" else "not-dispatched"
        return self._observation(change, {"kind": "chain-reorg-observation", "orphaned_blocks": orphaned_blocks,
                                         "new_tip": new_tip}, budget)

    def qualification(self):
        return {"status": "HOLD", "research_only": True, "production_qualified": False,
                "whole_chain_pq_qualified": False, "composition_coverage_proved": False, "actual_lifetime_failure_bound": None,
                "activation_performed": False, "custody_verified": False,
                "anchor_independence_verified": False, "actual_external_effects_verified": False,
                "native_m15_integration_complete": False}
