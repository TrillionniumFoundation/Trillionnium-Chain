"""Executable release-only Basic-HotStuff-style reference; NEVER a node runtime.

Real Ed25519; explicit trusted application predicate; durable-before-send SQLite
reference outbox. No PoN fallback, model installer, permission, or activation.
"""
from __future__ import annotations
import copy
import fcntl
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Callable
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"pon-nakamoto-v1"))
from strict_signature import strict_point, verify as strict_verify

PROFILE = "trnm-release-finality-v2"
DOMAIN = b"TRNM-RELEASE-FINALITY-V2\0"
MAX_WIRE = 2 * 1024 * 1024
MAX_MEMBERS = 32

class Refusal(ValueError):
    pass

class Crash(BaseException):
    """Test-only process-cut signal, never an accepted observation."""

def require(condition, reason):
    if not condition:
        raise Refusal(reason)

def fields(obj, names):
    require(type(obj) is dict and set(obj) == set(names.split()), "FIELDS")

def integer(value, minimum=0):
    require(type(value) is int and minimum <= value < 2**63, "INTEGER")
    return value

def digest(value):
    require(type(value) is str and len(value) == 64, "DIGEST")
    require(all(c in "0123456789abcdef" for c in value), "DIGEST")
    return value

def canonical(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("ascii")
    require(len(raw) <= MAX_WIRE, "WIRE_LIMIT")
    return raw

def decode(raw):
    require(type(raw) is bytes and len(raw) <= MAX_WIRE, "WIRE_LIMIT")
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, "DUPLICATE_KEY")
            result[k] = v
        return result
    try:
        result = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(Refusal("NUMBER")))
        require(canonical(result) == raw, "NONCANONICAL")
        return result
    except (RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        raise Refusal("DECODE") from exc

def identity(value):
    return hashlib.sha256(DOMAIN + canonical(value)).hexdigest()

def key_id(key):
    return key.public_key().public_bytes_raw().hex()

def signature(key, body):
    return {"signer": key_id(key), "body": copy.deepcopy(body),
            "signature": key.sign(DOMAIN + canonical(body)).hex()}

def verify_signature(signed, members):
    fields(signed, "signer body signature")
    require(signed["signer"] in members, "NONMEMBER")
    value = signed["signature"]
    require(type(value) is str and len(value) == 128 and
            all(c in "0123456789abcdef" for c in value), "SIGNATURE_ENCODING")
    try:
        strict_verify(bytes.fromhex(signed["signer"]), bytes.fromhex(value),
                      DOMAIN + canonical(signed["body"]))
    except Exception as exc:
        raise Refusal("SIGNATURE") from exc
    return signed["body"]

def quorum(n, f, q):
    integer(n, 1); integer(f); integer(q, 1)
    require(n <= MAX_MEMBERS and n >= 3*f + 1, "COMMITTEE_SIZE")
    require(q <= n-f and 2*q-n > f, "QUORUM_INTERSECTION_OR_LIVENESS")
    return q

def manifest(value):
    fields(value, "schema genesis epoch members fault_bound quorum")
    require(value["schema"] == "trnm-release-committee-v2", "MANIFEST_VERSION")
    digest(value["genesis"]); integer(value["epoch"])
    members = value["members"]
    require(type(members) is list and 1 <= len(members) <= MAX_MEMBERS, "MEMBERS")
    for member in members:
        digest(member)
        try:
            strict_point(bytes.fromhex(member))
        except ValueError as exc:
            raise Refusal("MEMBER_POINT") from exc
    require(members == sorted(set(members)), "MEMBER_ORDER_OR_DUPLICATE")
    quorum(len(members), value["fault_bound"], value["quorum"])
    return value

def context(members, height, parent, parent_model):
    manifest(members); integer(height, 1); digest(parent); digest(parent_model)
    return dict(profile=PROFILE, genesis=members["genesis"], epoch=members["epoch"],
                committee=identity(members), height=height, parent=parent,
                parent_model=parent_model)

def check_context(ctx, members):
    fields(ctx, "profile genesis epoch committee height parent parent_model")
    require(ctx == context(members, ctx["height"], ctx["parent"], ctx["parent_model"]), "CONTEXT")

def check_statement(value, ctx):
    fields(value, "context model evaluation availability retention_height state_root next_committee")
    require(value["context"] == identity(ctx), "STATEMENT_CONTEXT")
    for name in ("model", "evaluation", "availability", "state_root"):
        digest(value[name])
    integer(value["retention_height"], ctx["height"])
    if value["next_committee"] is not None:
        digest(value["next_committee"])
    return identity(value)

def vote_body(ctx, view, phase, value):
    integer(view)
    require(phase in ("availability", "prepare", "precommit", "commit"), "PHASE")
    require((view == 0) == (phase == "availability"), "PHASE_VIEW")
    digest(value)
    return dict(context=identity(ctx), view=view, phase=phase, value=value)

def certificate(ctx, view, phase, value, votes, members):
    body = vote_body(ctx, view, phase, value)
    require(type(votes) is list and members["quorum"] <= len(votes) <= len(members["members"]), "VOTE_COUNT")
    ids = []
    for signed in votes:
        require(verify_signature(signed, members["members"]) == body, "VOTE_BINDING")
        ids.append(signed["signer"])
    require(ids == sorted(set(ids)), "VOTE_ORDER_OR_DUPLICATE")
    return dict(body=body, votes=copy.deepcopy(votes))

def check_qc(qc, ctx, members, phase=None):
    fields(qc, "body votes")
    body = qc["body"]
    fields(body, "context view phase value")
    expected = certificate(ctx, body["view"], body["phase"], body["value"], qc["votes"], members)
    require(qc == expected, "QC_BINDING")
    if phase is not None:
        require(body["phase"] == phase, "QC_PHASE")
    return body

def high_qc(reports, ctx, members, view):
    integer(view, 1)
    require(type(reports) is list and members["quorum"] <= len(reports) <= len(members["members"]), "NEW_VIEW_COUNT")
    ids, candidates = [], []
    for report in reports:
        body = verify_signature(report, members["members"])
        fields(body, "context view phase high")
        require(body["context"] == identity(ctx) and body["view"] == view and body["phase"] == "new_view", "NEW_VIEW_BINDING")
        ids.append(report["signer"])
        if body["high"] is not None:
            prior = check_qc(body["high"], ctx, members, "prepare")
            require(prior["view"] < view, "NEW_VIEW_FUTURE_QC")
            candidates.append(body["high"])
    require(ids == sorted(set(ids)), "NEW_VIEW_DUPLICATE_OR_ORDER")
    if not candidates:
        return None
    top = max(q["body"]["view"] for q in candidates)
    highest = [q for q in candidates if q["body"]["view"] == top]
    require(len({q["body"]["value"] for q in highest}) == 1, "CONFLICTING_PREPARE_QC")
    return min(highest, key=canonical)

def leader(members, view):
    integer(view, 1)
    return members["members"][(view-1) % len(members["members"])]

def proposal(key, ctx, members, view, reports, statement, availability):
    require(key_id(key) == leader(members, view), "LEADER")
    value = check_statement(statement, ctx)
    high = high_qc(reports, ctx, members, view)
    require(high is None or high["body"]["value"] == value, "HIGHEST_QC_PROPOSAL")
    require(check_qc(availability, ctx, members, "availability")["value"] == value, "AVAILABILITY_BINDING")
    return signature(key, dict(context=identity(ctx), view=view, phase="proposal",
                               reports=reports, statement=statement, availability=availability))

class Replica:
    """Single-owner reference persistence. Directory/key/caller are trusted.

    SQLite FULL + held advisory lock is a process-crash model, not physical
    anti-rollback attestation. No production owner or Hepta key is used here.
    """
    def __init__(self, path, members, ctx, key, application_check: Callable):
        manifest(members); check_context(ctx, members)
        require(key_id(key) in members["members"] and callable(application_check), "REPLICA_OWNER")
        self.members, self.ctx, self.key = copy.deepcopy(members), copy.deepcopy(ctx), key
        self.application_check = application_check
        path = Path(path)
        require(path.parent.is_dir() and not path.is_symlink(), "STORE_PATH")
        self.lock = os.open(str(path)+".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.lock)
            raise Refusal("STORE_ALREADY_OWNED")
        try:
            self.db = sqlite3.connect(str(path), isolation_level=None)
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS outbox (slot TEXT PRIMARY KEY, value BLOB NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS decisions (context TEXT PRIMARY KEY, value BLOB NOT NULL)")
            stored = self.db.execute("SELECT value FROM state WHERE id=1").fetchone()
            if stored is None:
                self.db.execute("INSERT INTO state VALUES (1,?)", (canonical(self.initial()),))
            else:
                require(decode(stored[0])["context"] == ctx, "STORE_CONTEXT")
            self.fault = None
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            os.close(self.lock)
            raise

    def initial(self):
        return dict(context=self.ctx, view=0, high=None, locked=None, decided=None,
                    epoch_ready=self.members["epoch"] == 0)

    def state(self):
        return decode(self.db.execute("SELECT value FROM state WHERE id=1").fetchone()[0])

    def close(self):
        self.db.close(); os.close(self.lock)

    def _write(self, state, body=None, decision=None):
        signed = None
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if body is not None:
                suffix = (body["value"] if body["phase"] == "availability" else
                          "0" if body["phase"] == "epoch_ready" else str(body["view"]))
                slot = identity(self.ctx)+"/"+body["phase"]+"/"+suffix
                existing = self.db.execute("SELECT value FROM outbox WHERE slot=?", (slot,)).fetchone()
                if existing:
                    signed = decode(existing[0])
                    require(signed["body"] == body, "DOUBLE_SIGN")
                else:
                    signed = signature(self.key, body)
                    self.db.execute("INSERT INTO outbox VALUES (?,?)", (slot, canonical(signed)))
            self.db.execute("UPDATE state SET value=? WHERE id=1", (canonical(state),))
            if decision is not None:
                self.db.execute("INSERT INTO decisions VALUES (?,?)", (identity(self.ctx), canonical(decision)))
            if self.fault == "exit_before_commit":
                os._exit(79)
            if self.fault == "before_commit":
                raise Crash("before_commit")
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        if self.fault == "exit_after_commit":
            os._exit(80)
        if self.fault == "after_commit":
            raise Crash("after_commit_before_send")
        return signed

    def _admit(self, statement, artifact, availability=None):
        value = check_statement(statement, self.ctx)
        require(type(artifact) is bytes and len(artifact) <= MAX_WIRE, "ARTIFACT_LIMIT")
        require(hashlib.sha256(artifact).hexdigest() == statement["model"], "ARTIFACT_BYTES")
        require(self.application_check(copy.deepcopy(statement), artifact) is None, "APPLICATION_PREDICATE")
        if availability is not None:
            require(check_qc(availability, self.ctx, self.members, "availability")["value"] == value, "AVAILABILITY_BINDING")
        return value

    def attest(self, statement, artifact):
        require(self.state()["decided"] is None and self.state()["epoch_ready"], "HEIGHT_CLOSED_OR_EPOCH_PENDING")
        value = self._admit(statement, artifact)
        return self._write(self.state(), vote_body(self.ctx, 0, "availability", value))

    def new_view(self, view):
        integer(view, 1)
        state = self.state()
        require(state["epoch_ready"], "EPOCH_PENDING")
        require(state["decided"] is None and view >= state["view"], "VIEW_REGRESSION_OR_CLOSED")
        state["view"] = view
        return self._write(state, dict(context=identity(self.ctx), view=view, phase="new_view", high=state["high"]))

    def prepare(self, proposed, artifact):
        body = verify_signature(proposed, self.members["members"])
        fields(body, "context view phase reports statement availability")
        view = body["view"]
        require(proposed["signer"] == leader(self.members, view), "LEADER")
        require(body["context"] == identity(self.ctx) and body["phase"] == "proposal", "PROPOSAL_CONTEXT")
        high = high_qc(body["reports"], self.ctx, self.members, view)
        value = self._admit(body["statement"], artifact, body["availability"])
        require(high is None or high["body"]["value"] == value, "HIGHEST_QC_PROPOSAL")
        state = self.state()
        require(state["epoch_ready"] and state["decided"] is None and state["view"] == view, "PROPOSAL_VIEW")
        locked = state["locked"]
        require(locked is None or locked["body"]["value"] == value or
                (high is not None and high["body"]["view"] > locked["body"]["view"]), "LOCKED")
        return self._write(state, vote_body(self.ctx, view, "prepare", value))

    def receive_qc(self, qc, statement, artifact, availability, prepare_qc=None):
        body = check_qc(qc, self.ctx, self.members)
        require(body["phase"] in ("prepare", "precommit", "commit"), "PROTOCOL_QC_PHASE")
        value = self._admit(statement, artifact, availability)
        require(body["value"] == value, "QC_STATEMENT")
        state = self.state()
        require(state["epoch_ready"], "EPOCH_PENDING")
        if body["phase"] == "commit":
            if state["decided"] is not None:
                require(state["decided"] == value, "CONFLICTING_FINALITY")
                return self.decision()
            state["decided"] = value
            bundle = dict(context=self.ctx, statement=statement, availability=availability, commit=qc)
            self._write(state, decision=bundle)
            return self.decision()
        require(state["decided"] is None, "HEIGHT_CLOSED")
        if body["phase"] == "prepare":
            if state["high"] is None or state["high"]["body"]["view"] < body["view"]:
                state["high"] = qc
            if body["view"] != state["view"]:
                self._write(state)
                return None
            locked = state["locked"]
            require(locked is None or locked["body"]["value"] == value or body["view"] > locked["body"]["view"], "LOCKED")
            return self._write(state, vote_body(self.ctx, body["view"], "precommit", value))
        # A recovering voter must have the actual matching prepare QC, not a boolean.
        prior = check_qc(prepare_qc, self.ctx, self.members, "prepare")
        require(prior["view"] == body["view"] and prior["value"] == value, "PRECOMMIT_PREDECESSOR")
        require(body["view"] == state["view"], "PRECOMMIT_VIEW")
        locked = state["locked"]
        require(locked is None or body["view"] > locked["body"]["view"] or locked["body"]["value"] == value, "LOCKED")
        if state["high"] is None or state["high"]["body"]["view"] < prior["view"]:
            state["high"] = prepare_qc
        state["locked"] = qc
        return self._write(state, vote_body(self.ctx, body["view"], "commit", value))

    def decision(self):
        row = self.db.execute("SELECT value FROM decisions WHERE context=?", (identity(self.ctx),)).fetchone()
        require(row is not None, "NOT_DECIDED")
        return decode(row[0])

    def acknowledge_epoch(self, bundle, old_ctx, old_members, artifact):
        body = handoff_body(bundle, old_ctx, old_members, self.members)
        expected = context(self.members, old_ctx["height"]+1,
                           identity(bundle["statement"]), bundle["statement"]["model"])
        require(self.ctx == expected and self.state()["view"] == 0, "EPOCH_ENTRY")
        require(type(artifact) is bytes and len(artifact) <= MAX_WIRE and
                hashlib.sha256(artifact).hexdigest() == bundle["statement"]["model"], "HANDOFF_ARTIFACT")
        require(bundle["statement"]["retention_height"] >= self.ctx["height"], "HANDOFF_RETENTION")
        require(self.application_check(copy.deepcopy(bundle["statement"]), artifact) is None, "APPLICATION_PREDICATE")
        return self._write(self.state(), body)

    def activate_epoch(self, bundle, old_ctx, old_members, acks):
        expected = verify_handoff(bundle, old_ctx, old_members, self.members, acks)
        require(expected == self.ctx and self.state()["view"] == 0, "EPOCH_ENTRY")
        state = self.state(); state["epoch_ready"] = True
        self._write(state)

    def advance(self):
        old = self.decision()
        require(old["statement"]["next_committee"] is None, "EPOCH_SEALED")
        previous = self.ctx
        self.ctx = context(self.members, previous["height"]+1,
                           identity(old["statement"]), old["statement"]["model"])
        try:
            next_state = self.initial(); next_state["epoch_ready"] = True
            self._write(next_state)
        except BaseException:
            self.ctx = previous
            raise
        return copy.deepcopy(self.ctx)


def verify_decision(bundle, trusted_ctx, trusted_members):
    fields(bundle, "context statement availability commit")
    check_context(trusted_ctx, trusted_members)
    require(bundle["context"] == trusted_ctx, "TRUSTED_CONTEXT")
    value = check_statement(bundle["statement"], trusted_ctx)
    require(check_qc(bundle["availability"], trusted_ctx, trusted_members, "availability")["value"] == value, "AVAILABILITY_BINDING")
    require(check_qc(bundle["commit"], trusted_ctx, trusted_members, "commit")["value"] == value, "COMMIT_BINDING")
    return dict(value=value, finality_certificate_valid=True, model_quality_accepted=False,
                long_term_availability_accepted=False, hepta_final_use=False, production_activation=False)


def handoff_body(bundle, old_ctx, old_members, new_members):
    verify_decision(bundle, old_ctx, old_members); manifest(new_members)
    require(new_members["genesis"] == old_members["genesis"] and
            new_members["epoch"] == old_members["epoch"]+1, "EPOCH_SUCCESSOR")
    require(bundle["statement"]["next_committee"] == identity(new_members), "HANDOFF_MANIFEST")
    return dict(phase="epoch_ready", predecessor=identity(bundle["statement"]),
                old_context=identity(old_ctx), new_committee=identity(new_members))


def verify_handoff(bundle, old_ctx, old_members, new_members, acks):
    body = handoff_body(bundle, old_ctx, old_members, new_members)
    require(type(acks) is list and new_members["quorum"] <= len(acks) <= len(new_members["members"]), "HANDOFF_QUORUM")
    ids = []
    for ack in acks:
        require(verify_signature(ack, new_members["members"]) == body, "HANDOFF_BINDING")
        ids.append(ack["signer"])
    require(ids == sorted(set(ids)), "HANDOFF_DUPLICATE")
    return context(new_members, old_ctx["height"]+1, identity(bundle["statement"]), bundle["statement"]["model"])
