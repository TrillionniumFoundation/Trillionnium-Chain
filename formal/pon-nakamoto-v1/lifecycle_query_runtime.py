"""LQC1 reference dispatch/cache owner; never a world-complete query meter.

This instruments actual frozen MU1 terminal SHA-256 calls in one Python flow.
It does not mediate another process, prevent private precomputation, authenticate
an actor label, or implement a quantum oracle. Its phase barrier is shared by
all participants of this owner and cannot be reset by a helper/cache read.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import struct

import mandatory_units_relation as mu
from lifecycle_query_bound import LifetimeCaps, UNATTESTED


DOMAIN = b"TRNM-PON-LQC1\0"
_MU_HASH = mu.mu_hash


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _hash32(value: bytes) -> bytes:
    _need(type(value) is bytes and len(value) == 32, "TERMINAL_ADDRESS")
    return value


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class TerminalAddress:
    context_digest: bytes
    ordered_root: bytes
    identity: bytes


def terminal_address_without_ticket(raw: bytes, expected: mu.Context) -> TerminalAddress:
    """Frozen framing/nonterminal hashes only; NO unit or ticket validity result.

    This is the oracle-free output extractor used by the proof. Full unit
    validity is still checked by the native verifier in an actual emission.
    Tests compare every extracted byte with frozen inspect_packet.
    """
    expected_raw = mu.encode_context(expected)
    _need(type(raw) is bytes and len(raw) == mu.PACKET_BASE_BYTES
          + expected.units * mu.PACKET_UNIT_BYTES, "PACKET_LENGTH")
    _need(raw[:6] == mu.PACKET_MAGIC + struct.pack("<H", mu.VERSION), "PACKET_VERSION")
    end = 6 + len(expected_raw)
    _need(raw[6:end] == expected_raw, "EXPECTED_CONTEXT")
    _need(mu.decode_context(raw[6:end]) == expected, "EXPECTED_CONTEXT")
    digest = _MU_HASH(b"context", expected_raw)
    offset, leaves = end, []
    for j, task in enumerate(expected.tasks):
        _need(struct.unpack_from("<H", raw, offset)[0] == j, "UNIT_ORDER")
        _need(raw[offset + 2:offset + 34] == task, "UNIT_TASK_BINDING")
        proof = raw[offset + 34:offset + mu.UNIT_RECORD_BYTES]
        _need(len(proof) == mu.w1.PROOF_BYTES and proof[:4] == b"PNW1", "UNIT_ENCODING")
        leaves.append(_MU_HASH(b"unit-output", struct.pack("<H", j), task, proof))
        offset += mu.UNIT_RECORD_BYTES
    _need(offset == len(raw), "PACKET_TRAILING")
    root = _MU_HASH(b"ordered-units", digest, b"".join(leaves))
    return TerminalAddress(digest, root, _MU_HASH(b"identity", digest, root))


@dataclass(frozen=True)
class CacheReference:
    scope: str
    context_digest: bytes
    ordered_root: bytes
    origin_sequence: int
    ticket: bytes


class ReferenceQueryOwner:
    """A single bounded reference execution, not an adversarial security root.

    A new owner does NOT inherit a prior owner's paid/fresh status. Its empty
    dictionary is not evidence of an oracle-independent joint initial state.
    Hash-chained records and structural references are deliberately unsigned;
    they are not claimed to authenticate execution, physical cost or origin.
    """
    def __init__(self, scope: str, caps: LifetimeCaps):
        _need(type(scope) is str and 0 < len(scope) <= 128, "SCOPE")
        _need(type(caps) is LifetimeCaps, "LIFETIME_CAPS_TYPE")
        caps.check()
        _need(caps.domain_size == 1 << 512, "ACTUAL_MU1_TERMINAL_DOMAIN")
        self.scope, self.caps = scope, caps
        self.phase = "classical-prefix"
        self.prefix_used = self.post_used = self.outputs_used = 0
        self.hash_evaluations = self.cache_reads = self.total_credit = 0
        self._cache: dict[tuple[bytes, bytes], CacheReference] = {}
        self._credited: dict[bytes, int] = {}
        self.events: list[dict] = []
        self.emissions: list[dict] = []
        self._record("open-reference-scope", {
            "C": caps.classical_prefix_C, "Q": caps.post_prefix_Q,
            "M": caps.complete_outputs_M, "declared_before_this_owner_first_call": True})

    def _record(self, kind: str, details: dict) -> int:
        sequence = len(self.events) + 1
        body = {"schema": "pon-lifecycle-query-reference-event-v1", "scope": self.scope,
                "sequence": sequence, "previous": self.events[-1]["event_hash"]
                if self.events else "0" * 64, "kind": kind, "phase": self.phase,
                "details": details}
        self.events.append({**body, "event_hash": hashlib.sha256(DOMAIN + canonical(body)).hexdigest()})
        return sequence

    def begin_post_prefix(self) -> None:
        _need(self.phase == "classical-prefix", "PREFIX_ALREADY_CLOSED")
        self.phase = "post-prefix"
        self._record("irreversible-shared-phase-barrier", {
            "actual_quantum_query_observed": False,
            "world_first_coherent_query_attested": False})

    def query(self, digest: bytes, root: bytes, actor: str = "reference") -> bytes:
        key = (_hash32(digest), _hash32(root))
        _need(type(actor) is str and 0 < len(actor) <= 128, "ACTOR_LABEL")
        prior = self._cache.get(key)
        if prior is not None:
            return self.read_reference(prior, actor)
        used, cap = ((self.prefix_used, self.caps.classical_prefix_C)
                     if self.phase == "classical-prefix" else
                     (self.post_used, self.caps.post_prefix_Q))
        if used >= cap:
            self._record("denied-before-hash", {"reason": "QUERY_CAP", "actor": actor})
            raise ValueError("QUERY_CAP")
        if self.phase == "classical-prefix":
            self.prefix_used += 1
        else:
            self.post_used += 1
        self.hash_evaluations += 1
        ticket = _MU_HASH(b"ticket", *key)
        sequence = self._record("actual-terminal-sha256", {
            "actor_label": actor, "context_digest": digest.hex(), "ordered_root": root.hex(),
            "ticket": ticket.hex(), "marked": ticket <= mu.T0,
            "resource_kind": "reference-full-value-terminal-call"})
        self._cache[key] = CacheReference(self.scope, *key, sequence, ticket)
        return ticket

    def reference(self, digest: bytes, root: bytes) -> CacheReference:
        key = (_hash32(digest), _hash32(root))
        _need(key in self._cache, "UNOBSERVED_CACHE_ORIGIN")
        return self._cache[key]

    def read_reference(self, ref: CacheReference, actor: str = "helper") -> bytes:
        _need(type(ref) is CacheReference and ref.scope == self.scope, "FOREIGN_CACHE_SCOPE")
        _need(type(actor) is str and 0 < len(actor) <= 128, "ACTOR_LABEL")
        key = (_hash32(ref.context_digest), _hash32(ref.ordered_root))
        _need(self._cache.get(key) == ref, "UNOBSERVED_OR_CHANGED_CACHE_ORIGIN")
        self.cache_reads += 1
        self._record("shared-cache-read", {"actor_label": actor,
                     "origin_sequence": ref.origin_sequence, "adds_query_charge": 0})
        return ref.ticket

    @contextmanager
    def intercept_frozen_terminal(self, actor: str = "reference"):
        """Single-thread reference instrumentation, not a sandbox or OS hook."""
        _need(mu.mu_hash is _MU_HASH, "TERMINAL_HOOK_ALREADY_ACTIVE")

        def routed(tag, *parts):
            if tag == b"ticket":
                _need(len(parts) == 2, "TERMINAL_ADDRESS")
                return self.query(parts[0], parts[1], actor)
            return _MU_HASH(tag, *parts)

        mu.mu_hash = routed
        try:
            yield
        finally:
            mu.mu_hash = _MU_HASH

    def emit_native(self, packet: bytes, context: mu.Context, native_verifier: str,
                    actor: str = "publisher") -> dict:
        """Every complete emission consumes M; duplicates receive zero credit."""
        _need(self.outputs_used < self.caps.complete_outputs_M, "OUTPUT_CAP")
        self.outputs_used += 1
        output_index = self.outputs_used - 1
        packet_hash = hashlib.sha256(packet).hexdigest()
        self._record("complete-output-attempt", {"output_index": output_index,
                     "packet_sha256": packet_hash, "actor_label": actor})
        try:
            address = terminal_address_without_ticket(packet, context)
            with self.intercept_frozen_terminal(actor):
                verified = mu.verify_packet(packet, context, backend="native",
                                            native_verifier=native_verifier)
            _need(verified.identity == address.identity, "EXTRACTOR_IDENTITY_MISMATCH")
            previous = self._credited.get(verified.identity)
            _need(previous is None or previous == verified.credit, "IDENTITY_CREDIT_CONFLICT")
            added = verified.credit if previous is None else 0
            self._credited[verified.identity] = verified.credit
            self.total_credit += added
            row = {"accepted": True, "reason": "VALID_MU1", "credit_added": added,
                   "identity": verified.identity.hex(), "full_native_units_checked": context.units}
        except (ValueError, mu.RelationError) as error:
            row = {"accepted": False, "reason": str(error), "credit_added": 0,
                   "full_native_units_checked": context.units if str(error) == "AGGREGATE_TARGET" else None}
        row = {"output_index": output_index, "packet_sha256": packet_hash,
               "actor_label": actor, **row}
        self.emissions.append(row)
        self._record("complete-output-result", row)
        return row

    def global_budget_certificate(self):
        raise ValueError("GLOBAL_QUERY_CLOSURE_AND_JOINT_INITIAL_STATE_UNATTESTED")

    def report(self) -> dict:
        return {"schema": "pon-lifecycle-query-reference-report-v1", "scope": self.scope,
                "phase": self.phase, "declared_caps": {
                    "C": self.caps.classical_prefix_C, "Q": self.caps.post_prefix_Q,
                    "M": self.caps.complete_outputs_M},
                "reference_prefix_distinct_calls": self.prefix_used,
                "reference_post_prefix_calls": self.post_used,
                "reference_sha256_evaluations": self.hash_evaluations,
                "reference_cache_reads": self.cache_reads,
                "complete_emissions_including_duplicates": self.outputs_used,
                "unique_research_credit": self.total_credit,
                "checkpoint": {"scope": self.scope, "sequence": len(self.events),
                               "head_hash": self.events[-1]["event_hash"]},
                "reference_cap_checks_pass": (self.prefix_used <= self.caps.classical_prefix_C
                    and self.post_used <= self.caps.post_prefix_Q
                    and self.outputs_used <= self.caps.complete_outputs_M),
                "actor_labels_authenticated": False, "records_execution_attested": False,
                "actual_quantum_query_observed": False,
                "global_first_coherent_query_attested": False,
                **UNATTESTED}
