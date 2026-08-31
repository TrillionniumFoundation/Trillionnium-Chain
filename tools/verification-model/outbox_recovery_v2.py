#!/usr/bin/env python3
"""Candidate-only durable outbox/retry/appeal assurance model for G2C."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field


class Reject(ValueError):
    pass


def digest(*parts: object) -> str:
    h = hashlib.sha256()
    h.update(b"trnm.g2c.outbox.v2\x00")
    for part in parts:
        raw = str(part).encode("utf-8")
        h.update(len(raw).to_bytes(4, "big"))
        h.update(raw)
    return h.hexdigest()


@dataclass
class OutboxEventV2:
    event_id: str
    result_id: str
    kind: str
    sequence: int
    payload_digest: str
    created_height: int
    retry_after_height: int
    attempts: int = 0
    status: str = "pending"
    delivery_token: str | None = None


@dataclass
class ResultLifecycleV2:
    result_id: str
    challenge_deadline: int
    status: str = "ChallengeWindow"
    challenge_active: bool = False
    appeal_count: int = 0
    final_decision: str | None = None


@dataclass
class DurableOutboxV2:
    events: dict[str, OutboxEventV2] = field(default_factory=dict)
    next_sequence: int = 0
    quarantined: bool = False

    def enqueue(self, *, result_id: str, kind: str, payload_digest: str, height: int, retry_delay: int) -> OutboxEventV2:
        self._healthy()
        if not result_id or not kind or len(payload_digest) != 64:
            raise Reject("event-shape")
        if height < 0 or retry_delay <= 0:
            raise Reject("event-bounds")
        event_id = digest(result_id, kind)
        existing = self.events.get(event_id)
        if existing is not None:
            if existing.payload_digest != payload_digest:
                self.quarantined = True
                raise Reject("event-id-conflict")
            return existing
        event = OutboxEventV2(event_id, result_id, kind, self.next_sequence, payload_digest, height, height)
        self.events[event_id] = event
        self.next_sequence += 1
        return event

    def dispatch(self, event_id: str, height: int) -> str:
        self._healthy()
        event = self._event(event_id)
        if event.status == "acked":
            return event.delivery_token or ""
        if event.status not in {"pending", "sent"}:
            raise Reject("dispatch-state")
        if height < event.retry_after_height:
            raise Reject("retry-too-early")
        event.attempts += 1
        event.status = "sent"
        event.delivery_token = digest(event.event_id, event.sequence, event.payload_digest, event.attempts)
        event.retry_after_height = height + 2
        return event.delivery_token

    def recover_response_loss(self, event_id: str, height: int) -> None:
        self._healthy()
        event = self._event(event_id)
        if event.status != "sent":
            raise Reject("recover-state")
        if height < event.retry_after_height:
            raise Reject("retry-too-early")
        event.status = "pending"

    def acknowledge(self, event_id: str, delivery_token: str) -> None:
        self._healthy()
        event = self._event(event_id)
        if event.status == "acked":
            if delivery_token != event.delivery_token:
                self.quarantined = True
                raise Reject("acked-token-conflict")
            return
        if event.status != "sent" or delivery_token != event.delivery_token:
            raise Reject("delivery-token")
        event.status = "acked"

    def ordered_commitment(self) -> str:
        self._healthy()
        rows = [(e.sequence, e.event_id, e.result_id, e.kind, e.payload_digest, e.attempts, e.status, e.delivery_token) for e in sorted(self.events.values(), key=lambda row: row.sequence)]
        if [row[0] for row in rows] != list(range(len(rows))):
            self.quarantined = True
            raise Reject("sequence-gap-or-reuse")
        return digest(json.dumps(rows, separators=(",", ":"), sort_keys=False))

    def _event(self, event_id: str) -> OutboxEventV2:
        event = self.events.get(event_id)
        if event is None:
            raise Reject("unknown-event")
        return event

    def _healthy(self) -> None:
        if self.quarantined:
            raise Reject("outbox-quarantined")


def open_challenge(result: ResultLifecycleV2, height: int) -> None:
    if result.status != "ChallengeWindow" or result.challenge_active:
        raise Reject("challenge-conflict")
    if height > result.challenge_deadline:
        raise Reject("challenge-late")
    result.challenge_active = True
    result.status = "ChallengeOpened"


def decide_challenge(result: ResultLifecycleV2, *, upheld: bool) -> None:
    if result.status not in {"ChallengeOpened", "AppealPending"} or not result.challenge_active:
        raise Reject("decision-state")
    result.challenge_active = False
    result.final_decision = "ResultRejected" if upheld else "ResultFinal"
    result.status = result.final_decision


def open_appeal(result: ResultLifecycleV2) -> None:
    if result.status not in {"ResultRejected", "ResultFinal"}:
        raise Reject("appeal-state")
    if result.appeal_count >= 1:
        raise Reject("appeal-limit")
    result.appeal_count += 1
    result.challenge_active = True
    result.status = "AppealPending"


def finalize_unchallenged(result: ResultLifecycleV2, height: int) -> None:
    if result.status != "ChallengeWindow" or result.challenge_active:
        raise Reject("finalize-state")
    if height <= result.challenge_deadline:
        raise Reject("not-mature")
    result.status = "ResultFinal"
    result.final_decision = "ResultFinal"


def self_test() -> dict[str, object]:
    outbox = DurableOutboxV2()
    result = ResultLifecycleV2("result-1", challenge_deadline=10)
    payload = digest("payload-1")
    event = outbox.enqueue(result_id=result.result_id, kind="VerificationDecision", payload_digest=payload, height=1, retry_delay=2)
    assert outbox.enqueue(result_id=result.result_id, kind="VerificationDecision", payload_digest=payload, height=1, retry_delay=2) is event
    token1 = outbox.dispatch(event.event_id, 1)
    outbox.recover_response_loss(event.event_id, 3)
    token2 = outbox.dispatch(event.event_id, 3)
    assert token1 != token2
    outbox.acknowledge(event.event_id, token2)
    outbox.acknowledge(event.event_id, token2)
    root1 = outbox.ordered_commitment()
    assert root1 == outbox.ordered_commitment()

    open_challenge(result, 5)
    decide_challenge(result, upheld=True)
    open_appeal(result)
    decide_challenge(result, upheld=False)
    assert result.status == "ResultFinal"

    mature = ResultLifecycleV2("result-2", challenge_deadline=4)
    finalize_unchallenged(mature, 5)

    negatives: list[dict[str, str]] = []
    def reject(name: str, fn) -> None:
        try:
            fn()
        except Reject as exc:
            negatives.append({"case": name, "error": str(exc)})
        else:
            raise AssertionError(f"accepted:{name}")

    reject("unknown-event", lambda: outbox.dispatch("missing", 5))
    early_box = DurableOutboxV2()
    early = early_box.enqueue(result_id="early", kind="Decision", payload_digest=digest("early"), height=1, retry_delay=1)
    early_box.dispatch(early.event_id, 1)
    reject("retry-too-early", lambda: early_box.recover_response_loss(early.event_id, 2))
    reject("duplicate-appeal", lambda: open_appeal(result))
    reject("premature-finalize", lambda: finalize_unchallenged(ResultLifecycleV2("r3", 10), 10))
    reject("late-challenge", lambda: open_challenge(ResultLifecycleV2("r4", 4), 5))
    conflict = DurableOutboxV2()
    conflict.enqueue(result_id="r5", kind="Decision", payload_digest=digest("a"), height=1, retry_delay=1)
    reject("event-id-conflict", lambda: conflict.enqueue(result_id="r5", kind="Decision", payload_digest=digest("b"), height=1, retry_delay=1))
    token_box = DurableOutboxV2()
    token_event = token_box.enqueue(result_id="r6", kind="Decision", payload_digest=digest("c"), height=1, retry_delay=1)
    token_box.dispatch(token_event.event_id, 1)
    reject("delivery-token-mismatch", lambda: token_box.acknowledge(token_event.event_id, digest("wrong")))
    gap_box = DurableOutboxV2()
    gap_event = gap_box.enqueue(result_id="r7", kind="Decision", payload_digest=digest("d"), height=1, retry_delay=1)
    gap_event.sequence = 2
    reject("sequence-gap-or-reuse", gap_box.ordered_commitment)

    return {
        "schema": "trnm-g2c-outbox-recovery-evidence-v2",
        "positive": 10,
        "negative": negatives,
        "outbox_root": root1,
        "final_status": result.status,
        "unchallenged_status": mature.status,
        "candidate_only": True,
        "economic_authority": False,
        "order_reorg_authority": False,
        "governance_authority": False,
        "production_activation": False
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.self_test:
        raise SystemExit("use --self-test")
    print(json.dumps(self_test(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
