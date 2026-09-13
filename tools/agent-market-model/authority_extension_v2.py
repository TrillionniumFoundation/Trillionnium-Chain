#!/usr/bin/env python3
"""Candidate-only A12 authority/scope extension model.

This model is deliberately non-cryptographic. It freezes deterministic state,
attenuation, controller-generation and recovery-quorum semantics for later
CEV1/Rust implementations. It cannot create production authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable


class Reject(ValueError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _digest(domain: bytes, value: object) -> str:
    h = hashlib.sha256()
    h.update(domain)
    raw = _canonical(value)
    h.update(len(raw).to_bytes(8, "big"))
    h.update(raw)
    return h.hexdigest()


@dataclass(frozen=True)
class ResourceScopeV2:
    models: frozenset[str]
    tools: frozenset[str]
    endpoints: frozenset[str]
    privacy_classes: frozenset[str]

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "models": sorted(self.models),
            "tools": sorted(self.tools),
            "endpoints": sorted(self.endpoints),
            "privacy_classes": sorted(self.privacy_classes),
        }

    def attenuates(self, parent: "ResourceScopeV2") -> bool:
        return (
            self.models.issubset(parent.models)
            and self.tools.issubset(parent.tools)
            and self.endpoints.issubset(parent.endpoints)
            and self.privacy_classes.issubset(parent.privacy_classes)
        )


@dataclass
class CapabilityV2:
    capability_id: str
    generation: int
    operations: frozenset[str]
    lanes: frozenset[int]
    spend_limit: int
    scope: ResourceScopeV2
    revoked: bool = False


@dataclass
class SessionV2:
    session_id: str
    capability_id: str
    controller_generation: int
    capability_generation: int
    lanes: frozenset[int]
    scope: ResourceScopeV2
    revoked: bool = False


@dataclass
class ControllerAuthorityV2:
    agent_id: str
    controller_key: str
    controller_generation: int
    recovery_keys: frozenset[str]
    recovery_threshold: int
    capabilities: dict[str, CapabilityV2] = field(default_factory=dict)
    sessions: dict[str, SessionV2] = field(default_factory=dict)
    consumed_rotation_ids: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not self.agent_id or not self.controller_key:
            raise Reject("identity")
        if self.controller_generation <= 0:
            raise Reject("controller-generation")
        if not self.recovery_keys:
            raise Reject("recovery-keys")
        if self.recovery_threshold <= 0 or self.recovery_threshold > len(self.recovery_keys):
            raise Reject("recovery-threshold")

    def state_commitment(self) -> str:
        return _digest(
            b"trnm.agent-market.authority-state.v2\x00",
            {
                "agent_id": self.agent_id,
                "controller_key": self.controller_key,
                "controller_generation": self.controller_generation,
                "recovery_keys": sorted(self.recovery_keys),
                "recovery_threshold": self.recovery_threshold,
                "capabilities": [
                    {
                        "capability_id": item.capability_id,
                        "generation": item.generation,
                        "operations": sorted(item.operations),
                        "lanes": sorted(item.lanes),
                        "spend_limit": item.spend_limit,
                        "scope": item.scope.as_dict(),
                        "revoked": item.revoked,
                    }
                    for item in sorted(self.capabilities.values(), key=lambda row: row.capability_id)
                ],
                "sessions": [
                    {
                        "session_id": item.session_id,
                        "capability_id": item.capability_id,
                        "controller_generation": item.controller_generation,
                        "capability_generation": item.capability_generation,
                        "lanes": sorted(item.lanes),
                        "scope": item.scope.as_dict(),
                        "revoked": item.revoked,
                    }
                    for item in sorted(self.sessions.values(), key=lambda row: row.session_id)
                ],
            },
        )

    def add_capability(self, capability: CapabilityV2) -> None:
        if capability.capability_id in self.capabilities:
            raise Reject("duplicate-capability")
        if capability.generation <= 0 or capability.spend_limit <= 0:
            raise Reject("capability-shape")
        if not capability.operations or not capability.lanes:
            raise Reject("capability-shape")
        self.capabilities[capability.capability_id] = capability

    def add_session(self, session: SessionV2) -> None:
        if session.session_id in self.sessions:
            raise Reject("duplicate-session")
        capability = self.capabilities.get(session.capability_id)
        if capability is None or capability.revoked:
            raise Reject("capability-missing-or-revoked")
        if session.controller_generation != self.controller_generation:
            raise Reject("controller-generation-mismatch")
        if session.capability_generation != capability.generation:
            raise Reject("capability-generation-mismatch")
        if not session.lanes or not session.lanes.issubset(capability.lanes):
            raise Reject("lane-escalation")
        if not session.scope.attenuates(capability.scope):
            raise Reject("resource-scope-escalation")
        self.sessions[session.session_id] = session

    def authorize_session(self, session_id: str) -> SessionV2:
        session = self.sessions.get(session_id)
        if session is None or session.revoked:
            raise Reject("session-missing-or-revoked")
        capability = self.capabilities.get(session.capability_id)
        if capability is None or capability.revoked:
            raise Reject("capability-missing-or-revoked")
        if session.controller_generation != self.controller_generation:
            raise Reject("stale-controller-generation")
        if session.capability_generation != capability.generation:
            raise Reject("stale-capability-generation")
        if not session.scope.attenuates(capability.scope):
            raise Reject("resource-scope-escalation")
        return session

    def rotate_controller(
        self,
        *,
        current_key: str,
        expected_generation: int,
        new_key: str,
        rotation_id: str,
    ) -> str:
        if current_key != self.controller_key:
            raise Reject("controller-authority")
        return self._apply_rotation(expected_generation, new_key, rotation_id)

    def recover_controller(
        self,
        *,
        recovery_signers: Iterable[str],
        expected_generation: int,
        new_key: str,
        rotation_id: str,
    ) -> str:
        signers = list(recovery_signers)
        if len(signers) != len(set(signers)):
            raise Reject("duplicate-recovery-signer")
        if not set(signers).issubset(self.recovery_keys):
            raise Reject("unknown-recovery-signer")
        if len(signers) < self.recovery_threshold:
            raise Reject("insufficient-recovery-quorum")
        return self._apply_rotation(expected_generation, new_key, rotation_id)

    def _apply_rotation(self, expected_generation: int, new_key: str, rotation_id: str) -> str:
        if not new_key or new_key == self.controller_key:
            raise Reject("new-controller-key")
        if expected_generation != self.controller_generation:
            raise Reject("stale-controller-generation")
        if not rotation_id or rotation_id in self.consumed_rotation_ids:
            raise Reject("rotation-replay")
        self.consumed_rotation_ids.add(rotation_id)
        self.controller_key = new_key
        self.controller_generation += 1
        for session in self.sessions.values():
            session.revoked = True
        return self.state_commitment()


def child_scope(parent: ResourceScopeV2, **overrides: frozenset[str]) -> ResourceScopeV2:
    candidate = ResourceScopeV2(
        models=overrides.get("models", parent.models),
        tools=overrides.get("tools", parent.tools),
        endpoints=overrides.get("endpoints", parent.endpoints),
        privacy_classes=overrides.get("privacy_classes", parent.privacy_classes),
    )
    if not candidate.attenuates(parent):
        raise Reject("resource-scope-escalation")
    return candidate


def self_test() -> dict[str, object]:
    parent = ResourceScopeV2(
        models=frozenset({"model/a", "model/b"}),
        tools=frozenset({"tool/search", "tool/calc"}),
        endpoints=frozenset({"endpoint/inference", "endpoint/storage"}),
        privacy_classes=frozenset({"public", "confidential"}),
    )
    authority = ControllerAuthorityV2(
        agent_id="agent-1",
        controller_key="controller-1",
        controller_generation=1,
        recovery_keys=frozenset({"recovery-1", "recovery-2", "recovery-3"}),
        recovery_threshold=2,
    )
    capability = CapabilityV2(
        capability_id="cap-1",
        generation=1,
        operations=frozenset({"create-task", "cancel-task"}),
        lanes=frozenset({1, 2}),
        spend_limit=1000,
        scope=parent,
    )
    authority.add_capability(capability)
    scoped = child_scope(
        parent,
        models=frozenset({"model/a"}),
        tools=frozenset({"tool/search"}),
        endpoints=frozenset({"endpoint/inference"}),
        privacy_classes=frozenset({"confidential"}),
    )
    authority.add_session(
        SessionV2(
            session_id="session-1",
            capability_id="cap-1",
            controller_generation=1,
            capability_generation=1,
            lanes=frozenset({1}),
            scope=scoped,
        )
    )
    first_root = authority.state_commitment()
    assert first_root == authority.state_commitment()
    authority.authorize_session("session-1")
    second_root = authority.rotate_controller(
        current_key="controller-1",
        expected_generation=1,
        new_key="controller-2",
        rotation_id="rotation-1",
    )
    assert second_root != first_root

    negatives: list[dict[str, str]] = []

    def reject(name: str, fn) -> None:
        try:
            fn()
        except Reject as exc:
            negatives.append({"case": name, "error": str(exc)})
        else:
            raise AssertionError(f"accepted:{name}")

    reject("old-session-after-rotation", lambda: authority.authorize_session("session-1"))
    reject(
        "stale-controller-generation",
        lambda: authority.rotate_controller(
            current_key="controller-2",
            expected_generation=1,
            new_key="controller-3",
            rotation_id="rotation-2",
        ),
    )
    reject(
        "wrong-controller",
        lambda: authority.rotate_controller(
            current_key="controller-x",
            expected_generation=2,
            new_key="controller-3",
            rotation_id="rotation-2",
        ),
    )
    reject(
        "rotation-replay",
        lambda: authority.rotate_controller(
            current_key="controller-2",
            expected_generation=2,
            new_key="controller-3",
            rotation_id="rotation-1",
        ),
    )
    reject(
        "insufficient-recovery-quorum",
        lambda: authority.recover_controller(
            recovery_signers=["recovery-1"],
            expected_generation=2,
            new_key="controller-3",
            rotation_id="rotation-3",
        ),
    )
    reject(
        "duplicate-recovery-signer",
        lambda: authority.recover_controller(
            recovery_signers=["recovery-1", "recovery-1"],
            expected_generation=2,
            new_key="controller-3",
            rotation_id="rotation-3",
        ),
    )
    reject(
        "unknown-recovery-signer",
        lambda: authority.recover_controller(
            recovery_signers=["recovery-1", "unknown"],
            expected_generation=2,
            new_key="controller-3",
            rotation_id="rotation-3",
        ),
    )
    reject(
        "model-scope-escalation",
        lambda: child_scope(parent, models=frozenset({"model/a", "model/c"})),
    )
    reject(
        "tool-scope-escalation",
        lambda: child_scope(parent, tools=frozenset({"tool/search", "tool/admin"})),
    )
    reject(
        "endpoint-scope-escalation",
        lambda: child_scope(parent, endpoints=frozenset({"endpoint/inference", "endpoint/root"})),
    )
    reject(
        "privacy-scope-escalation",
        lambda: child_scope(parent, privacy_classes=frozenset({"public", "secret"})),
    )

    recovered_root = authority.recover_controller(
        recovery_signers=["recovery-1", "recovery-3"],
        expected_generation=2,
        new_key="controller-3",
        rotation_id="rotation-3",
    )
    assert recovered_root != second_root
    return {
        "schema": "trnm-agent-market-authority-extension-evidence-v2",
        "positive": 7,
        "negative": negatives,
        "controller_generation": authority.controller_generation,
        "state_commitment": authority.state_commitment(),
        "candidate_only": True,
        "cryptographic_authority": False,
        "global_state_authority": False,
        "production_activation": False,
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
