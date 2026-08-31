#!/usr/bin/env python3
"""Candidate-only owner-issued immutable ManifestView commitment model.

The HMAC issuer represents a separately administered owner in this assurance
model. It is not a production HSM, governance key, finality proof or JMT
commissioning authority.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from dataclasses import asdict, dataclass


class Reject(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def hash_value(domain: bytes, value: object) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    raw = canonical(value)
    digest.update(len(raw).to_bytes(8, "big"))
    digest.update(raw)
    return digest.hexdigest()


def hex64(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


@dataclass(frozen=True)
class PlaneViewV2:
    plane: str
    generation: int
    source_identity: str
    state_root: str

    def validate(self) -> None:
        if not self.plane or not isinstance(self.generation, int) or self.generation < 0:
            raise Reject("plane-view-shape")
        if not hex64(self.source_identity) or not hex64(self.state_root):
            raise Reject("plane-view-digest")


@dataclass(frozen=True)
class ManifestViewV2:
    namespace_id: str
    predecessor_checkpoint: str
    height: int
    order_header_hash: str
    application_root: str
    manifest_hash: str
    planes: tuple[PlaneViewV2, ...]
    nonce: int
    view_version: int = 2

    def validate(self) -> None:
        if not self.namespace_id or not isinstance(self.height, int) or self.height <= 0:
            raise Reject("manifest-view-shape")
        if not isinstance(self.nonce, int) or self.nonce < 0 or self.view_version != 2:
            raise Reject("manifest-view-shape")
        for name, value in (
            ("predecessor", self.predecessor_checkpoint),
            ("order-header", self.order_header_hash),
            ("application-root", self.application_root),
            ("manifest", self.manifest_hash),
        ):
            if not hex64(value):
                raise Reject(name)
        if not self.planes:
            raise Reject("planes-empty")
        plane_names = [plane.plane for plane in self.planes]
        if plane_names != sorted(plane_names) or len(plane_names) != len(set(plane_names)):
            raise Reject("planes-order-or-duplicate")
        for plane in self.planes:
            plane.validate()

    def commitment(self) -> str:
        self.validate()
        return hash_value(
            b"trnm.g2f.manifest-view.v2\x00",
            {
                "namespace_id": self.namespace_id,
                "predecessor_checkpoint": self.predecessor_checkpoint,
                "height": self.height,
                "order_header_hash": self.order_header_hash,
                "application_root": self.application_root,
                "manifest_hash": self.manifest_hash,
                "planes": [asdict(plane) for plane in self.planes],
                "nonce": self.nonce,
                "view_version": self.view_version,
            },
        )


@dataclass(frozen=True)
class OwnerViewPermitV2:
    key_id: str
    permit_id: str
    view_commitment: str
    issued_height: int
    expires_after_height: int
    token: str


class OwnerViewIssuerV2:
    def __init__(self, key_id: str, secret: bytes) -> None:
        if not key_id or len(secret) < 32:
            raise Reject("issuer-shape")
        self.key_id = key_id
        self._secret = bytes(secret)
        self._used_permits: set[str] = set()

    def issue(self, view: ManifestViewV2, *, issued_height: int, ttl: int) -> OwnerViewPermitV2:
        view_commitment = view.commitment()
        if issued_height < 0 or ttl <= 0:
            raise Reject("permit-window")
        expires_after_height = issued_height + ttl
        permit_id = hash_value(
            b"trnm.g2f.view-permit-id.v2\x00",
            {
                "key_id": self.key_id,
                "view_commitment": view_commitment,
                "issued_height": issued_height,
                "expires_after_height": expires_after_height,
            },
        )
        unsigned = {
            "key_id": self.key_id,
            "permit_id": permit_id,
            "view_commitment": view_commitment,
            "issued_height": issued_height,
            "expires_after_height": expires_after_height,
        }
        token = hmac.new(
            self._secret,
            b"trnm.g2f.view-permit-token.v2\x00" + canonical(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return OwnerViewPermitV2(token=token, **unsigned)

    def verify_and_consume(
        self,
        permit: OwnerViewPermitV2,
        view: ManifestViewV2,
        *,
        current_height: int,
    ) -> str:
        if permit.key_id != self.key_id:
            raise Reject("issuer-key")
        if current_height < permit.issued_height or current_height > permit.expires_after_height:
            raise Reject("permit-expired-or-not-yet-valid")
        view_commitment = view.commitment()
        if not hmac.compare_digest(view_commitment, permit.view_commitment):
            raise Reject("view-commitment")
        unsigned = {
            "key_id": permit.key_id,
            "permit_id": permit.permit_id,
            "view_commitment": permit.view_commitment,
            "issued_height": permit.issued_height,
            "expires_after_height": permit.expires_after_height,
        }
        expected = hmac.new(
            self._secret,
            b"trnm.g2f.view-permit-token.v2\x00" + canonical(unsigned),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, permit.token):
            raise Reject("permit-token")
        if permit.permit_id in self._used_permits:
            raise Reject("permit-replay")
        self._used_permits.add(permit.permit_id)
        return hash_value(
            b"trnm.g2f.consumed-view.v2\x00",
            {
                "permit_id": permit.permit_id,
                "view_commitment": view_commitment,
                "current_height": current_height,
            },
        )


def text_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fixture() -> ManifestViewV2:
    planes = tuple(
        PlaneViewV2(
            plane=name,
            generation=1,
            source_identity=text_hash(f"{name}-source"),
            state_root=text_hash(f"{name}-root"),
        )
        for name in sorted(("agent", "da", "execution", "result", "safety", "settlement"))
    )
    return ManifestViewV2(
        namespace_id="namespace-a",
        predecessor_checkpoint=text_hash("predecessor"),
        height=10,
        order_header_hash=text_hash("order-header"),
        application_root=text_hash("application-root"),
        manifest_hash=text_hash("manifest"),
        planes=planes,
        nonce=7,
    )


def replace_view(view: ManifestViewV2, **changes: object) -> ManifestViewV2:
    values = asdict(view)
    values.update(changes)
    values["planes"] = tuple(
        PlaneViewV2(**plane) if isinstance(plane, dict) else plane for plane in values["planes"]
    )
    return ManifestViewV2(**values)


def self_test() -> dict[str, object]:
    view = fixture()
    issuer = OwnerViewIssuerV2("owner-key-1", b"k" * 32)
    permit = issuer.issue(view, issued_height=9, ttl=4)
    consumed = issuer.verify_and_consume(permit, view, current_height=10)
    if len(consumed) != 64 or view.commitment() != view.commitment():
        raise AssertionError("positive commitment failure")

    negatives: list[dict[str, str]] = []

    def reject(name: str, operation) -> None:
        try:
            operation()
        except Reject as error:
            negatives.append({"case": name, "error": str(error)})
        else:
            raise AssertionError(f"accepted:{name}")

    reject("permit-replay", lambda: issuer.verify_and_consume(permit, view, current_height=10))
    fresh = OwnerViewIssuerV2("owner-key-1", b"k" * 32)
    reject(
        "coordinated-nonzero-view-recompute",
        lambda: fresh.verify_and_consume(permit, replace_view(view, nonce=8), current_height=10),
    )
    reject(
        "namespace-copy",
        lambda: fresh.verify_and_consume(permit, replace_view(view, namespace_id="namespace-copy"), current_height=10),
    )
    reject(
        "same-height-fork",
        lambda: fresh.verify_and_consume(
            permit,
            replace_view(view, order_header_hash=text_hash("fork-header")),
            current_height=10,
        ),
    )
    reject(
        "application-root-drift",
        lambda: fresh.verify_and_consume(
            permit,
            replace_view(view, application_root=text_hash("other-application")),
            current_height=10,
        ),
    )
    reject(
        "manifest-drift",
        lambda: fresh.verify_and_consume(
            permit,
            replace_view(view, manifest_hash=text_hash("other-manifest")),
            current_height=10,
        ),
    )
    planes = list(view.planes)
    planes[0] = PlaneViewV2(
        planes[0].plane,
        2,
        planes[0].source_identity,
        planes[0].state_root,
    )
    reject(
        "generation-aba",
        lambda: fresh.verify_and_consume(permit, replace_view(view, planes=tuple(planes)), current_height=10),
    )
    planes = list(view.planes)
    planes[0] = PlaneViewV2(
        planes[0].plane,
        planes[0].generation,
        text_hash("copied-source"),
        planes[0].state_root,
    )
    reject(
        "source-identity-drift",
        lambda: fresh.verify_and_consume(permit, replace_view(view, planes=tuple(planes)), current_height=10),
    )
    tampered = OwnerViewPermitV2(
        permit.key_id,
        permit.permit_id,
        permit.view_commitment,
        permit.issued_height,
        permit.expires_after_height,
        "0" * 64,
    )
    reject("token-tamper", lambda: fresh.verify_and_consume(tampered, view, current_height=10))
    reject("expired", lambda: fresh.verify_and_consume(permit, view, current_height=14))
    wrong_issuer = OwnerViewIssuerV2("owner-key-2", b"z" * 32)
    reject("wrong-issuer", lambda: wrong_issuer.verify_and_consume(permit, view, current_height=10))

    return {
        "schema": "trnm-g2f-owner-view-commitment-evidence-v2",
        "positive": 4,
        "negative": negatives,
        "view_commitment": view.commitment(),
        "consumed_commitment": consumed,
        "candidate_only": True,
        "production_hsm_authority": False,
        "canonical_jmt_authority": False,
        "order_finality_authority": False,
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
