#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass, field
import argparse
import hashlib
import hmac
import json
import re
from typing import Any, Iterable

TRANSACTION_BATCH = "transaction-batch"
ARTIFACT_EVIDENCE = "artifact-evidence"
NAMESPACES = {TRANSACTION_BATCH, ARTIFACT_EVIDENCE}
FULLREP_MODE = "DA-FULLREP-V1"
DAS_MODE = "DA-DAS-V1"
MAX_PROVIDER_ID_BYTES = 64
MAX_OBJECT_ID_BYTES = 64
MAX_HOLD_BYTES = 128
MAX_NONCE_BYTES = 128
MAX_REQUESTER_ID_BYTES = 128
MAX_AUTH_KEY_BYTES = 128
MAX_OBJECT_BYTES = 16 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

class Reject(ValueError):
    pass


def _text(value: Any, label: str, limit: int) -> str:
    if type(value) is not str or not value:
        raise Reject(f"invalid-{label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise Reject(f"invalid-{label}") from exc
    if len(encoded) > limit:
        raise Reject(f"invalid-{label}")
    if not value.isascii() or any(ord(ch) < 0x20 for ch in value):
        raise Reject(f"invalid-{label}")
    return value


def _bytes(value: Any, label: str, limit: int, *, nonempty: bool = False) -> bytes:
    if type(value) is not bytes or len(value) > limit or (nonempty and not value):
        raise Reject(f"invalid-{label}")
    return value


def _uint(value: Any, label: str, *, positive: bool = False) -> int:
    # bool is an int subclass, but it is never a valid protocol integer.
    if type(value) is not int or value < (1 if positive else 0):
        raise Reject(f"invalid-{label}")
    return value


def _object_id(value: Any) -> str:
    value = _text(value, "object-id", MAX_OBJECT_ID_BYTES)
    if HEX64.fullmatch(value) is None:
        raise Reject("invalid-object-id")
    return value


def _manifest_checksum(
    namespace: str,
    object_id: str,
    length: int,
    retention_until: int,
) -> str:
    raw = json.dumps(
        {
            "namespace": namespace,
            "object_id": object_id,
            "length": length,
            "retention_until": retention_until,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(b"trnm.da-fullrep.manifest.v1\x00" + raw).hexdigest()


def _canonical_json(value: Any) -> bytes:
    """Encode an envelope without accepting NaN/Infinity or key ambiguity."""
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise Reject("invalid-envelope") from exc


def _auth_tag(envelope: dict[str, Any], key: bytes) -> str:
    key = _bytes(key, "auth-key", MAX_AUTH_KEY_BYTES, nonempty=True)
    return hmac.new(
        key,
        b"trnm.da-fullrep.auth-envelope.v1\x00" + _canonical_json(envelope),
        hashlib.sha256,
    ).hexdigest()


def digest(namespace: str, data: bytes) -> str:
    namespace = _text(namespace, "namespace", 64)
    if namespace not in NAMESPACES:
        raise Reject("unknown-namespace")
    data = _bytes(data, "object-bytes", MAX_OBJECT_BYTES)
    h=hashlib.sha256()
    h.update(b"trnm.da-fullrep.object.v1\x00")
    h.update(namespace.encode("ascii"))
    h.update(len(data).to_bytes(8,"big"))
    h.update(data)
    return h.hexdigest()

@dataclass
class Record:
    namespace: str
    data: bytes
    object_id: str
    retention_until: int
    manifest_checksum: str = ""
    durable: bool = False
    attested_sequence: int | None = None
    holds: set[str] = field(default_factory=set)
    tombstoned: bool = False

@dataclass
class Provider:
    provider_id: str
    journal_sequence: int = 0
    records: dict[tuple[str,str],Record] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.provider_id, "provider-id", MAX_PROVIDER_ID_BYTES)
        _uint(self.journal_sequence, "journal-sequence")

    def persist(self, namespace: str, data: bytes, retention_until: int) -> Record:
        namespace = _text(namespace, "namespace", 64)
        data = _bytes(data, "object-bytes", MAX_OBJECT_BYTES, nonempty=True)
        retention_until = _uint(retention_until, "retention-until", positive=True)
        if namespace not in NAMESPACES:
            raise Reject("invalid-persist")
        object_id=digest(namespace,data)
        key=(namespace,object_id)
        prior=self.records.get(key)
        if prior:
            if (
                prior.data != data
                or prior.retention_until != retention_until
                or prior.manifest_checksum != _manifest_checksum(
                    namespace, object_id, len(data), retention_until
                )
                or not prior.durable
                or prior.tombstoned
            ):
                raise Reject("conflicting-replay")
            return prior
        # The manifest is computed and marked durable before the record can be
        # observed by attest().  A future SQLite implementation must preserve
        # this ordering across its durable manifest/journal transaction.
        manifest_checksum = _manifest_checksum(
            namespace, object_id, len(data), retention_until
        )
        rec=Record(
            namespace,
            data,
            object_id,
            retention_until,
            manifest_checksum=manifest_checksum,
            durable=True,
        )
        self.records[key]=rec
        return rec

    def attest(self, namespace: str, object_id: str) -> dict:
        namespace = _text(namespace, "namespace", 64)
        object_id = _object_id(object_id)
        rec=self.records.get((namespace,object_id))
        if rec is None or not rec.durable or rec.tombstoned:
            raise Reject("attest-before-durable")
        if rec.manifest_checksum != _manifest_checksum(
            namespace, object_id, len(rec.data), rec.retention_until
        ):
            raise Reject("manifest-not-durable")
        if rec.attested_sequence is None:
            self.journal_sequence += 1
            rec.attested_sequence=self.journal_sequence
        return {"provider":self.provider_id,"namespace":namespace,"object_id":object_id,
                "length":len(rec.data),"retention_until":rec.retention_until,
                "sequence":rec.attested_sequence,"mode":FULLREP_MODE,
                "content_digest":object_id,"manifest_checksum":rec.manifest_checksum}

    def retrieve(self, namespace: str, object_id: str) -> bytes:
        namespace = _text(namespace, "namespace", 64)
        object_id = _object_id(object_id)
        rec=self.records.get((namespace,object_id))
        if rec is None or rec.tombstoned:
            raise Reject("not-found-or-withheld")
        if not rec.durable or rec.manifest_checksum != _manifest_checksum(
            namespace, object_id, len(rec.data), rec.retention_until
        ):
            raise Reject("manifest-not-durable")
        if digest(namespace,rec.data) != object_id:
            raise Reject("stored-digest-drift")
        return rec.data

    def add_hold(self, namespace: str, object_id: str, hold: str) -> None:
        namespace = _text(namespace, "namespace", 64)
        object_id = _object_id(object_id)
        hold = _text(hold, "hold", MAX_HOLD_BYTES)
        record = self.records.get((namespace, object_id))
        if record is None or record.tombstoned:
            raise Reject("unknown-record")
        record.holds.add(hold)

    def release_hold(self, namespace: str, object_id: str, hold: str) -> None:
        namespace = _text(namespace, "namespace", 64)
        object_id = _object_id(object_id)
        hold = _text(hold, "hold", MAX_HOLD_BYTES)
        record = self.records.get((namespace, object_id))
        if record is None or record.tombstoned:
            raise Reject("unknown-record")
        record.holds.discard(hold)

    def gc(self, namespace: str, object_id: str, height: int, node_permit: bool) -> None:
        namespace = _text(namespace, "namespace", 64)
        object_id = _object_id(object_id)
        height = _uint(height, "height")
        if type(node_permit) is not bool or not node_permit:
            raise Reject("node-permit-required")
        rec=self.records.get((namespace,object_id))
        if rec is None or rec.tombstoned:
            raise Reject("unknown-record")
        if height <= rec.retention_until or rec.holds:
            raise Reject("retention-or-hold-active")
        rec.tombstoned=True
        rec.data=b""

def _attestation_row(row: Any) -> dict[str, Any]:
    if type(row) is not dict:
        raise Reject("invalid-attestation")
    provider = _text(row.get("provider"), "provider-id", MAX_PROVIDER_ID_BYTES)
    namespace = _text(row.get("namespace"), "namespace", 64)
    if namespace not in NAMESPACES:
        raise Reject("unknown-namespace")
    object_id = _object_id(row.get("object_id"))
    length = _uint(row.get("length"), "length")
    retention_until = _uint(row.get("retention_until"), "retention-until", positive=True)
    sequence = _uint(row.get("sequence"), "attestation-sequence", positive=True)
    mode = _text(row.get("mode"), "mode", 64)
    if mode != FULLREP_MODE:
        raise Reject("sampling-mode-disabled")
    content_digest = row.get("content_digest", object_id)
    if content_digest != object_id:
        raise Reject("stored-digest-drift")
    manifest_checksum = row.get(
        "manifest_checksum",
        _manifest_checksum(namespace, object_id, length, retention_until),
    )
    manifest_checksum = _object_id(manifest_checksum)
    if manifest_checksum != _manifest_checksum(namespace, object_id, length, retention_until):
        raise Reject("manifest-not-durable")
    return {
        "provider": provider,
        "namespace": namespace,
        "object_id": object_id,
        "length": length,
        "retention_until": retention_until,
        "sequence": sequence,
        "mode": mode,
        "content_digest": content_digest,
        "manifest_checksum": manifest_checksum,
    }


def certificate(attestations: Iterable[dict], threshold: int) -> dict:
    threshold = _uint(threshold, "threshold", positive=True)
    try:
        rows = [_attestation_row(row) for row in attestations]
    except TypeError as exc:
        raise Reject("invalid-attestation-list") from exc
    if len(rows) < threshold:
        raise Reject("insufficient-threshold")
    rows.sort(key=lambda row: row["provider"])
    providers=[row["provider"] for row in rows]
    if len(providers) != len(set(providers)):
        raise Reject("duplicate-provider")
    statement={
        (
            row["namespace"],
            row["object_id"],
            row["length"],
            row["retention_until"],
            row["mode"],
            row["manifest_checksum"],
        )
        for row in rows
    }
    if len(statement) != 1:
        raise Reject("statement-mismatch")
    statement_value = next(iter(statement))
    certificate_id = hashlib.sha256(
        b"trnm.da-fullrep.certificate.v1\x00"
        + json.dumps(
            {"statement": statement_value, "providers": providers, "threshold": threshold},
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    return {
        "certificate_id": certificate_id,
        "statement": list(statement_value),
        "providers": providers,
        "threshold": threshold,
        "mode": FULLREP_MODE,
    }

def repair(
    target: Provider,
    namespace: str,
    object_id: str,
    retention_until: int,
    sources: Iterable[Provider],
    certificate_value: dict[str, Any] | None = None,
) -> Record:
    if type(target) is not Provider:
        raise Reject("invalid-repair-target")
    namespace = _text(namespace, "namespace", 64)
    object_id = _object_id(object_id)
    retention_until = _uint(retention_until, "retention-until", positive=True)
    if certificate_value is not None:
        _validate_certificate_binding(certificate_value, namespace, object_id, retention_until)
    try:
        source_rows = list(sources)
    except TypeError as exc:
        raise Reject("invalid-repair-sources") from exc
    if not source_rows or any(type(source) is not Provider for source in source_rows):
        raise Reject("invalid-repair-sources")
    good=[]
    for source in source_rows:
        try:
            data=source.retrieve(namespace,object_id)
        except Reject:
            continue
        if digest(namespace,data)==object_id:
            good.append(data)
    if not good or any(data != good[0] for data in good):
        raise Reject("no-consistent-complete-source")
    return target.persist(namespace,good[0],retention_until)

def _validate_certificate_binding(
    certificate_value: Any,
    namespace: str,
    object_id: str,
    retention_until: int | None = None,
) -> dict[str, Any]:
    if type(certificate_value) is not dict:
        raise Reject("invalid-certificate")
    providers = certificate_value.get("providers")
    if type(providers) is not list or not providers:
        raise Reject("invalid-certificate")
    if any(type(provider) is not str for provider in providers):
        raise Reject("invalid-certificate")
    if len(providers) != len(set(providers)):
        raise Reject("duplicate-provider")
    threshold = _uint(certificate_value.get("threshold"), "threshold", positive=True)
    if threshold > len(providers):
        raise Reject("invalid-certificate")
    statement = certificate_value.get("statement")
    if type(statement) is not list or len(statement) not in {5, 6}:
        raise Reject("invalid-certificate")
    if statement[0] != namespace or statement[1] != object_id:
        raise Reject("stale-certificate")
    if retention_until is not None and statement[3] != retention_until:
        raise Reject("stale-certificate")
    if statement[4] != FULLREP_MODE:
        raise Reject("sampling-mode-disabled")
    if len(statement) == 6 and statement[5] != _manifest_checksum(namespace, object_id, statement[2], statement[3]):
        raise Reject("stale-certificate")
    if certificate_value.get("mode", FULLREP_MODE) != FULLREP_MODE:
        raise Reject("sampling-mode-disabled")
    certificate_id = certificate_value.get("certificate_id")
    if certificate_id is not None:
        certificate_id = _object_id(certificate_id)
        expected_id = hashlib.sha256(
            b"trnm.da-fullrep.certificate.v1\x00"
            + json.dumps(
                {"statement": statement, "providers": providers, "threshold": threshold},
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        if certificate_id != expected_id:
            raise Reject("stale-certificate")
    return certificate_value


def withholding_evidence(
    provider: Provider,
    certificate_value: dict,
    namespace: str,
    object_id: str,
    request_nonce: str,
) -> dict:
    if type(provider) is not Provider:
        raise Reject("invalid-provider")
    namespace = _text(namespace, "namespace", 64)
    object_id = _object_id(object_id)
    request_nonce = _text(request_nonce, "request-nonce", MAX_NONCE_BYTES)
    _validate_certificate_binding(certificate_value, namespace, object_id)
    if provider.provider_id not in certificate_value["providers"]:
        raise Reject("provider-not-certified")
    try:
        provider.retrieve(namespace,object_id)
    except Reject:
        return {
            "provider": provider.provider_id,
            "namespace": namespace,
            "object_id": object_id,
            "certificate_id": certificate_value.get("certificate_id"),
            "request_nonce": request_nonce,
            "outcome": "withheld",
        }
    raise Reject("bytes-available")


def retrieve_authenticated_full_range(
    provider: Provider,
    certificate_value: dict,
    request: dict[str, Any],
    requester_key: bytes,
    responder_key: bytes,
    current_height: int,
    max_response_bytes: int,
) -> dict[str, Any]:
    """Verify a bounded authenticated full-range request and response.

    This is a transport-independent candidate envelope.  The keyed tag keeps
    the independent model executable with Python's standard library; it is
    intentionally not a production Ed25519 signer or a peer registry.
    """
    if type(provider) is not Provider or type(request) is not dict:
        raise Reject("invalid-request")
    requester_id = _text(request.get("requester_id"), "requester-id", MAX_REQUESTER_ID_BYTES)
    namespace = _text(request.get("namespace"), "namespace", 64)
    object_id = _object_id(request.get("object_id"))
    first_byte = _uint(request.get("first_byte"), "first-byte")
    byte_count = _uint(request.get("byte_count"), "byte-count", positive=True)
    request_nonce = _text(request.get("request_nonce"), "request-nonce", MAX_NONCE_BYTES)
    request_height = _uint(request.get("request_height"), "request-height")
    expiry_height = _uint(request.get("expiry_height"), "expiry-height")
    current_height = _uint(current_height, "current-height")
    max_response_bytes = _uint(max_response_bytes, "max-response-bytes", positive=True)
    if expiry_height < request_height or current_height < request_height or current_height > expiry_height:
        raise Reject("request-expired")
    if first_byte != 0:
        raise Reject("incomplete-range")
    if byte_count > max_response_bytes:
        raise Reject("response-quota")
    request_unsigned = {
        "requester_id": requester_id,
        "namespace": namespace,
        "object_id": object_id,
        "first_byte": first_byte,
        "byte_count": byte_count,
        "request_nonce": request_nonce,
        "request_height": request_height,
        "expiry_height": expiry_height,
    }
    signature = request.get("request_signature")
    if type(signature) is not str or not hmac.compare_digest(signature, _auth_tag(request_unsigned, requester_key)):
        raise Reject("unauthenticated-request")
    _validate_certificate_binding(certificate_value, namespace, object_id)
    if provider.provider_id not in certificate_value["providers"]:
        raise Reject("provider-not-certified")
    payload = provider.retrieve(namespace, object_id)
    if byte_count != len(payload):
        raise Reject("incomplete-range")
    response_unsigned = {
        "provider": provider.provider_id,
        "requester_id": requester_id,
        "namespace": namespace,
        "object_id": object_id,
        "request_nonce": request_nonce,
        "first_byte": first_byte,
        "byte_count": len(payload),
        "response_height": current_height,
        "payload_digest": digest(namespace, payload),
    }
    return {
        **response_unsigned,
        "payload": payload.decode("utf-8", errors="surrogateescape"),
        "request_signature": signature,
        "response_signature": _auth_tag(response_unsigned, responder_key),
        "mode": FULLREP_MODE,
    }

def self_test() -> dict:
    p1,p2,p3,p4=(Provider(f"p{i}") for i in range(1,5))
    data=b"canonical transaction batch"
    recs=[p.persist(TRANSACTION_BATCH,data,100) for p in (p1,p2,p3)]
    atts=[p.attest(TRANSACTION_BATCH,r.object_id) for p,r in zip((p1,p2,p3),recs)]
    assert p1.retrieve(TRANSACTION_BATCH,recs[0].object_id)==data
    repaired=repair(p4,TRANSACTION_BATCH,recs[0].object_id,100,[p1,p2,p3])
    assert repaired.data==data
    # The withholding witness must be a member of the certificate.  Certify
    # p4 only after its complete repair/readback, then make it unavailable
    # under an active certificate so the negative is bound to a real member.
    p4_attestation=p4.attest(TRANSACTION_BATCH,repaired.object_id)
    cert=certificate([atts[0],atts[1],p4_attestation],3)
    p4.add_hold(TRANSACTION_BATCH,repaired.object_id,"challenge:1")
    requester_key = b"requester-key-v1"
    responder_key = b"responder-key-p4-v1"
    request_unsigned = {
        "requester_id": "repair-agent-1",
        "namespace": TRANSACTION_BATCH,
        "object_id": repaired.object_id,
        "first_byte": 0,
        "byte_count": len(data),
        "request_nonce": "nonce-auth-1",
        "request_height": 10,
        "expiry_height": 20,
    }
    authenticated_request = {
        **request_unsigned,
        "request_signature": _auth_tag(request_unsigned, requester_key),
    }
    # p1 is still available and is a certificate member; this exercises the
    # complete-range/authentication path before p4 is intentionally withheld.
    authenticated_response = retrieve_authenticated_full_range(
        p1,
        cert,
        authenticated_request,
        requester_key,
        responder_key,
        current_height=15,
        max_response_bytes=len(data),
    )
    assert authenticated_response["payload_digest"] == repaired.object_id
    negatives=[]
    def reject(name,fn):
        try: fn()
        except Reject as exc: negatives.append({"case":name,"error":str(exc)})
        else: raise AssertionError(f"accepted:{name}")
    reject("attest-before-durable",lambda: Provider("x").attest(TRANSACTION_BATCH,recs[0].object_id))
    reject("cross-namespace",lambda: p1.retrieve(ARTIFACT_EVIDENCE,recs[0].object_id))
    reject("duplicate-provider",lambda: certificate([atts[0],atts[0],atts[1]],3))
    bad=dict(atts[0]); bad["mode"]="DA-DAS-V1"
    reject("sampling-disabled",lambda: certificate([bad,atts[1],atts[2]],3))
    reject("gc-with-hold",lambda: p4.gc(TRANSACTION_BATCH,repaired.object_id,101,True))
    reject("gc-without-node-permit",lambda: p4.gc(TRANSACTION_BATCH,repaired.object_id,101,False))
    p4.release_hold(TRANSACTION_BATCH,repaired.object_id,"challenge:1")
    p4.gc(TRANSACTION_BATCH,repaired.object_id,101,True)
    evidence=withholding_evidence(p4,cert,TRANSACTION_BATCH,repaired.object_id,"nonce-1")
    strict_negatives=[]
    def reject_strict(name,fn):
        try: fn()
        except Reject as exc: strict_negatives.append({"case":name,"error":str(exc)})
        else: raise AssertionError(f"accepted:{name}")
    reject_strict("malformed-provider-id",lambda: Provider(1))
    reject_strict("nonboolean-node-permit",lambda: p1.gc(TRANSACTION_BATCH,recs[0].object_id,101,1))
    drifted = p1.records[(TRANSACTION_BATCH, recs[0].object_id)]
    original_manifest = drifted.manifest_checksum
    drifted.manifest_checksum = "0" * 64
    reject_strict("manifest-drift",lambda: p1.attest(TRANSACTION_BATCH,recs[0].object_id))
    drifted.manifest_checksum = original_manifest
    reject_strict("stale-object-id",lambda: p1.retrieve(TRANSACTION_BATCH,"0"))
    incomplete_request = {**authenticated_request, "byte_count": len(data) - 1}
    incomplete_request["request_signature"] = _auth_tag(
        {key: value for key, value in incomplete_request.items() if key != "request_signature"},
        requester_key,
    )
    reject_strict("incomplete-range",lambda: retrieve_authenticated_full_range(
        p1, cert, incomplete_request, requester_key, responder_key, 15, len(data)
    ))
    stale_cert = dict(cert)
    stale_cert["statement"] = list(cert["statement"])
    stale_cert["statement"][3] += 1
    reject_strict("stale-certificate",lambda: withholding_evidence(
        p4, stale_cert, TRANSACTION_BATCH, repaired.object_id, "nonce-stale"
    ))
    reject_strict("cross-namespace-object",lambda: p1.retrieve(
        ARTIFACT_EVIDENCE, recs[0].object_id
    ))
    reject_strict("duplicate-provider",lambda: certificate([atts[0],atts[0],atts[1]],3))
    reject_strict("das-profile",lambda: certificate([
        {**atts[0], "mode": DAS_MODE}, atts[1], p4_attestation
    ],3))
    reject_strict("incomplete-repair",lambda: repair(
        Provider("empty"), TRANSACTION_BATCH, repaired.object_id, 100, [Provider("none")]
    ))
    auth_negatives=[]
    def reject_auth(name,fn):
        try: fn()
        except Reject as exc: auth_negatives.append({"case":name,"error":str(exc)})
        else: raise AssertionError(f"accepted:{name}")
    nonmember_request = {
        **authenticated_request,
        "request_signature": _auth_tag(request_unsigned, requester_key),
    }
    reject_auth("nonmember-responder",lambda: retrieve_authenticated_full_range(
        Provider("p9"), cert, nonmember_request, requester_key, responder_key, 15, len(data)
    ))
    tampered_certificate = dict(cert)
    tampered_certificate["certificate_id"] = "0" * 64
    reject_auth("certificate-id-tamper",lambda: withholding_evidence(
        p4, tampered_certificate, TRANSACTION_BATCH, repaired.object_id, "nonce-tampered"
    ))
    return {
        "schema":"trnm-da-fullrep-model-evidence-v1",
        "positive":5,
        "negative":negatives,
        "strict_negative":strict_negatives,
        "authenticated_negative":auth_negatives,
        "withholding":evidence,
        "certificate":cert,
        "authenticated_response":authenticated_response,
        "candidate_only":True,
        "network_authority":False,
    }

def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--self-test",action="store_true")
    args=parser.parse_args()
    if not args.self_test: raise SystemExit("use --self-test")
    print(json.dumps(self_test(),sort_keys=True,separators=(",",":")))
    return 0
if __name__=="__main__": raise SystemExit(main())
