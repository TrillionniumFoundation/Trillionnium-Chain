"""WLC1: authenticated observation fragments, never a resource upper certificate.

Actual ML-DSA-65 signatures bind source declarations to independently supplied
public-key and endpoint pins.  Full W1/MU1 artifact replay verifies predicates,
not that a signer executed a program or saw all computation.  This fresh
off-chain namespace changes no MU1 v1 bytes or native authority.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import re
import struct
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey

import mandatory_units_relation as mu
from work_lifecycle_help import HelpPolicy


DOMAIN = b"TRNM-PON-WLC1\0"
SCHEMA = "pon-work-lifecycle-observation-v1"
CHECKPOINT_SCHEMA = "pon-work-lifecycle-checkpoint-v1"
PURPOSE = "signed-observations-no-resource-or-consensus-authority"
SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
MAX_EVENTS = 2048
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024


class LifecycleError(ValueError):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise LifecycleError(code)


def fields(value: Any, names: set[str], code: str) -> dict:
    need(type(value) is dict and set(value) == names, code)
    return value


def integer(value: Any, minimum: int = 0, maximum: int = (1 << 64) - 1) -> int:
    need(type(value) is int and minimum <= value <= maximum, "INTEGER")
    return value


def hash_text(value: Any) -> str:
    need(type(value) is str and HEX64.fullmatch(value) is not None, "HASH_ENCODING")
    return value


def label(value: Any) -> str:
    need(type(value) is str and 0 < len(value) <= 128 and value.isascii(), "LABEL")
    return value


def canonical(value: Any) -> bytes:
    def visit(item, depth=0):
        need(depth <= 12, "CANONICAL_DEPTH")
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            need(-(1 << 63) <= item < (1 << 64), "CANONICAL_INTEGER")
            return
        if type(item) is str:
            need(item.isascii() and len(item) <= 16384, "CANONICAL_STRING")
            return
        if type(item) is list:
            need(len(item) <= MAX_EVENTS, "CANONICAL_ARRAY")
            for x in item:
                visit(x, depth + 1)
            return
        if type(item) is dict and all(type(k) is str for k in item):
            need(len(item) <= MAX_EVENTS, "CANONICAL_OBJECT")
            for k, v in item.items():
                visit(k, depth + 1)
                visit(v, depth + 1)
            return
        raise LifecycleError("CANONICAL_TYPE")
    visit(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("ascii")
    need(len(raw) <= MAX_DOCUMENT_BYTES, "DOCUMENT_LIMIT")
    return raw


def strict_load(raw: bytes) -> dict:
    need(type(raw) is bytes and len(raw) <= MAX_DOCUMENT_BYTES, "DOCUMENT_LIMIT")
    def pairs(rows):
        result = {}
        for k, v in rows:
            need(k not in result, "DUPLICATE_JSON_KEY")
            result[k] = v
        return result
    def no_constant(_):
        raise LifecycleError("NONFINITE_JSON")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleError("JSON") from error
    canonical(value)
    need(type(value) is dict, "DOCUMENT_TYPE")
    return value


def sha256(raw: bytes) -> str:
    need(type(raw) is bytes, "ARTIFACT_TYPE")
    return hashlib.sha256(raw).hexdigest()


def domain_digest(tag: bytes, value: Any) -> str:
    raw = canonical(value)
    return sha256(DOMAIN + struct.pack("<H", len(tag)) + tag + struct.pack("<I", len(raw)) + raw)


def public_spki(key: MLDSA65PrivateKey) -> bytes:
    need(isinstance(key, MLDSA65PrivateKey), "MLDSA65_PRIVATE_KEY")
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id(spki: bytes) -> str:
    need(type(spki) is bytes and len(spki) == 1974 and spki.startswith(SPKI_PREFIX),
         "MLDSA65_PINNED_SPKI")
    # Existing repository key-identity domain; new observation messages have
    # their own WLC1 domain and do not become TPQ1 authorization statements.
    return sha256(b"TRNM/PoN/PQKey/v1\0" + spki)


def checkpoint_message(statement: dict) -> bytes:
    raw = canonical(statement)
    return DOMAIN + b"checkpoint\0" + struct.pack("<I", len(raw)) + raw


@dataclass(frozen=True)
class EndpointPin:
    sequence: int
    head: str


@dataclass(frozen=True)
class ObservationPin:
    """Caller-owned expectations, not keys/endpoints adopted from a document."""
    public_spki: bytes
    header_digest: str
    start: EndpointPin
    end: EndpointPin


class ObservationWriter:
    """Signer of observations; possession of this key is not a trusted monitor."""
    def __init__(self, key: MLDSA65PrivateKey, *, session: str, source_commit: str,
                 source_manifest: dict[str, str], help_policy: HelpPolicy):
        self._key = key
        self._spki = public_spki(key)
        self.header = {
            "schema": SCHEMA, "purpose": PURPOSE, "session": hash_text(session),
            "key_id": key_id(self._spki), "algorithm": "ML-DSA-65",
            "relation_parameters": mu.RELATION_PARAMETERS.hex(),
            "source_commit": source_commit, "source_manifest": copy.deepcopy(source_manifest),
            "help_policy": help_policy.wire(), "initial_state_certificate": None,
            "complete_mediation_attested": False,
        }
        validate_header(self.header)
        self._header_digest = domain_digest(b"header", self.header)
        self._head = self._header_digest
        self._events: list[dict] = []
        self._closed = False
        self._start = self._checkpoint(False)

    def _checkpoint(self, closed: bool) -> dict:
        statement = {
            "schema": CHECKPOINT_SCHEMA, "purpose": PURPOSE,
            "session": self.header["session"], "header_digest": self._header_digest,
            "key_id": self.header["key_id"], "sequence": len(self._events),
            "head": self._head, "closed": closed,
        }
        try:
            signature = self._key.sign(checkpoint_message(statement))
        except UnsupportedAlgorithm as error:
            raise LifecycleError("MLDSA65_UNAVAILABLE_NO_FALLBACK") from error
        need(len(signature) == 3309, "MLDSA65_SIGNATURE_LENGTH")
        return {"statement": statement, "signature": signature.hex()}

    def append(self, kind: str, body: dict) -> str:
        need(not self._closed, "OBSERVATION_CLOSED")
        need(len(self._events) < MAX_EVENTS, "EVENT_LIMIT")
        event = {"sequence": len(self._events) + 1, "previous": self._head,
                 "kind": label(kind), "body": copy.deepcopy(body)}
        canonical(event)
        self._head = domain_digest(b"event", event)
        self._events.append(event)
        return self._head

    def close(self) -> tuple[dict, ObservationPin]:
        need(not self._closed, "OBSERVATION_CLOSED")
        self._closed = True
        end = self._checkpoint(True)
        document = {"header": copy.deepcopy(self.header), "events": copy.deepcopy(self._events),
                    "start": copy.deepcopy(self._start), "end": end}
        pin = ObservationPin(self._spki, self._header_digest,
                             EndpointPin(0, self._header_digest),
                             EndpointPin(len(self._events), self._head))
        return document, pin


def validate_header(header: Any) -> HelpPolicy:
    fields(header, {"schema", "purpose", "session", "key_id", "algorithm",
                    "relation_parameters", "source_commit", "source_manifest", "help_policy",
                    "initial_state_certificate", "complete_mediation_attested"}, "HEADER_FIELDS")
    need(header["schema"] == SCHEMA and header["purpose"] == PURPOSE, "OBSERVATION_NAMESPACE")
    need(header["algorithm"] == "ML-DSA-65", "SIGNATURE_ALGORITHM")
    need(header["relation_parameters"] == mu.RELATION_PARAMETERS.hex(), "MU1_RELATION_BINDING")
    for name in ("session", "key_id"):
        hash_text(header[name])
    need(type(header["source_commit"]) is str and HEX40.fullmatch(header["source_commit"]) is not None,
         "SOURCE_COMMIT")
    manifest = header["source_manifest"]
    need(type(manifest) is dict and 1 <= len(manifest) <= 128, "SOURCE_MANIFEST")
    for name, digest in manifest.items():
        label(name)
        hash_text(digest)
    need(header["initial_state_certificate"] is None
         and header["complete_mediation_attested"] is False, "UNSUPPORTED_RESOURCE_AUTHORITY")
    try:
        return HelpPolicy.from_wire(header["help_policy"])
    except ValueError as error:
        raise LifecycleError(str(error)) from error


def verify_checkpoint(envelope: Any, header: dict, pin: ObservationPin,
                      endpoint: EndpointPin, *, closed: bool) -> None:
    fields(envelope, {"statement", "signature"}, "CHECKPOINT_ENVELOPE")
    s = fields(envelope["statement"], {"schema", "purpose", "session", "header_digest",
                                      "key_id", "sequence", "head", "closed"}, "CHECKPOINT_FIELDS")
    expected = {"schema": CHECKPOINT_SCHEMA, "purpose": PURPOSE, "session": header["session"],
                "header_digest": pin.header_digest, "key_id": key_id(pin.public_spki),
                "sequence": endpoint.sequence, "head": endpoint.head, "closed": closed}
    need(s == expected and type(s["sequence"]) is int and type(s["closed"]) is bool,
         "EXTERNAL_CHECKPOINT_PIN")
    encoded = envelope["signature"]
    need(type(encoded) is str and len(encoded) == 6618 and encoded == encoded.lower(),
         "SIGNATURE_ENCODING")
    try:
        signature = bytes.fromhex(encoded)
        need(len(signature) == 3309, "SIGNATURE_ENCODING")
        MLDSA65PublicKey.from_public_bytes(pin.public_spki[22:]).verify(
            signature, checkpoint_message(s))
    except (ValueError, InvalidSignature) as error:
        raise LifecycleError("MLDSA65_SIGNATURE_REJECTED") from error
    except UnsupportedAlgorithm as error:
        raise LifecycleError("MLDSA65_UNAVAILABLE_NO_FALLBACK") from error


def artifact(artifacts: dict[str, bytes], digest: Any, length: Any = None) -> bytes:
    hash_text(digest)
    need(digest in artifacts, "MISSING_ARTIFACT")
    raw = artifacts[digest]
    need(type(raw) is bytes and sha256(raw) == digest, "ARTIFACT_HASH")
    if length is not None:
        need(type(length) is int and len(raw) == length, "ARTIFACT_LENGTH")
    return raw


def _native_predicate(body: dict, artifacts: dict[str, bytes], manifest: dict) -> int:
    fields(body, {"mode", "program_sha256", "input_sha256", "input_bytes", "output_sha256",
                  "output_bytes", "stderr_sha256", "stderr_bytes", "returncode"}, "NATIVE_EVENT_FIELDS")
    need(body["mode"] in ("prove", "generic", "verify"), "NATIVE_MODE")
    hash_text(body["program_sha256"])
    need(body["program_sha256"] in manifest.values(), "UNPINNED_OBSERVED_PROGRAM")
    inp = artifact(artifacts, body["input_sha256"], body["input_bytes"])
    out = artifact(artifacts, body["output_sha256"], body["output_bytes"])
    artifact(artifacts, body["stderr_sha256"], body["stderr_bytes"])
    integer(body["returncode"], -255, 255)
    if body["returncode"] != 0:
        return 0  # A reported process failure is preserved, not converted to valid work.
    try:
        if body["mode"] == "verify":
            need(len(inp) == 96 + mu.w1.PROOF_BYTES, "NATIVE_VERIFY_INPUT")
            mu.w1.verify(inp[:32], inp[32:64], inp[64:96], inp[96:])
            need(out == mu.w1_hash("native-work-verification", inp), "NATIVE_RECEIPT_BINDING")
        else:
            need(len(inp) == 32 + 8 * mu.w1.CELLS, "NATIVE_PROVE_INPUT")
            need(out[4:4 + 8 * mu.w1.CELLS] == inp[32:], "NATIVE_PROVE_MATERIAL_BINDING")
            values = struct.unpack("<" + "I" * (2 * mu.w1.CELLS), inp[32:])
            task = mu.w1.task_id(values[:mu.w1.CELLS], values[mu.w1.CELLS:])
            mu.w1.verify(inp[:32], task, mu.UNIT_TARGET, out)
    except ValueError as error:
        raise LifecycleError("ARTIFACT_FULL_W1_PREDICATE:" + str(error)) from error
    return 1


def verify_collection(documents: dict[str, dict], pins: dict[str, ObservationPin],
                      artifacts: dict[str, bytes], root: str) -> dict[str, object]:
    """Verify a signed source DAG rooted in separately provided expectation pins.

    Every linked source is cryptographically verified here; no caller-provided
    `signature_valid` boolean or fabricated VerifiedLog object is accepted.
    Source signatures and complete anchored records still do not attest hidden
    execution, physical measurements, query bounds, or initial independence.
    """
    need(type(documents) is dict and type(pins) is dict and 1 <= len(documents) <= 32,
         "OBSERVATION_COLLECTION")
    need(type(artifacts) is dict, "ARTIFACT_STORE")
    cache, visiting = {}, set()

    def verify(name: str, depth: int = 0) -> dict:
        label(name)
        need(depth <= 8, "SOURCE_DEPTH")
        need(name in documents and name in pins, "UNRESOLVED_SIGNED_SOURCE")
        need(name not in visiting, "SOURCE_CYCLE")
        if name in cache:
            return cache[name]
        visiting.add(name)
        doc = fields(documents[name], {"header", "events", "start", "end"}, "DOCUMENT_FIELDS")
        canonical(doc)
        pin = pins[name]
        need(type(pin) is ObservationPin and type(pin.start) is EndpointPin
             and type(pin.end) is EndpointPin, "EXTERNAL_PIN_TYPE")
        for endpoint in (pin.start, pin.end):
            integer(endpoint.sequence, 0, MAX_EVENTS)
            hash_text(endpoint.head)
        hash_text(pin.header_digest)
        header = doc["header"]
        policy = validate_header(header)
        need(header["key_id"] == key_id(pin.public_spki), "EXTERNAL_SIGNER_PIN")
        need(domain_digest(b"header", header) == pin.header_digest, "EXTERNAL_HEADER_PIN")
        need(pin.start.sequence == 0 and pin.start.head == pin.header_digest, "INITIAL_ENDPOINT_PIN")
        events = doc["events"]
        need(type(events) is list and len(events) == pin.end.sequence <= MAX_EVENTS,
             "ANCHORED_EVENT_EXTENT")
        verify_checkpoint(doc["start"], header, pin, pin.start, closed=False)
        verify_checkpoint(doc["end"], header, pin, pin.end, closed=True)
        head, seen_slots, exports, links = pin.start.head, [], {}, []
        accepted_packets, accepted_proofs = set(), set()
        counters = {"reported_native_calls": 0, "reported_native_nonzero_exits": 0,
                    "full_W1_artifact_predicates_rechecked": 0, "MU1_predicates_rechecked": 0,
                    "terminal_records": 0, "bounded_help_deliveries": 0,
                    "unmetered_import_records": 0, "resource_readings": 0}
        for index, event in enumerate(events, 1):
            fields(event, {"sequence", "previous", "kind", "body"}, "EVENT_FIELDS")
            need(type(event["sequence"]) is int and event["sequence"] == index
                 and event["previous"] == head, "EVENT_CHAIN_ORDER")
            kind, body = event["kind"], event["body"]
            need(type(kind) is str and type(body) is dict, "EVENT_BODY")
            event_hash = domain_digest(b"event", event)
            if kind == "native_call":
                counters["reported_native_calls"] += 1
                counters["full_W1_artifact_predicates_rechecked"] += _native_predicate(
                    body, artifacts, header["source_manifest"])
                counters["reported_native_nonzero_exits"] += body["returncode"] != 0
                if body["returncode"] == 0:
                    if body["mode"] == "verify":
                        accepted_proofs.add(sha256(artifact(artifacts, body["input_sha256"])[96:]))
                    else:
                        accepted_proofs.add(body["output_sha256"])
            elif kind == "mu1_observation":
                fields(body, {"context_sha256", "packet_sha256", "context_digest", "ordered_root",
                              "ticket", "identity", "units", "result", "refusal"}, "MU1_EVENT_FIELDS")
                context = mu.decode_context(artifact(artifacts, body["context_sha256"]))
                raw = artifact(artifacts, body["packet_sha256"])
                try:
                    parsed = mu.inspect_packet(raw, context)
                    expected = (parsed.context_hash.hex(), parsed.outputs_root.hex(), parsed.ticket.hex(),
                                parsed.identity.hex(), context.units)
                    actual = tuple(body[k] for k in ("context_digest", "ordered_root", "ticket", "identity", "units"))
                    need(actual == expected and type(body["units"]) is int, "MU1_HASH_BINDING")
                    try:
                        mu.verify_packet(raw, context)
                        result, refusal = "accepted", None
                    except mu.RelationError as error:
                        result, refusal = "rejected", str(error)
                    need(body["result"] == result and body["refusal"] == refusal, "MU1_PREDICATE_OUTCOME")
                except mu.RelationError as error:
                    raise LifecycleError("MU1_ARTIFACT:" + str(error)) from error
                counters["terminal_records"] += 1
                counters["MU1_predicates_rechecked"] += 1
                if result == "accepted":
                    accepted_packets.add(body["packet_sha256"])
            elif kind == "publish_artifact":
                fields(body, {"artifact_sha256", "artifact_bytes", "role"}, "PUBLISH_FIELDS")
                artifact(artifacts, body["artifact_sha256"], body["artifact_bytes"])
                need(body["role"] in ("complete_mu1_packet", "full_w1_proof", "classical_help"),
                     "PUBLISH_ROLE")
                if body["role"] == "complete_mu1_packet":
                    need(body["artifact_sha256"] in accepted_packets, "PUBLISH_WITHOUT_COMPLETE_MU1_PREDICATE")
                elif body["role"] == "full_w1_proof":
                    need(body["artifact_sha256"] in accepted_proofs, "PUBLISH_WITHOUT_COMPLETE_W1_PREDICATE")
                exports[event_hash] = body["artifact_sha256"]
            elif kind == "help_delivery":
                fields(body, {"delivery", "payload_sha256", "source_reference"}, "HELP_EVENT_FIELDS")
                payload = artifact(artifacts, body["payload_sha256"])
                try:
                    slot = policy.validate_delivery(body["delivery"], payload)
                except ValueError as error:
                    raise LifecycleError(str(error)) from error
                need(slot == len(seen_slots), "HELP_SLOT_ORDER_OR_REPLAY")
                seen_slots.append(slot)
                reference = body["source_reference"]
                if reference is not None:
                    fields(reference, {"label", "header_digest", "end_sequence", "end_head", "publish_event"},
                           "SOURCE_REFERENCE_FIELDS")
                    for digest_field in ("header_digest", "end_head", "publish_event"):
                        hash_text(reference[digest_field])
                    integer(reference["end_sequence"], 0, MAX_EVENTS)
                    need(reference["label"] == body["delivery"]["source"], "SOURCE_LABEL_BINDING")
                    source = verify(reference["label"], depth + 1)
                    need(reference["header_digest"] == source["header_digest"]
                         and reference["end_head"] == source["end_head"]
                         and type(reference["end_sequence"]) is int
                         and reference["end_sequence"] == source["end_sequence"], "SIGNED_SOURCE_ENDPOINT")
                    need(source["exports"].get(reference["publish_event"]) == body["payload_sha256"],
                         "SIGNED_SOURCE_ARTIFACT_BINDING")
                    links.append(reference["label"])
                counters["bounded_help_deliveries"] += 1
            elif kind == "unmetered_import":
                fields(body, {"source", "artifact_sha256", "artifact_bytes", "state_kind"}, "IMPORT_FIELDS")
                label(body["source"])
                artifact(artifacts, body["artifact_sha256"], body["artifact_bytes"])
                need(body["state_kind"] in ("classical", "opaque_quantum"), "IMPORT_STATE_KIND")
                counters["unmetered_import_records"] += 1
            elif kind == "resource_reading":
                fields(body, {"quantity", "value", "bound_direction"}, "RESOURCE_READING_FIELDS")
                need(body["quantity"] in ("elapsed_ns", "process_user_ns", "max_rss_bytes"), "RESOURCE_QUANTITY")
                integer(body["value"])
                need(body["bound_direction"] == "observation_only", "RESOURCE_BOUND_PROMOTION")
                counters["resource_readings"] += 1
            else:
                raise LifecycleError("UNSUPPORTED_EVENT_KIND")
            head = event_hash
        need(head == pin.end.head, "FINAL_ANCHOR_HEAD")
        need(seen_slots == list(range(len(policy.slots))), "INCOMPLETE_HELP_SLOT_RECORD")
        value = {"label": name, "header_digest": pin.header_digest, "key_id": header["key_id"],
                 "end_sequence": pin.end.sequence, "end_head": pin.end.head, "exports": exports,
                 "signed_source_links": links, "counters": counters,
                 "signatures_verified_against_supplied_external_pin": True,
                 "anchored_observation_fragment_complete": True,
                 "help_observations_fit_declared_policy": True,
                 "real_independent_trust_root_established": False,
                 "recorder_execution_attested": False, "all_world_events_covered": False,
                 "lifecycle_query_upper_bound": None, "initial_oracle_independence_proved": False,
                 "help_policy_global_support_certified": False,
                 "actual_sha_qrom_composition_proved": False, "physical_resource_bound": False,
                 "native_confirmation_risk": False}
        visiting.remove(name)
        cache[name] = value
        return value

    result = verify(root)
    return {"schema": "pon-work-lifecycle-verification-result-v1", "root": result,
            "verified_sources": {name: cache[name] for name in sorted(cache)},
            "query_budget_eligible": False,
            "eligibility_refusal": "LIFECYCLE_COVERAGE_AND_INITIAL_STATE_UNATTESTED"}


def query_budget_from_observation(_verified_observation: Any):
    """There is no supported promotion from these records to a global budget."""
    raise LifecycleError("LIFECYCLE_COVERAGE_AND_INITIAL_STATE_UNATTESTED")


def pin_wire(pin: ObservationPin) -> dict:
    return {"public_spki": pin.public_spki.hex(), "header_digest": pin.header_digest,
            "start": {"sequence": pin.start.sequence, "head": pin.start.head},
            "end": {"sequence": pin.end.sequence, "head": pin.end.head}}
