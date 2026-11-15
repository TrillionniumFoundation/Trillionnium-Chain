"""Authenticate provider readback declarations for the research root journal.

The owner constructs a fresh request and retains its exact operation, intent,
provider and orphan epoch. A provider's pinned ML-DSA-87 2-of-3 AND
SLH-DSA-SHA2-256s 2-of-3 quorum signs the complete response in a distinct domain.
An ordinary success receipt cannot erase a subsequently orphaned liability.

These signatures authenticate what the configured provider declared. They do
not prove a real payment, API call, consumed resource, independent custody or
production deployment. No function here dispatches an effect or grants a retry.
"""
from __future__ import annotations

import hashlib
import secrets

from pq_operation_budget import OperationBudget
import pq_root_recovery_policy_v1 as model
import pq_root_recovery_signatures_v2 as signatures

SCHEMA = "trnm.root-effect-provider-readback.v2"
DOMAIN = b"TRNM/RootRecoveryJournal/ProviderReadback/v2\x00"
REQUEST_DOMAIN = b"TRNM/RootRecoveryJournal/ProviderReadbackRequest/v2\x00"
MAX_IDENTITY = 256
MAX_MESSAGE = 4096
REQUEST_FIELDS = ("schema", "scope", "challenge", "operation_id", "intent_sha512",
                  "provider", "orphaned_at")
RECEIPT_FIELDS = ("schema", "scope", "challenge", "request_sha512", "operation_id",
                  "intent_sha512", "provider", "receipt_id", "outcome",
                  "reconciled_reorg", "reconciliation")
OUTCOMES = ("unknown", "applied", "not-applied", "compensated")
RECONCILIATION = {"applied": "liability-retained", "not-applied": "not-applied",
                  "compensated": "compensated"}
Reject = model.Reject


def _require(condition, code):
    model.require(condition, code)


def _identity(value, where):
    # Identifiers are opaque, bounded printable ASCII without whitespace. They
    # are not display names, URLs to fetch, or a source of replacement keys.
    _require(type(value) is str and 0 < len(value) <= MAX_IDENTITY
             and all(0x21 <= ord(character) <= 0x7e for character in value),
             where + ":identity")


def _epoch(value, where):
    if value is not None:
        model.uint(value, where)


def _request(value):
    model.fields(value, REQUEST_FIELDS, "provider-request")
    # All accepted values are scalars. Detach the container before any callback.
    value = dict(value)
    _require(type(value["schema"]) is str and value["schema"] == SCHEMA,
             "provider-request:schema")
    for name in ("scope", "operation_id", "intent_sha512"):
        model.hex_bytes(value[name], 64, "provider-request:" + name)
    model.hex_bytes(value["challenge"], 32, "provider-request:challenge")
    _identity(value["provider"], "provider-request:provider")
    _epoch(value["orphaned_at"], "provider-request:orphaned-at")
    return value


def _receipt(value):
    model.fields(value, RECEIPT_FIELDS, "provider-receipt")
    value = dict(value)
    _require(type(value["schema"]) is str and value["schema"] == SCHEMA,
             "provider-receipt:schema")
    for name in ("scope", "request_sha512", "operation_id", "intent_sha512"):
        model.hex_bytes(value[name], 64, "provider-receipt:" + name)
    model.hex_bytes(value["challenge"], 32, "provider-receipt:challenge")
    for name in ("provider", "receipt_id"):
        _identity(value[name], "provider-receipt:" + name)
    outcome, reconciliation = value["outcome"], value["reconciliation"]
    _require(type(outcome) is str and outcome in OUTCOMES, "provider-receipt:outcome")
    _epoch(value["reconciled_reorg"], "provider-receipt:reconciled-reorg")
    if reconciliation is None:
        _require(value["reconciled_reorg"] is None,
                 "provider-receipt:epoch-without-reconciliation")
    else:
        _require(type(reconciliation) is str and outcome in RECONCILIATION
                 and reconciliation == RECONCILIATION[outcome],
                 "provider-receipt:outcome-reconciliation")
        _require(value["reconciled_reorg"] is not None,
                 "provider-receipt:reconciliation-without-epoch")
    return value


def request_sha512(request):
    raw = model.canonical(_request(request))
    return hashlib.sha512(REQUEST_DOMAIN + len(raw).to_bytes(8, "big") + raw).hexdigest()


def request_for(scope, operation_id, intent_sha512, provider, orphaned_at=None):
    """Create the owner's fresh request; callers cannot supply its challenge.

    The caller must obtain these expected fields from its current protected
    journal, keep this exact request across the transport, and use one original
    operation budget. Parsing an incoming request is not this trust bootstrap.
    """
    return _request({"schema": SCHEMA, "scope": scope,
                     "challenge": secrets.token_hex(32), "operation_id": operation_id,
                     "intent_sha512": intent_sha512, "provider": provider,
                     "orphaned_at": orphaned_at})


def receipt_for(request, *, receipt_id, outcome, reconciliation=None):
    """Construct an unsigned declaration for a provider to inspect and sign.

    Reconciliation must be explicit. If supplied it names exactly the requested
    orphan epoch: applied/liability-retained, not-applied/not-applied, or
    compensated/compensated. Unknown never supplies reconciliation.
    """
    request = _request(request)
    return _receipt({"schema": SCHEMA, "scope": request["scope"],
                     "challenge": request["challenge"],
                     "request_sha512": request_sha512(request),
                     "operation_id": request["operation_id"],
                     "intent_sha512": request["intent_sha512"],
                     "provider": request["provider"], "receipt_id": receipt_id,
                     "outcome": outcome,
                     "reconciled_reorg": request["orphaned_at"] if reconciliation is not None else None,
                     "reconciliation": reconciliation})


def receipt_message(receipt):
    """The complete, role-separated message signed by both provider families."""
    raw = model.canonical(_receipt(receipt))
    message = DOMAIN + len(raw).to_bytes(8, "big") + raw
    _require(len(message) <= MAX_MESSAGE, "provider-receipt:message-size")
    return message


def verify_readback(provider_policy, provider_keys, request, response, budget):
    """Verify a fresh provider declaration against the owner's exact request.

    ``provider_policy`` and ``provider_keys`` are independently enrolled pins,
    never selected by ``response``. ``reorg_reconciliation_verified`` means a
    signed declaration matched the exact requested orphan epoch. It does not
    prove the external outcome or grant another effect dispatch.
    """
    _require(isinstance(budget, OperationBudget), "provider-readback:budget")
    budget.check()
    request = _request(request)
    model.fields(response, ("receipt", "approvals"), "provider-response")
    receipt = _receipt(response["receipt"])
    for name in ("scope", "challenge", "operation_id", "intent_sha512", "provider"):
        _require(receipt[name] == request[name], "provider-readback:binding:" + name)
    _require(receipt["request_sha512"] == request_sha512(request),
             "provider-readback:request-binding")
    reconciled = receipt["reconciliation"] is not None
    if reconciled:
        _require(request["orphaned_at"] is not None
                 and receipt["reconciled_reorg"] == request["orphaned_at"],
                 "provider-readback:orphan-epoch")
    verification = signatures.verify_quorum(provider_policy, provider_keys,
                                            receipt_message(receipt), response["approvals"],
                                            budget=budget)
    _require(verification["signatures_verified"] is True
             and verification["verified_signatures"] == 4,
             "provider-readback:incomplete-quorum")
    budget.check()
    return {"schema": SCHEMA, "status": "HOLD", "research_only": True,
            "provider_declaration_verified": True, "signatures_verified": True,
            "verified_signatures": 4, "receipt": receipt,
            "request_sha512": request_sha512(request),
            "message_sha512": verification["message_sha512"],
            "outcome_known": receipt["outcome"] != "unknown",
            "reorg_reconciliation_verified": reconciled,
            "authorization_granted": False, "redispatch_permitted": False,
            "activation_performed": False, "production_qualified": False,
            "custody_verified": False, "actual_external_effects_verified": False,
            "whole_chain_pq_qualified": False, "composition_coverage_proved": False,
            "actual_lifetime_failure_bound": None}
