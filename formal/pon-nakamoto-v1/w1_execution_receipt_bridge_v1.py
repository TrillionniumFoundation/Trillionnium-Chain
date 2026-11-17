"""Authenticate a pinned W1 execution receipt without claiming physical execution.

The signer authenticates the exact receipt bytes.  This reader independently
replays the scalar W1/accounting bridge and checks receipt/source/binary/result
bindings.  A valid signature is not remote attestation, customer evidence,
net-benefit evidence, native admission, or an all-algorithm cost lower bound.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

INPUT_SCHEMA = "pon-w1-execution-receipt-input-v1"
PIN_SCHEMA = "pon-w1-execution-receipt-review-pins-v1"
RECEIPT_SCHEMA = "pon-w1-execution-receipt-v1"
SCHEMA = "pon-w1-execution-receipt-view-v1"
MAX_BYTES = 4 * 1024 * 1024
SIGNING_DOMAIN = b"trnm-pon-w1-execution-receipt-v1\0"
SOURCE_BLOBS = {
    "formal/pon-nakamoto-v1/four_propositions_w1_v2.py":
        "f03d2c1e76f37525d57447d08e7bc3f2f575c9f1",
}
AUTHORITY = dict(payment_authorized=False, adoption_authorized=False,
                 consensus_credit_authorized=False, production_activation=False)


def require(condition, code):
    if not condition:
        raise ValueError("W1_RECEIPT_" + code)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), "FIELDS")


def hex_bytes(value, size):
    require(type(value) is str and len(value) == size * 2
            and all(c in "0123456789abcdef" for c in value), "HEX")
    return bytes.fromhex(value)


def canonical(value):
    def visit(item, depth=0):
        require(depth <= 48, "JSON_DEPTH")
        if item is None or type(item) in (bool, str):
            return
        if type(item) is int:
            require(-(1 << 63) <= item < (1 << 64), "INTEGER")
            return
        if type(item) is list:
            for child in item:
                visit(child, depth + 1)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                visit(child, depth + 1)
            return
        raise ValueError("W1_RECEIPT_JSON_TYPE")
    visit(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode()
    require(len(raw) <= MAX_BYTES, "INPUT_LIMIT")
    return raw


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def same(actual, expected, code):
    require(canonical(actual) == canonical(expected), code)


def loads(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "INPUT_LIMIT")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_KEY")
            result[key] = value
        return result

    def no_float(_):
        raise ValueError("W1_RECEIPT_NONINTEGER_JSON")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=no_float,
                           parse_constant=no_float)
        canonical(value)
        return value
    except RecursionError as error:
        raise ValueError("W1_RECEIPT_JSON_DEPTH") from error


def dependencies(source_root=None):
    """Pin the composed V2 reader before loading it."""
    root = Path(source_root or Path(__file__).resolve().parents[2]).resolve()
    for name, expected in SOURCE_BLOBS.items():
        path = root / name
        require(path.is_file()
                and not any(part.is_symlink() for part in (path, *path.parents)),
                "SOURCE_PATH")
        data = path.read_bytes()
        require(len(data) <= MAX_BYTES, "SOURCE_LIMIT")
        observed = hashlib.sha1(
            b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(observed == expected, "SOURCE_BYTES:" + name)
    path = root / "formal/pon-nakamoto-v1/four_propositions_w1_v2.py"
    spec = importlib.util.spec_from_file_location(
        "_trnm_w1_execution_receipt_reviewed_v2", path)
    require(spec is not None and spec.loader is not None, "SOURCE_LOADER")
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    return root, bridge


def source_identity(value):
    fields(value, ("commit", "tree"))
    hex_bytes(value["commit"], 20)
    hex_bytes(value["tree"], 20)
    return dict(value)


def relation_identity(value):
    fields(value, ("challenge", "target", "task", "proof_sha256"))
    for name in ("challenge", "target", "task", "proof_sha256"):
        hex_bytes(value[name], 32)
    return dict(value)


def result_identity(value):
    fields(value, ("ticket", "product_bytes_sha256", "output_content",
                   "qualified_work", "w1_view_sha256"))
    for name in value:
        hex_bytes(value[name], 32)
    return dict(value)


def receipt_body(receipt):
    fields(receipt, ("schema", "source_before", "source_after",
                     "binary_before_sha256", "binary_after_sha256",
                     "command_sha256", "environment_sha256", "relation",
                     "completed", "exit_code", "result",
                     "signer_public_key", "signature"))
    require(receipt["schema"] == RECEIPT_SCHEMA, "RECEIPT_SCHEMA")
    body = dict(receipt)
    del body["signature"]
    return body


def verify_signature(receipt):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    body = receipt_body(receipt)
    public = hex_bytes(receipt["signer_public_key"], 32)
    signature = hex_bytes(receipt["signature"], 64)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, SIGNING_DOMAIN + canonical(body))
    except (InvalidSignature, ValueError) as error:
        raise ValueError("W1_RECEIPT_SIGNATURE") from error


def _project(value, pins, *, source_root=None):
    fields(value, ("schema", "w1_input", "receipt"))
    fields(pins, ("schema", "input_sha256", "w1_pins", "expected_source",
                  "expected_binary_sha256", "expected_command_sha256",
                  "expected_environment_sha256", "signer_public_key"))
    require(value["schema"] == INPUT_SCHEMA and pins["schema"] == PIN_SCHEMA,
            "SCHEMA")
    for name in ("input_sha256", "expected_binary_sha256",
                 "expected_command_sha256", "expected_environment_sha256"):
        hex_bytes(pins[name], 32)
    hex_bytes(pins["signer_public_key"], 32)
    same(sha(value), pins["input_sha256"], "INPUT_BINDING")

    receipt = value["receipt"]
    body = receipt_body(receipt)
    before = source_identity(body["source_before"])
    after = source_identity(body["source_after"])
    expected_source = source_identity(pins["expected_source"])
    same(before, after, "SOURCE_CHANGED")
    same(before, expected_source, "SOURCE_PIN")

    for name in ("binary_before_sha256", "binary_after_sha256",
                 "command_sha256", "environment_sha256"):
        hex_bytes(body[name], 32)
    same(body["binary_before_sha256"], body["binary_after_sha256"],
         "BINARY_CHANGED")
    same(body["binary_before_sha256"], pins["expected_binary_sha256"],
         "BINARY_PIN")
    same(body["command_sha256"], pins["expected_command_sha256"],
         "COMMAND_PIN")
    same(body["environment_sha256"], pins["expected_environment_sha256"],
         "ENVIRONMENT_PIN")
    require(body["completed"] is True and type(body["exit_code"]) is int
            and body["exit_code"] == 0, "PROCESS_RESULT")
    same(body["signer_public_key"], pins["signer_public_key"], "SIGNER_PIN")
    verify_signature(receipt)

    root, bridge = dependencies(source_root)
    w1_view = bridge.project(value["w1_input"], pins["w1_pins"],
                             source_root=root)
    expected_relation = {
        name: w1_view["relation"]["statement"][name]
        for name in ("challenge", "target", "task")
    }
    expected_relation["proof_sha256"] = w1_view["relation"]["proof_sha256"]
    same(relation_identity(body["relation"]), expected_relation,
         "RELATION_BINDING")
    expected_result = dict(
        ticket=w1_view["relation"]["ticket"],
        product_bytes_sha256=w1_view["relation"]["product_bytes_sha256"],
        output_content=w1_view["derived_binding"]["output_content"],
        qualified_work=w1_view["derived_binding"]["qualified_work"],
        w1_view_sha256=bridge.sha(w1_view),
    )
    same(result_identity(body["result"]), expected_result, "RESULT_BINDING")

    return dict(
        schema=SCHEMA,
        input_sha256=sha(value),
        review_pins_sha256=sha(pins),
        source_identity=before,
        binary_sha256=body["binary_before_sha256"],
        command_sha256=body["command_sha256"],
        environment_sha256=body["environment_sha256"],
        receipt_signature_verified=True,
        receipt_signer_public_key=body["signer_public_key"],
        execution_receipt_origin_authenticated=True,
        execution_receipt_statement_binding_verified=True,
        execution_receipt_source_identity_pinned=True,
        execution_receipt_binary_digest_pinned=True,
        signer_independence_verified=False,
        original_w1_view=w1_view,
        reader_blob_pins=dict(SOURCE_BLOBS),
        reader_source_scope=(
            "checked-reader-bytes; trusted-local-python-and-cryptography-runtime"),
        execution_source_provenance_authenticated=False,
        physical_execution_authenticated=False,
        native_header_statement_authenticated=False,
        native_admission_verified=False,
        cross_proposition_semantic_binding_authenticated=False,
        real_customer_authenticity_verified=False,
        independent_net_benefit_verified=False,
        all_algorithm_cost_bound=None,
        authority=dict(AUTHORITY),
    )


def project(value, pins, *, source_root=None):
    """Authenticate the receipt and replay V2; never promote physical execution."""
    try:
        canonical(value)
        canonical(pins)
        return _project(value, pins, source_root=source_root)
    except (KeyError, TypeError, IndexError, AttributeError,
            RecursionError) as error:
        raise ValueError("W1_RECEIPT_INPUT_SHAPE") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--check-view", type=Path)
    args = parser.parse_args()

    def read(path):
        return loads(path.read_bytes())

    result = project(read(args.input), read(args.pins),
                     source_root=args.source_root)
    if args.check_view is not None:
        same(result, read(args.check_view), "VIEW_MISMATCH")
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error) or type(error).__name__, file=sys.stderr)
        sys.exit(2)
