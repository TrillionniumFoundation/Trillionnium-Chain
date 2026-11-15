"""Read-only fixed-W1 relation to exact matrix-content accounting bridge.

V2 roots describe new records; historical V1 signatures retain their meaning.
Scalar verification checks only the supplied relation, not native admission,
real demand, net benefit, physical execution or Sybil hardness.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

INPUT_SCHEMA = "pon-four-propositions-w1-input-v2"
PIN_SCHEMA = "pon-four-propositions-w1-review-pins-v2"
SCHEMA = "pon-four-propositions-w1-view-v2"
MAX_BYTES = 4 * 1024 * 1024
PROOF_BYTES = 49188
PROFILE = "pon-matmul-transcript-64-v1"
SOURCE_BLOBS = {
    "formal/pon-nakamoto-v1/four_propositions_v1.py": "12436c7a0740d0a184814958fbb789a7a4ba7c86",
    "formal/pon-nakamoto-v1/work_oracle.py": "9cbfccd2d50af48fc43522b967ffdfb1f45ec098",
    "formal/pon-nakamoto-v1/contract_wire.py": "37f62b2f0913e372bc1c75fed2cd3a3e1267870b",
}
DESCRIPTOR = {
    "work_profile": PROFILE, "field_modulus": 4294967291,
    "input_shapes": [[64, 64], [64, 64]], "output_shape": [64, 64],
    "layout": "row-major", "scalar_encoding": "u32-little-endian",
    "product_semantics": "A*B-modulo-field_modulus",
    "proof_encoding": "PNW1-full-tiled-transcript-v1",
}
AUTHORITY = dict(payment_authorized=False, adoption_authorized=False,
                 consensus_credit_authorized=False, production_activation=False)


def require(condition, code):
    if not condition:
        raise ValueError("W1_BRIDGE_" + code)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), "FIELDS")


def hex_bytes(value, size):
    require(type(value) is str and len(value) == 2 * size and
            all(c in "0123456789abcdef" for c in value), "HEX")
    return bytes.fromhex(value)


def canonical(value):
    def visit(item, depth=0):
        require(depth <= 40, "JSON_DEPTH")
        if item is None or type(item) in (bool, str):
            return
        if type(item) is int:
            require(-(1 << 63) <= item < (1 << 64), "INTEGER")
        elif type(item) is list:
            for child in item:
                visit(child, depth + 1)
        elif type(item) is dict and all(type(k) is str for k in item):
            for child in item.values():
                visit(child, depth + 1)
        else:
            raise ValueError("W1_BRIDGE_JSON_TYPE")
    visit(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
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
        for key, item in items:
            require(key not in result, "DUPLICATE_KEY")
            result[key] = item
        return result
    def no_float(_):
        raise ValueError("W1_BRIDGE_NONINTEGER_JSON")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_float)
        canonical(value)
        return value
    except RecursionError as error:
        raise ValueError("W1_BRIDGE_JSON_DEPTH") from error


def dependencies(source_root=None):
    """Check bytes before imports; the local Python runtime remains trusted."""
    root = Path(source_root or Path(__file__).resolve().parents[2]).resolve()
    for name, expected in SOURCE_BLOBS.items():
        path = root / name
        require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), "SOURCE_PATH")
        with path.open("rb") as source:
            data = source.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "SOURCE_LIMIT")
        observed = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(observed == expected, "SOURCE_BYTES:" + name)
    path = root / "formal/pon-nakamoto-v1/four_propositions_v1.py"
    spec = importlib.util.spec_from_file_location("_trnm_w1_bridge_reviewed_v1", path)
    require(spec is not None and spec.loader is not None, "SOURCE_LOADER")
    view = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(view)
    # Pin original reader/config closure and refuse foreign preloaded modules.
    modules = view.dependencies(root)
    source = root / "formal/pon-nakamoto-v1"
    sys.path.insert(0, str(source))
    try:
        oracle = importlib.import_module("work_oracle")
    finally:
        sys.path.pop(0)
    require(Path(oracle.__file__).resolve() == source / "work_oracle.py", "LOADED_SOURCE")
    return root, view, modules["contract_wire"], oracle


def statement(relation):
    fields(relation, ("challenge", "target", "task", "proof_hex"))
    for name in ("challenge", "target", "task"):
        hex_bytes(relation[name], 32)
    hex_bytes(relation["proof_hex"], PROOF_BYTES)
    return {name: relation[name] for name in ("challenge", "target", "task")}


def _verify_and_derive(relation, wire, oracle):
    exact_statement = statement(relation)
    proof = hex_bytes(relation["proof_hex"], PROOF_BYTES)
    # No work_backend selection or precheck-only success path exists here.
    ticket, product = oracle.verify(*(hex_bytes(exact_statement[k], 32) for k in
                                     ("challenge", "task", "target")), proof)
    inputs = proof[4:4 + 2 * 4096 * 4]
    a_bytes, b_bytes = inputs[:4096 * 4], inputs[4096 * 4:]
    descriptor = canonical(DESCRIPTOR)
    output_spec = wire.H("w1-accounting-output-spec-v2", descriptor)
    product_bytes = struct.pack("<" + "I" * 4096, *product)
    proof_sha = hashlib.sha256(proof).hexdigest()
    binding = dict(inputs=exact_statement["task"], work_profile=PROFILE,
        task_content=wire.H("w1-accounting-task-content-v2", descriptor, a_bytes, b_bytes).hex(),
        output_spec=output_spec.hex(),
        output_content=wire.H("w1-accounting-output-content-v2", output_spec, product_bytes).hex(),
        qualified_work=wire.H("w1-accounting-qualified-work-v2", canonical(exact_statement),
                              bytes.fromhex(proof_sha)).hex())
    return binding, dict(statement=exact_statement, proof_sha256=proof_sha, ticket=ticket.hex(),
        product_bytes_sha256=hashlib.sha256(product_bytes).hexdigest(),
        numeric_semantics=json.loads(descriptor))


def derive_binding(relation, *, source_root=None):
    """Verify the supplied relation and derive fresh roots for new records.

    This helper has no reviewer pins or real-world/native authentication.
    project() independently pins the statement and composes accounting.
    """
    canonical(relation)
    _, _, wire, oracle = dependencies(source_root)
    return _verify_and_derive(relation, wire, oracle)[0]


def _project(value, pins, *, source_root=None):
    fields(value, ("schema", "accounting_input", "relation"))
    fields(pins, ("schema", "input_sha256", "statement", "proof_sha256", "accounting_pins"))
    require(value["schema"] == INPUT_SCHEMA and pins["schema"] == PIN_SCHEMA, "SCHEMA")
    hex_bytes(pins["input_sha256"], 32)
    hex_bytes(pins["proof_sha256"], 32)
    same(sha(value), pins["input_sha256"], "INPUT_BINDING")
    exact_statement = statement(value["relation"])
    fields(pins["statement"], ("challenge", "target", "task"))
    for name in pins["statement"]:
        hex_bytes(pins["statement"][name], 32)
    same(exact_statement, pins["statement"], "STATEMENT_BINDING")
    proof = hex_bytes(value["relation"]["proof_hex"], PROOF_BYTES)
    same(hashlib.sha256(proof).hexdigest(), pins["proof_sha256"], "PROOF_BINDING")
    root, view, wire, oracle = dependencies(source_root)
    binding, relation_facts = _verify_and_derive(value["relation"], wire, oracle)
    accounting = value["accounting_input"]
    require(type(accounting) is dict and type(accounting.get("binding")) is dict, "ACCOUNTING_SHAPE")
    for name, expected in binding.items():
        same(accounting["binding"][name], expected, "DERIVED_BINDING:" + name)
    original_view = view.project(accounting, pins["accounting_pins"], source_root=root)
    context = accounting["binding"]["context"]
    output_key = wire.H("unique-useful-output-v1", wire.canonical(dict(context=context,
        task_content=binding["task_content"], output_content=binding["output_content"]))).hex()
    return dict(schema=SCHEMA, input_sha256=sha(value), review_pins_sha256=sha(pins),
        relation=dict(status="VERIFIED_SUPPLIED_W1_RELATION", verifier="independent-scalar-work_oracle.py",
            full_transcript_and_product_verified=True, **relation_facts),
        derived_binding=binding, unique_output_key=output_key,
        exact_matrix_accounting_binding_verified=True,
        content_scope="same-context-fixed-profile-exact-matrix-bytes; no-global-semantic-dedup",
        accounting_namespace="new-v2-content-roots-only; historical-signatures-unchanged",
        original_accounting_view=original_view, reader_blob_pins=dict(SOURCE_BLOBS),
        reader_source_scope="checked-source-bytes; trusted-local-python-runtime; no-execution-attestation",
        native_header_statement_authenticated=False, native_admission_verified=False,
        execution_source_provenance_authenticated=False,
        cross_proposition_semantic_binding_authenticated=False,
        real_customer_authenticity_verified=False, independent_net_benefit_verified=False,
        all_algorithm_cost_bound=None, authority=dict(AUTHORITY))


def project(value, pins, *, source_root=None):
    """Report only after full relation and original accounting replay succeed."""
    try:
        canonical(value)
        canonical(pins)
        return _project(value, pins, source_root=source_root)
    except (KeyError, TypeError, IndexError, AttributeError, RecursionError) as error:
        raise ValueError("W1_BRIDGE_INPUT_SHAPE") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--check-view", type=Path)
    args = parser.parse_args()
    def read(path):
        with path.open("rb") as source:
            return loads(source.read(MAX_BYTES + 1))
    result = project(read(args.input), read(args.pins), source_root=args.source_root)
    if args.check_view is not None:
        same(result, read(args.check_view), "VIEW_MISMATCH")
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error) or type(error).__name__, file=sys.stderr)
        sys.exit(2)
