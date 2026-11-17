# W1 signed execution-receipt bridge V1

Status: **HOLD / NO-GO**. This read-only bridge authenticates the origin and
exact contents of a reviewer-pinned execution receipt. It does not authenticate
the physical process that produced the receipt, a remote host, native admission,
a customer, net benefit, or an all-algorithm resource lower bound. It grants no
payment, adoption, consensus-credit or production authority.

## Composition

[w1_execution_receipt_bridge_v1.py](../../formal/pon-nakamoto-v1/w1_execution_receipt_bridge_v1.py)
first pins and loads the reviewed
[W1 V2 accounting bridge](../../formal/pon-nakamoto-v1/four_propositions_w1_v2.py).
V2 independently verifies the complete scalar transcript and matrix product,
derives the exact content roots, and replays the original four-proposition
accounting view. The new reader then checks one Ed25519-signed receipt against
independent review pins.

The input schema is `pon-w1-execution-receipt-input-v1`. The receipt fixes:

- identical source-before/source-after commit and tree identities;
- identical binary-before/binary-after SHA-256 values;
- canonical command and environment SHA-256 values;
- the exact V2 challenge, target, task and proof digest;
- the V2 ticket, product digest, output-content root, qualified-work root and
  complete V2-view digest;
- successful completion and exit code zero; and
- the exact signing public key and signature.

The signature domain is `trnm-pon-w1-execution-receipt-v1\0` followed by
sorted compact ASCII JSON of every receipt field except `signature`. The
review-pin schema independently fixes the entire input digest, source identity,
binary/command/environment digests, public key, and all original V2 pins.
Duplicate keys, floats, NaN/infinity, unknown fields, type aliases, source or
binary drift, failed processes, signature changes and result changes refuse.

## Exact scope

A successful view reports
`execution_receipt_origin_authenticated=true`: the pinned public key signed
these exact canonical receipt bytes. It also reports exact W1 statement/result,
source-identity and binary-digest bindings. This closes only the ambiguity
between an unsigned result summary and its reviewed receipt origin.

It deliberately retains all of the following:

- `execution_source_provenance_authenticated=false`;
- `physical_execution_authenticated=false`;
- `native_header_statement_authenticated=false`;
- `native_admission_verified=false`;
- `signer_independence_verified=false`;
- real-customer and independent-net-benefit fields false;
- `all_algorithm_cost_bound=null`; and
- every authority field false.

A signer can truthfully authenticate what it stated without proving that the
stated binary was the running image or that the environment excluded
replacement, virtualization, shared control, or measurement error. A future
physical-execution claim therefore needs a separate attestation and admission
contract; it must not reinterpret this receipt flag.

The [regressions](../../formal/pon-nakamoto-v1/test_w1_execution_receipt_bridge_v1.py)
cover the positive composition, independent signer/source/binary pins,
before/after drift, statement and result tampering, failed-process refusal,
strict JSON, source-byte drift, CLI reproduction, and unchanged false/null
boundaries. Their matrices, signer and receipt are synthetic.

```bash
python3 formal/pon-nakamoto-v1/test_w1_execution_receipt_bridge_v1.py -v
python3 formal/pon-nakamoto-v1/w1_execution_receipt_bridge_v1.py \
  --input input.json --pins pins.json --check-view prior-view.json
```

CLI exit zero authenticates only the supplied signed receipt and its replayed
bindings. It is not a four-proposition PASS.
