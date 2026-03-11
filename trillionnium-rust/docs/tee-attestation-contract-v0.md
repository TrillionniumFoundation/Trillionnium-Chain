# TEE Attestation Contract v0

This document defines the minimal feature-gated TEE attestation contract used by `trnm-pouw` when `real-tee-backend` is enabled.

## Purpose
The current goal is **not** to ship a production SGX/TDX/SNP verifier yet.
The goal is to freeze the backend handoff surface so future real attestation backends plug into a stable fail-closed contract.

## Receipt envelope
TEE receipts continue to use the bound envelope form:

```text
TEE:task_id=<u64>,worker=<id>,proof_type=tee,result_hash=<hex>,attestation_target=<token>,measurement=<value>,report_data_hash=<hex>,quote=<value>
```

The semantic verifier still owns:
- envelope prefix validation
- `task_id` / `worker` / `proof_type` / `result_hash` binding

The feature-gated real TEE backend additionally owns:
- `attestation_target` canonicalization
- required attestation fields
- minimal target-specific fixture matching
- `report_data_hash` ↔ task `result_hash` consistency

## Canonical attestation_target tokens
If `attestation_target` is provided, it must normalize to one of:
- `sgx-dcap`
- `tdx-qgs`
- `sev-snp`

Unknown values must fail closed before any cryptographic verification attempt.

## Required fields
The backend currently requires:
- `attestation_target`
- `measurement`
- `report_data_hash`
- `quote`

Missing or empty values are malformed receipts.

## report_data_hash binding
`report_data_hash` must match the task `result_hash` carried by the bound envelope.
This keeps the future attestation path aligned with the task result binding already enforced by the semantic verifier.

## Current implementation scope
With `real-tee-backend`, `trnm-pouw` registers a fixture-backed `real-tee-backend` implementation.
It validates the contract above against embedded SGX and TDX fixture vectors.
This is a **readiness scaffold**, not a production verifier.
