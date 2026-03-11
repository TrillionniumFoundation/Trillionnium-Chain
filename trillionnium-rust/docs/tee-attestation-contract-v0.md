# TEE Attestation Contract v0

This document defines the feature-gated TEE attestation contract used by `trnm-pouw` when `real-tee-backend` is enabled.

## Purpose
The current goal is **not** to ship a production SGX/TDX/SNP verifier yet.
The goal is to freeze the backend handoff surface so future real attestation backends plug into a stable fail-closed contract.

## Receipt envelope
TEE receipts continue to use the bound envelope form:

```text
TEE:task_id=<u64>,worker=<id>,proof_type=tee,result_hash=<hex>,attestation_target=<token>,measurement=<value>,report_data_hash=<hex>,<evidence-field>=<value>[,<target-specific-verifier-metadata>]
```

The semantic verifier still owns:
- envelope prefix validation
- `task_id` / `worker` / `proof_type` / `result_hash` binding

The feature-gated real TEE backend additionally owns:
- `attestation_target` canonicalization
- target-specific measurement slot validation
- target-specific evidence kind validation (`quote` vs `report`)
- required attestation fields
- target-specific verifier metadata validation
- `report_data_hash` ↔ task `result_hash` consistency

## Canonical attestation target matrix

| target | adapter | verifier kind | evidence field | measurement prefix | required verifier metadata | notes |
| --- | --- | --- | --- | --- | --- | --- |
| `sgx-dcap` | `SgxDcapAdapter` | `quote-verifier` | `quote` | `mrenclave:` | `collateral`, `cert_chain`, `issuer` | Intel SGX DCAP-style quote path |
| `tdx-qgs` | `TdxQgsAdapter` | `quote-verifier` | `quote` | `mrtd:` | `collateral`, `cert_chain`, `issuer` | Intel TDX QGS quote path |
| `sev-snp` | `SevSnpAdapter` | `report-verifier` | `report` | `measurement:` | `vcek`, `cert_chain`, `report_signer` | AMD SEV-SNP report path |

Unknown values must fail closed before any cryptographic verification attempt.

## Required fields
All targets require:
- `attestation_target`
- `measurement`
- `report_data_hash`

Target-specific evidence is also required:
- `sgx-dcap` → `quote`
- `tdx-qgs` → `quote`
- `sev-snp` → `report`

Target-specific verifier metadata is now explicit:
- quote-based targets (`sgx-dcap`, `tdx-qgs`) require:
  - `collateral`
  - `cert_chain`
  - `issuer`
- report-based target (`sev-snp`) requires:
  - `vcek`
  - `cert_chain`
  - `report_signer`

Cross-family metadata must fail closed:
- quote-based targets must not rely on `vcek` / `report_signer`
- report-based targets must not rely on `collateral` / `issuer`

Missing or empty values are malformed receipts.

## Backend handoff contract
The scaffold canonicalizes TEE receipts into an intermediate `TeeVerifierHandoff` with these fields:

- `attestation_target`
- `verifier_kind` (`quote-verifier` or `report-verifier`)
- `measurement_field` (`mrenclave` / `mrtd` / `measurement`)
- `measurement`
- `report_data_hash`
- target-specific evidence (`quote` or `report`)
- structured verifier metadata

A target-specific adapter then turns that handoff into one of two concrete verifier inputs.

### Quote verifier input
Used by SGX DCAP and TDX QGS adapters.

```text
{
  attestation_target,
  verifier_kind: "quote-verifier",
  measurement_field,
  measurement,
  report_data_hash,
  quote,
  collateral,
  cert_chain,
  issuer
}
```

### Report verifier input
Used by SEV-SNP adapter.

```text
{
  attestation_target,
  verifier_kind: "report-verifier",
  measurement_field,
  measurement,
  report_data_hash,
  report,
  vcek,
  cert_chain,
  report_signer
}
```

This is the seam future real quote/report verifiers should consume.

## report_data_hash binding
`report_data_hash` must match the task `result_hash` carried by the bound envelope.
This keeps the future attestation path aligned with the task result binding already enforced by the semantic verifier.

## Current implementation scope
With `real-tee-backend`, `trnm-pouw` registers a fixture-backed `real-tee-backend` implementation.
It validates the contract above against embedded fixture vectors for:
- SGX DCAP quote verifier input
- TDX QGS quote verifier input
- SEV-SNP report verifier input

This is a **readiness scaffold**, not a production verifier.
