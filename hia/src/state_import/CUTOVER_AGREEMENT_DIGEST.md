# Native cutover record digest

The private `trnm_state_import_cutover_agreement_digest` computes only the
value of the original `CutoverAgreementV0::canonical_digest()`. It does
not verify an agreement, signature, signer identity, weight, change of
state, account, or deployment policy. The scalar fields are values to hash,
not assertions of an agreement or proof that any required weight was met.

Use `f0(input, output, work)` with disjoint, caller-owned spans. The 184-byte
input is:

| Offset | Field |
| ---: | --- |
| 0 | Eight bytes `NCAD0001` |
| 8, 40, 72 | Plan digest, target state root, target genesis ID (32 bytes each) |
| 104, 112 | Signed and required weight as u64 big-endian |
| 120 | Signer-set digest (32 bytes) |
| 152 | Cached agreement digest value (32 bytes, not read for the hash) |

The SHA-256 transcript contains `trnm.migration.cutover-agreement-record.v0`
and the six fields at offsets 8 through 151. Each part, including the
domain, is prefixed by its unsigned eight-byte big-endian byte length.
The cached digest and private ABI tag are not part of this transcript.

Status 0 writes exactly 32 bytes, leaving the output suffix untouched.
Status 100 rejects a malformed private frame; status 102 refuses a short
output or work buffer (minima 32 and 1456 bytes). Neither refusal writes
any of these spans. Internal status 103 publishes no digest. Work is
transient caller-owned storage; no data is persisted and there is no I/O.
