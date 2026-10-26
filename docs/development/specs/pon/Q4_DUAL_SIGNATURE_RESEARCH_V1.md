# Q4 dual-signed renewal packet differential research (non-authoritative)

This is a subordinate M01/M05/M06 research artifact under the sole Trillionnium-Chain development plan. It **does not** change Q4 revision9, QDL2/QWA2/PNX1 signing semantics, Revision12 Maintenance, W1, target, DAA, transaction admission, durable Node ownership or activation.

## Scope and exact provenance

- `formal/pon-nakamoto-v1/q4_signed_renewal_research.py` independently decodes the native 1,187-byte tag22 PNX1, 344-byte QDL2, 684-byte QWA2 and 584-byte QWT1 layouts, using the existing domain-separated PoN hash framing. It verifies the requester and source Ed25519 signatures over the exact, separate native signing digests, compares derived demand/lease/source/withdrawal/output-meter IDs, the old and proposed immutable Q4 fields, and inclusion-height/nonce/source-sequence limits.
- `checked_prepare` calls the existing research outbox only after a matching valid packet; it never dispatches a transaction, signs, issues a runtime token, resets a deadline/CPU/fee budget or substitutes Genesis Maintenance for a revoked selected lease.
- `formal/pon-nakamoto-v1/q4_research_go/verify_q4_vectors.go` is a separately authored, standard-library Go verifier. It checks the same packet independently, including both Ed25519 signatures. The frozen JSON vector contains one actual **development-only** dual-signed packet and nine individually modified packets that must reject.
- `test_q4_signed_renewal_research.py` covers actual two-key signatures, all 1,187 single-byte packet mutations, altered network/lease/context, expiry and nonce boundaries, absent crypto backend, and refusal to call the outbox after a mismatched intent. Python needs the optional `cryptography` dependency; absent dependency is an explicit *skip*, not a verified signature or a production pass. The Go verifier needs only the Go standard library.

Run independently from `formal/pon-nakamoto-v1`:

```sh
python3 -m unittest -v test_q4_signed_renewal_research.py
go run q4_research_go/verify_q4_vectors.go q4_signed_vectors_v1.json
```

The local source files were tested on a single research host: **11 Python tests PASS**, including 1,187 mutated full packets and all 344 old QDL2 bytes, and **1 Go positive plus 9 negative vectors PASS**. The Go source additionally passes `gofmt` and `go vet` in this local environment. Git blob SHA-1 identities for this candidate are:
- Python verifier: `46ccb72861f962217a45e0ac1cadca1e07dbabe8`
- Python tests: `4c648ac12e380fba8099caedab549ff82fee38d8`
- Go verifier: `f770d1c79c2eff6e9bd1d48e7f6d5d50a7b90546`
- JSON vector: `d9e776e38751ee27307a086e57fb7d92056aed13`

These are same-operator research observations, **not a native Rust test run or an independent institutional audit**. The Python `cryptography` and Go `crypto/ed25519` verification APIs do not inherit the full original native `verify_strict` weak-key/canonical-equivalence claim; future native differential tests must include low-order/canonical-negative vectors.

## Fixed old-Lease identity bypass in the research verifier

An independently discovered negative control changed the still-canonical old QDL2 `not_before` at byte offset 312. The original research decoder accepted the newly signed successor because it validated the old lease's format and temporal overlap but did not pin that supplied predecessor to an independently expected old lease ID. **This was a defect in the research verifier, not a demonstrated original native M06 bug.** The exact previously expected old lease ID is now a *mandatory*, caller-supplied and hash-checked argument; the old lease has no authority when it differs. The caller must obtain this ID from the genuinely verified parent-state owner, not from a peer or from the same submitted renewal request.

The new Python+Go experiments mutate every one of the 1,187 signed transaction bytes and every one of the 344 predecessor lease bytes, retaining 9 named negative vectors. **11/11** local Python tests PASS, plus Go valid/negative/exhaustive mutations and local Go vet PASS. No original Node/W1/fork-owned chain admissibility, native Rust strict-signature compatibility or independent institutional review follows from these research-only tests.

## Unclosed authorities and blockers

The original lease, owner snapshot, current withdrawal state and caller-provided original source sequence are trusted *inputs* to this study. Matching Ed25519 signatures prove possession of the supplied keys, **not** independent administration, current on-chain authority, genuine demand, storage retention, source data consent or model value. In particular this independent reader cannot prove that the supplied old lease is the currently eligible parent-state lease; M06 must bind it to verified ancestry, account/fee/nonces and the branch's exact Q4 signer authority.

The existing research outbox has sticky `DISPATCH_UNKNOWN` and crash/ACK-fencing logic. This packet reader does not turn an untrusted `OBSERVED_CONFIRMED` label into a client proof, advance FinalUse, or authorize retry on ambiguity. P0-B closes only after the ordinary signed live owner, original durable intent, actual W1-maintained inclusion, independent native client verification, reorg/expiration/restart, all 32 slots and retained-source/custody failures pass on the exact integrated source.

P0-C fastest legal neural work and hostile ingress, P1-A/P1-C separately versioned native DAA, P1-B adversarial timing/effective-work economics and P2 independent-host WAN/storage remain **OPEN**. Production activation is unchanged.
