# Q4 dual-signature byte oracle — independent research v1

**Scope:** subordinate P0-B test aid under `TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md` and the unchanged revision9 Q4 / revision12 optional-lease contract. This is not a new consensus profile, a production verifier, a signer, a dispatcher, an ordinary Hepta owner or an automatic renewal service. It never changes `CURRENT`, FinalUse, network parameters, the installed DAA, Q4 source signatures or producer authority.

## Why this exists

The existing `q4_renewal_outbox_research.py` deliberately accepts opaque laboratory 1,187-byte data. Its `DispatchUnknown` journal correctly prevents blind resubmission, but it **does not** validate the two Ed25519 signatures or the signed height/current-source binding. Treating an outbox receipt as authorization would be a category error. The new `q4_signed_wire_oracle_v1.py` provides a separately coded, read-only inspection boundary for the exact historical bytes. It produces only a local `CheckedQ4Bytes` research fact; it is not wired into an outbox dispatcher or a production node.

The caller must provide an independently current *parent-state* QDL2 old lease, its active status, actual containing height, network and parameter digests, requester account nonce, previous source sequence and previously bound model/input/task/meter. The caller cannot establish these facts by copying them out of the proposed transaction. The oracle cannot authenticate the caller or its parent-state snapshot, real source rights, withdrawal head, actual 16,384-byte material, fee balance, storage custody or original external operation history.

## Exact syntax and cryptographic checks

- Require 1,187-byte PNX1, correct network, tag22, 1,028-byte payload, expected account nonce, positive nonce, adequate transaction expiry, fee upper bound and authenticated requester signature over the original `H('tx-sign', unsigned PNX1)`.
- Decode 344-byte QDL2 with fixed fields, slot in 0..31, nonzero identities, valid derived demand ID, immutable generation/requester/source/authorization/DA identity, strictly incrementing revision, at most 1,000 block validity and `available_until=expires+100`.
- Check **actual inclusion height** satisfies `old.not_before <= next.not_before <= h <= old.expires`, with successor expiring strictly later. A queued preview is not guaranteed inclusion.
- Decode 684-byte QWA2, including canonical 584-byte QWT1. Recompute its source record/frontier, exact model layer identity, output meter, numeric profile, shapes, field/domain hashes, signed source sequence and old material binding; require the source Ed25519 signature over `H('qualified-task-source-sign-v2', unsigned QWA2)`.
- Reject changed requester/source signatures and data bytes, cross-context packets, substitution of model/input, unsigned data, invalid slot/revision/height, bad nonce, re-signing with the wrong source, noncanonical point/`S` checks and missing externally supplied parent-state fields.
- Return only the native `H('tx-id', full PNX1)` identity plus the observed source/lease and inclusion-time facts; neither a signature nor a full byte match proves an independent administrator or consensus inclusion.

`cryptography` supplies the local Ed25519 verification implementation. The oracle explicitly checks canonical point/S encodings but does **not** claim to be bit-for-bit equivalent to every small-order/weak-key policy in native `ed25519-dalek`; native strict signature verification and dedicated hostile-key parity remain required before any product reuse. The test keys are derived from public deterministic development strings, not real identities.

## Executed local scope

Run from `formal/pon-nakamoto-v1`:

```bash
python3 -m unittest -v test_q4_signed_wire_oracle_v1.py
```

The initial local run exposed an assertion mismatch (a successor made `source==requester` and was correctly rejected at lease identity validation before comparing old/new sources); the test was corrected without weakening validation. The corrected local Python 3.13.5 / `cryptography` 46.0.4 run passes **8/8** tests. Test categories: delayed repeated signed heights; exact two signatures and negative mutations; lease expiry/revocation; unsigned/length/flag refusal; requester nonce/source sequence; immutable lease/material; network/domain separation; external owner-state requirements. No original native Rust build or Python/Go/Rust cross-language parity has been run on the complete source tree in this environment.

Positive fixture is 1,187 bytes with SHA-256 `d667617c5c6d395704d38e1287b751180c7a5da57cd53da023e898a589b58356`, transaction ID `6e06b05dae97786544b0c67481378427b1ef6f1311e28a10642d44f0639f8bc3`, previous lease ID `d0cc2e03f7fe6f23eb2e85036413c42dda529f564b6a06d1eafa01f1136428d5` and successor lease ID `8f61579266e5aed4543034c25022b9cf458d60bd586420f04224710feda569c1`. It is signed with development keys for an invented study network, not admitted on the real native chain. The same raw packet verifies at heights 850, 899, 900, 950, 999 and 1000 against the supplied old lease; 849/1001/1100 reject. No fresh signature is created during rechecking.

## Strict open blockers

1. Produce matching byte/sig/negative vectors via the exact native Q4 parser and a separately authored verifier, including weak/small-order public keys. No authority should be based on this Python success.
2. Bind the original authorized `kernel.operations` outbox to the signed original operation and verified native parent lease/current withdrawal frontier; reconcile lost ACK and reorg without issuing a second submission or extending budgets.
3. Execute real native Maintenance + new registration + independent client confirmation, all 32 slots and the full post-retention re-open tests from the exact candidate, with independent source/owner operators. No CI outcome is a proxy for these observations.
4. W1 cheapest valid cost, hostile invalid proof/public ingress, native ASERT activation candidate, and independent 72-hour WAN remain separate P0-C/P1/P2 blockers.
