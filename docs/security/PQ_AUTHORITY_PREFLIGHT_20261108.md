# PQ authority preflight and root-signature research — 2026-11-08

Status: **Draft / HOLD**. This continuation starts from the existing PQ
integration candidate `12e510b211110d93d9ead07e02c07a1eecc28ae9`, tree
`a8c9634b9e0d59ccc9fd6a03875eee7fc76c099f`. The sole development plan remains
[the existing plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The [execution record](../../evidence/pq-authority-preflight-20261108-9d315/README.md)
records the actual tested successor and toolchain.

This source also preserves concurrent migration qualification through
`8d8f05566b2a1612a3bf4a6c6c71635df454d397`, including its independent CI
controls. Execution records distinguish the original and integrated commits.

## Actual release-owner change

The existing ML-DSA-65 release kernel checked a signature's membership and then
immediately verified that signature. A duplicate or unknown signer at the end
of the same set could therefore cause preceding verification work. A malformed
successor quorum could also be discovered only after the old root quorum was
verified. This is a rejection-cost finding; the reviewed path did not accept
those malformed quorums or grant them an effect.

The existing `verify_quorum` path now prepares the complete bounded set before
checking any signature mathematics. Preparation checks count, duplicate IDs,
current role membership, exact retained verifier/public-key correspondence and
the fixed signature length. Root rotation prepares both old and new quorums
before either is mathematically verified. Every supplied signature still has
to verify, including signatures beyond the threshold. A private prepared set
contains borrowed inputs only and grants no current authorization.

This preserves the original signed messages, root/release namespaces, quorum
thresholds, original source bounds and owner transition rules. Among already
invalid inputs, some error precedence changes deliberately: a later structural
error is now detected before an earlier mathematically invalid signature.
Successor root parsing and public-key validation still have their original
cost; this change does not claim that malformed root admission is cost-free.

The original kernel with the new regression overlay produced **6 failures and
3 passes**. The repaired kernel produced **9 passes**. The six red cases observe
the original error ordering for a late duplicate, unknown role member, missing
retained key, and malformed successor quorum. The cache test's first red case
is the missing entry; its mismatched key-ID and SPKI cases execute in the green
loop, rather than constituting separate red observations. Tests compare the
entire authority state after refusals, exercise bad additional signatures on
both root sides, and compare successful release/rotation/recovery state.
Source control flow plus those error-order regressions establish the ordering;
this is not a low-level verification-call counter or latency benchmark.

The canonical signature-length constant comes from `trnm-protocol`. That
existing exact-version dependency moves from test-only to normal dependencies
so non-test builds can use the same constant. `trillionnium/Cargo.lock` is
unchanged. The independent `tests/fuzz/Cargo.lock` adds that one normal local
dependency edge; all package identities and versions remain unchanged. The
original missing-edge CI refusal is retained with the repair observation.

## Native timing-fixture correction

The integrated-source-01 run on
`af6b06fa1cb944e639148b58e9765fe2bb0065ab` completed all 31 command gates.
Thirty passed. The Node release-owner gate reported 39 passed, one failed and
one existing ignored test. Its positive post-admission completion test was
refused by the conservative time check before reaching `Admitted`: the signed
fixture allowed only two trusted seconds, while its real clock advances at
twice wall-clock speed. The original failure and every other gate are retained
in the execution record; that run remains FAIL.

The test now signs one 30-trusted-second window, deliberately waits past the
former two-second setup window, and starts the original two-second service
deadline only when sending the request. At the actual `Admitted` hook it checks
that admission occurred before the signed expiry, then waits on the same real
fixture clock until that exact expiry. An independent 20-wall-second bound
prevents an unbounded test wait. The existing lost-after-durable-completion
error, committed row/frontier/floor/fence checks and cold no-redispatch checks
remain. Both negative pre-admission expiry tests remain unchanged.

This changes only test scheduling. Production clock/expiry validation, service
deadlines, crypto, wire bytes and authority transitions are unchanged. The
follow-up exact native test and complete integrated validation identify their
own corrected source commit; earlier results are not relabelled.

## Binding and current-authority review

The following is a source-scoped review of the existing owner paths, not a
complete control-flow proof for every binary, plugin or external application.

| Actual boundary | Signed or independently pinned binding | Current-effect check |
| --- | --- | --- |
| NPQ6 account/application | Selected versioned command domain; network, parameters, genesis, account, generation, nonce, expiry, fee and exact role witnesses | M06 resolves keys from current State, charges the original verification budget and applies the original nonce/balance/task transition |
| PNQ2 network | Protected Settings and fixed peer policy; network/genesis policy, signer, generation, sequence, expiry, direction and payload commitment | Original Node ingress retains replay/resource accounting and then invokes the separate native work/application owner |
| Release and root rotation | Fixed ML-DSA-65 domain; network; complete root role rosters and thresholds; root generation; previous root; release role/version, expiry, expected checkpoint, previous/current content and explicit content rollback | Old and successor root quorums must both verify; rejected calls leave state unchanged; current release checks require current root generation, content and lifetime |
| M15 installation/launch/use | Protected namespace and trust configuration; complete signed configuration and bundle; exact artifact/platform/process; root digest/generation, checkpoint, policy, nonce and expiry | Independent frontier reconciliation, current checks at use, and durable single-use launch claims remain with the original owner |
| CPQ1 parameter research | Trusted bound profile includes network/genesis/protocol and suite; full canonical message binds purpose, owner generation, key epoch, sequence, lifetime and pinned signer set | Returns a mathematical candidate observation; current-profile selection refuses candidate profiles |

The owners do not share one universal wire schema. In particular, CPQ1's
explicit profile fields must not be described as fields already inserted into
legacy release or transaction signatures. Indirect binding is valid only when
the owner authenticates and rechecks the exact referenced configuration. A new
wire or stored schema requires its own version and migration contract.

Distinct public keys do not establish independently administered custodians.
Production custody, independent recovery anchors and cross-repository Hepta
CURRENT/FinalUse still need their own actual evidence. An old valid signature
can remain historical evidence while failing every current-effect check.

## Root-signature experiment

The original CPQ1 matrix already measures complete ML-DSA-65/87 candidate
messages and frames with 1/2/4/8 required signers. Its verifier requires all
pinned signers; those measurements are not a q-of-n root lifecycle benchmark.
Its repeated fixture message also does not sample distinct root operations.

The accompanying research harness compares fresh canonical proposals with an
ML-DSA-87 2-of-3 component observation and an ML-DSA-87 2-of-3 **AND**
SLH-DSA-SHA2-256s 2-of-3 complete candidate observation. The component result
always has `hybrid_policy_satisfied=false`; its separate frame cannot satisfy
the complete verifier, including after relabelling. The trusted configuration fixes
both complete rosters, thresholds, algorithm choices and the composition rule.
Both families sign the same complete proposal. New operation IDs and sequence
values vary across 64 paired samples. Algorithm selectors in untrusted frames
cannot change the expected configuration.

The full verifier accepts exactly two distinct selected keys from each fixed
three-key roster. It refuses redundant signature entries rather than defining
a general variable-cardinality root policy. The existing release owner retains
its original rule that every supplied signature must verify. The research
protocol is a separate namespace and does not replace that owner.

This experiment uses the explicitly pinned OpenSSL 3.5.9 command-line provider.
Reported times include command startup and file handling; they are not warm EVP
or production Node measurements. Key provisioning uses temporary experiment
keys, and no deployed key, root or execution permission is changed. The output
retains raw samples, negative cases, provider/source identities and explicit
false production/effect claims. Signing/encoding, complete frame verification
and their combined latency are recorded separately. The frame includes the
proposal and selected signer SPKIs/signatures. The complete trusted 3+3
configuration is encoded and counted separately; prior configuration
distribution and custody are outside the measured frame and latency. This is
not total key-management lifecycle cost. The shared host is not isolated and
may have concurrent Cargo validation load; measured sample tails are descriptive.

Native controls cover all nine legal pairs of 2-of-3 subsets and twelve
refusals, including either missing family, stale generation/epoch, wrong state,
wrong context, expired view, split proposals across the families, and a bad last
signature. Fixed current views in this research do not implement durable
anti-replay, root transitions or independent recovery custody.

The actual local run completed 64 pairs, all nine legal combinations and all
twelve refusal controls using 877 OpenSSL commands. Each proposal was 846
bytes. The component frame was 15,484 bytes; the complete AND frame was 75,378
bytes. The separately encoded trusted configuration was 8,717 bytes.

| Command-cold path, 64 samples | Signing and encoding median | Complete frame verification median | Combined median | Combined empirical p95 |
| --- | ---: | ---: | ---: | ---: |
| ML-DSA-87 component | 20.468 ms | 16.539 ms | 37.429 ms | 47.128 ms |
| ML-DSA-87 AND SLH-DSA-SHA2-256s | 4,120.412 ms | 36.787 ms | 4,160.439 ms | 4,682.190 ms |

The approximately four-second combined path is dominated by signing/encoding,
not frame verification. These descriptive p95 values use nearest rank and do
not estimate production tail guarantees. Requested runtime resource limits
were recorded, but their historical enforcement was not proven by the
post-exit systemd query. Raw records and stage maxima remain in the execution
record; no samples were discarded as outliers.

An OR recovery rule would have different security semantics: either accepted
path could grant the recovery authority. A second signature family does not by
itself establish security after compromise of either path. The AND experiment
requires both families, without assuming independent implementation failures or
multiplying their failure probabilities.

## Standard status and sizes

Checked against NIST publications on 2026-11-08. FIPS 203, 204 and 205 are final;
NIST still lists FIPS 206/FN-DSA as in development and HQC as selected for
standardization. HQC is a KEM, not a digital-signature replacement.

| Parameter | NIST category | Raw public key | Signature |
| --- | ---: | ---: | ---: |
| ML-DSA-65 | 3 | 1,952 bytes | 3,309 bytes |
| ML-DSA-87 | 5 | 2,592 bytes | 4,627 bytes |
| SLH-DSA-SHA2-256s | 5 | 64 bytes | 29,792 bytes |

Two signatures from each experimental family contain 68,838 signature bytes
before framing. This arithmetic is not a latency measurement. NIST categories
are relative primitive security categories, not a quantified whole-chain
quantum security claim. FIPS 205's additional message-binding discussion is also
relevant to dispute/recovery semantics; operation IDs must be fixed and signed
as part of the complete canonical operation. Signature bytes are not an
appropriate operation identifier.

LMS/XMSS remain outside this frequent snapshot/rollback path. Their security
requires non-reuse of signing state, including durable advancement before a
signature is released. Their mathematical post-quantum status does not remove
that operational requirement.

Sources: [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final),
[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final),
[current NIST standardization status](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization),
[NIST stateful signatures](https://csrc.nist.gov/projects/stateful-hash-based-signatures),
[RFC 8554](https://www.rfc-editor.org/rfc/rfc8554.html),
[OpenSSL 3.5 SLH-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-SLH-DSA/).

## Qualification boundary

Exact component tests and the root-signature experiment do not establish full
entrypoint migration, independent custody, original fixed-Host availability,
WAN acceptance, a complete PQ proof composition or quantum PoN work cost.
The original whole-chain HOLD and independent acceptance requirements remain.
