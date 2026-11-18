# Native-invalid body backpressure candidate

This candidate extends the measured r20 source `119cbdc8b7060df28b74230fa9265ada7bc75541` with the signed resource revision `r21-native-invalid-body-backpressure-v1`. It is an engineering repair candidate. The original hosted confirmation campaign on this new source is **NOT_RUN** at this source freeze; no efficacy, public-network, production, or independent-operator qualification is claimed.

## Causal evidence

The original confirmation campaign uses the same seven signed honest packets in its attack-free and 16-worker pressure phases. Both `7e4b96d4` and `119cbdc8` genuinely ran the original four-second window under the fixed 0.25-CPU parent. Both architectures confirmed 0/1 under pressure. Latest r20 originals and artifact hashes are recorded in [r20-original-window.json](r20-original-window.json), from [required-baseline run 44298913299](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44298913299).

The earlier 7e4 observations establish why adding another W1 verdict cache is insufficient. The existing strict negative cache already served 375/398 observed W1 attempts on x64 and 460/483 on arm64. Only 23 full native replays occurred in each pressure phase: 16 original invalid proofs and seven honest submissions. Rotating authenticated callers still caused paid request negotiation, canonical decoding, Node context checks, response encoding, and client work for every repeated body. The protected mutation CPU bucket did not refuse these requests; its budget does not account for every other thread sharing the external parent. Independent History replay retains 1,099 fresh Host checks per W1 packet. Its authority and freshness are unchanged here.

## Change and boundedness

A completed paid Submit may publish its already-authenticated, canonical request-body digest only after the original native Transcript/Product failure or an exact fact returned by the existing strict negative cache. A Hello cannot create or refresh a hint. Malformed statements, cancellation, Host/context errors, and valid work do not publish.

Each live server owns 256 fixed slots. A hint delays challenge eligibility for the identical body for at most 1,000 ms from that completed rejection. Lookups do not refresh the timestamp; live entries are never evicted; expired slots may be reused. Lock contention or poison omits an optional scheduling hint. There are no per-caller rows.

The waiting connection remains in the existing bounded WaitChallenge machinery and keeps the original Hello and overall deadlines. It owns no paid grant, raw body reservation, or worker slot. A not-yet-eligible entry cannot be the FIFO head, so eligible new bodies and read requests proceed. At eligibility, all original challenge, signature, spent-ticket, body-digest, canonical decoding, context, fresh Host, verifier, and CPU-owner checks still apply. The hint is neither a verdict nor an authorization.

The original challenge strength/rate, external 4 s / 0.25 CPU / 16 workers, attack client loops and inputs, original confirmation target, CPU burst/refill/start reservation, worker count, and Host checks remain unchanged. No `honest` label or test-specific identity is used.

## Policy and accounting

The resource commitment changes honestly. For challenge bits 8 / 12 / 16, the r21 identifiers are:

- `eac3a96f115592a98d5ebea84ef80b7752f8abbc4270ef7cc6d1e4050510505e`
- `49613f580225a1696c484d45721c8e5c9a342557df434b9d33a020c86e3add0b`
- `559547f1aa93a3d6aa24399f4e2d7c9fd62926778e459eada7c488f5387bceea`

Historical r20 and earlier vectors remain retained. Signed r20 challenges are explicitly rejected by the new profile, and arithmetic profiles remain separate. The reader's original file-size and numeric bounds are preserved.

`known_invalid_body_cooldown_publications` and `known_invalid_body_cooldown_waits` count retained hints and affected waits. Waiting duration is already included in `pending_challenge_wait_ns`; it is not an additional CPU debit. The original process CPU boundaries include failed, cancelled, retried, joined-service, setup, and readback work. Actor, dispatch, verifier, and Host clocks remain nested and must not be added to the enclosing process interval. Physical network bytes and energy remain unknown.

## Validation and remaining gate

[engineering-validation.json](engineering-validation.json) and [engineering-originals.tar.xz](engineering-originals.tar.xz) bind the actual commands, process records, stdout/stderr, failed attempts, selected test results, and final source digests. The real TCP control observes a second invalid body waiting before paid work while a Head, History, and different valid Submit finish; the delayed request subsequently receives the original native refusal. Controls also cover forged-Hello non-publication, absence of diagnostic-observer authority, cancellation, FIFO eligibility/expiry, fixed capacity, caller grants, input decoding, and signed policy separation.

The first compile's missing test-field initializer and the first strict Clippy dead-code refusal are retained; the implementation was corrected without weakening either gate. An initial zero-match test selector is retained as a lookup error and contributes no passing tests.

The decisive next result is the original hosted-CI confirmation report for this new candidate. A successful local test or Cargo exit does not establish the business target. Full archives from the r20 failure remain retained separately, and the r21 result must be reported against its own exact commit and signed policy.
