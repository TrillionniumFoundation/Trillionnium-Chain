# Explicit PQ backend contract and actual bounded r8 observations

Status: research candidate, **HOLD / NO_GO** for complete production
authorization and whole-chain post-quantum security. Original 189 hosted
failures and interrupted e642 native qualification retain their original result.

## Changes and limits

Five Python protocol oracles now require a canonical absolute OpenSSL executable,
SHA-256 and declared version (at least 3.5), matching the native `OPENSSL_DIR`.
There is no system-PATH selection in these wrappers. They use the default provider,
empty configuration and fixed modules path. Provider, provider-path, engine and
configuration overrides, including double-dash and equals aliases, are rejected
before the version child. Wire bytes, DER/OID checks, signature checks and original
protocol assertions remain intact.

The helper owns the direct trusted child, preserves its absolute operation
deadline/cancellation, and kills and reaps on failure. Private signing/keygen
diagnostics expose only exit code, stderr length and digest. This is not an
arbitrary-child or output-memory sandbox: output bounds apply after capture.
Only Envelope/Cell callers currently carry one budget across a logical operation;
the other wrappers receive a fresh 15-second budget per command.

CI still builds the exact pinned OpenSSL 3.5.9 archive and performs real
ML-DSA-65 keygen/sign/verify/wrong-message rejection before exporting the native
and CLI binding. The receipt has a fresh `trnm-ci-pq-provider-v3` namespace.
Three auxiliary workflows now prepare this provider before their original
all-features Clippy gate. The public Host passes only enumerated backend
variables. No original native selector, resource budget or passing denominator
was removed, and no optional PQ feature was skipped.

## Actual bounded executions

| Observation | Result | Scope |
| --- | --- | --- |
| Original M06 account target | 8/8 passed, 0 ignored; 47.548597 s wall including build; 47.316821 CPU s; wait4 peak RSS 561,068 KiB | Locked/offline, one build job, original synthetic keys/state, dirty 189-based source |
| Five real protocol suites | 72/72 passed, 0 skipped; 59.824179 s wall; 61.596870 CPU s; wait4 peak RSS 90,776 KiB | Genesis 23, Envelope 9, PQL4 12, PQL5 18, PQL6 10; dirty combined source at 5c8cbaa010e65123664bd75e38d5744b19d60b26 |
| Final backend controls | 13 passed, including 48 provider-alias refusal cases | Fault drivers fail every cryptographic call; no successful mock signature or verifier |
| Provider / Host environment / child controls | 9 / 20 / 2 passed | Wiring and child ownership, not a new hosted build or service qualification |

Both real commands were individually bounded and accepted by automatic review
after the earlier interrupted broader execution. They used ephemeral fixtures,
no deployed data/keys and no external network. Original intents, command lines,
complete stdout/stderr, wait4 costs and equal before/after source digests are
retained. The final backend review also retains its earlier 12-control state.

Rust and Python use the same underlying cryptographic implementation. Their
agreement is protocol evidence, not independent cryptographic implementation.
Local CLI SHA-256:
`0f9db29e103b1c7da08c7fe45ae47f84a0e9c388775520114598646a9041867f`.
These observations do not qualify a later unexecuted source.

## Exact source pins

[source-pin-review.json](source-pin-review.json) records all old/new blobs,
SHA-256 values and full text diffs. Seventeen existing pins are updated and two
required backend/control pins added. Original required paths, false activation
flags and native-owner contracts remain unchanged.

Six inherited mismatches are byte-identical to published 189: observation
wording, SQLite hooks, detached admission/activation retry, r14 policy, reorg
lifecycle schema and Node initializer. They are separated from the eleven
changed oracle/fixture files. Repinning binds actual source; it does not grant
runtime or whole-authorization acceptance. Both historical/current schema
vectors remain in the separate exact-reader evidence.

## Remaining gates

Cell/task/Operator/Hepta authorization, independently authenticated migration
history, pure-PoN quantum hardness, proof-system quantum soundness, physical
rollback protection, sustained-depletion service and independent WAN remain
open. Other standalone research fixtures still contain direct PATH OpenSSL
calls; they are outside the five-suite result, not silently counted as passing.
Exact hosted qualification of the published combined candidate remains required.

See [readback.json](readback.json), the runtime subdirectories and
[the provider-alias review](provider-alias-review/control-receipt.json).

Raw unified diffs and the exact M06 stdout are transported without byte edits in
[the raw archive](exact-raw-whitespace-records.zip).
[The transport receipt](exact-raw-transport.json) records original paths, digests
and the initial whitespace-check failure. No whitespace check is disabled.
