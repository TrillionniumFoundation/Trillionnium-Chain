# Passive original Node LPV1 observation

This optional standalone test reads Network, Parameters and Genesis from
the actual open original Rust Node and the other values from its typed
disposable policy fixture. It captures the original Rust serialization and
hash before calling the original enable API. Direct and self-host LPV1
receive only the captured frame during this pause. The only acknowledgement
that enters the original Node is a fixed, content-free continuation token.
Neither the native frame nor a match/refusal can authorize a database write.

The real test cases are a no-shadow reference, a matching shadow, a one-bit
wrong-Parameters shadow, and a matching shadow on a different legal policy
that original Node refuses as `POOL_CONTEXT`. Wrong Parameters produce a
well-formed but different context, not an LPV1 authentication error. The
independent comparison detects that after native evaluation, during the
pause. Read-only SQLite before/during/after establishes both independence
and persistence; the original public API checks unchanged active State.

Use the pinned HIA toolchain and the admitted original Node build from the
[held-policy recipe](../../src/mempool/HELD_POLICY_QUALIFICATION.md).

```sh
python3 -B hia/qualification/m05_owner_shadow/observe.py \
  --expect-source <exact-observation-head> \
  --original-build-source <exact-compiled-original-source> \
  --rustc <absolute-pinned-rustc> --cargo-target <original-target> \
  --cargo-messages <actual-locked-cargo-jsonl> \
  --cargo-messages-sha256 <immutable-event-digest> \
  --node-library-sha256 <immutable-original-rlib-digest> \
  --output <fresh-report-outside-checkout>
```

If reusing an earlier build, independently validate and retain exact Rust
inputs, external include graph, actual Cargo depfile and toolchain bindings,
as required by the held-policy recipe. The report separates the compiled
original source from the observation source. Nothing here is a new Node owner,
signed protected or continuous authorization, in-transaction rollback,
handover to native code, or a hosted Node/M05 test.
