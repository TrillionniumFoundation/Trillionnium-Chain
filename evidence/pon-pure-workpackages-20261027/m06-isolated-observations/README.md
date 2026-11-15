# Isolated M06: actual deadline and service counterexamples

**BLOCKED.** These are copied original observations from source
`dcdf0503a1c52c4423963e9acba176f13fea2913`, successor of
`08d647017c38eb0213f8d60db938222df4f59195`. Neither prototype implementation nor
its ancestry is integrated into this candidate. The source/binary identities,
original process statuses and compressed stdout/stderr are retained in the
[readback](readback.json). Gzip decompression reproduces each original byte.

The exact original signed frame resumed its own durable intent after the actual
10-second request deadline, once on a new socket; this control passed. Changed
payload, other target/context, future nonce and unrelated Head were refused.
The original requester then withholding its frame produced a separate **failing**
service test: the next honest mutation completed 0/1, with
`REORG_IN_PROGRESS`; the intent remained unfinished, nonce 1 unacknowledged,
audit count 1 and work verification count 1. No fresh CPU account was created.
The deadline was actually elapsed, not injected as a typed test error.

The detached group retained **11 pass / 1 fail / 1 ignored**. Its valid custom
8,625,548-byte parent state exhausted 3,008,232,223 ns of original owner CPU before
any M06 worker spawned. The original validator and a real signed parent admitted
that seeded fixture. It does not prove natural default-genesis history reaches
that state or provide a paired held-path causal comparison. The authenticated
backend half after the failing assertion did not run.

The final affected regression group retained **373 pass / 1 fail / 3 ignored,
377 planned**. The original signed Head cost observation planned 256 requests,
reported the 64-success checkpoint, then failed with `REMOTE_RETRYABLE:BUSY:Duplicate`.
Its exact failure nonce was not printed and remains unknown. The failure was not
relabelled as successful refusal, retried away or removed from the denominator.
The other deliberate panic controls in stderr are distinguished by their
individual test verdicts; stderr alone is not a count of failed tests.

These source-bound results do not qualify the main candidate, all honest service,
an independent operator, WAN availability or recovery under every owner mode.
