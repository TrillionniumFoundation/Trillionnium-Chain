# Account sequence names in signed native test fixtures

The native evaluation observation, round observation, pool mining and shared
operator fixtures call their account transaction sequence argument
`account_sequence`. It is the value assigned to the existing `Envelope.nonce`
field. The fixtures deliberately use fixed consecutive sequences to exercise
admission, replay rejection, atomic renewal, restart and fork behavior.

This argument is not a cryptographic random nonce. The fixtures sign the
unchanged `Envelope::signing_digest()` with Ed25519. This naming correction
does not change transaction fields, signed bytes, signature domains, fixture
sequence values, assertions, `next_nonce`, or `demand_nonce`.

The CodeQL Rust `HardcodedCryptographicValue` extension at commit
`6e9f9e38390175c41b99070a423c875f450759ca` includes a parameter-name heuristic
for a parameter named `nonce`. The observed alerts follow literal fixture
account sequences through these helper parameters. See the pinned
[query extension source](https://github.com/github/codeql/blob/6e9f9e38390175c41b99070a423c875f450759ca/rust/ql/lib/codeql/rust/security/HardcodedCryptographicValueExtensions.qll).

The shared operator helper is also called by the checkpoint operator tests;
those callers and their assertions remain unchanged. This correction does not
suppress a query, dismiss an alert, change CI, or certify any future CodeQL run.
The retained SARIF observation and the subsequent selected tests are separate
evidence. Development fixture keys remain development fixture keys; changing
the sequence argument name does not strengthen their key custody or establish
public deployment readiness.
