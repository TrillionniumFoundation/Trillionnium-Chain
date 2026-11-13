# HEPLCP03 source-corpus pin correction

The published compatibility source is Chain
`ced03a7aa4a09af36825a6fa258fd6bd80c79fa7`, tree
`ff1e6c252e273b45ed29a7150f7fd24dc5934b2c`. Its source-corpus manifest still
contained six blobs from the #847 parent despite the corresponding reviewed
HEPLCP03/CI/plan files changing. The unchanged original corpus inspector
actually returned exit 1 and `changed source` for the closure workflow.
This is retained as a source-fence failure, not an ordinary learning failure.

The repair changes exactly those six values in
`config/pon/pq-cross-branch-corpus-v1.json`. It preserves the complete 1,079-pin
key set, all 987 required paths in their original order, provenance parents,
original observations, original acceptance flags and every other manifest field.
There is no reader, native production source, test, threshold or gate change.
The changed corpus metadata is part of subsequent builds; no old binary identity
or native execution qualification is transferred to a new tree.

[RESULT.json](RESULT.json) records each old and actual blob, the unchanged set
identities, original refusal and fresh validation commands. Original streams
are retained in deterministic gzip files or their original regular text format;
empty outputs remain present. The actual unchanged inspector reads all 1,079
original source files and returns HOLD after the correction. The original
corpus-negative suite is executed without changing a test or expectation.

The source-only qualification remains **HOLD_NO_GO / DENY_ALL**. There is no
new model training, ordinary operation, independent consumer, authenticated
FinalUse, native node activation, settlement or physical rollback acceptance.
The [original compatibility evidence](../heplcp03-interop-20261111/README.md)
and its failed observations are unchanged.

## Separate hosted observations on the published parent

The retained Actions logs belong specifically to the old published parent
`ced03a7aa4a09af36825a6fa258fd6bd80c79fa7` and its prospective merge
`79bac6d55192c902649bccea3ffe002a0d65c7dd`, both with tree
`ff1e6c252e273b45ed29a7150f7fd24dc5934b2c`.
The scope jobs each ran the original 11 scope and 17 trainer-NoUpdate controls
successfully. Their before/after source fences verified 27,942 tracked entries
and 2,552,114,660 bytes. These historical source and reader results do not
assert any native model training or certify the successor pin-repair tree.
The log manifest carries the original job URLs, byte lengths and SHA-256 values.

The business-readback job on that published parent passed 144 controls and two
original-material readbacks, preserving HOLD, DENY_ALL and the unauthenticated
retrospective-bindings boundary. It is distinct from the earlier 198-control
local compatibility observation.

The arm64 native from-zero job on the same parent failed the existing
`CONFIRMATION_TARGET`: its original four-second baseline confirmed one required
transaction while its pressure window confirmed zero of one. All five named
Rust tests and formatting completed successfully, but the original acceptance
gate still refused the observed business target. The unmodified failed native
manifest, confirmation report, systemd log and job log are retained separately.
This source-pin correction does not claim to resolve that runtime result.

The first local corpus control attempt exceeded its 180-second execution budget;
its complete observed streams and exit 124 remain present. The subsequent run
uses the same unmodified tests with a 600-second execution budget. It executed
all 59 controls, including inherited real-filesystem race tests. No acceptance
threshold, assertion or production timeout was changed.
