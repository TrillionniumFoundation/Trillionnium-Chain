# Current W1 selected-profile binding repair

The original exact-head closure job 130949243361 in run 43147686515 refused the
current mapping before selected-profile inspection. The binding retained the
former 43,170-byte mapping SHA256 `ee41a559c91b613be46a80081dd45d87130d83d95e2d068352ea03a85240c93f`.
The unchanged current mapping has 44,427 bytes and SHA256
`8e4508d132ae2103f086025b7614a19ef30bae04a7fec17f5834897fa1c83d36`.

Review found only the source checkpoint, local closure and its zero-paired note
changed: 138 to 139 local Rust paths, with no deletion. The 16 selected project
files, 15 proof obligations, lifetime register and qualification flags remain
unchanged. This repair updates the exact mapping pin and the workflow descriptor
to `0d47e23d395d6332a0bdf1c9093cf5b19816aad9841e3db6e8cb24f53e0f18b3`.
It preserves the reader, its exact byte bound and all security obligations.

Three added controls reject growth, shrinkage and equal-length substitution.
The original 26-test failure and repaired 29-test observations are separate.
Precommit observations retain their own source state; they do not qualify a
future committed candidate. The first local corpus-control observation reached
its stricter 300-second caller timeout after 36 methods reported success. That
timeout is not an assertion failure or a result under the original 600-second
budget. The later candidate must run the original budget independently.

The [control manifest](control-observation-manifest.json) binds retained raw
records, including failures. `validate-candidate.py` records a fresh committed
candidate's original source guards, provider pins, locked graphs, retained
controls, formatting and strict Clippy into a new external directory. Its
receipt is separate from the earlier measurements and is never inherited.
The [predecessor PR description](predecessor-pr935.json) retains its original
native/evidence sources, publication failures and recovery observations.

The [V5 artifact readback](../pon-w1-v5-twoarch-readback-20261112/README.md)
and [original failed service](../pon-w1-service-readback-20261112/README.md)
remain executions of source `229b14c2d366a257f51f287d502a550df2332338`.
This repair changes no Rust, formal guest, target, reward, chainwork, resource
limit or production authority. Whole-chain qualification remains HOLD.

The first integration attempt was refused before commit: the original stderr
records and patch context contain trailing whitespace. The exact failed check,
terminal output, executed helper and all retained precommit records are preserved in the
[raw archive](precommit-controls.tar.xz). Its manifest binds every original byte.
Archival changes no log bytes or checker policy; all original external files
remain unchanged. Unpack into a new external directory to inspect the records.
