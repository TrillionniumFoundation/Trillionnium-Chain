# Quantum tip / current-clock preparation observations

Status at capture: **HOLD / NO-GO**. These are original preparation observations,
not an exact-commit qualification of the published continuation.

The working-tree base was `e4abb172147e941b62483652b0ceabaae4317624`.
The initial Python run passed network 55, adversarial 12 and resource-clock 18
tests (85 total). The summary also records compile exit zero. The simulator
SHA-256 was `384c8e13ad7e0c8043dfdbc947bd3a12cdb3f5cb11415078f1ae5f3c3aeff2ed`.
The actual earlier test and runner source snapshots are retained under
`precommit-source/`; their hashes match the original receipts.

The final test source subsequently adds three reader controls, and the runner
adds committed-source checks, strict report key validation, timing validation,
and an outside-source output restriction. The 85-test observation must not be
attributed to that later source. The paired 72-run experiment and replay had
not been executed at this capture. A future exact-source CI run must provide
its own receipts.

The native preflight passed. The native driver started a baseline command with
the new TCP regression and original production implementation. The last
successfully read state was `RUNNING_03-baseline-new-regression`. The files
named `RUNNING-snapshot` and `observed-prefix` are deliberately nonfinal:
neither an expected assertion failure nor any fixed-source result has been
read. A runtime service interruption prevents a conclusion about the still
owned process. It has not been restarted or cancelled.

All JSON and log bytes here were actually read back before the interruption.
The earlier runner snapshot was recovered from the original preparation text
and its SHA-256 independently matched the receipt. Unavailable raw compile and
Python-preflight logs have not been reconstructed. Service errors do not count
as behavioral regressions or test successes.

These observations grant no activation, independent acceptance, native
quantum-security bound, CP/CG/CQ guarantee, or lifetime failure probability.
