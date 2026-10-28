# F0 first hosted attempt: detached-source preflight correction

This is a narrow preparation fix. It does not change the work relation, native
Rust, lockfiles, Host/controller ownership, resource ceilings, original service
and request limits, cleanup authority or qualification flags.

## Original hosted failure

[Run 40741611297, attempt 1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40741611297)
tested exact head `439681f324482c0d5a7fb6f7cc9190f60dd16e2a`, tree
`ea2cca3c0bbf8e3b65db2f3be96ccc31b256964f`. Its sole job
`123004393839` failed during preparation. The independent source and parser
steps, compiler installation and locked dependency fetch succeeded. Both
controller arming and Host execution were skipped.

`artifact-12839802698.zip` is the original 19,973-byte hosted artifact, SHA-256
`812a7ce4fdf332aa4a1e728c1783f6d866d14030c94444ded6acf1ad7c3dbf6b`.
All 34 ZIP members match the 33 payload hashes plus `artifact-files.json`;
CRC and every declared size/hash were checked. `job-123004393839.log.gz`
losslessly retains the complete decoded job log. The API job/artifact lists
each contain exactly one item and are retained without truncation.

Inside that artifact, `prepared/preflight.step.json` records the command
`/bin/bash scripts/project-preflight.sh`, exit code 2 and 0.0398877 seconds.
The complete stderr is:

```text
project boundary failed: not an allowed development branch
```

The launcher defaults to `--dev` when the mode is omitted. An exact-SHA GitHub
checkout is detached, so the developer branch-name gate correctly rejects it.
The earlier workflow source step explicitly uses `--audit` and passed. This is
a caller-mode mismatch, not an ELF, compiler, resource or Host failure. The
prepared record has `prepared: false`, `PREFLIGHT_FAILED` and
`selector_invocation_attempted: false`. No preparation format, Clippy, build or
native source-control selector was reached.

The always-finalizer correctly retained all **6 confirmations and 42 business
exposures as unobserved**. All three service observations report
`FROZEN_PREPARATION_REQUIRED`, no cleanup attempt and unknown remaining state.
Missing ownership does not establish an empty service. The finalizer failure
must remain visible; it is not repaired by promoting incomplete preparation.
Actual source-before and source-after identities are equal and fully verified.

## Minimal change and regression boundary

The sole production change is one explicit `--audit` argument in
[`prepare()`](../../scripts/run_fixed_host_root_f0.py). Its preceding
`source_snapshot`/`validate_source` and `verify_ci_source.py` checks still bind
the exact expected head, tree and clean source. The complete audit boundary
still checks repository identity/origin, pure-PoN development target, refusal
flags, preservation policy and the workspace/path-dependency inventory.
[`project_boundary.py`](../../scripts/ci/project_boundary.py) and all original
`--dev`, `--staged` and `--push` branch/protected-main checks are unchanged.

Three new [preparation controls](../../scripts/ci/test_fixed_root_preflight.py)
execute the actual selected boundary command in an isolated detached Git
fixture, then stop at an explicit native-command barrier. They check the
successful audit route, refusal of a foreign origin and source-check failure
before any preflight/native command. They do not create a passing prepared
ELF or run a service. The source identity inside this small fixture is mocked;
the independent original source-integrity controls remain required.

The same three controls were first run against the unchanged old runner. Two
negative controls passed and the detached preparation regression failed with
`PREFLIGHT_FAILED`; the raw failure and source binding are retained here.
This establishes that the new control detects the actual omitted-argument
failure instead of merely checking a constant. The original 78 launcher/F0
controls (11 original launcher plus 67 F0) and the project-boundary controls
remain selected. The three new preparation controls increase that combined
launcher/F0 denominator to 81.

On the corrected precommit source, all 11 original launcher controls, all 70
F0 controls, 16 original project-boundary controls and 34 original source-
integrity controls pass. The development-mode preflight, distributed source
inventory and repository/document checker also pass; the latter checks 25
workspace packages, 976 inventoried Rust files and 1,555 local links. Python
AST and shell syntax checks execute no native project code. Complete raw
outputs are retained in `precommit-static.zip`, explicitly bound to dirty
precommit source rather than claimed as a future commit's result.

The preservation receipt covers all 1,043 tracked Rust files, Cargo manifests
and lockfiles in the source baseline, including research trees outside the
976-file main inventory. Their filesystem bytes and Git blob identities remain
equal to local `6eaf5f8d6f9b12546878bc8286b1fcac219a0d4a`, whose tree equals the
observed remote `439681f` tree. The production Python diff is exactly the one
argument above. Final committed-source receipts are generated separately so
they do not assert the hash of a commit containing their own receipt.

There was no local native execution for this correction. Fresh hosted
preparation and the original fixed-Host experiment remain required. No service,
throughput, depletion, restart-credit, independent-WAN or production success is
inferred from Python controls or the corrected argument.
