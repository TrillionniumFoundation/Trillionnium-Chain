# Complete architecture tests in the existing fixed Host

**Historical candidate, superseded in the current composition.** The active
architecture-only Cargo runner described here was replaced by the owner's
current-ELF public-fixture framework from `b28098c092dca72165c0d26054fce95a8636d777`,
retained in `12171edc890df1611bf68503038bfad3d66a5a88`. This file preserves its
actual original failures and controls. To reproduce these historical helper
commands, check out `4204c4b0b1300cbb5d5325d9915a161173983491` in a separate
worktree. The current integration is documented in
[the readiness composition](../cell-rendezvous-readiness-20261103/README.md).
No original native failure is promoted by supersession.

This candidate repairs an actual runtime fixture failure. It does not qualify
the original four-second, sixteen-hostile-client service budget or declare a
consensus architecture winner.

## Original failure

Required CI run 41649603030, job 125963945036, executed source
`6ee97ee8f2955d2d0cd4a451268a906c5aa07584`, tree
`29994c32f554f7f5201bb793a19e54f6616a3354`. All eighteen architecture samples
failed `PUBLIC_HOST_KERNEL_PARENT` when the independent client imported its
first successful History reply. Each sample had accepted the seven block
submissions and could reopen its local store, but had zero independently
confirmed transactions. The source-bound native failure is retained by artifact
13241266546. Its ZIP SHA256 is
`65a52c44e60fdad1822d70f9c1678e540307841cc5c5baa65e3e4a79ff1cfe12`.

`original-failure-derived.json` retains selected fields for every sample, plus
the exact complete report digest. It deliberately omits large signed packet
payloads and is a derived summary, not a new execution. The original source
receipt, failed shard receipt and unchanged complete shard command are retained
beside it. The architecture Rust test is unchanged at candidate base
`0443a5e2e68be9c5df68b87ebeb5fed3b96ec5d2`.

## Execution change

The runtime shard still executes the complete original workspace Cargo command
and subsequent original release tests and oracles. Only the complete
`architecture_delivery_compare` binary is routed through the existing
`run_from_zero_host.py` controller. Every other target uses `execv` with its
original executable, arguments, environment and package working directory.

Cargo performs its original build outside the fixed service. Its selected debug
test binary, exact tracked source, job, package working directory and required
non-secret runtime environment are bound before execution. The existing Host
controller owns its original root-owned parent and unprivileged service, with
the unchanged quarter-CPU, 2 GiB, zero-swap and 256-task limits. The public
History parent check is unchanged, including for loopback peers.

Both original tests run once and without a selector. The controller retains
actual Host observations, exit status and cleanup, while the adapter binds the
two-test transcript and complete eighteen-sample native report. The original
2-second call limit, 15-second round limit and 180-minute job deadline remain.
There is no added native timeout or retry. Source, binary, environment, report
or Host drift refuses acceptance. Runtime shard success also requires the
completed current-job Host binding; a zero child without it fails.

The Cargo runner and inside-service checks compare their actual current runtime
environment. The outer shard reads the resulting bound observations, because
Cargo-injected package variables and library paths cannot propagate back to its
parent. The execution records both runtime environments and requires equality
with preparation. This distinction fixes a real review-found false failure; it
does not remove execution-time environment validation.

## Validation and limits

Run the retained control commands from the checkout root:

```sh
python3 scripts/ci/test_architecture_delivery_host.py -v
python3 scripts/ci/test_rust_baseline_shards.py -v
python3 scripts/ci/test_from_zero_host_ci.py -v
python3 scripts/ci/check_ci_contract.py
bash scripts/project-preflight.sh --dev
```

The first three commands passed 9, 9 and 35 controls. They include actual
harmless subprocesses, immutable tiny Git fixtures, argument/environment/cwd
preservation, unfiltered transcript completeness, all eighteen sample identities,
confirmation rules, source/binary drift and missing/failed Host-result rejection.
They never provision a local Host or execute the native Chain workload.

The tiny Rust control in `cargo-invocation-control/` independently observed
Rust/Cargo 1.95 passing one absolute binary argument and the original package
cwd to the target runner. Its two trivial tests are not native business proof.
The control source, original invocation and output are retained without a build
cache or binary. To reproduce it, use an isolated target and set
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER` to `python3 /absolute/capture.py`
before `cargo test --manifest-path /absolute/Cargo.toml --workspace --all-targets
--all-features`; the capture script writes the observation to its recorded
fixture directory, so adjust that output location when recreating the fixture.

Hosted head and prospective-merge runtime qualification is still pending at
publication. The original full required CI remains authoritative. A passing
synthetic receipt is not authenticated native execution. The candidate cannot
close #639, #629, independent WAN/fault, whole-chain PQ, protocol-switch or
production-activation gates.
