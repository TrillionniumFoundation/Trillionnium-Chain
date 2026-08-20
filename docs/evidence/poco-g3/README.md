# PoCO G3 Stage0 evidence truth

This directory records the claim boundary for the bounded PoCO G3 lab lane.
It now contains a content-addressed, operator-observed native Linux x86_64 and
Apple arm64 reproducible-build record for the exact `d6bb34c1` source
candidate. It does not contain a validator run, formal multihost evidence,
performance evidence, or any production claim. The machine-readable boundary
is [`status.toml`](status.toml), and the raw build records are under
[`stage0-repro-d6bb34c1-20260820`](stage0-repro-d6bb34c1-20260820/README.md).

## Strict source and build contract

Formal evidence must start from one clean Git commit and the
`clean-commit-v1` source profile. The required sequence is:

1. make the intended source a commit and require an empty Git status;
2. create two fresh clones of that exact commit;
3. run `prepare_source_candidate.py --require-clean` once in each clone;
4. require the two candidate tar files to be byte-identical with `cmp` and
   pass both through `check_source_candidate.py --require-clean`;
5. run `build_reproducible_lab_candidate.py` independently on each required
   native architecture; and
6. pass the two exact schema-3 local reports and all four binaries to
   `assemble_reproducible_build_report.py`, which emits the schema-3 aggregate.

The strict candidate binds the commit payload to its Git tree, and binds every
candidate path to its `git_blob_oid`, executable/non-executable mode, byte
length, and SHA-256. The checker reconstructs the Git tree from those records.
It also requires exactly one non-empty, non-executable
`trillionnium/Cargo.lock` and binds that file's exact hash and length.

`source_tree_sha256` is a historical aggregate-field name: it is the SHA-256 of
the canonical candidate **tar bytes** (the same value as
`source_candidate_sha256`). It is not a Git tree identifier. The actual Git
tree is `source_git_tree_oid`; `source_git_object_format` defines its object-ID
width. Schema-3 builder reports, the schema-3 aggregate build report, and the
schema-3 no-fault summary must preserve these fields together with the empty
status and `Cargo.lock` bindings. Legacy candidate/build/summary schemas fail
closed on the current formal path.

The Python builder and assembler tests still exercise schema and failure
boundaries rather than proving external execution. Separately, the
`d6bb34c1` evidence directory preserves two manual-SSH X230 builder reports and
two native macOS builder reports. Each report covers two independent release
builds; the role binaries agree byte-for-byte within each architecture, and a
schema-3 aggregate binds both architectures to the same strict candidate and
`Cargo.lock`. The source and common Linux ELF binaries pass the deep verifier.

This remains an unsigned operator observation. It does not cryptographically
attest runner identity, the physical host, or tool/cache use, and it must not be
described as a hosted-CI or supply-chain-attested build.

## Readiness evidence boundary

The raw `lan-fleet-probe-2026-08-13.json` and
`lan-run-readiness-2026-08-13.json` files are historical/audit-only material.
They must not be copied into a current gate or described as current readiness.
The current acceptors require a fresh
`probe-fleet-v1` report and a fresh `run-readiness-v2` report produced for the
campaign being gated; they explicitly reject the historical filenames and
legacy shapes.

Passing `check_baseline_test.py` or
`check_run_readiness_evidence_test.py` proves only the producer/acceptor
contract. It is not an on-fleet observation and does not prove reachability,
tooling, capacity, fault authority, a build, or a validator run. No current
readiness observation is claimed here.

## Restart boundary

The direct-seven runtime contract reaches the durable process-1 sequence
`restart_prepare -> restart_cut -> restart_park -> restart_parked_ack`. The
target handoff retains the exact RestartCut, RestartPark, and RestartParkedAck
artifacts, the N/N ParkedAck admission-set identity, the local statement, and
the corresponding journal events. Only after that boundary and runtime
resource shutdown may the target process 1 emit its exact schema-2 handoff and
exit with status `75`. Status 75 means only that the bounded parked handoff was
completed; it is neither a normal completed report nor a successful restart.

The supervisor then starts process 2 with the exact process-1 command. Process
2 must independently reopen and authenticate the complete
RestartCut/RestartPark/RestartParkedAck triple and replay boundary, then stops
at the exact inert boundary. It has no authenticated catch-up activation, no
operational RecoveryReady or RecoveryStart transition, and no Core, signer,
timer, or ordinary-consensus activation authority. The expected inert stop is
not a passed process-kill fault and must never be reported as a successful
restart.

## Claim boundary

Positive statements are limited to the retained contracts/self-tests and the
scoped native reproducible-build observation. Validator execution, signed
multihost runtime evidence, fault completion, performance, LAN multihost,
geo-WAN, and production claims remain false.
