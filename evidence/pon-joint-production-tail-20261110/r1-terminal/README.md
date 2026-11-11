# Original ROG r1 terminal and complete raw-record recovery

The original request is now resolved from **UNKNOWN to FAILED / exit 2**.
This closes only the execution-identity/terminal-observation ambiguity. The
thirteen actual joint qualification obligations remain open, and no native
gate or security probability is supplied by this recovery.

The exact original `native-control/start-request.json` was submitted to the
same controller with host `rog`, the unchanged executable/arguments, source
`4716bade250f327b012a098418f4eece6b73fcaa`, key
`joint-tail-rust-gates-20261110-8e76-r1` and all original resource parameters.
`recovery-request.json` preserves that exact request. The controller returned
`reused=true`, `retried_launch=false` and original job `1a1c474c012-cf39-350`.
No alternate native request, key, host or provider was launched.

The original terminal is durable, output-complete, not truncated and confirmed
by a separate `process_status` read. It reports failure at
`2026-11-10T08:01:12.793652+00:00`, without timeout or automatic retry.
The full 1,085-byte stdout and zero-byte stderr were retrieved from offset zero
through their exact final offsets. Both raw tool receipts and stream bytes are
retained here. Earlier timeout and UNKNOWN records remain in Git history and
the original packet; this later observation does not rewrite their history.

## What failed

The original runner raised `AssertionError: insufficient free space before
setup`. Its unchanged guard requires at least **6,442,450,944 bytes (6 GiB)**
free. The final disk observation records **5,414,273,024 bytes** free; this is
the final observation, not a separately sampled guard-time disk value.
The original `commands` list is empty. The guard precedes clone/setup and all
Cargo/source-gate subprocesses. Thus this run executed **zero Rust gates**.
It is an environmental preparation failure, with no observed native consensus
failure and no current format, graph, Clippy or native-test pass. The summary's
`source_before_after_equal=false` is an unset success field after early refusal,
not a source-mismatch measurement. There is no built-binary identity to report.

The recovered runner is 17,583 bytes with SHA256
`66f2e33da06d9e1167a5240027d6363defa79ff7e235e7763d96980c47d603b8`, identical
to the originally deployed and published runner. The exact original raw archive
is 7,178 bytes, SHA256
`f804c99db721cff21206eabb4b54aff4628e9b624a8101a6a2091c43d0bc3000`.
It is preserved losslessly as `data_base64` inside `archive_read.json`; all five
archive members are also preserved byte-for-byte under `raw/`. The original
four-file raw index, the archive file/version receipt, per-chunk checksum and
full checksum have all been reconciled. No original record was regenerated.

## Hosted evidence remains separate

The read-only snapshot of source Actions run `42778406804` still contains all
18 jobs queued, each with no steps, no runner and no conclusion. Its artifact
list is empty. Head `a782b1b501c9030d9f9f6fecd27b5858a702c9a8` has 16 workflows
pending or queued, without conclusions. Its required-baseline job list is
empty at this observation. Prospective merge
`b2dae0c0510ee95570e0f1729d3a3db8c9c6be93` has the recorded #843 and #863
parents, and tree `d134778faa7f8828e07b3c178a15a385346a4048`; tree identity
does not establish its hosted execution. No workflow was rerun.

Concurrent #868 already owns the bounded dynamic-input repair; this recovery
does not duplicate or overwrite it. No disk contents were deleted, no minimum
space or test requirement was reduced, and no replacement native job was started.

Run `python3 verify.py` from this directory to recheck this packet. Its result
is byte/receipt consistency only, not a new native test pass. The previously
completed 299-method source validation and seven marginal-coupling controls
retain their original execution identities; neither was rerun or relabeled.
Native CP/CG/CQ, six-successor and lifetime bounds remain null; production
activation remains false and qualification remains **HOLD_NO_GO**.

Local packet, repository/link and actual CI-contract checks passed before
the evidence commit. The first attempted CI command used a nonexistent script
path and exited 2; its raw command/error are retained as `wrong-command-path`
under `validation/`. The corrected existing `check_ci_contract.py` returned 0.
These local evidence checks do not change the original ROG failure attribution.
