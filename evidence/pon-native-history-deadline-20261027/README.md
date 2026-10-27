# Native History continuation: retained local observations

Measured code: `bb2d444a3f5fe24b0077c1f01ed1d0953c2b6ff1`.
Tree: `9d646f30c7db395079836ddce491966612f8ae67`.
This evidence commit does not retroactively qualify a later source tree.

[summary.json](summary.json) records outcomes and their scope.
[files.json](files.json) hashes every retained member of
[observations.tar.gz](observations.tar.gz). The archive retains original runner
manifests, stdout/stderr, failed gates, reports and the actual from-zero release
test binary. It also retains the earlier failed regression and its corrected
run. Extract it into a new directory to inspect original runner outputs.

## Outcomes

The new History controls passed, including real SIGKILL at four cuts: durable
epoch, halfway through actual W1 transcript replay, native admit before CPU
settlement, and activation before settlement. The broader History regression
first returned 69 PASS / 1 FAIL / 4 ignored. Its failing #498 remote-error
identity control was repaired; the subsequent run returned 70 PASS / 4 ignored.
All 8 typed-error tests, 14 peer-polling tests and the real socket History test
passed. Strict all-target Clippy and 34 source-integrity negative controls passed.
These are precommit controls, not a fabricated clean-source campaign.

The original service runner then executed on the committed clean source before
and after. It retained all 130 attempts: 32/32 honest probes and 16/16 honest
mutations succeeded, 16 false transcripts and 32 paid invalid requests were
refused, 32 unpaid prefixes were sent, and two injected EOFs were retained.
Its finite target passed. The largest honest probe completion gap including
restart was 45,102,914 ns. This finite test does not demonstrate CPU depletion
or public fairness.

The original from-zero runner rebuilt and executed all five named release
tests successfully, but its overall verdict is **FAIL**. Its strict report
reader rejected `CONFIRMATION_TARGET`, and the inherited full-workspace format
gate also failed. Both attack-free and hostile confirmation modes completed
zero independent client confirmations; 32 `PUBLIC_HOST_KERNEL_PARENT`
observations were retained. A passing Rust invariant test cannot replace this
failed service criterion.

The sustained from-zero phases rejected 471/471 and 460/460 hostile calls and
completed 78/78 and 76/76 honest reads plus one honest submission in each phase.
They did not exhaust the original budget: the minimum sampled stored balances
were 1,861,886,037 ns and 1,890,095,836 ns, with zero CPU-budget refusals. Neither
is a saturated-service acceptance result.

The original physical resource preflight refused this host. Observed limits
were `cpu.max=800000 100000`, `memory.max=8589934592`, nice 0; the unchanged
runner requires `400000 100000`, 16 GiB, nice 10. Its actual failure is
`ACTUAL_400_PERCENT_16_GIB_REQUIRED`. The original A03 three-run matrix was not
executed: 0/3 complete runs, 0/9 phases, and no proof of its 27 planned timely
confirmations. No resource profile was loosened or substituted to turn that
refusal into a pass.

No independent WAN, computational hardness, physical power-loss, full capacity,
honest fairness under budget exhaustion, or production-activation gate is closed
by these observations. The retained initial compile failures and first SIGKILL
expectation failure were also reported in the implementation work log; they are
not rewritten as successful baseline tests.
