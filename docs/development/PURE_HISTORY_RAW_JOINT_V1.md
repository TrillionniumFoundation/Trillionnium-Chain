# Pure raw-W1 and ordinary History integration v1

This is an additional research integration based on History head
`96f5e502d677fa37d53e0241208ce228a913d907`. It does not turn that head's
failed protected campaigns into passed pure-PoN campaigns. It combines a new
explicit zero-search admission profile with the original raw r13 W1 path and
the ordinary History implementation retained by that head.

## Signed profile and unchanged work

The profile is `public-pure-pon-history-raw-development-v1`. At the campaign's
2,000 ms cookie lifetime its independently computed resource-policy ID is:

```
bf409dae237253a2ce14152c54198ed06e824e709763946e9c84e68e894eee58
```

The hash domain `public-pure-pon-history-raw-resource-v1` binds the profile name,
the original r13 resource contract with zero ticket bits, and the explicit pure
raw-W1 contract. The old protected constructor still accepts only 8 through 20
bits, and its identifiers are unchanged. Cookie MACs and signatures, caller
acknowledgements, and signed responses all retain their ordinary context checks
and bind the selected resource-policy ID. There is no negotiation or fallback.

The transport framing remains the existing protected-v3 wire schema. This new
resource namespace does not claim wire identity with E's pure-v1 or pure-v2
profiles. It does not enable their product prefilter or arithmetic-facts reuse.
Pure configuration rejects the rejection cache, arithmetic-facts and native
growth profiles. Every paid Submit follows the original full W1 path, including
transcript and product work at their original failure boundaries. Consensus
header, task, challenge, target, ticket and matrix rules are unchanged.

The zero-bit acknowledgement accepts only nonce 0. The client selects a search
budget of zero and records zero trials and a zero search-duration field;
the signing, I/O and ordinary request CPU still incur their actual cost. A
`pure_history_acknowledgement` is a client observation of that branch, not a
second independently signed proof. Its nonce is absent if that stage was never
reached. Successful client completion still requires the actual signed response
and its expected profile context.

## Ordinary CLI and process routing

For supported ordinary public commands, explicitly select:

```
--admission-profile public-pure-pon-history-raw-development-v1 --admission-bits 0
```

The pure profile defaults to zero bits if `--admission-bits` is absent. A nonzero
override is rejected before store or network I/O. Existing pinned server keys,
development acknowledgement, key files, pool settings, journal, authenticated
state and public-host requirements still apply to the selected ordinary command.
The normal admission, activation and History paths remain enabled.

The test-only `PureHistoryRawV1` work profile uses an explicit job binding with
both its work-profile name and policy observation. Original raw actor jobs keep
their original bytes and protected policy. Missing, partial, foreign or mixed
bindings are refused. The added campaign requires `authenticated-v1` and routes
the normal History importer through the same independent verifier process used
by the original strict or N8 selector.

The new selectors are:

```
separate_process_pure_history_raw_strict_campaign
separate_process_pure_history_raw_graph_fence_campaign
```

They retain the same 1,024 signed seed transfers, four seed blocks, 21 business
blocks, three 30-second phases, 24 attack actors and original from-zero and
late-product input mix. Paid CPU remains a 2-second burst, 0.25 CPU-second/second
refill, 0.1-second starting reserve and two workers. The independent verifier
retains its actual root-owned fixed parent, 25% CPU, 2 GiB memory, zero swap and
256 tasks. The original outer campaign retains four CPUs and 16 GiB ceilings.

No phase, search, confirmation, import or actor limit is raised. Full state
equality, actual paid-credit depletion, overlap during all signed rounds, all
three depth-six confirmations inside the original window, complete observations
and final independent verifier close/exit remain mandatory. The added pure
acknowledgement check is another conjunct; it cannot replace an original gate.

## Evidence and validation boundaries

The additive workflow `pon-pure-history-raw-joint.yml` uses its own concurrency
group and artifact prefix. Each strict/N8 job retains the original 80-minute job
ceiling, three predeclared 600-second campaign executions and the original
12-minute owner-death step. Permissions remain `contents: read`. Source-before,
source-after, immutable release ELF, fixed-parent lease, cleanup and partial
artifact retention are copied from the original workflow. The protected workflow
is unchanged. A failed earlier run is never replaced by a later run's result.

Six library controls exercise the fixed signed-policy vector, profile exclusions,
actual TCP zero-search valid and full-W1-invalid requests, cold authenticated
state readback, both protected/pure cookie mismatch directions, a correctly
signed nonzero acknowledgement, and a same-key re-signed foreign response.
Two CLI controls exercise the real executable and pre-I/O nonzero-bit refusal.
Two campaign controls exercise explicit actor bindings and receipt rejection.
These component controls do not substitute for the fixed-cgroup campaign.

The independent reader requires the new top-level schema, exact policy and each
actual client call's zero-search receipt, then invokes the original independent
History IPC/lifeline reader without an in-process bypass. It retains the original
depletion and finite phase results. It reads complete ordered native W1 phase
observations and refuses arithmetic-facts records. Its nine synthetic controls
test malformed/mixed receipts, actual-ledger predicate preservation, missing
verifier/lifeline evidence, duplicate JSON and the original equality/window/
settlement requirements. Synthetic fixtures are explicitly not native evidence.

Actual owner-death controls cover the existing three process boundaries, and
normal campaign receipts cover the original final Node close and paid CPU
settlement. Those observations alone do **not** demonstrate interruption in the
middle of journal or activation commit, durable child settlement after every
crash boundary, or successful resumed useful work after all such failures.
That additional fault-injection/restart coverage remains a separate necessary
P0 task. In particular, the ordinary listener's existing persistent crash fence
does not itself implement the separately signed V6 operation-ID journal and
recovery interface. An unclean ordinary epoch retains its existing cold-start
refusal; this profile does not erase that fence or bridge V6 recovery into the
ordinary importer. That integration remains open. No result from this profile
alone closes that task or qualifies
production activation, independent operators, WAN service or quantum hardness.
