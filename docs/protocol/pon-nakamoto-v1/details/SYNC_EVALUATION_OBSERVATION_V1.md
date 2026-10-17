# Native public-sync evaluation observation v1

The existing ordinary development `sync` command can optionally consume a local
typed [v2 confirmed-round observation](EVALUATION_CONFIRMED_ROUND_OBSERVATION_V2.md)
after complete pinned public history reception:

```text
trnm-pon-node sync --development --store OWNED_LOCAL_STORE \
  --evaluation-policy native-public-evaluation-dev-v1 \
  --admission-profile public-protected-development-v3 \
  --peer PINNED_ADDRESS --server-public PINNED_PUBLIC_KEY \
  --auth-secret OWNED_DEVELOPMENT_TRANSPORT_KEY --tip FIXED_TIP --pages PAGE_BUDGET \
  --evaluation-candidate CANONICAL_HEX32 --evaluation-round-blocks 4096
```

Original namespace/task/model/operator context and resource-policy flags must match
the existing store and pinned service. Public V2 and V3 are supported; this optional
query does not add a transport operation or guest permission. The transport key is
only the existing resource-ticket identity, never source/evaluator/reward authority.

## Exact integration and refusal

`--evaluation-candidate` must be canonical lowercase32-byte hex. Its optional
`--evaluation-round-blocks` defaults to4096 and is required in1..4096. A bound without
a candidate, invalid hash/bound, or selecting the observation on a non-public sync
profile rejects before `Node::open`. Omission keeps the original sync behavior and
default output fields.

The existing receiver verifies page context, cursor, packet bytes and complete native
work/state/admission. Complete reception invokes the existing observed activation
owner. Only after this succeeds does the same exclusive local Node construct the
private typed v2 observation from its actual active tip/generation and root-checked
State. The observer clock is captured freshly after reception, using
`ingress::now()`. The existing network-command guard rejects `--logical-now` before
opening the store. Standalone local observation queries retain their explicit trusted
test-clock input; sync always uses the actual local clock. This local observation is
not an independent time certificate.

Successful optional output adds `evaluation_observation` and
`evaluation_observation_scope.schema=native-sync-evaluation-observation-v1`.
The latter states complete native reception, the same exclusive local owner,
unsigned observation and false transport/public authority. The typed v2 result retains
all its false authority, global-prefix/global-clock-history and public-readiness flags.

If the query is unknown, retired, clock-deferred, outside its window, on an unsupported
native evaluation profile, or otherwise refused, exit2 explicitly reports
`SYNC_COMPLETED_EVALUATION_OBSERVATION_REFUSED` with verified delivery tip and actual
active tip/generation plus the underlying refusal. There is no successful default phase.
Already admitted/activated synchronization facts remain durable; a failed subsequent
query neither rolls them back nor claims that no sync occurred. A refused or incomplete
history sync never constructs a successful observation at all. Its already admitted
prefix keeps the existing interrupted-sync recovery semantics.

The delivered fixed tip need not replace a heavier already observed local branch.
The observation always belongs to the actual local active tip, separately identified
in the result. A signed remote page is transport evidence, not a remotely supplied
confirmed phase. This operation does not certify the globally latest network tip.

## Lifecycle and retained boundaries

An extension or reorganization invalidates the old current-view observation. Existing
`Node::check_evaluation_round_observation` requires the same namespace/tip/generation
and a fresh clock re-observation. Native contribution/archive retirement can remove
the candidate; a new query then refuses explicitly instead of reviving an old score.
Native tags14–17, admitted-height deadlines, roster and signatures, adoption, funded
claims, stored schema, signed domains and chainwork remain unchanged.

This consumes a finite read-only observation in an existing sync operation. It is
not a durable cross-restart evaluator/action journal, irrevocable-effect rollback,
external-model operation capability, independent roster governance or ML-quality
certificate. Normal exclusive Node open/recovery can write checkpoint/recovery data;
the command is not an OS read-only opener and cannot be launched over another active
owner's store. No new persistent owner, RPC, signing permission or authority cache is
created.

`tests/evaluation_sync_observation.rs` runs the actual executable through ordinary
pinned loopback public V3 history traffic and full native signed candidate blocks.
It checks same-owner API/output identity, unchanged default output, incomplete reception,
unknown/window/context refusals, actual-clock capture and the network test-clock guard,
plus an API-only low-clock refusal, heavier-fork invalidation of the old typed
observation, lighter-branch reception and actual archive retirement. Each CLI child is
waited; each network CLI phase owns a fresh original120-second listener that is stopped
and joined before offline construction or another phase. The retirement fixture
receives all241 real successors using three planned64-page partial syncs followed by
the final49-page completion. Each partial result's canonical cursor, stored ancestry
and missing next page are checked after reopen; the final retired evaluation query
refuses with the actual `STATE` result. This is12 network CLI phases across the two
tests, not an uninterrupted241-block transfer or the earlier9-command fixture.
The historical hosted failure after150 responses within one120-second lease remains
unresolved as a single-transfer performance boundary. Planned page-budget resume is
not a retry of arbitrary transport failure. These controlled development tests do
not imply independent operators, WAN capacity or public readiness.
