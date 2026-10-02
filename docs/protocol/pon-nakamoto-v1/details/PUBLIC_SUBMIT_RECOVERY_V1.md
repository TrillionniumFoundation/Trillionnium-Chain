# Bounded local PublicV3 Submit recovery V1

`push --reliable-submit` is an optional honest-client operation for the existing
`public-protected-development-v3` signed transport. The ordinary `push` result,
policy, domains and single-call API remain unchanged. This introduces no ledger
operation, registry, fee, reward, durable guest state, server worker or queue.

The operator supplies an existing local producer store and its exact installed
Settings. The pending packet must already be retained and Native admitted in
that store, with byte-identical canonical encoding. Actual parent records,
full reconstructed State and roots are checked by the existing Node owner.
The helper never admits a supplied parent claim, makes work, re-signs a
transaction, rebases a packet, changes an account sequence or fabricates a
missing record. Normal `Node::open` may perform its existing recovery; this
operation is not an OS read-only open or a certificate against arbitrary local
database replacement.

## Options and finite budgets

| Option | Default | Accepted range |
| --- | --- | --- |
| `--submit-deadline-ms` | 60000 | 1..60000 |
| `--submit-attempts` | 3 | 1..3 per distinct packet |
| `--submit-call-cap` | 16 | 1..64 across all attempted RPCs, including failures |
| `--submit-parent-depth` | 1 | 0..16 restored parent packets |

These options require `--reliable-submit`, command `push`, and explicit PublicV3.
Other commands/profiles and invalid combinations reject before opening a store.
The CLI starts one epoch before parsing, Settings, packet input and `Node::open`.
All construction, cookie acquisition, solution search, Submit/Head/History calls,
parent restoration and 100ms retry pauses consume that same deadline and total
call cap. The library exposes a 0..1000ms pause within the same plan.

The optional client deadline only shortens the original 30s call and existing
phase bounds. It retains the original cookie policy, nonce search bound and
signature/context checks. `None` preserves the ordinary API behavior. SQLite
and Native State/root work are nonpreemptive; a late return is an explicit
failure, not an on-time completion. These limits are not a hard OS interruption
guarantee, an SLA, a fastest-producer bound, or a combined physical-memory bound.

## Recovery and dependency readiness

Every call is recorded, including every transport failure and authenticated
business refusal. Only exact `FRAME_EOF` observed in `challenge` or
`solution-body-response` permits a bounded retry. A generic CLI exit2, IO string,
external timeout, signature/context failure, clock deferral, or unknown error
does not. Retrying retains the original complete packet bytes; transport cookies
and their nonces are fresh, while account sequences and packet work do not change.

Authenticated `UNKNOWN_PARENT` may restore a finite actual local parent path
in ancestry order to a signed Head already known and fully State/root checked
locally. Unknown local Head, a different fork, missing records or a path beyond
the bound refuses. A planned parent repair does not recursively expand its
budget after an unexpected branch change.

The Native same-byte duplicate path can acknowledge an already admitted packet.
`DUPLICATE_CONTENT` instead means the same block id with different complete
bytes and is a permanent refusal. Neither a fresh ACK nor a same-byte duplicate
ACK alone proves active membership: strict-greater-chainwork activation can
leave an equal-work or inactive fork unadopted.

After an ACK or uncertain lost response, the helper checks a fixed signed Head
against a real locally admitted block, full State/root and current local clock.
The existing checked ancestry owner must place the pending packet on that Head's
actual path. Signed History must return exactly that packet's complete canonical
bytes and cursor/context. A second Head must retain the same tip, generation and
root. Unknown forks, changed observations or unmatched bytes refuse. No bare
height, advertised chainwork or cached remote response becomes authority.

Only this complete active-membership observation sets `may_advance_dependency`.
Formal depth/work/clock confirmation remains unmeasured (`null`) in this API:
requiring six confirmations before producing the descendants needed for those
confirmations would deadlock a linear producer. Consumers needing financial
confirmation must separately use the installed full Native confirmation rule.
The signed server observation is not a proof of remote physical persistence,
independent custody or consensus finality.

## Outputs, partial facts and scope

The optional CLI emits `public-v3-local-submit-recovery-v1`. `ok:false` retains
all completed attempt records, real ACKs, completed parent memberships and any
uncertain Submit outcome, then exits2. `ok:true` reports only the membership
condition above. The caller must not advance its logical dependency cursor on
a refusal, cap/deadline, unknown branch or unresolved transport outcome. No
completed admission is rolled back or rewritten by observation failure.

`submission_outcome_uncertain` preserves a conservative history fact: a Submit
client error during challenge, solution search or response handling cannot certify
that the remote Node had no effect. An authenticated ACK is retained when it was
actually observed. Later successful membership resolution does not erase an earlier
uncertain attempt. Permanent non-EOF response timeout or deadline remains a refusal,
without another Submit or permission to advance; the receiver may already retain
the original packet. This flag is not a present consensus verdict.

Raw RPC attempted/accepted/business-refused/transport-failed counts include
retries and parent restoration; unique logical completion is a different
denominator. Stage elapsed times overlap and are not server CPU or physical
wire bytes. Records omit request bodies, peer addresses and guest identities;
returned error/reply facts remain local operator diagnostics. A response-lost
Submit can resolve by complete membership without inventing a missing ACK.

All public readiness, production, identity authority, fairness, independence,
hardness and model-utility claims remain false. This repair does not protect a
receiver from Sybil starvation, confer privileges on a caller/IP, or change an
old failed workload into a passing run. Any future dependency-aware measurement
needs its own source-bound preregistration, all failure denominators and actual
finite closure.
