# PoCO-BFT v0 Apalache evidence — 2026-08-04

Status: **bounded evidence; not an unbounded proof**

This record covers the `noConflictingFinality` invariant in
[`poco_bft.qnt`](poco_bft.qnt). The model has four equal-power validators,
one Byzantine validator, two conflicting three-block branches, durable
`lastVotedView`, the lock rule, and direct three-certified-block finality.

## Toolchain

- Quint: `0.32.0`
- Apalache: `0.56.1`
- Java: Temurin OpenJDK JRE `17.0.20+8`
- Apalache archive SHA-256:
  `91125e5a3646b9c9d3a7d921d3323f321fac5071909f72b3960c66ff2f998ee1`
- JRE archive SHA-256:
  `ef491a51a46ef90cc47fbc4abb219fde32483ff91be5ec66ddc896df43524b27`

The archives and extracted tools were used from an isolated temporary
directory. They were not installed system-wide and are not repository
dependencies.

## Results

The checker was invoked through Quint's `verify` command against
`poco_bft.qnt`, selecting `noConflictingFinality` and the stated step bound.

| Bound | Outcome | Evidence |
| --- | --- | --- |
| `max-steps = 10` | **PASS** | Apalache reported `State 10: state invariant 0 holds` followed by `The outcome is: NoError`; wall time was approximately 8.6 seconds. |
| `max-steps = 20` | **INCONCLUSIVE** | The checker established the invariant through state 12, entered the state-13 invariant query, and had not completed after 15 minutes. The run was interrupted deliberately. The resulting interrupted solver session reported `UNKNOWN`; it is neither a counterexample nor a pass. |

The successful depth-10 detailed log had SHA-256
`3f5c999873af5983bba6651733d64d8012eaf237752e4033f6739783b7511104`.
The interrupted depth-20 detailed log had SHA-256
`3a86fa650545fe34b816ca0ef13f23868cfdfc2b4c1709dddb3485e568e97ed2`.

Relevant successful checker output:

```text
State 10: Checking 1 state invariants
State 10: state invariant 0 holds.
The outcome is: NoError
PASS #13: BoundedChecker [OK]
```

Relevant progress from the interrupted deeper run:

```text
State 12: Checking 1 state invariants
State 12: state invariant 0 holds.
State 13: Checking 1 state invariants
```

## Interpretation and limits

The depth-10 result exhaustively checks the symbolic executions represented
by this finite model within that bound. It does **not** establish unbounded
protocol safety, cryptographic correctness, liveness, data availability,
network recovery, heterogeneous weights, epoch handoff, or light-client
safety. Those dimensions have separate bounded Quint models and retained
failing mutants; deeper symbolic coverage remains an open P0 obligation.

The depth-20 attempt is recorded to prevent an interrupted run from being
misreported as verification success. Future evidence should either reduce the
model state space, split the invariant, or run with a reviewed resource bound
before raising the verified depth.
