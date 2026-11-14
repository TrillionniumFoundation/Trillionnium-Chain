# Branch-derived time and integer ASERT reference V1

## Result and source boundary

The [executable reference](../../../../formal/pon-nakamoto-v1/branch_time_daa_v1.py)
implements a frozen, height-selected rule schedule, parent-branch anchors,
integer ASERT, nondecreasing timestamps, cache validation, and canonical cold
replay. Its [31 named controls](../../../../formal/pon-nakamoto-v1/test_branch_time_daa_v1.py)
passed on the isolated continuation of
`b16bae2824e6c8236ef2011fc93a74df3ac7f039`. The 18 external numerical ASERT
vectors are included in those controls, not 18 additional test methods.

This is a temporal reference component. `TemporalHeader` has a fresh research
namespace and is **not** PNH1, PGH2, a native block, or a W1-verified packet.
`append` validates only the declared temporal fields. It does not create native
admission authority, chain-selection authority, payments or model adoption.
No production Rust owner, packet format, source identity, existing rule or
activation flag is changed by these new files. Native/database integration,
independent clock/recovery custody and mixed-consensus security remain open.

The preceding
[joint audit](JOINT_CONSENSUS_DAA_AUDIT_20261108.md) already retains native
negative-endpoint executions. This continuation does not relabel those historical
native results as executions of the new Python component. The sole project plan
remains the existing development plan.

## Frozen schedule and identities

`Schedule` fixes a 32-byte network identity, genesis time and raw target,
`pow_limit`, legacy parameters, and at most 16 strictly ordered upgrades. Each
upgrade specifies its first block height, spacing, half-life and future skew.
Only `aserti3-raw-u256-monotone-v1` is implemented. An unknown algorithm refuses;
it never falls back to the periodic rule. Each first height is at least two so
that its anchor has an actual parent.

The schedule is precommitted for this experiment. It is not an implementation
of future governance authorization or arbitrary amendment of an existing chain.
Changing even a future entry changes the schedule commitment and all associated
record identities. An actual migration needs its own authorized, versioned
native protocol; a caller cannot amend this experiment schedule in place.

The commitment grammars have fixed-width fields and fresh domains:

| Identity | Domain prefix | Bound values in order |
| --- | --- | --- |
| Schedule | `TRNM-BRANCH-TIME-SCHEDULE1\0` | network ID, genesis time, genesis target, limit, legacy parameters, upgrade count, complete ordered upgrade encodings |
| Rule epoch | `TRNM-BRANCH-TIME-RULE1\0` | schedule commitment and epoch index |
| Temporal record | `TRNM-BRANCH-TIME-HEADER1\0` | schedule and rule IDs, parent record ID, height, timestamp, target, opaque body ID |
| Branch anchor | `TRNM-BRANCH-TIME-ANCHOR1\0` | schedule and rule IDs, activation height, anchor ID/height/time/target, actual anchor-parent ID/time |
| Recovery snapshot | `TRNM-BRANCH-TIME-SNAPSHOT1\0` | complete canonical snapshot bytes |

All identities use SHA-256 for this component's byte binding. This choice is not
a claim about the project's complete post-quantum security. IDs have exactly
64 lowercase hexadecimal characters. Heights, times and parameters encode as
eight-byte little-endian unsigned integers; targets encode as 32-byte big-endian
integers. Counts and epoch indices use two-byte little-endian integers. An upgrade
begins with the four bytes `ASR1`. Concatenation is unambiguous because these
lengths and the upgrade count are fixed.

`body_id` is only an opaque caller-supplied binding field in this reference.
Neither its authenticity nor the existence, availability or correctness of the
referenced body is established here. The actual work/header adapter must supply
those checks before this interface could contribute to native admission.

## Parent-branch anchor and ASERT arithmetic

For a candidate at height `h`, the frozen schedule selects an epoch from `h`.
If its first height is `H`, let `A` be the selected parent's ancestor at `H-1`.
The ASERT time origin is the timestamp of **A's actual parent**, at `H-2`.
Both IDs and their numerical fields are part of the anchor commitment. The
candidate's own time and target do not select the anchor or compute its target.

For evaluation parent `P`, write

\[
\Delta t=t_P-t_{\operatorname{parent}(A)},\qquad
n=h_P-h_A+1.
\]

The exact integer computation is

\[
e=\operatorname{trunc}_{0}
\left(\frac{65536(\Delta t-sn)}{\tau}\right),\qquad
q=\left\lfloor\frac e{65536}\right\rfloor,\qquad
r=e-65536q,
\]

\[
f=65536+
\left\lfloor\frac{
195766423245049r+971821376r^2+5127r^3+2^{47}}{2^{48}}\right\rfloor,
\]

\[
T_{\mathrm{next}}=
\operatorname{clamp}_{[1,T_{\max}]}
\left(\left\lfloor\frac{T_A f2^q}{65536}\right\rfloor\right).
\]

`trunc_0` divides toward zero; the decomposition of `e` uses an arithmetic right
shift, equivalent to flooring. These two rounding operations are intentionally
different for negative exponents. No floats are used. The scaled numerator must
fit signed i128; all inputs have explicit integer bounds and Boolean aliases
refuse. Very large shifts return only their mathematically determined clamp,
without allocating an integer proportional to the shift value.

The polynomial and anchor-parent time convention follow the
[BCHN ASERT specification](https://bitcoin-cash-node.gitlab.io/bchn-sw/bitcoincash-upgrade-specifications/2020-11-15-asert/).
The tests reuse the repository's immutable
[18-vector fixture](../../../../formal/pon-nakamoto-v1/vectors/quantum-daa-asert-bchn-v1.json),
which identifies BCHN commit
`07576013c91ff4a3a74acd85f189c69121cdad1b`,
[algorithm blob](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/pow.cpp)
`52b37822da2d4c132b31113a1fc1e3d7b670e3a7`, and
[test blob](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/test/pow_tests.cpp)
`fd3ea96b9a663b28a7020393e5a71a413b2ed355`.

This candidate differs from the BCH protocol: it keeps the exact raw u256 target,
has no compact `nBits` rounding, uses a precommitted height schedule, adds a
nondecreasing-time rule, and has no testnet minimum-difficulty reset. Matching
the numerical vectors does not establish BCH protocol compatibility or import
any blockchain security theorem. The implementation does not call the existing
`quantum_daa_model.asert_target`; the numerical source is independently coded.

Before an upgrade, the reference retains the periodic target rule, the native
upper-median convention and the existing future limit. Its old-rule negative
span reproduces `-42` and the next required-work value `7`. This control preserves
the known old behavior instead of silently rewriting its historical validity.

## Time acceptance, caches and upgrade seams

For a candidate under ASERT, all three tests are required:

\[
t_{\mathrm{candidate}}\ge t_P,\qquad
t_{\mathrm{candidate}}>\operatorname{upperMedian}
(\text{last at most 11 parent-branch times}),\qquad
t_{\mathrm{candidate}}\le t_{\mathrm{observed}}+\mathrm{skew}.
\]

Equality with the parent is permitted only while the strict median inequality
also holds. Near genesis, an even-size window uses the upper middle value, as
the current native owner does. The clock sum is exact and cannot wrap at u64.
A future timestamp produces typed `TimeDeferred` and does not mutate the graph;
the identical record may pass once the caller's observed clock is sufficiently
late. These are supplied logical clock inputs, not measured elapsed mining time.

A second scheduled epoch derives a new anchor from its own preceding block and
uses its own committed parameters. A cache from the preceding epoch refuses.
Changing the caller-selected branch back below an activation height returns the
rule for that branch and height; a global active-tip height is never used.

An optional `BranchAnchor` cache is compared with a fresh derivation from the
selected parent's ancestry. Numeric equality alone is insufficient: two fork
anchors can have identical times and targets yet different block identities.
Such cross-branch cache substitution refuses. Descendant forks sharing the same
actual anchor may reuse it. This implementation deliberately pays the ancestry
walk to validate cache membership; it claims no optimized native lookup cost.

The component reports the retained arithmetic convention
`floor(2^256/(target+1))` as `Requirement.required_work`. It awards no credit and
implements no fork choice. In particular, this variable-target component is not
an implementation of fixed `p0` with variable mandatory work `u`.

## Cold replay and externally expected recovery identity

`snapshot()` emits ASCII canonical JSON with exact field sets, sorted keys,
compact separators and one final newline. u64 values are canonical decimal
strings and targets are fixed-width lowercase hex. It contains the schedule and
genesis IDs and parent-before-child records. Every record retains its original
clock input and derived anchor commitment. Cached verdicts and an active tip
are not persisted as authorities.

`restore(snapshot, schedule, expected_snapshot_id)` requires an independently
supplied schedule and an **externally expected** complete snapshot identity.
It verifies that identity, then recomputes record identities, parent topology,
height/version selection, targets, time rules and each anchor commitment.
Duplicate records, duplicate JSON keys, unknown fields, numeric aliases,
noncanonical encodings and missing parents refuse. Rehashing a false target's
temporal record does not make the target pass the recomputed rule.

The external expectation matters. A truncated snapshot may be a perfectly valid
older prefix. Holding the original expected identity rejects that rollback.
Replacing both the bytes and the caller's expected identity can restore the
old prefix, as an explicit negative-scope control demonstrates. This component
therefore does not establish independent anti-rollback custody, monotonic
external storage or freshness of an authority's recovery decision.

Historical accepted clock inputs are replayed exactly; they are not signatures
by a trusted time source. Successful reconstruction does not activate anything.
Before considering a restored or warm tip for use, the owner has the same
`check_activation_clock(tip, observed_now)` hook. It checks the current observer
clock against every ancestor with that ancestor's selected skew. A clock that
has moved backward can defer both warm and cold use without deleting history.
The native implementation must call this hook; no Python type can prove that a
separate owner actually called it.

The experiment is explicitly bounded to 32,768 records, 16 upgrades and a
32-MiB snapshot. Exceeding a limit refuses; it does not truncate history, reset
an anchor or change algorithms. These are reference-process resource limits,
not proposed production chain-length limits or a disk database implementation.
An append walks its complete ancestor path; replay of a single long branch is
quadratic in its record count. These input limits do not establish a production
CPU-rejection bound, the original quarter-CPU public-service deadlines, or native
cold-recovery qualification.

## What the controls establish and leave open

| Control family | Named tests | Meaning |
| --- | ---: | --- |
| Integer ASERT | 4 | 18 pinned external raw-target vectors, independent test-only compact encoding, signed rounding, saturation and invalid numeric input |
| Versions and anchors | 8 | Complete schedule binding, real anchor-parent time, same-number/different-ID forks, correct shared anchors, cache contamination, second upgrade and branch reselection |
| Time rules | 8 | Retained `-42` old span, new refusal, parent equality plus strict MTP, typed future deferral, exact header fields, duplicate transport, upper median and u64 boundaries |
| Cold replay | 11 | Warm/cold equality, current-clock recheck, externally pinned rollback refusal, explicit joint-rollback counterexample, semantic mutations, canonicality and bounded-resource refusal |

A second explicit counterexample remains essential: a strictly increasing
one-second timestamp schedule passes the new time rules under the declared
logical clocks while the nominal spacing is ten seconds. The ASERT target
decreases along that schedule. Nondecreasing timestamps eliminate the specific
high-first/low-last negative-span mechanism; they do not certify honest elapsed
time, prevent all withholding or timestamp strategies, or prove a classical or
quantum economic lower bound.

Before native qualification, the same exact version must connect these fields
to the complete native header/work challenge, both relevant admission owners,
stored schemas, cold opening, reorganization, activation and clock source.
Independent recovery-anchor custody, full W1 verification, original resource
limits, network observations, legal optimized-work costs and CP/CQ/CG/lifetime
arguments remain separate acceptance obligations. No successful reference test
waives them. `qualification()` keeps all such qualification flags false.

Reproduce the component controls from the repository root:

```sh
bash scripts/project-preflight.sh
python -m unittest discover -s formal/pon-nakamoto-v1 -p test_branch_time_daa_v1.py -v
```
