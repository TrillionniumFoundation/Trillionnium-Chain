# Native owner observations to exact local score witnesses

This continuation connects actual `Node` calls to the deterministic accounting
in [the native execution certificate](NATIVE_EXECUTION_CERTIFICATE_V1.md).
The [native owner census](NATIVE_OWNER_OBSERVATION_V1.md) revalidates one held
owner's complete current admitted PNP1 relation in a consistent read snapshot.
The independent [reader](native_owner_score_bridge.py) checks its exported
arithmetic and binds actual confirmation observations to that same local
context. Neither component supplies a world-ready inventory, authenticated
physical clock, probabilistic network law or all-algorithm resource lower bound.

## What is actually executed

The Rust `native_owner_observation_v1` example creates two fresh native owners.
Its block construction, full PNW1 verification, admission, application state
execution, fork activation and transaction confirmation are ordinary native
calls. It retains complete produced packets and a separately marked malformed
product control. Controlled header timestamps and validation clocks are inputs
to these calls. They are not measured creation times or a simulated probability
distribution over real network executions.

The sequence includes six successors above an included transaction, a second
owner that has never seen that block, a hidden eight-block fork, an admitted
nine-block target-containing chain that remains unselected, a future ancestor
with a current-timestamp child, a strict tie, an actual reorganization, later
timestamp maturity, cancellation and a census block-budget refusal. This
tests the existing submitted-candidate activation rule: admission of a heavier
candidate does not itself establish that the active tip is the maximum of
all eligible admitted candidates.

The observer supplies two distinct clocks. Process-local `Instant` brackets
the census invocation. Caller-provided `observed_now` determines native future
eligibility. Neither is exported as a globally authenticated wall clock,
first-ready time or final-parent-binding time. Owner attempt numbers increase
through the actual reorganization; they are not chain state.

## Independent exported-data checks

Native cumulative work is an unsigned **512-bit** value, serialized as exactly
128 lowercase hexadecimal digits. A non-genesis target is 256 bits and nonzero.
The reader independently recomputes the existing native rule

\[
w(b)=\left\lfloor\frac{2^{256}}{T(b)+1}\right\rfloor,
\qquad S(b)=S(\operatorname{parent}(b))+w(b).
\]

Genesis alone has zero work, height zero and no packet. Every other row must
have its parent earlier in the complete exported tree, height increment one,
correct cumulative work and a retained complete packet with matching digest
and size. Duplicate identities, missing parents, partial replay flags and
inconsistent packet substitutions are refused. The raw native packet verifier
is executed by the Rust emitter; the Python reader does not pretend to replace
the full native application or transaction-membership verifier.

For a caller validation time \(t\) and installed future allowance \(\delta\),
eligibility is recomputed along every ancestor:

\[
E_t(g)=1,\qquad
E_t(b)=E_t(\operatorname{parent}(b))
       \land [\operatorname{timestamp}(b)\le t+\delta].
\]

A child with a current timestamp cannot hide a future-ineligible ancestor.
The reader recomputes the entire active path, maximum eligible score, all
maximizing identities and raw selection deficit. An ineligible active tip
has no eligible-view deficit witness; the comparison refuses it. The native
emitter separately rechecks MTP, branch target legality and the work/application
relations, so the future-time predicate is not being used as complete block
validity.

The local-view commitment is independently reproduced with the original
`TRNM-PON1` framing and the new `pon-native-local-owner-view-v1` tag. It binds
the exported view bytes. It is a public, unkeyed commitment; a coherent new
plaintext export and its recomputed commitment do not authenticate an emitter.
The test suite explicitly exhibits this limitation.

## Actual six-successor observation binding

For the actual installed confirmation observation the reader requires matching
network, parameters, genesis, tip, active generation and validation time.
Installed depth and work multiplier come from the native settings export,
not merely the policy's text label. It recomputes inclusion on the active path,
depth, work delta and the logical AND of both gates. A reorganization observation
must have no active inclusion, no depth/work delta and `confirmed=false`.

In the six-successor profile, confirmation of block \(b\) at tip \(C_0\) implies

\[
\operatorname{height}(C_0)-\operatorname{height}(b)\ge6,
\qquad S(C_0)-S(b)\ge6w(b),
\]

and therefore

\[
K_b=S(C_0)-S(\operatorname{parent}(b))\ge7w(b).
\]

This is an inclusive local score threshold. It does not say that an adversary
must produce seven new units after confirmation. Previously ready inventory,
unseen honest branches, selection lag and network availability remain in the
failure accounting.

## Exact comparison witness and its limits

Let \(D\) be an eligible active tip in the compared owner view, with \(b\) absent
from its prefix. The views share immutable block identities and score rules.
Let \(a\) be the last common ancestor of \(C_0,D\), \(R=S(C_0)\), and \(M\) the
maximum eligible score in that compared complete local view. Define

\[
L_a=(R-M)_+,
\qquad L_s=(\min(R,M)-S(D))_+.
\]

Because \(D\) belongs to the eligible view, \(S(D)\le M\), and hence

\[
L_a+L_s=(R-S(D))_+,
\qquad
S(D)-S(a)+L_a+L_s\ge S(C_0)-S(a).
\]

The reader checks both equalities/inequalities with actual exported scores.
The complete competing suffix is kept as such: producer attribution, initial
inventory and first global readiness are not present in the export. Relabeling
that suffix as newly produced adversarial work would invalidate the reduction.

If the compared view additionally contains an eligible target-containing chain
\(Q\), write

\[
g=S(Q)-S(\operatorname{parent}(b)),\qquad q=M-S(D).
\]

Since \(M\ge S(Q)\) and \(S(a)\le S(\operatorname{parent}(b))\),

\[
S(D)-S(a)\ge g-q.
\]

This uses current local knowledge of \(Q\); it does not insert that chain into
the initial confirmation view. If no eligible target-containing chain is known,
the positive-known-chain witness is absent, not silently assumed.

For the fresh development run all sampled blocks have native weight two. The
early unseen view has \(R=14,M=S(D)=0\), so availability deficit pays all fourteen
score units and the competing suffix is zero. After the real reorganization,
\(M=18,S(D)=16\): the raw selection deficit is two, while the deficit capped at
the original \(R=14\) is zero. When the future ancestry becomes eligible without
selection, \(M=22,S(D)=16\) and the raw deficit grows to six. These are exact
local observations under a controlled schedule, not attack probabilities.

## Reproduction and failure handling

Build the native example with the repository's pinned compiler and dependencies,
then supply its actual executable explicitly:

```sh
TRNM_NATIVE_OWNER_OBSERVATION=/absolute/path/to/native_owner_observation_v1 \
TRNM_NATIVE_OWNER_RECORD_DIR=/absolute/path/to/new-output \
python3 formal/pon-nakamoto-v1/test_native_owner_score_bridge.py -v
```

An absent executable is a failure. The test invokes the native program afresh;
there is no historical fixture fallback. A retained invocation records bounded
stdout/stderr, return code, executable hashes before and after, complete native
JSON, packets and the independent score report. A new output directory is
mandatory. A failed invocation remains failed and is not overwritten by a retry.

An existing record can be checked without executing a new owner:

```sh
python3 formal/pon-nakamoto-v1/native_owner_score_bridge.py \
  --input /absolute/path/to/native.json
```

That second command validates an existing exported record only. All independent
runtime, world coverage, physical clock, resource lower-bound and six-successor
risk qualification fields remain false; failure probability remains unknown.
