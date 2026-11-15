# W1 successor R4: public SHA schedules, actual Node admission and lifetime accounting

## Decision

**All five substantive production gates remain HOLD_NO_GO.** This successor
starts from published PR783 head `cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`.
It adds executable research results, a real development Node bridge and explicit
proof/model restrictions. It does not grant PQ128, a production speedup, a global
rejection-cost bound, universal physical-work hardness or production activation.
Earlier observations, failures and qualification decisions remain unchanged.

| Gate | New result | Remaining substantive condition |
| --- | --- | --- |
| Concrete noninteractive security and lifecycle | A proved restricted classical leaf lemma; actual shared-permutation counts for old and new components; exact source-bound, fail-closed lifecycle calculator | Full restricted MMCS/PCS extraction, actual duplex Fiat–Shamir composition, concrete instantiation, quantum reduction and whole-lifetime bounds |
| Positive production backend benefit | Two-input, eight-full-proof ABBA improves total research pipeline, RSS and payload; current native reference is measured separately | Independent verifier regresses; complete research payload and cost remain above the native candidate |
| Global malicious rejection cost | Fixed fifth profile plus actual Node-adapter refusal/cancellation boundaries and a separately labeled shared-cgroup study | Original production owner, global queue/accounting, all malformed inputs, cleanup and honest-service contract |
| Universal cheapest-lawful physical cost | Lawful nonce banking strictly exceeds the old strategy class; smaller exact global-input compiler and fresh full selected-local native acceptance | Quantification over all lawful algorithms/advice/representations and a justified physical cost model |
| Production Node admission and qualification | Two complete real P3 proofs feed the actual development Node library; persistence, duplicate, recovery, reorg and cancellation controls | Production profile and PGH2/growth integration, original resource contract, owned I/O and independent deployment qualification |

This report keeps distinct the implementation proof, conditional cryptographic
models, actual experiments and deployment authority. Passing a narrow test does
not discharge a different gate.

## 1. Security: one proved subgame, exact implementation accounting

The new [lifecycle package](../w1_security_lifecycle_r4/README.md) pins the
actual P3 0.8.0 code and its two historical source revisions. Its instrumented
permutation and challenger preserve native proof serialization, preprocessing
commitments, successful verification and repeated challenge values. An
independent Python replay reconstructs the actual absorb/squeeze count from the
recorded operation lengths.

### A restricted leaf lemma

An actual binary FRI leaf flattens two quadratic extension elements into four
base-field elements. This fixed-width leaf is

\[
H_4(m)=\operatorname{left}_4\Pi(m\|0^4).
\]

For a classical ideal permutation on `X × X`, let `N=|X|=p^4` and let `Q` count
**all shared forward and inverse queries**, including other roles, epochs,
honest subroutines, declared precomputation and offline work. After `Q` calls an
adversary returns two distinct messages. Including their two verification calls,
`T=Q+2`, the proved bound is

\[
\Pr[H_4(m_0)=H_4(m_1),\ m_0\ne m_1]
\le \min\left(1,\frac{NT(T-1)}{2(N^2-T+1)}\right),\quad T\le N^2.
\]

For larger `T`, use one. The proof charges adaptive inverse queries explicitly
through lazy exposure of a consistent permutation. It uses a conditional union
argument and requires no independence between bad events. Exact rational edge
cases and exhaustive four-point toy permutations check the distinction between
restricted leaves and unrestricted raw compression.

This does not overturn the prior raw-compressor collision observation: that
function permits all eight input elements, while this leaf fixes the last four
to zero. Nor does the lemma prove a Merkle opening, tree extraction, general
leaf widths, PCS soundness, a fixed Poseidon2 instantiation or quantum security.
The complete proof and exclusions are in [THEOREM.md](../w1_security_lifecycle_r4/THEOREM.md).

### Actual costs charged to one shared primitive

The following are actual Poseidon2 evaluation counts for the retained proofs,
including counted SIMD padding and repeated inputs. They are not total CPU,
all hash work or a worst-case count for arbitrary rejected proofs.

| Component | Configuration initialization | Independent preprocessing | One verification | Cold total |
| --- | ---: | ---: | ---: | ---: |
| Original SHA, component 1 | 12 | 262,143 | 136,754 | 398,909 |
| Packed arithmetic, component 4 | 12 | 3,014,655 | 14,971 | 3,029,638 |
| Public-schedule SHA, component 5 | 12 | 1,179,647 | 98,990 | 1,278,649 |
| New component 5 + 4 pair | **24** | **4,194,302** | **113,961** | **4,308,287** |

Component 4 was measured under both source revisions and retains its identity.
The new SHA verification count divides into 89,160 leaf, 4,308 branch and 5,522
transcript permutation evaluations. The exact receipts and challenge inventories
are retained; the new component is not silently covered by old measurements.
Keccak transcript-pattern/algebra-identity machinery is explicitly outside these
Poseidon2 counters.

The lifecycle calculator merges every role and epoch using the same primitive
**before** applying a quadratic accounting term. It refuses missing offline
forward/inverse budgets and rejects attempts to make a domain/version tag
resample the permutation. Its separate adaptive-event lemma requires bounds
conditional on the complete prior history; a marginal probability estimate is
not substituted. A supplied query budget is a scenario assumption, not an
experimentally established bound on an adversary.

The conditional RBR estimate remains approximately **63.95384529640614 bits**.
No mapping from that number to the complete fixed PCS/duplex construction or
its lifetime has been established. Actual noninteractive, quantum and lifetime
security fields remain `null`; `pq128` stays false. The calculator cannot enable
them through assumption checkboxes. Primary-source applicability, including
unread/failed retrieval boundaries, is recorded in
[PRIMARY_SOURCES.md](../w1_security_lifecycle_r4/PRIMARY_SOURCES.md).

A tempting hypothesis was explicitly falsified: zero-difficulty PoW witness
fields are **not** arbitrary free transcript bytes. The actual FRI/uni-stark
verifiers enforce canonical zero. Five typed nonzero mutations per receipt
pass structural admission but fail the native cryptographic verifier without
panic. The failed hypothesis remains in the evidence and is not called an attack.

## 2. Backend: genuine research improvements, preserved verifier regression

The new `ScheduledShaAir` independently derives the standard 64-word SHA schedule
from each canonical public block and places it in preprocessing. The proof still
checks all 64 compression rounds, state bits, IV, cross-block links and final
digests. It does not replace the SHA constraints with a native digest comparison.
The public parser, message planner and original SHA AIR remain byte-identical to
the baseline.

Main columns fall from 7,728 to 5,392; public preprocessing grows from 27 to 139.
Both variants retain 8,192 SHA rows, degree 13, two quotient chunks and 64 FRI
queries. The new component is 5, with envelope `W1P3SCS4`; old profiles remain.
Its maximum encoded SHA envelope is 3,338,565 bytes. The independent relation
review constructs a satisfying old row from any satisfying new row by inserting
the canonical public schedule and auxiliaries. This relation-preservation
argument does not prove the surrounding PCS/hash/Fiat–Shamir system secure.

Two distinct retained/dense task inputs each received an ABBA block: **eight
fresh complete proving executions**, four per backend. Each includes preparation,
both fresh proof components, serialization/persistence and an independent
verifier. Both arms used the same eight CPU affinities/Rayon 8, read-back 800%
CPU quota and 4 GiB memory cap on the shared host. Source, binary and input pins
were equal before and after. Every sample is retained.

| Aggregate median | R3 SHA + packed carry | Public-schedule SHA + packed carry | Change |
| --- | ---: | ---: | ---: |
| Complete pipeline | 14.519395 s | 11.862382 s | **18.30% lower** |
| Proving process | 12.834679 s | 10.377300 s | **19.15% lower** |
| Independent verifier | 0.972321 s | 1.068500 s | **9.89% higher** |
| Prover peak RSS | 2,035,728 KiB | 1,463,658 KiB | **28.10% lower** |
| Statement plus proof envelopes | 5,187,028 bytes | 3,978,068 bytes | **23.31% lower** |

Both input families show a verifier regression. The measured SHA preprocessing
median grows from 45.8566 to 202.0868 ms, while SHA PCS verification falls from
261.7273 to 177.2076 ms. The larger independently reconstructed public schedule
has a paid cost; the local verification saving does not erase that cost. Full
phase records, source pins and limitations are in
[PUBLIC_SCHEDULE_MEASUREMENTS.md](PUBLIC_SCHEDULE_MEASUREMENTS.md).

The measured payload remains **80.3553 times** the 49,506-byte native candidate;
the 377,290-byte public statement alone is 7.6211 such candidates. The Node
adapter also retains the native packet, so these research payload figures do
not claim that the adapter's whole storage or transport is this smaller number.

A separate contemporary native reference used six fresh processes and 600
actual FullLimb calls across the same two task inputs. Pooled inner-call medians
were 1.7933015 ms and 1.7988155 ms. They include header-challenge computation,
but input/header reads and process startup are outside the inner timer. Each
100-call process has its own outer timing and first-call observations. This is
an independently timed primitive reference with no Node admission; it is not
an ABBA native-versus-STARK end-to-end deployment comparison. It supplies no
production benefit claim. Its first attempted acquisition failed during source
inventory, made zero native calls and is retained.

## 3. Node: actual admission and recovery, with fresh native checks preserved

The new [Node adapter](../w1_node_adapter_research/README.md) is a separate
research Cargo workspace depending on the actual runtime Node, protocol and
crypto crates. Production crate inventory and dispatch remain unchanged.

Its trusted plan fixes profile, network, parameters, genesis, expected header
and actual artifact commitments. Both fixed proof frames are scanned before
either allocating proof decode or preprocessing. The exact canonical packet's
header/PNW1 proof is bound to the public statement. Both real PCS proofs must
verify before a private immutable borrowed capability is returned. The CLI
opens or recovers Node only after that verification. Live Node context, parent
height and target are checked again before the original `Node::admit` call.

A new packet from the actual development `Node::make` path received **one fresh
complete two-component proof**, independently verified before the Node controls.
All 519 SHA messages and 32,768 cumulative prefix cells were reconstructed and
checked, as were all 81,920 original arithmetic relations. This is a new Node-generated complete candidate and context; it is not
claimed as a third independently sampled matrix family. The nine new complete
proving executions across these experiments are distinct from all replay controls
and small four-row PCS unit tests.

The 12 real integration tests cover admission/activation, exact duplicate
idempotency, cold reopen, false public arithmetic, independent artifact/header
binding, live genesis mismatch, precommit and postcommit cancellation, a native
competing-branch reorganization, incomplete/corrupt archives, interrupted
operations, spent work and independent CLI proof-before-open controls. Separate
CLI owners exercise persisted state and native cold recovery; their complete
records are in the adapter evidence.

Two review corrections matter to the interpretation:

- A bad certificate or `BeforeProof` cancellation now leaves no receiver Node
  directory. The early draft opened a new development Node before verifying;
  the final CLI verifies first in both `exercise` and `reopen`.
- Exact duplicates use the original Node shortcut for already admitted bytes.
  Receipt v2 reports native admission-path invocation and fresh/duplicate policy;
  it no longer falsely labels every call as a fresh FullLimb replay.

After a successful native commit, later cancellation must preserve
`native_admitted: true`. Skipping the adapter's activation call is not a promise
of permanent non-activation: the original `Node::open` recovery can activate the
best committed packet. Reorg observation reports current native membership,
not the old receipt's activation label. The adapter never constructs the native
private work capability, replaces native verification or manufactures chainwork.

The archive completion marker and digests are non-authoritative. Reload requires
independent expectations and both complete proofs again. Its 16-entry cap counts
interrupted operations and refuses enumeration errors, under an explicitly
exclusive-directory assumption. The local start counter is not a persistent or
global resource budget. Checkpoint cancellation does not interrupt an ongoing
PCS call. These limits cannot be promoted into the production rejection gate.

The actual SQLite boundary build warns `UNQUALIFIED: external native build
override CARGO_ENCODED_RUSTFLAGS` for the research native-target flags. The guard
is retained without modification. These ordinary development `Node::open`
experiments do not qualify the production-owned VFS/I/O boundary. PNH1 support
also does not provide PGH2/growth, a public RPC/network ingress or independent
administrator/WAN qualification.

## 4. Production budgets and refusal behavior

The original contract is unchanged: **four seconds, one-quarter CPU, 2 GiB,
zero swap, 256 PIDs, sixteen hostile producers and seven honest submissions**,
with original request/history rules and independent deployment acceptance.
The current process read-back found no `/sys/fs/cgroup/trnmponpublic.slice` and
no direct write access to the system cgroup root. New user-owned diagnostic
units do not instantiate that production owner/service contract.

The original two sixteen-request campaigns remain immutable negative results:
zero completed cryptographic rejections within four seconds and sixteen killed
unfinished processes each. A timeout, worker kill, structural scan, local start
counter or archive cap is not a completed cryptographic refusal or a global
adversarial bound.

R4's separately declared Node-adapter study uses a shared user-owned cgroup and
23 fresh adapter processes: sixteen typed, structurally legal bad proofs and
seven independent **replays of the same valid new Node fixture**. These are not
seven independent production submissions to one live Node. Input preparation,
controller/observer and single-process cryptographic controls are outside the
four-second quota and are separately charged/reported. The retained report
must distinguish completed valid admissions, cryptographic refusals, timeouts,
SIGKILL and actual Node-directory observations.

The single predeclared batch forked, moved and executed all 23 requests under
the shared quota. Within four seconds it completed **zero cryptographic
refusals and zero valid admissions**. All 23 requests exited as unfinished
SIGKILL outcomes, and all were reaped. No receiver Node directory was created
for any request; missing `node_opened` receipts remain unknown/null rather than
being invented as false. Five separately billed preflight executions established
one real valid admission/activation and four actual late cryptographic refusals
(`FinalPolyMismatch` / `CapMismatch`); they do not count toward deadline success.
No request produced an observed `BeforeProof` checkpoint. Consequently this
batch does **not** measure late-PCS verification/rejection cost. No request
produced a recorded checkpoint establishing entry into proof verification.
Each request's precise final execution stage is unknown. The scheduled deadline was four seconds, but the controller decision
occurred at 4.072752 seconds, kill request at 4.075440 seconds, last wait4 at
4.213891 seconds and cgroup disappearance at 4.262711 seconds. This is not a
four-second hard termination or cleanup guarantee. Before killing, the actual
kernel limit was `cpu.max=25000/100000`, burst zero. The last observed pre-kill
kernel `memory.peak` was 175,022,080 bytes and `pids.peak` was 24, including the
sentinel, with no observed OOM/OOM-kill/PID-limit events.
Source, binary and input hashes remained unchanged. Cgroup emptiness and process
cleanup were independently read back. See the
[Node pressure record](../w1_node_adapter_research/resource_pressure/README.md)
for kernel limits, exact timing, resource usage and the complete raw evidence.

This experiment can expose failure of the candidate under its stated limits;
it cannot establish the universal production-service bound. Fresh source/profile
changes receive new input and binary pins rather than inheriting R3 results.

## 5. Physical cost: a larger strategy class and an exact smaller representation

The new [nonce-bank research](../selected_nonce_bank_research/README.md) uses
the unchanged **selected-local-event** relation. It is not cumulative W1, a
STARK or Node admission. Its cheap field schedules are achieved algorithms,
not universal physical lower bounds.

A lawful producer can pay for a bank of nonce selectors first, retain them,
group by selected coordinate and then choose the continuation order. Every paid
selector remains charged even if no ticket is attempted for it. This legal
action was absent from the old immediate-decision online strategy class.

A strictly finite separation uses two coordinates, three allowed paid selectors,
independent ticket success `1/2`, one useful-result slot and positive prices
`gate=1`, `continuation=1`, `useful result=100`. For success at least `3/4`, the
old class's exact Bellman/dual certificate gives expected cost at least
`877/8 = 109.625`. Banking three selectors and attempting two in the most
frequent bucket achieves that success at cost `209/2 = 104.5`. This disproves
extending the old class bound to the bank action; it does not refute the original
scoped theorem or prove a probability law for concrete SHA.

For a fixed already-purchased bank with independent Bernoulli tickets, empty
initial useful-result cache and explicitly charged acquisitions, an optimum
exists with contiguous buckets ordered by
`u_i / (1-(1-p)^n_i)`. One useful-result slot suffices in that model. All initial
acquisition or historical-cache costs must be charged or assigned an explicit
amortization model. The proof covers interleaving, prefetch, eviction,
recomputation, randomization and history dependence **within that atomic priced
model**. It does not optimize how many selectors to buy or bound other algorithms.

The actual original task matrices have an additional global affine structure.
The exact recognizer checks all 8,192 canonical words. Its compiled useful-block
representation has 329 field words, or **1,316 bytes**. Setup costs
**26 multiplications + 8,533 additions**, plus 8,192 equality checks and range,
shape and input-reading work. Each acquired useful 8-by-8 block then costs
**0 multiplications + 73 additions**. The prior broader per-block affine family
used 448M+8,512A setup, 2,048 bytes and 5M+71A per acquired block. The new family
is narrower and must not be substituted for arbitrary valid input.

The predeclared actual-SHA interval was nonce 512–1023. The bank paid 512 gates,
attempted seven tickets, acquired two useful blocks and found nonce 561; it
therefore paid for **505 selectors it never continued**. The ascending strategy
paid/attempted 50 and acquired 50 blocks to the same winner. Every failure,
recognition step, bank record, ordering cost and cache event is retained.

The full instrumented `hashlib` producer executes **7,878 compression blocks for
the bank versus 5,946 sequentially**. A separately executed bounded-prefix
replay, with every digest checked, uses 2,748 versus 3,254. The replay is not
relabeled as the live producer implementation or a measured speedup. Field
multiplications, additions, hashing, storage, time and energy are not collapsed
into an invented common physical currency.

All 164 attempted strategy witnesses match the full frozen producer bytes.
There are 17 new Python tests, 243 independent scheduling/cache DP comparisons
and 2,048 complete dense-product comparisons. Fresh unchanged native
selected-local verification accepted 13 distinct target hits plus five strategy
winner invocations, **18 total**, and rejected two new winner mutations. Each
acceptance executed the native noisy and useful arithmetic checks. None is
counted as a new cumulative W1, STARK or production Node acceptance.

## 6. Provenance, retained failures and publication checks

The backend code source is `eb944645cc3e30af5955edf9dbbcb43488fa38c1`; its
research measurements, original compiler failures and documentation follow-up
retain that identity. The integration includes the original measured commit
in its Git ancestry so the source-bound lifecycle checker can read it in a
fresh clone. Historical `cc836` receipts remain distinct. The native reference
uses a pinned earlier adapter v3 binary; its exact input, source and graph pins
are separate from final admission receipt v2 and the v4 pressure binary.

Raw original failures are retained, including incomplete worktree checkout,
first SHA helper/type compilation, initial Node `WireError` formatting,
incorrect native provenance path before any native sample, and transport size
or truncation refusals. Raw logs with trailing whitespace are losslessly
archived with original byte lengths/hashes rather than edited into passing
logs. The false zero-PoW hypothesis and Node duplicate-label correction are
also preserved. No failing performance sample or timed-out request is dropped.

The first final-commit check also exposed seven historical R3 `.log` fixtures
that the broad Git ignore rule had omitted from the tracked tree. The retained
24-test suite stopped with `FileNotFoundError`; this failed attempt and all its
earlier passing logs are preserved in the [initial final-check archive index](../w1_node_adapter_research/evidence/initial-final-check-v1-index.json).
All seven files are restored byte-for-byte from the original R3 proposal archive,
including three originally empty budget logs. Existing expected hashes, test
conditions and historical measurements are unchanged. The [restoration receipt](../physical_strategy_frontier_research/R4_FIXTURE_REPAIR.json) records each original
member and SHA-256; the complete focused gate set is then run on the repair commit.

The focused final gate set requires repository/Markdown checks, the 50
repository negatives and 43 source-integrity negatives; locked/offline Cargo
graphs, formatting, strict Clippy and both Rust research suites; the security
and physical Python suites; evidence/source/binary hashes; and equality of
source receipts before and after final checks and publication. Complete
repository-wide Node CI, production service qualification and administrator
acceptance are not claimed by this focused gate set.

The sole development plan is appended with this successor's bounded conclusion.
The existing draft PR is updated by an ordinary fast-forward push after the
exact final-source checks. Runtime/configuration/qualification scopes and the
original service contract remain unchanged. There is no main-branch merge,
production activation, self-approval or relaxation of any outstanding gate.
