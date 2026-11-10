# P3 sampling: adapter facts and conditional counting

This closes a narrowly scoped sampler-accounting task. It does not discharge
the concrete field-sampling, Fiat-Shamir, FRI, knowledge-extraction or quantum
security obligations. All production and consensus qualifications stay false.

## Exact source path

The fixed route registry separates `DuplexChallenger<Goldilocks,...>` from
`SerializingChallenger64<Goldilocks,HashChallenger<u8,...,64>>`.
The new reader first reproduces that registry and its frozen input pins. It
then checks the P3 lockfile and the complete SHA256 of two published dependency
archives, without extracting files onto the filesystem:

| Package | Version | Cargo registry checksum |
|---|---|---|
| p3-challenger | 0.8.0 | `92cccaed1c107ad279e76dfd10aa71cff1c1898eb282f406288ad556e65e5a8f` |
| p3-fri | 0.8.0 | `9571ee760e131fc7f63115ded567d3b3d0f6d587c35b16818e266c9d6bd3bc9d` |

The selected dependency sources establish the call path
`FRI query_phase -> challenge_bits -> CanSampleBits`. This path does not call
`sample_uniform_bits`. The latter's rejection policy cannot therefore be
used to describe these actual FRI index draws.

The report records the exact selected member byte hashes and scope. This is
selected dependency-source accounting, not a complete binary-source proof.

## Base and extension field sampling

Write `p = 2^64 - 2^32 + 1` and `U = 2^64`. In the SHA3 profile,
`SerializingChallenger64` reads eight bytes as a little-endian integer and
rejects candidates at least `p`. It samples extension coefficients separately.
`HashChallenger` supplies bytes by popping each digest in reverse order.

**Conditional proposition.** Suppose an unbounded source emits independent
uniform bytes. Each accepted base sample is exactly uniform on `[0,p)`, and
two independently accepted coefficients are uniform on the fixed degree-two
extension. A candidate is rejected with probability
`r = (U-p)/U = (2^32-1)/2^64`. For a fixed `a < p`, summing the geometric series
gives `P(output=a) = sum_{j>=0} r^j/U = 1/p`. Independence of disjoint accepted
candidate sequences gives extension atom probability `1/p^2`.

The expected candidate count for an extension sample is `2U/p`. The chance
that the first four candidates are all rejected is `r^4`; that event is not
an error probability for the implementation, which continues sampling.
There is no finite worst-case candidate limit in this adapter. These average
and tail calculations do not establish a resource bound for an adversarial
concrete transcript or an honest node under hostile traffic.

## FRI query indices

At the two fixed tagged W1 component widths, `b=15` and `b=16`, the byte adapter
reads a raw eight-byte word and returns its low `b` bits. It does not reject or
reduce that word as a field element. Under the independent uniform byte-source
assumption each index has exactly `2^(64-b)` preimages and probability `2^-b`.

For the retained Poseidon2 adapter, `sample_bits` masks a sampled canonical
Goldilocks element instead. Under a separate ideal independent uniform
base-field-source assumption, write `p = q*2^b + t`. Indices less than `t`
have `q+1` preimages and the others have `q`. Total variation distance from
uniform is exactly `t(2^b-t)/(2^b p)`. Here `t=1`, so this difference is small
and nonzero. Comparing adapters at the same width does not assert that every
retained Poseidon2 AIR has one of the tagged profile's fixed trace shapes.

Both adapters produce **64 draws with replacement**. They do not require 64
distinct evaluation positions. For `m=2^b` independent uniform indices, the
probability of at least one duplicate is

`1 - (m*(m-1)*...*(m-63))/m^64`.

The expected number of colliding pairs is `2016/m`, also an upper bound on
the duplicate-event probability. A duplicate event is not a false-proof
event and this expression must not be substituted for FRI soundness. Any
soundness theorem must use its actual with-replacement query model.

## Evidence and remaining scope

Integer counts and rational probabilities are computed exactly. Independent
finite enumeration checks the preimage/variation identities and the duplicate
formula on small spaces. Provided native fixtures are designed to exercise the actual pinned adapter's
modulus boundary, extension coefficients, raw index masking, little-endian
interpretation, repeated indices and real tagged SHA3 digest pop order. Their
existence alone is not execution evidence; native execution requires a separate
terminal record tied to exact test and dependency bytes.

Neither fixture enumeration nor the ideal-source proposition establishes that
the shared concrete SHA3 or Poseidon2 construction emits an ideal independent
stream. Adaptive transcript selection, initial advice, state restoration,
actual FRI/PCS soundness and list size, noninteractive compilation, quantum
extraction, recursion and lifetime composition remain open. The old profile's
conditional estimator input is not transferred to the new profile.
