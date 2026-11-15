# Goldilocks low-bit query sampling: exact component bound

## Scope and source-path status

This is a component derivation under the explicit assumption that each sampled base-field value is independently uniform over Goldilocks, also conditional on the preceding transcript. It is not a proof that concrete Poseidon2 meets this assumption and not a complete Fiat–Shamir/PCS/NIZK or quantum soundness theorem. Qualification remains **HOLD_NO_GO**.

The complete query-index call chain has now been checked against the actual pinned 0.8.0 registry sources. FRI uses the ordinary low-bit API, not the distinct rejection-based uniform-bit API. The code-path question is closed for these query indices; the independent-uniform-base-field hypothesis remains a mathematical assumption.

| Step | Actual source behavior |
|---|---|
| `TwoAdicFriFolding::extra_query_index_bits` | Returns zero. |
| `verify_fri` | Derives the maximum input log-height as `max(log2(claimed domain size) + log_blowup)` and sets `FriShape.index_bits` to that value plus the zero extra bits. |
| `VerifierTranscript::query_phase` | Calls `state.challenge_bits(QUERY_INDICES, index_bits, num_queries)` after observing the fixed-length final polynomial. |
| `fs::VerifierState::challenge_bits` | Performs exactly `count` calls to `self.challenger.sample_bits(width)` and collects them; it does not call `challenge_uniform_bits`. |
| `DuplexChallenger::sample_bits` | Samples one base-field element, obtains its canonical u64 representation, and masks the low `bits` bits. |

The fixed runner uses 64 queries and `log_blowup = 2`. Its accepted full trace domains have log sizes 13 and 17, so the actual index widths are **15 and 19**. The verifier derives these shapes from the requested opening domains and parameters, checks proof lengths against them, and only then samples the indices. Subsequent fold indices are deterministic shifts of this query vector.

The precise upstream source identities for this chain are:

| Original crate-relative source | SHA-256 |
|---|---|
| `p3-fri/src/two_adic_pcs.rs` | `926b6ecfe0c3c2ae3956d77f78795c3d5d4b7b171c16ec1ae251852c2d2a24cb` |
| `p3-fri/src/verifier.rs` | `975392a464c823c93c9ec50ce4e73d17a8b0fbdf22f047f887fb749dcf7280a3` |
| `p3-fri/src/transcript.rs` | `a9ee1af03b02514bffffa6519c1f0544c91457c3e2327024cdfcfd84273ab6e9` |
| `p3-challenger/src/fs/state/verifier.rs` | `9365f4007a3bfc1ac05e9be3359b36d6cb09c62c7057e268f77fb0dbdf246c77` |
| `p3-challenger/src/duplex_challenger.rs` | `82d7f006d285015d358e70e3c08378cc907ebb5416a1d1ad2d03d374c56f62e9` |

Inspected sampler local audit identifier: `round2_runtime/p3_challenger_duplex.rs.txt`; original source SHA-256 `82d7f006d285015d358e70e3c08378cc907ebb5416a1d1ad2d03d374c56f62e9`. Local `round2_runtime` names identify the files used during review; they are not delivery dependencies. `AUDIT_SOURCE_LOCATORS.json` gives pinned official crate/source locations and hashes, including [p3-challenger 0.8.0](https://crates.io/crates/p3-challenger/0.8.0).

## 1. Exact distribution

Write

`P = 2^64 - 2^32 + 1 = 18446744069414584321`, `n = 2^b`.

For the intended query widths `b = 15` and `b = 19`, P is congruent to one modulo n. Set `a = (P-1)/n`. If X is uniform on the integers from zero through P−1 and `Y = X & (n-1)`, then

`Pr[Y=0] = (a+1)/P`,

`Pr[Y=y] = a/P` for each `1 <= y < n`.

The reason is exact residue counting: there are a full runs through all n residues followed by the single additional value an, whose residue is zero. The maximum atom is therefore `(a+1)/P`. The sampler is not perfectly uniform.

Against the uniform distribution U on n positions, the deviations are

`Pr[Y=0] - 1/n = (n-1)/(nP)`,

`Pr[Y=y] - 1/n = -1/(nP)` for nonzero y.

Consequently the exact single-query total variation distance is

`TV(Y,U) = (n-1)/(nP)`.

The exact largest probability-density ratio is

`max_y Pr[Y=y]/Pr[U=y] = n*(a+1)/P = 1 + (n-1)/P`.

The smallest ratio is `1 - 1/P`.

## 2. Multiplicative transfer for 64 queries

Let D be the distribution of k independent copies of Y and let U^k be k independent uniform queries on the same positions. For every vector y,

`D(y) / U^k(y) <= (1 + (n-1)/P)^k`.

Summing this pointwise inequality over any bad event B gives

`Pr_D[B] <= (1 + (n-1)/P)^k * Pr_uniform[B]`.

The factor is exact as a worst-case density bound: the all-zero vector attains it. It also survives any deterministic processing of the query vector, such as deduplicating repeated indices, because the pointwise inequality can be summed over the corresponding preimages.

The same likelihood-ratio argument applies to adaptive conditional draws if, at every relevant draw, the conditioned base-field value remains fresh uniform and the index width is fixed or predictably bounded. The two compared processes must have identical transition rules at the same history except for the query-sampling kernel. With at most 64 such draws and predictable widths bounded by b, the factor remains at most `(1 + (2^b-1)/P)^64`. This is a hypothesis of the comparison argument. It is not established merely by the concrete challenger's Rust type.

Using an additive total-variation union bound `k*TV` would be valid but needlessly loose for a rare bad event. The multiplicative transfer preserves the small uniform-model probability instead of adding an unrelated absolute error floor. It does not license omitting any other transcript or cryptographic error.

## 3. Exact reproducible values

The Fraction script computes all probabilities and ratios exactly. Decimal logarithms are presentation only. For k = 64:

| Width b | Positions n | Joint max density ratio | Loss in bits, log2(ratio) |
|---|---:|---|---:|
| 15 | 32768 | `(1 + 32767/P)^64` | about `1.64010431679598e-13` |
| 19 | 524288 | `(1 + 524287/P)^64` | about `2.624241987182235e-12` |

The retained JSON includes full exact numerator/denominator pairs, maximum and other point masses, single-query TV, density excess and the unused additive-TV comparison. Four small examples are also checked by direct enumeration of residues, including a non-unit remainder, to cross-check the counting formula.

An independent mathematical read-through by the work-bound reviewer confirmed the residue counts, total variation, joint density comparison and the script's general-remainder formula. That read-through did not rerun the script or establish the cryptographic assumptions or FRI source path.

From the directory containing this review and its script, run:

```sh
python3 goldilocks_query_sampling.py \
  --bits 15 19 --queries 64 \
  --output /tmp/w1-goldilocks-query-sampling.json
```

The script uses only the Python standard library and writes the requested output path; moving this review directory does not change the calculation.

For the full SHA trace, `log2(8192) + log_blowup(4) = 13 + 2 = 15`; for the full arithmetic trace, `17 + 2 = 19`. The checked source chain above confirms that these are the actual maximum-domain query widths. Subsequent deterministic shifts of a sampled index do not need additional independent sampling charges.

## 4. What this does not establish

The result neither proves the field sampler's independence under Poseidon2 nor covers the polynomial-commitment binding, AIR composition, out-of-domain sampling, Fiat–Shamir compilation, cross-proof composition or quantum access. It refines one sampling component of a conditional model. The fixed code's proof-of-work settings are all zero, so no proof-of-work security credit is claimed. An adversary can still try multiple Fiat–Shamir transcripts; accounting for that adversarial oracle budget belongs to the missing compilation theorem and is not paid by this density-ratio calculation.
