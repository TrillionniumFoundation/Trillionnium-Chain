# Fixed PQ provider preparation on AI395

This is **provider preparation and smoke evidence**, not a Root native test
result. The unchanged C5 preparation script built the pinned OpenSSL 3.5.9
provider and observed ML-DSA-65 sign/verify plus wrong-message rejection. The original
result is `PREPARED_AND_SMOKE_VERIFIED`; it grants no system qualification.

The [original archive](provider-observation-artifacts.tar.gz) contains ten exact
regular-file members, including the executed script, source/preflight records,
environment, original preparation result, provider receipt and complete build
and smoke log. Its 42,711 bytes have SHA-256
`aaa772604c518247aceaead25b62601b6c6cff213d51d5569f11d80468e2b963`.
The complete decoded build log is 1,323,704 bytes with SHA-256
`68513cdf163bc2e56094ea68050a7e6549d5d39437417dc104ca4a07516613ef`.
The provider CLI has the separate recorded SHA-256
`09362cd9a4f5ef29e9cdd9fe26092a706ffe589f1e52c8c5572bd74df7ccdc1d`.

The [v2 readback manifest](provider-readback-manifest-v2.json) records every
decoded member's length and digest. Its `payload_root` names the temporary
extraction directory used by the readback; the complete payloads are supplied
in the archive. The [independent binding check](provider-independent-bindings.json)
also checks the three original result/log bindings, the exact C5 script Git
blob and the consistency of the five provider input pins. Two original JSON
receipts were independently read from the remote host and matched the archive
bytes. This readback did not rebuild or execute the provider binaries.

The [prior derived manifest](provider-readback-manifest-v1.json) is preserved.
It used `matches_prior_pin: false` for five entries with no separately provided
prior pin. That boolean was ambiguous, not an observed digest mismatch. V2
explicitly marks these comparisons `not_applicable` with a null match value;
all five provided prior pins match. Original payload bytes and the independent
verification record are unchanged.

The first preparation launch acknowledgement was uncertain. The original
operation's completed result and on-host artifacts established the outcome;
the provider was not rebuilt to obtain a new successful observation.
