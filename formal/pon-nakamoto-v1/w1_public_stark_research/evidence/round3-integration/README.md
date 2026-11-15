# Round 3 integration evidence

Qualification remains **HOLD_NO_GO**. These records distinguish the original
measurement source, the later guarded integration and final delivery checks.

- [Guarded full ABBA summary](guarded-abba-summary.json): four fresh complete
  proving executions; one input; both verifiers use structural admission.
- [Carry successor controls](carry-controls-summary.json): two positives and
  34 negatives, 36 verifier processes, zero newly generated proofs.
- [Native primitive audit](native-hash-audit-receipt.json): actual P3 API checks,
  registry/source/archive pins and ten Python audit tests.
- [Resource batches](resource-batches-summary.json): both 16-request batches
  timed out without cryptographic refusal; all exits and cleanup were observed.
- [Node source scope](node-source-check.json): runtime/configuration/qualification
  directories unchanged, with no live production Node invocation.
- [Build/source binding](build-binding.json): actual compiled source and binary
  hashes, subsequently compared to the final committed source by delivery checks.
- [Archive index](evidence-index.json) and [lossless raw evidence](integration-evidence.tar.gz):
  all included files retain their original bytes and individual hashes. The
  index also records omitted proof/input and executable bytes by digest.
- [Measured backend source bundle](backend-measured-source.bundle): original
  ac4927c and 9fe8aba commits, requiring the published 3bbd072 baseline. It
  preserves their exact source identities without relabeling them as integration.

The raw archive includes failures and incomplete requests. A successful
controller exit or cleanup is not a cryptographic rejection, Node qualification
or successful original four-second benign-service gate. The first delivery's
raw-log whitespace refusal and gh GraphQL compatibility failure are retained.
The latter was resolved by a verified REST PR-body update. Raw logs were never
trimmed to pass a whitespace check.
