# Independent CEV1 registry conformance fixtures

The files in this directory are A09-owned inputs to the independent
standard-library parser:

- `operation-mapping-v1.json` is the independently authored `0..29` semantic
  assignment map (including body type, authority, nonce lane, status and
  enablement).  Its A08 commit/tree fields pin the corrected candidate
  `6c42673db5bc46f82934dddc678a1752a092ca04` /
  `df8f6bf0cfe0868668f86ba9b41fc34ce1a085c4`.
- `negative-cases.json` is the retained mutation index.  The harness copies
  all registry inputs into a temporary directory before applying each mutation;
  no candidate source file is changed.

These are candidate, non-normative evidence only.  The shell gate requires a
clean checkout and that exact A08 source commit/tree before a module closure
candidate is considered; pin verification is not protocol or production
activation.
