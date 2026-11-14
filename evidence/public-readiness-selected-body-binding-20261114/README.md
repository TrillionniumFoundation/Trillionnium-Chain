# Current selected-opener source review

This record follows the two actual external-evidence-contract failures in
workflow run 43567821538 at source dc42ce4df5cff79cc61c5addbaf01074b56b06ca.
Both original job logs record 76 tests, 46 failures and 23 errors. The reader
stopped at its complete selected-opener implementation digest, before many
negative controls could reach their intended checks. Those failures remain
unaltered in original-C0/external-evidence-originals.zip.

The previous observation_only digest e89baea593c5a31e16760c3ad42854d9112775b2e51a8994262f06eee379f1d3
matches the actual 20493-byte open_selected_mode body at historical source
2bb56596e637908c44b5a2ef5984c9c37c7d3cc8 and candidate 332d7f723d71707d88a2cffa52b3754579a46926.
The current 20846-byte body is f79b2baf4938ca8f410a26559118505fb36ba3b21b50efb3971bc9ba82845978.
Its bytes are the same at dc42, F2 and reviewed source checkpoint
e1bf4299a0c57ba797baf2cc50192321e8843b6b. This checkpoint identifies reviewed
source bytes, not the later metadata commit.

The complete old/current body comparison contains only the previously selected
PQ_TLS_ENDPOINT_WITNESS_REQUIRED check. A policy that requires a TLS endpoint
witness must select PqWitnessV4 and provide the witness. This check executes
before namespace effects; the existing M06 account-profile refusal remains
ahead of it. The current reader changes one reviewed body digest and its
comment. It accepts no alternate old digest. All historical growth, DDL, domain,
typed-mode and schema-selection checks remain unchanged.

The original 76 test methods retain their exact source and AST. One new method
checks old-body rollback, an ignored witness refusal, and moving the check after
namespace creation. These are source-inspection controls, not native execution.
All runtime, public readiness and authority qualifications remain unchanged.
Focused validation is recorded separately before commit. This record does not
claim a complete external-evidence lane, a hosted pass or a security proof.

## Actual targeted result and remaining gate

The original macOS run attempted all 77 methods: 69 passed, 8 errored and none
failed an assertion. The new method and its three refusal cases passed. Seven
errors occurred while importing the actual collector because cryptography was
not installed. The eighth came from the child-runtime probe that imports numpy
and cryptography. The complete original stderr and failed summary are retained
unchanged under validation; this is not an all-pass result.

All 76 original methods preserve their source and AST. The nine explicitly
selected inputs matched before the run and at the later post-run readback,
with no source edit between. No Mac dependency installation, source relaxation
or test skip was performed. The final acceptance condition remains all 77
methods passing in the exact Linux environment with numpy 1.26.4 and
cryptography 50.0.2, followed by the relevant complete lanes. Those successor
results are not claimed here. This source-inspection repair grants no public
readiness, production activation or hosted qualification.
