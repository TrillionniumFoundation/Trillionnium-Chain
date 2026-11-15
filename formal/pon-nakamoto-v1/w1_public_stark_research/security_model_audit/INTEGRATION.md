# Native execution of the shared-primitive audit

The original README and its manifest are retained byte for byte as a historical
Python-audit snapshot. The later native integration executed
`examples/hash_role_probe.rs` against the actual locked P3 0.8.0 crates on the
research build host. Its assertions passed: both independently derived inverse
witnesses map to the specified chosen outputs; the raw compressor outputs
match; and both fixed-width role overlaps match the exact expected field words.

The receipt is [native-hash-audit-receipt.json](../evidence/round3-integration/native-hash-audit-receipt.json).
It records ten passing Python tests, the native executable/source hashes,
all eleven primary source-file matches to the build's actual Cargo registry,
six official archive hashes matching Cargo.lock, and an independent Git-object
match for the historical W1 proof configuration. Source bindings matched before
and after the integrated checks. Raw stdout, stderr, command records and source
receipts are preserved in the accompanying integration evidence archive.

The probe performs native forward evaluation of externally constructed inverse
witnesses; it does not substitute a Python hash implementation into the proof
system. The findings restrict primitive models. They are not a Merkle-tree
binding break, a complete W1 forgery, or a new noninteractive security estimate.

The integrated metadata retains the old estimator input and approximately
63.95384529640614 conditional RBR estimate. It explicitly labels that input's
scope and leaves concrete restricted-tree binding, noninteractive, quantum and
lifecycle bits unknown (`null`). Metadata schemas were advanced. The proof
parameters, shared permutation and transcript domain separators were not
changed by this metadata correction. Qualification remains **HOLD_NO_GO**.
