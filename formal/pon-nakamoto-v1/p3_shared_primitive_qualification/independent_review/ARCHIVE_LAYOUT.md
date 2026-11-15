# Review archive layout

The files in this directory preserve two internal, model-assisted reviews
and their original source identities and local Python observations. They are
not an external cryptographic audit or the exact-commit native gate receipt.

The reports and JSON receipts intentionally retain their original absolute
staging paths. `verify_final_delta.py` was run in a layout with sibling
`tagged_profile_impl`, `root_docs`, and `independent_review` directories under
`/workspace/scratch/3acf892fe0ad`. Its historical delta comparison also keys
the preceding receipt by those original paths. It is archived unchanged;
do not treat it as a directly relocatable repository CI test.

The report's source snapshot precedes native rustfmt/export. The complete
native campaign records actual source and binary hashes, while the final
integration gate checks the exact committed tree. These are distinct receipt
scopes and must not be conflated. The independent fixed vectors are unchanged
through those stages. Their portable byte regeneration and actual Rust role
checks are performed by the qualification runner in the parent directory.

The skipped-suite stdout/stderr are deliberately failing coverage examples:
all 40 bodies were skipped. They demonstrate the former parser weakness and
must never be added to a passing-test count. The 11 parser-expression controls
check the repaired gate predicates only and do not run native qualification.
