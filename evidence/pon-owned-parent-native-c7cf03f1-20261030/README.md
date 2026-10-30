# Owned-parent execution evidence

These packs preserve original command receipts and raw output, including failed
lint observations, reader failures, and the predeclared finite timeout probe.
Base64 retains every raw byte, including trailing whitespace. The index records
actual tested commits and trees. GitHub commit mappings identify the same tree;
they do not claim that an execution occurred under a different commit identity.
The fixed required-input inventory binds all 53 terminal phases, the three
included-source probe phases, their key originals, four summaries, and six
tested source trees. `summary.json` reports the completed H5 suite counts and
scope; the packed historical failures remain available independently.

Run `python3 verify_native_evidence.py --root .` to verify every pack, part and
original file hash. To reconstruct the originals, add `--extract /new/directory`.
The destination must not exist. Fixed relative prefixes and exclusive writes
prevent overwriting existing files. The verifier grants byte-integrity results,
not native-test, consensus, model, post-quantum or production acceptance.

Large metadata reproduction files are explicitly listed as omitted, with their
original hashes. ELF/target/registry contents and private environment dumps are
not included. Actual ELF hashes and command/source identities remain in the
original receipts. The full Cargo graph can be regenerated from the recorded
source and lock; exact original metadata bytes additionally depend on paths and
the original environment.
