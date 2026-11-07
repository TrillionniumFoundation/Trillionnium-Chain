# NPQ6 migration controls and reviewed legacy evidence extraction

This is a component execution receipt, not a second development plan or a production approval.
The implementation commit is `a5065327a3079430c6d15e6f8f4d08dbd91c9ab2`, based on
`840522d0b65b4989f1a2a1d09c0ad51af1a1956d`. Exact tested commits, trees, commands,
profiles, executable observations, durations, failed attempts and log hashes are
in [receipt.json](receipt.json) and its losslessly compressed raw files.

## Executed changes

- Three real RustCrypto ML-DSA-65 NPQ6 integration tests passed on clean
  `4fe4543c54a356b5710d3968f6e6b12aeaf2de6f`: trusted anchored source accounting,
  nonce/fees, escrow/refund, immature reward release, dual-possession claim,
  rotation, cold reopen, wrong-domain/signature/replay rejection, and refusal to
  discard an admitted legacy checkpoint's unsupported work state.
- The positive source checkpoint is an explicit trusted fixture. It is not an
  authenticated history or ownership migration of a deployed old chain.
- The actual ordinary opener moved into `open_selected_mode`. The legacy schema
  reader now verifies its complete ordinary delegation, exact modes, unguarded
  item headers, schema bindings and the complete reviewed implementation bytes.
  Unknown bodies cannot fall back to an older recognized opener. The exact-body
  pin requires review when the implementation changes; this is not a Rust evaluator.
- Nine additional adversarial source mutations failed before the closure and are
  now refused, including an early return into another backend and cfg-disabled
  declarations. This establishes an extractor defect and repair, not a demonstrated
  bypass of the complete artifact acceptance pipeline.
- The complete reader suite passed 71/71 on clean implementation commit `a5065327`;
  CI contracts passed 104/104 on the same clean commit. PQ source-contract controls
  passed 38/38 on `4fe4543`. Workspace formatting and strict Clippy for the new
  native integration target passed without changing the Cargo profiles or lock.
- All three native selectors are wired into the existing PQ workflow with exact
  selectors and the actual-execution reader. They do not inflate the existing
  52-control library roster or count a list/build command as test execution.

## Retained failures and scope

The original schema extraction failure, nine accepted source mutations, first
native build's two private-method errors, and intermediate suite's three missing
GNU time errors are retained. The repaired tests read public parameters. A real
observed GNU time executable was selected through the existing explicit interface;
no failing control was removed or changed into an unmeasured success.

The default-feature Node/library run does not qualify the feature-gated NPQ6 CLI.
The SQLite build reported `normal Cargo loader directory set incomplete`; this
run does not certify the physical VFS boundary, crash durability or execution
attestation. These file/compiler observations are not independent hardware evidence.

The deployed source chain's finality, retirement and ownership registry remain
external assumptions. Unsupported legacy work rows are preserved by refusal.
No deployment custody, public WAN confidentiality, whole-directory rollback,
Hepta/Node complete effect coverage or quantum PoN/proof-composition acceptance
is granted. The separate Chain `62cb191` / Hepta `5cba396` observations must not be
combined with these results as one tested revision.

Each `runs/*.gz` contains the exact original bytes; decompress with `gzip -dc`.
`receipt.json` records both the decompressed and stored SHA-256 values.
