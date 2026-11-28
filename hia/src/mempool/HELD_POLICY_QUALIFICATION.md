# Optional original held-policy / LPV1 comparison

This standalone check exercises the **original** Rust Node on two disposable
development SQLite namespaces. Both LPV1 backends must reproduce the actual
committed context and raw compact policy bytes using the owner-observed Settings
identities. Each cold phase runs in a new process after the original handle is
closed. The comparison reads actual closed SQLite metadata separately.

The fixture asks for an invalid limit and for a different valid policy under
the same Settings identities. It requires the accepted metadata and active
tuple to remain unchanged in both cases after reopen. A separate temporary
namespace deliberately keeps the correct stored context but changes just its
limits BLOB. The original readback and enable each refuse it without rewriting
the observed rows. This tests **pre-write refusal**, not in-transaction rollback,
restricted-owner permits, Node/M05 full hosted qualification or native ownership.

## Reuse the original build recipe

Start from a clean exact checkout. Use a new disposable Cargo target, the
canonical pinned Rust/Cargo, and locked registry inputs. Provide enough disk
for the original Node library (reserve about 1 GiB for this focused build).
This is not the larger original Node/M05 full-oracle target or its disk gate.
The original compiler-loader rule derives only `<rustc-sysroot>/lib` **after**
rejecting external loader or tool overrides; the original SQLite witness must
actually qualify. No fallback is admitted.

From the checkout, with absolute paths for `rustc`, `cargo`, `target` and
your fresh capture files, and after applying the original
[override rejection and loader rule](../../platform/mempool_node/rust_oracle.py):

~~~sh
sysroot=$("$rustc" --print sysroot)
env RUSTC="$rustc" LD_LIBRARY_PATH="$sysroot/lib" \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_INCREMENTAL=false \
  "$cargo" build --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib --target-dir "$target" --message-format=json \
  >"$cargo_messages" 2>"$cargo_stderr"
~~~

Retain the exact head, actual Cargo message digest, and actual Node rlib
digest from that build. Set the normal pinned HIA toolchain environment; run
the observer outside the inner Cargo loader override:

~~~sh
python3 -B hia/tools/qualify_m05_held_policy.py observe \
  --expect-source "$exact_head" --cargo-target "$target" --rustc "$rustc" \
  --cargo-messages "$cargo_messages" --cargo-messages-sha256 "$messages_sha256" \
  --node-library-sha256 "$original_rlib_sha256" --output "$new_receipt_directory"

python3 -B hia/tools/qualify_m05_held_policy.py readback \
  --expect-source "$exact_head" --input "$new_receipt_directory" --sha256 "$receipt_sha256"
~~~

The observer links only a test adapter to the admitted original library.
It records identities for the build, test bridge, and both native artifacts;
database files, the bridge and the full library are not copied into the compact
receipt. Readback repeats the byte comparisons and checks the archived Cargo
and SQLite witness bytes from the caller-pinned receipt digest. It verifies a
retained local observation, not a new run or an independently attested build.

By default both commands bind the original build to the observation checkout.
An explicitly reused build must pass `--original-build-source <full-build-commit>`
to both commands. The receipt distinguishes that earlier build commit from
the observation commit and checks ancestry, the complete Rust tree, lock and
Rust pin. Those checks are not an equivalence proof for inputs outside the
Rust tree. Before reusing a build, independently check and retain the exact
external include graph, build environment and artifact digests across both
commits; otherwise rebuild from the observation commit.
