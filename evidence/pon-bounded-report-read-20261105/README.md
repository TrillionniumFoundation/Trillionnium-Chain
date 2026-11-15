# Descriptor-bound native campaign report reads

The campaign phase reader previously checked a pathname's size and type, then performed an unbounded `Path.read_bytes()`. A report could grow after the check or its pathname could be replaced by a FIFO before the read. The post-read digest and length checks did not bound acquisition or prevent blocking.

The reader now opens once with `O_NOFOLLOW | O_NONBLOCK`, checks the opened descriptor is a regular file within the original 256 MiB limit, and reads it directly with `os.read` in at most 64 KiB chunks, retaining at most the original limit and probing one overflow byte. A `finally` closes the descriptor on success and every check/read failure. The same raw-byte SHA256, duplicate-key/nonfinite JSON rejection, source/policy requirements and business observations remain unchanged.

## Validation and scope

Exact base: `84179f7b0f74bdc0152f904ffbf0b11709eec036`. Local final source: `aceafd9cce6471bc52c7647f1529cc3c900b2811`, tree `7f3ebaa4066eda20fab5f1d11e459b08361143b8`. The source patch in the archive reconstructs this tree; publication adds only this evidence.

56 reader tests pass, including original valid complete reports, exact digest mismatch, empty/exact/over-limit inputs, short reads, post-stat file growth, pathname replacement after opening, and symlink/directory/FIFO refusal. The growth test observes a single 9-byte direct read and an actual descriptor offset of 9 under an 8-byte test cap. Rejection tests verify descriptors are closed. Seven policy reader tests, 37 source controls, 100 CI controls, all 522 source pins, unchanged generated inventory, strict all-target/all-feature workspace Clippy and formatting pass.

Independent review caught two problems in the first unpublished implementation: buffered `fdopen` prefetched beyond the request, and directory rejection before entering the context manager leaked the descriptor. Both were fixed before publication using direct descriptor operations; independent re-review passed the 55-test suite, followed by the final 56-test suite including short-read/offset checks. These earlier problems are retained here rather than hidden.

No Rust source, native admission, CPU budget, packet limit or four-second/16-hostile-W1 criterion changes. Native runtime suites were not rerun for this Python-only change. Bounded byte acquisition is not a total JSON-memory/RSS limit, a coherent filesystem snapshot, execution attestation or original business-gate qualification. The explicit digest remains responsible for the exact read bytes. Parent-directory symlink policy is unchanged.

Reproduce: `python3 scripts/ci/test_pon_public_v3_phase_read.py` and `python3 scripts/ci/test_pon_public_v3_policy_read.py`. [Raw validation and source patch](raw-validation.zip); [identities and hashes](verification.json).
