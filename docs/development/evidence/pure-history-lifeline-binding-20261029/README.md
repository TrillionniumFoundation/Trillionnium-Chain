# Pure History build binding for independent lifecycle controls

The pure raw History workflow at commit `f8b79050282fe0561b9cae1a8253e735d7fb0f6c`
retained real compiler output and a native test ELF, but its independent lifecycle
runner stopped before any owner-death case. The build reader recognized the older
strict and N8 campaign schemas, not `pon-pure-history-raw-joint-ci-v1`.
Both hosted arms reported `recognized actual campaign source observation required`;
their lifecycle result had no binary and an empty case list. The original native
campaign failures remain failures.

This change accepts the new schema only with the exact pure work profile,
authenticated state backend, policy identifier, integer zero admission search
budget, and one of the two exact resource-profile/native-selector pairs. The
strict lifecycle result must remain explicitly separate. All original source,
compiler-artifact and ELF binding checks still execute. The reader returns only
the bound binary and build record; campaign failure is not promoted to lifecycle
success. The workflow adds the five new reader controls beside the original eight.

## Validation

- Before the change, both positive pure-profile fixtures failed with the same
  schema refusal as the actual hosted run. The original failure log is retained.
- After the change, all five new reader methods and all eight original lifecycle
  reader methods passed. These use synthetic build metadata and do not execute a
  native verifier.
- The actual N8 artifact `12893938279` was separately checked. The original reader
  rejected its build; the changed reader bound the eight retained build inputs and
  the 10,574,600-byte ELF with SHA-256
  `625fa3cd23132d3405e53b0e7feb4e61c79c2c488591665bc704a6659b41fe2b`.
  The failed campaign result was preserved. This readback did not execute the ELF
  or rerun any lifecycle case.
- All 34 original tracked-source integrity controls passed. The changed workflow's
  14 Bash blocks and three Python heredocs passed syntax checks. Project preflight
  and `git diff --check` passed.
- An independent reviewer read the complete build-binding function and diff and
  separately reran all five new methods successfully. Their review did not claim
  a second ZIP audit or native execution.

The real native lifecycle results require the new hosted workflow run. This change
does not change any CPU/memory/window/depletion/state-equality gate, campaign or
lifecycle timeout, native Rust code, or durable recovery behavior. The follow-up
uses source-pin repair commit `98873ccfbb4a416218c49df39082f0b3a842b5c8` as its remote
base; it leaves the failed earlier commit and run intact.

`validation.json`, the exact raw control log strings in `control-logs.json`, and
`actual-build-red-green.json` provide the bounded local evidence. The local staging
checkout is a selected source snapshot, not a claim to reproduce the complete
remote repository tree. Publication verifies the exact remote base and every
changed UTF-8 file, mode, size and Git blob.
