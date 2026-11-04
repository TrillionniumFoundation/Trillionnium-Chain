# Original DA diagnostic log readback

This is a push-only, read-only investigation of immutable artifact 13295132077 from failed diagnostic run 41771237697 / job 126381158783, source e5adb2df25db655800f9e52806e91b427d734490. The original native module reported 174 passed and three exact sequence observations returned zero, while its new wrapper rejected the module's successful-name set. The failed original receipt is preserved without reinterpretation.

The reader authenticates GitHub API metadata and source, fetches one 61,541-byte ZIP using an uncredentialed redirect request, verifies its SHA256 and the five selected members' CRCs, binds the source receipts and exact log hashes, and compares registry names with successful libtest lines. It does not extract or execute archive members and performs no native rerun. Output is bounded structured metadata and ASCII libtest identifiers; raw test text, endpoints and signed URLs are not printed.

Limits: 128 KiB compressed download allowance, 4 MiB declared archive total and returned decoded byte caps, 1 MiB per selected member, 64 members, 128 KiB serialized output, 512 MiB address-space cap. The member count is checked after ZIP central-directory parsing. These are not RSS or codec internal-buffer limits. The original immutable archive remains the authoritative failed diagnostic, not an original whole-workspace DA acceptance result.

Reproduce using the exact source in the push-only workflow: `python3 qualification/da-sequence-log-readback-20261104/readback.py --out "$RUNNER_TEMP/da-log-readback"`. The environment is restricted to the declared repository/branch; contents/actions tokens are read-only. Original `verify_ci_source.py` and `scripts/project-preflight.sh --audit` execute on the hosted reader before it runs.

No local Python, Cargo, native or Host execution was available before publication. Native, original-baseline, Host, performance and production qualification remain false.

The v2 readback retained a real MEMBER_BYTE_LIMIT failure before any result was emitted. The successor keeps the original caps and decodes only the five explicitly named logs. Other members are inventoried by hashed name and declared byte size; their CRC and decoded SHA256 are explicitly unverified. No full archive decoded-content claim is made. Original raw failed diagnostic and both earlier failed reader runs remain durable.
