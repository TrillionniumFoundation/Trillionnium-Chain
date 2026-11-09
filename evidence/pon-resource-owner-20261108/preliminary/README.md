# Retained preparation observations

These records are preparation failures, not qualification passes. The partial
local editing snapshot was not an authoritative complete source checkout.
All three Cargo attempts exited 101 and ran no native tests. The second attempt
reached original opt-level 3 code generation and received SIGKILL; its cause
remains unconfirmed. Original loader warnings and missing-file diagnostics
remain in the logs. The metadata hashes the exact retained bytes and the exact
baseline fixture recovered between attempts.

The publisher record separately retains the Python 3.9 tomllib preflight
failure and the successful retry with an existing Python 3.14.3. It is not a
native-test or GitHub-publication receipt.

The first evidence-commit attempt passed preflight, inventory and staged
whitespace checks but Git refused the unset commit identity (exit 128).
No final-source test had started. Its original output is retained in
[commit-identity-preparation.json](commit-identity-preparation.json). The retry
uses the preceding implementation commit identity for this invocation;
no global Git identity is changed.
