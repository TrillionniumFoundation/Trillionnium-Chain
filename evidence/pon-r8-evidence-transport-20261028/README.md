# Exact imported evidence transport

The final combined candidate at `e3afbbf4703946fb15c1e216c9173efcbf6dc8ea`
failed `git diff --check` with exit 2 because five imported raw records contain
significant unified-diff context or compiler whitespace. The complete failed
stdout and stderr are retained in [the archive](original-records.zip).

The same archive retains all five records at their original repository-relative
paths, byte for byte. [The transport manifest](transport.json) binds every
member's original byte count and SHA-256, and the archive itself. Every member
was read back and compared before its redundant loose copy was removed.

The original evidence hash manifests and historical Markdown-target readbacks
are retained unchanged. Their old paths identify archive members now; they are
historical observations, not claims that those loose files still exist. The four
current README links point to this archive. No source code, log bytes, failure
denominator, whitespace rule or acceptance gate was edited to make this pass.
