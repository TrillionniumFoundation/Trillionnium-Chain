# Exact committed-source local gate

The complete local repository check passed on commit `b66e66d2465258d808c0f56ff851123306d4bdb4`, tree `11eee4a56ccab63394102a19204ab3922021d87c`. The repository was clean before and after the checks. All evidence in this directory was written outside the repository; no repository files were changed.

## Repository gate

`bash scripts/project-preflight.sh` returned PASS and exit 0. `python3 scripts/ci/check_repository.py` then returned PASS and exit 0 in 41.423 seconds. The command inspected the full local repository tree according to its existing exclusions. The observed HEAD/tree did not change, and all CI Python source hashes matched at the two endpoints.

- [Summary](attempt-01/summary.json)
- [Raw stdout](attempt-01/check-repository.stdout.log)
- [Raw stderr](attempt-01/check-repository.stderr.log)
- [Arguments, return code, elapsed time and log hashes](attempt-01/check-repository.command.json)
- [State and CI source hashes before](attempt-01/state-before.json)
- [State and CI source hashes after](attempt-01/state-after.json)
- [Preflight stdout](attempt-01/preflight.stdout.log), [stderr](attempt-01/preflight.stderr.log), and [command record](attempt-01/preflight.command.json)

## Tracked Markdown target audit

A separate read-only audit examined 565 physical Markdown files and 3,868 local link occurrences. All 3,857 file targets belonged to Git's tracked set; the 11 directory targets each had at least one tracked descendant. There were zero missing, escaping, or untracked targets, and all 565 Markdown source files were tracked. HEAD/tree/status and every Markdown SHA matched before and after the audit.

The syntax scope matches the existing repository check's inline-link syntax after fenced-code removal and additionally checks reference definitions. No reference definitions with local targets were present. This does not claim to be a general CommonMark parser, HTML link validator, or fragment-anchor validator. Directory links are classified separately because Git tracks files rather than directories.

- [Audit summary](markdown-tracked-attempt-01/summary.json)
- [Complete local link mapping](markdown-tracked-attempt-01/local-link-targets.json)
- [Failures: empty](markdown-tracked-attempt-01/failures.json)
- [Audit command record](markdown-tracked-attempt-01/command.json)
- [Audit implementation](audit_markdown_tracked_targets.py)
- [State before](markdown-tracked-attempt-01/state-before.json) and [after](markdown-tracked-attempt-01/state-after.json)
- [Markdown SHA before](markdown-tracked-attempt-01/markdown-sha256-before.json) and [after](markdown-tracked-attempt-01/markdown-sha256-after.json)

These results establish the reported local source checks and tracked-target membership. They do not promote any runtime, work-security, physical execution, or production qualification.
