# Frozen execution-payload credential-pattern scanner

## Preparation status

This scanner is prepared and statically checked only. It has not scanned any payload, run its main function or helpers, or received a final scope manifest. Execute only after root supplies the explicit final manifest and its SHA-256. Current stage counts are not authorization to choose a scope.

The five pattern byte strings are extracted with ast.literal_eval from the unique top-level PATTERNS assignment in the exact prior driver, SHA-256 5c292f6554bbf1345d6e58a3c64cf9099230223fc9c70f217a575f6f20ee7368. The old driver is never executed or imported. Static review compares the new PATTERNS literal byte-for-byte, including insertion order; runtime re flags remain empty.

## Exact input and command

The manifest must have exactly payload_root, file_count, total_bytes and files. The existing optional schema field is accepted only when exactly trnm-frozen-execution-payload-manifest-v1. Each files item has exactly path, bytes, sha256 and origin; origin has exactly host (mac or rog) and the original absolute path. Origin paths are metadata, never opened.

payload_root must be a canonical direct child of /private/tmp/chain-consolidation-20261114-root named execution-receipts-*. Relative paths must be normalized, unique and non-overlapping; .git, dot/parent traversal, symlinks, nonregular files and hard links are refused. Duplicate actual payload file identities are refused. The tool reads only listed payload paths; it does not discover or add files.

After root provides the final pinned inputs, use the prepared scanner with an isolated Python invocation:

/opt/homebrew/bin/python3 -I -B /private/tmp/chain-execution-payload-credential-scanner-20261114-v1/scan_frozen_execution_payload_v2.py --manifest ABSOLUTE_FINAL_MANIFEST --manifest-sha256 EXACT_FINAL_SHA256 --evidence-dir /private/tmp/chain-execution-payload-credential-scanner-20261114-v1/run-FROZEN_SCOPE_NAME

The run directory must not exist. It is created only as a direct run-* child of this preparation directory. No source, Git, ROG, network or existing evidence mutation is performed. There is no recursive ZIP/pack/archive decompression, checkout discovery, history traversal or fsck.

## Bounds and validation

Maximum 10,000 declared files, 256 MiB per payload file, 512 MiB declared total and 16 MiB manifest. JSON duplicate keys, non-finite numbers, bool-as-count and unexpected fields are rejected. The pinned manifest is verified before payload scanning.

Parent directories and leaves are opened with no-follow file descriptors. Every payload is a regular single-link file; its exact declared byte length, full SHA-256 and stable FD metadata are verified before regex scanning. Regexes scan only those verified raw bytes in memory, including binary formats without decompression. Each file identity is checked after scanning and again at the end; the root identity and manifest bytes/identity are also checked again. No unlisted path is read to claim directory completeness.

## Outputs and interpretation

coverage.jsonl reports path, size and SHA-256 for each fully checked listed file. hits.jsonl reports only category, count, path, byte offsets, file size and SHA-256. It never emits matching bytes, context, decoded credentials or a snippet. Offsets are zero-based raw-byte positions. All five categories run on each file; findings are not automatically classified as examples, fixtures, safe markers or false positives.

summary.json includes the pinned manifest identity, bounded coverage, per-category counts and scope limitations. Exit 0 means NO_PATTERN_HITS_IN_DECLARED_SCOPE only; it is not a security PASS or proof of all secrets being absent. Any hit produces REVIEW_REQUIRED and exit 3. Invalid input, identity/hash drift or an execution error produces incomplete coverage and exit 2. If any hit was already observed, REVIEW_REQUIRED remains set even after a later failure; otherwise the status is FAILED. The counts in an incomplete report are partial. Partial outputs are retained; there is no cleanup-on-failure or automatic retry.

This review does not cover files absent from the supplied manifest, compressed contents, other credential types, encodings not matched by these exact regexes, data acquired after the frozen scope, or any repository/history object scan. Reports appended after a scan are outside that earlier scope until explicitly included in a later pinned manifest.

## Static revision note

The first prepared version is retained. V2 removes argparse help exits from the execution path and retains REVIEW_REQUIRED if a later file fails after a prior hit. Match counters update when each offset is observed. The five pattern bytes, input caps, filesystem fences and all scope limits are unchanged. Only AST parsing/compilation was performed; no scanner helper or scan was executed.
