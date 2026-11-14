# R1 two-phase execution-payload scope: static review of V1

## Decision

The set construction and two-phase plan are sound when their checks run. **Do not rely on V1's `assert not sys.flags.optimize` to reject optimized Python.** That assertion itself is removed under `-O` or `PYTHONOPTIMIZE`; the same applies to the wrapper's hash, preserved-row and union assertions. Use an ordinary non-assert refusal before relying on those checks, and bind the actual wrapper through the planned pinned launcher compiled with `optimize=0`.

This is a static inference, not an executed counterexample. The original scanner remains unchanged and its own `require` checks are not assert-based.

## Exact inputs

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| prepare_scope_and_scan.py | 3,788 | bd6531cd52adcc65bb301b35a1480a936046b839298eb0424ccc2275709630e6 |
| PLAN.txt | 711 | c0e55abf3e92c68ccdb63b2407462a4b21086e5e1d96981c5b6123d625210ebe |
| scan_frozen_execution_payload_v2.py | 14,664 | 14305dfe4b3edaecb601dffed336a13c916fe6a9182a9547770f0637031b50b6 |

## Scope and type review

With assertions enabled, the wrapper requires the baseline to be a subset of full and compares every preserved row, including origin. The residual `new` contains exactly the full paths absent from old. The underlying validator already requires actual integers for row bytes and aggregate counts, exact row fields, SHA/path syntax, duplicate-key/path rejection and no file/directory prefix collision. Consequently Python's `True == 1` row-equality shortcut is not available through those validated rows.

The new outer pin envelope is less strict: it uses ordinary JSON parsing, lacks explicit integer type checks for pin bytes, and does not reject duplicate/nonfinite outer JSON itself. This does not remove the pinned-manifest SHA or delegated inner validation. Root's planned V2 can close this narrow envelope gap without changing the scanner.

The saved producer currently trusts `sys.argv[1]`. It should instead be the verified bytes of the executed wrapper. The scanner is pinned before module loading but later reopened by `execv`; the fixed scanner path must stay unchanged through actual execution. No race was observed.

## Final proof that is still required

The wrapper proves one residual set at a time. It does not by itself bind the first phase's P to the second phase's baseline, consume all three real scan receipts, or authorize publication. The independent final checker must bind those exact manifest hashes; prove old/A/B are disjoint and their complete rows equal F; and verify all three actual complete zero-hit scans, coverage rows, manifests, producer pins and process terminals.

The code's fixed output directories lie outside the payload. Keeping the last scan receipt and final verifier report outside F avoids a circular self-scan declaration. Those excluded records cannot be advertised as already scanned through F.

This review did not execute the wrapper, import the scanner, call its helpers, perform a scan or run tests. It made no source, Git, stage or network changes. Raw-byte pattern coverage does not establish all-secrets absence and does not decompress ZIPs or packs.
