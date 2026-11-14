# R1 payload scope V2: final static review

**No remaining scope blocker was found in the reviewed V2, under the stated SHA-pinned launcher.** This is a static result, not a scan or publication result.

V2 is 4,994 bytes, SHA256 `c9bf8f7d90440f36ec0608f0b714cc4a445b5745b8460cbbce0e47d61b0be012`. The exact V1-to-V2 diff is 4,761 bytes, SHA256 `a567693fbc473daaa041d6b5e94f5f1898de69e3ba26f164b85e37cce4aa43c4`. The underlying 14,664-byte scanner remains SHA256 `14305dfe4b3edaecb601dffed336a13c916fe6a9182a9547770f0637031b50b6`.

## Closed findings

- **V1 optimization guard:** closed. V2 uses ordinary `if sys.flags.optimize: raise RuntimeError` before assertions. The original V1 finding was source reasoning, not an observed runtime failure. V1 and its original review stay unchanged.
- **Outer input/pin types:** closed. V2 rejects duplicate/nonfinite JSON, requires exact dictionaries and phase string, actual bounded integer bytes, and lowerhex SHA. Inner manifest and row validation remains unchanged.
- **Producer identity:** closed with the declared launcher. V2 binds its fixed `__file__`, reads stable actual program bytes, compares the supplied original bytes, saves those bytes and rechecks identity. The actual launcher must pin this file and compile with `optimize=0`; it was not supplied for execution in this review.

The fixed P/F paths prevent selecting a different baseline location for the second phase. Every old row must still equal its full-manifest row, including origin. Residual manifests are exact unique-path set differences and are validated again. Output directories remain outside the payload; no new payload mutation or recursive self-scan claim was introduced.

## Remaining actual acceptance work

The wrapper proves one step at a time. Before publication, the independent checker must bind the identical P hash between phases, prove `old ⊎ A ⊎ B = F` using complete rows, and verify all three real complete zero-hit scans and authoritative terminals. A scope-prepared print or a proof boolean is insufficient.

The scanner's fixed pathname must remain pinned during execution. Its raw-byte-only scope and existing pattern definitions are unchanged. The last scan receipt and final checker output stay outside F; they cannot be described as already scanned by F.

This review executed no target code, helper, scanner, test or network request and changed no source, Git object/ref or stage file. It only saved this small independent review outside the payload.
