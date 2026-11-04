# Final CI wiring — 58 declared workspace controls

[Final static validation](final-58-static-validation.json) and [the exact diff against b811](final-58-versus-b811.patch) describe the final active workflow wiring after the checked-prefix M06 candidate was placed on HOLD. The three stored workflow snapshots are the exact validated bytes, copied again after final pin maintenance; their source SHA values still matched.

- Workspace preserves all 56 original b811 selections, including its two Growth controls, and adds only the two direct-append controls: **58 declared selections**. Post-write readback remains 23. The removed publication-cost ignored branch is absent.
- PQ preserves the original 49 required controls, complete Node regression, strict Clippy, existing cost commands, budgets and failure retention. One additional explicit step runs the 13 pre-existing transaction-scope controls. The new known-write and M06 selectors are absent.
- Recent acceptance preserves b811's native authenticated 91 / post-write 23 execution and exact reader. Only the literal store.rs pin differs from b811, and all observed literal pins matched their current source.

The validation used duplicate-key-rejecting YAML parsing, `bash -n` on 44 run blocks, Python AST checks on seven embedded scripts, and strict text comparisons against b811. Removing only the added direct-append group from workspace, or only the added original-scope step from PQ, recovers the complete corresponding b811 file byte for byte. Recent recovers b811 after substituting only its store.rs pin. The 13 added scope names were also found in b811's actual separate test module.

**This is static wiring evidence.** No libtest registry or native control was executed by this validation, so 58 is a declared selection count, not 58 native passes. The final built ELF still requires its own source-bound registry and test evidence.

## Frozen snapshots

- [Workspace workflow](pon-original-workspace-large-state-cpu.yml.gz)
- [Recent workflow](pon-recent-batch-acceptance.yml.gz)
- [PQ workflow](pon-pq-system-continuation.yml.gz)
- [Copy verification](copy-verification.json)

The earlier provisional 63-selector state is preserved separately: [historical static report](historical-63-static-validation.json), [historical diff](historical-63-versus-b811.patch). It retained five tentative M06 selectors before the sole three-arm experiment produced HOLD; it is not the final active selection and does not assert native or performance qualification. The historical report was not overwritten or relabeled.

```bash
sha256sum --check SHA256SUMS
```
