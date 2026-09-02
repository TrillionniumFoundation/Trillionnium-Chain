#!/usr/bin/env python3
"""Remove the redundant must-use attribute rejected by pinned Clippy."""

from pathlib import Path

path = Path("trillionnium/crates/trnm-tx-lifecycle-v0/src/lib.rs")
text = path.read_text()
old = "    #[must_use]\n    pub fn record(&self, tx_id: TxIdV0) -> Result<&TxRecordV0, TxLifecycleErrorV0> {\n"
new = "    pub fn record(&self, tx_id: TxIdV0) -> Result<&TxRecordV0, TxLifecycleErrorV0> {\n"
if old not in text:
    raise SystemExit("tx record lint anchor changed")
path.write_text(text.replace(old, new, 1))
