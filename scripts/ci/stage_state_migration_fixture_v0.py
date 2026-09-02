#!/usr/bin/env python3
"""Repair the previously uncompiled migration row fixture."""

from pathlib import Path

path = Path("trillionnium/crates/trnm-migration-v0/src/lib.rs")
text = path.read_text()
old = """    fn row(key: u8) -> ExportRowV0 {
        let namespace = b\"accounts\".to_vec();
        let key = vec![key];
        let value = vec![key, key];
"""
new = """    fn row(byte: u8) -> ExportRowV0 {
        let namespace = b\"accounts\".to_vec();
        let key = vec![byte];
        let value = vec![byte, byte];
"""
if old not in text:
    raise SystemExit("migration row fixture anchor changed")
path.write_text(text.replace(old, new, 1))
