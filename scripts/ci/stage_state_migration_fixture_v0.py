#!/usr/bin/env python3
"""Repair previously uncompiled or non-canonical migration helpers."""

from pathlib import Path

path = Path("trillionnium/crates/trnm-migration-v0/src/lib.rs")
text = path.read_text()

old_fixture = """    fn row(key: u8) -> ExportRowV0 {
        let namespace = b\"accounts\".to_vec();
        let key = vec![key];
        let value = vec![key, key];
"""
new_fixture = """    fn row(byte: u8) -> ExportRowV0 {
        let namespace = b\"accounts\".to_vec();
        let key = vec![byte];
        let value = vec![byte, byte];
"""
if old_fixture not in text:
    raise SystemExit("migration row fixture anchor changed")
text = text.replace(old_fixture, new_fixture, 1)

old_capacity = "let mut next = Vec::with_capacity((level.len() + 1) / 2);"
new_capacity = "let mut next = Vec::with_capacity(level.len().div_ceil(2));"
if old_capacity not in text:
    raise SystemExit("migration Merkle capacity anchor changed")
text = text.replace(old_capacity, new_capacity, 1)

path.write_text(text)
