#!/usr/bin/env python3
"""Move composition truth assertions to compile time for pinned Clippy."""

from pathlib import Path

path = Path("trillionnium/crates/trnm-poco-node-production-v0/src/lib.rs")
text = path.read_text()
old = """        assert!(!PRODUCTION_COMPOSITION_OWNS_DOMAIN_STATE_V0);
        assert!(!PRODUCTION_COMPOSITION_ACTIVATION_V0);
"""
new = """        const {
            assert!(!PRODUCTION_COMPOSITION_OWNS_DOMAIN_STATE_V0);
            assert!(!PRODUCTION_COMPOSITION_ACTIVATION_V0);
        }
"""
if old not in text:
    raise SystemExit("composition constant assertion anchor changed")
path.write_text(text.replace(old, new, 1))
