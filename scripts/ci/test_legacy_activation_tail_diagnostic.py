#!/usr/bin/env python3
"""Exact H5DF native control erasure and local mutation negatives.

This is a diagnostic source control, not a qualification or corpus pin repair.
Only explicitly listed observer additions/private argument plumbing are erased.
All original bytes (including SQL, progress/Host calls, cleanup and deadlines)
must then reproduce the reviewed source. Update only after independent review.
"""
import hashlib
import io
from pathlib import Path
import re
import tokenize
import unittest

ROOT = Path(__file__).resolve().parents[2]
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"
CANCEL = "trillionnium/crates/trnm-pon-node/src/store/reorg_cancellation.rs"
LEGACY_TESTS = "trillionnium/crates/trnm-pon-node/src/store/legacy_reorg_observation_tests.rs"
BASE = {
    LEGACY_TESTS: "72f5be79c3c3621152c094daa7c5ebd355dd5775805ffe58919d07521ec22acf",
    STORE: "5918270368c61b420d26910dc5934714e1423f71c686b2d01f8d2e3ccceb990c",
    CANCEL: "17fdbd32d06c4c4613267fc1ca236945cd34329a6796dfdf50f8b0c255fc8eeb",
}

# Shared wording deliberately limits what a repinned map can establish. This is
# a bounded comment contract, not a general natural-language provenance proof.
PROVENANCE_READERS = (
    "scripts/ci/pq_authority_effect_register.py",
    "formal/pon-nakamoto-v1/joint_consensus_qualification.py",
    "scripts/ci/hash_use_contract.py",
    "scripts/w1_lifetime_current_observation.py",
)
PROVENANCE_SCOPE = (
    "Historical revision anchors retain review lineage, not current source identity.",
    "The reviewed map binds current candidate bytes, including uncommitted changes.",
    "It does not establish exact git-show identity at an anchor or a candidate commit.",
    "Source consistency does not authenticate provenance or grant qualification.",
)
STALE_EXACT_REVISION_CLAIMS = (
    "Generated from git show at the exact revision",
    "after comparing all 23 source files to the named Git commit",
    "This literal binds that new reviewed map",
)


def source_provenance_scope(text):
    comments = [token.string.removeprefix("#").strip()
                for token in tokenize.generate_tokens(io.StringIO(text).readline)
                if token.type == tokenize.COMMENT]
    normalized = " ".join(" ".join(comments).split()).casefold()
    return (all(comments.count(line) == 1 for line in PROVENANCE_SCOPE)
            and not any(claim.casefold() in normalized
                        for claim in STALE_EXACT_REVISION_CLAIMS))


def original(path, text):
    if path == LEGACY_TESTS:
        text = text.replace("pub(super) fn fork_pair(", "fn fork_pair(")
        text = text.replace("pub(super) fn lifecycle(", "fn lifecycle(")
    text = text.replace("        tail_origin: Option<&native_authenticated::LegacyTailOrigin>,\n", "")
    text = text.replace("self.resume_intent_with_progress(hook, progress, tail_origin)",
                        "self.resume_intent_with_progress(hook, progress)")
    if path == STORE:
        text = text.replace("#[cfg(test)]\nmod legacy_activation_tail_tests;\n", "")
        text = text.replace("""        let tail_origin = self
            .native_legacy_reorg_observation_enabled()
            .then(|| self.authenticated_arithmetic.history.legacy_tail_origin())
            .flatten();
""", "")
        text = text.replace("self.resume_owned_reorg(&mut hook, progress, termination_cpu, tail_origin.as_ref())?;",
                            "self.resume_owned_reorg(&mut hook, progress, termination_cpu)?;")
        text = text.replace("self.resume_intent_with_progress(&mut hook, progress, tail_origin.as_ref())",
                            "self.resume_intent_with_progress(&mut hook, progress)")
        text = text.replace("self.resume_intent_with_progress(hook, &mut || Ok(()), None)",
                            "self.resume_intent_with_progress(hook, &mut || Ok(()))")
        text = text.replace("        let mut tail = tail_origin.map(native_authenticated::LegacyTailOrigin::begin);\n", "")
        text = re.sub(r"(?m)^ +native_authenticated::LegacyTailObservation::advance\(\n +&mut tail,\n +native_authenticated::LegacyTailPhase::[A-Za-z]+,\n +\);\n", "", text)
        text = text.replace("        native_authenticated::LegacyTailObservation::complete(&mut tail);\n", "")
    return hashlib.sha256(text.encode()).hexdigest() == BASE[path]


class NativeControlErasure(unittest.TestCase):
    def test_only_observer_plumbing_is_added_to_native_control(self):
        for path in BASE:
            self.assertTrue(original(path, (ROOT / path).read_text()), path)

    def test_original_legacy_assertion_weakening_is_rejected(self):
        text = (ROOT / LEGACY_TESTS).read_text().replace("assert_eq!(", "ignored_assert!(", 1)
        self.assertFalse(original(LEGACY_TESTS, text))

    def test_removed_progress_is_rejected(self):
        text = (ROOT / STORE).read_text().replace("        progress()?;", "", 1)
        self.assertFalse(original(STORE, text))

    def test_changed_sql_is_rejected(self):
        text = (ROOT / STORE).read_text().replace(
            "SELECT ordinal,kind,block FROM steps ORDER BY ordinal",
            "SELECT ordinal,kind,block FROM steps", 1)
        self.assertFalse(original(STORE, text))

    def test_cancellation_cleanup_bypass_is_rejected(self):
        text = (ROOT / CANCEL).read_text().replace(
            "self.finish_or_cancel_reorg(&reservation, outcome, hook)", "outcome", 1)
        self.assertFalse(original(CANCEL, text))

    def test_changed_native_check_order_is_rejected(self):
        text = (ROOT / STORE).read_text().replace(
            "self.continuous_activation_gate(target)?;\n        self.mining_activation_gate(target)?;",
            "self.mining_activation_gate(target)?;\n        self.continuous_activation_gate(target)?;", 1)
        self.assertFalse(original(STORE, text))


class CurrentSourceProvenance(unittest.TestCase):
    def test_current_maps_distinguish_historical_anchor_and_candidate_bytes(self):
        for path in PROVENANCE_READERS:
            with self.subTest(path=path):
                self.assertTrue(source_provenance_scope((ROOT / path).read_text()))

    def test_missing_or_changed_scope_is_refused(self):
        for path in PROVENANCE_READERS:
            text = (ROOT / path).read_text()
            for line in PROVENANCE_SCOPE:
                with self.subTest(path=path, line=line):
                    self.assertFalse(source_provenance_scope(text.replace("# " + line, "")))
                    self.assertFalse(source_provenance_scope(text.replace(
                        "# " + line, "# The current map is exact git-show content at the anchor.")))

    def test_stale_claim_cannot_coexist_with_the_scope_disclaimer(self):
        for path in PROVENANCE_READERS:
            text = (ROOT / path).read_text()
            for claim in STALE_EXACT_REVISION_CLAIMS:
                with self.subTest(path=path, claim=claim):
                    self.assertFalse(source_provenance_scope(text + "\n# " + claim + "\n"))


if __name__ == "__main__":
    unittest.main()
