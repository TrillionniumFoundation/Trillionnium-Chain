"""Exact held recursive SQLite fold to declared-length cutoff, with no Node or packets."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import unittest

from hia.tests.history_page_fold_original import ORIGINAL, PREFIX, RUST_ROOT, extract, original
from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
WITNESS = Path(__file__).with_name("rust_history_page_handoff_reference.rs")
OUT = b"\xb9"
ARENA = b"\x71"


def sha(raw):
    return sha256(raw).hexdigest()


def handoff_sources():
    sources, pins = extract()
    history = (RUST_ROOT / (PREFIX + "store/history_page.rs")).read_bytes()
    if sha(history) != pins["original"]["hashes"][PREFIX + "store/history_page.rs"]:
        raise ValueError("Wrong frozen history source for the exact traversal")
    tail = history[history.index(b"    fn history_with_decoders("):]
    section, = re.findall(rb"^        let mut window = VecDeque::with_capacity\(limit\);\n.*?^        Ok\(packets\)\n", tail, re.MULTILINE | re.DOTALL)
    assert section.count(b"self.history_page_ancestors(") == 1
    assert section.count(b"for id in window.into_iter().rev()") == 1
    witness = WITNESS.read_bytes()
    marker = b"        // EXACT_ORIGINAL_TRAVERSAL_AND_SELECTION\n"
    assert witness.count(marker) == 1
    base = sources["main.rs"]
    assert base.count(b"\nfn main() {\n") == 1
    base = base[:base.index(b"\nfn main() {\n")]
    old_id, = re.findall(rb"^fn id\(n:u64\)->Hash \{.*?^}\n", base, re.MULTILINE | re.DOTALL)
    base = base.replace(old_id, b"fn id(n:u64)->Hash { held_id(n) }\n")
    return {**sources, "main.rs": base + b"\n" + witness.replace(marker, section)}, {
        **pins, "handoff_witness": sha(witness), "original_traversal_and_selection": sha(section),
    }


def observations(raw):
    at = 0

    def read(n):
        nonlocal at
        assert 0 <= n <= len(raw) - at
        start = at
        at += n
        return raw[start:at]

    def words(n):
        return struct.unpack(f"<{n}Q", read(8 * n))

    while at < len(raw):
        name_len, batches, entries, result_len, visited, num_cues, status = words(7)
        assert 0 <= batches <= 2 and entries == 65
        assert 0 <= visited <= 16 and 0 <= num_cues <= 2
        tip, after = read(32), read(32)
        name = read(name_len).decode("ascii")
        lengths = {read(32): words(1)[0] for _ in range(entries)}
        assert len(lengths) == entries
        frames = []
        for _ in range(batches):
            size, expected = words(2)
            frames.append((read(size), read(expected)))
        yield name, tip, after, lengths, frames, status, read(result_len), [read(32) for _ in range(visited)], words(num_cues)
    assert at == len(raw)


def header_result(raw):
    assert len(raw) >= 16 and (len(raw) - 16) % 32 == 0
    chosen, total = struct.unpack_from("<2Q", raw)
    assert chosen == (len(raw) - 16) // 32
    return chosen, total


class HistoryPageHandoff(unittest.TestCase):
    def test_exact_recursive_select_continuation_to_original_final_cutoff(self):
        with tempfile.TemporaryDirectory(prefix="trnm-held-history-handoff-") as tmp:
            raw, pins = original(Path(tmp), source_factory=handoff_sources)
        obs = list(observations(raw))
        self.assertEqual([row[0] for row in obs], [
            "maximum-window", "exact-byte-limit", "plus-one",
            "first-over-limit", "second-fold-refusal", "empty-no-select",
        ])
        first_batches = {False: set(), True: set()}
        first_outputs = set()
        root = ROOT / "hia/src/node"
        receipt = {}
        for backend in ("direct", "selfhost"):
            with NativeModule(root / "history_page_fold.hepta", backend=backend, byte_exports=("f0",)) as fold, \
                 NativeModule(root / "history_page_cutoff.hepta", backend=backend, byte_exports=("f0",)) as cutoff:
                recorded = []
                for ordinal, (name, tip, after, lengths, frames, original_status, expected, visits, cues) in enumerate(obs):
                    with self.subTest(backend=backend, case=name):
                        cursor, window, combined_links, selects = tip, b"", 0, 0
                        input_hashes, output_hashes = [], []
                        refused = False
                        for i, (capture, original_report) in enumerate(frames):
                            self.assertEqual(capture[:8], b"HPF00001")
                            rows, limit, captured_seed = struct.unpack_from("<3Q", capture, 8)
                            self.assertEqual((rows, limit), ((64, 1)[i], 16))
                            # Use the actual native cursor and deque for the next ABI call.
                            # Bind them to the start and seed of this inert *captured frame*
                            # before consuming its rows. No host selection/reordering.
                            self.assertEqual((capture[32:64], capture[64:96]), (cursor, after))
                            row_at = 128 + captured_seed * 32
                            self.assertEqual(capture[128:row_at], window)
                            frame = (capture[:24] + struct.pack("<Q", len(window) // 32)
                                     + cursor + capture[64:128] + window + capture[row_at:])
                            self.assertEqual(frame, capture)
                            if i == 0:
                                first_batches[original_status != 0].add(sha(frame))
                            input_hashes.append(sha(frame))
                            got = fold.call("f0", [frame, OUT * 584, ARENA * 519]).require_returned()
                            self.assertEqual((got.abi_status, got.arguments[0], got.arguments[2][512:]), (0, frame, ARENA * 7))
                            selects += 1
                            if not original_report:
                                self.assertEqual((i, got.value, original_status, got.arguments[1]), (1, 41, 41, OUT * 584))
                                refused = True
                                break
                            self.assertEqual((got.value, got.arguments[1]), (0, original_report))
                            output_hashes.append(sha(got.arguments[1]))
                            combined_links += struct.unpack_from("<Q", got.arguments[1])[0]
                            cursor = got.arguments[1][8:40]
                            self.assertEqual(struct.unpack_from("<4Q", got.arguments[1], 40), (16, 1, rows, 16))
                            window = got.arguments[1][72:584]
                            if not i:
                                first_outputs.add(sha(got.arguments[1]))
                                self.assertNotEqual(cursor, after)
                                self.assertEqual(combined_links, 64)
                        if refused:
                            self.assertEqual((expected, visits, cues, combined_links, selects), (b"", [], (0,), 64, 2))
                            recorded.append(dict(case=name, status=41, fold_input=input_hashes,
                                                 fold_output=output_hashes, cutoff_called=False))
                            continue
                        self.assertEqual((original_status, cursor), (0, after))
                        self.assertEqual((combined_links, selects, cues), (0, 0, (0,)) if not frames else (65, 2, (0, 65)))
                        retained = [window[j:j+32] for j in range(0, len(window), 32)]
                        self.assertEqual(len(set(retained)), len(retained))
                        self.assertEqual(visits, list(reversed(retained))[:len(visits)])
                        cutoff_frame = (b"HPCB0001" + struct.pack("<Q", len(retained))
                                        + b"".join(key + struct.pack("<Q", lengths[key]) for key in retained))
                        got = cutoff.call("f0", [cutoff_frame, OUT * 535, ARENA * 17]).require_returned()
                        self.assertEqual((got.abi_status, got.value, got.arguments), (
                            0, 0, [cutoff_frame, expected + OUT * (535 - len(expected)), ARENA * 17],
                        ))
                        self.assertEqual(header_result(expected), (
                            (16, 792264), (2, 800000), (1, 400000),
                            (1, 1048576), (0, 0), (0, 0),
                        )[ordinal])
                        if name in {"exact-byte-limit", "plus-one", "first-over-limit"}:
                            self.assertEqual(len(visits), header_result(expected)[0] + 1)
                        if name == "maximum-window":
                            too_short = cutoff.call("f0", [cutoff_frame, OUT * 527, ARENA * 17]).require_returned()
                            self.assertEqual((too_short.abi_status, too_short.value, too_short.arguments),
                                             (0, 102, [cutoff_frame, OUT * 527, ARENA * 17]))
                        recorded.append(dict(case=name, status=0, fold_input=input_hashes, fold_output=output_hashes,
                                             cutoff_called=True, cutoff_input=sha(cutoff_frame), cutoff_output=sha(expected),
                                             selected_count=header_result(expected)[0], selected_declared_bytes=header_result(expected)[1],
                                             read_cues=cues))
                receipt[backend] = dict(fold=fold.artifact_sha256, cutoff=cutoff.artifact_sha256, cases=recorded)
        # The refusal fixture's first batch already observes the optional parent
        # field of block 1. That raw projection differs, but its successful
        # first fold must emit the same cursor/window and never reject early.
        self.assertEqual({kind: len(batch) for kind, batch in first_batches.items()}, {False: 1, True: 1})
        self.assertFalse(first_batches[False] & first_batches[True])
        self.assertEqual(len(first_outputs), 1)
        self.assertNotEqual(receipt["direct"]["fold"], receipt["selfhost"]["fold"])
        self.assertNotEqual(receipt["direct"]["cutoff"], receipt["selfhost"]["cutoff"])
        self.assertEqual(receipt["direct"]["cases"], receipt["selfhost"]["cases"])
        if proof := os.environ.get("HIA_HISTORY_HELD_HANDOFF_PROOF"):
            proof_path = Path(proof)
            proof_path.with_suffix(".raw").write_bytes(raw)
            paths = [Path(__file__), WITNESS, root / "history_page_fold.hepta", root / "history_page_cutoff.hepta"]
            proof_path.write_text(json.dumps(dict(frozen_tree=ORIGINAL, pins=pins, raw_sha=sha(raw), raw_bytes=len(raw),
                sources={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in paths},
                stock=receipt), indent=2, sort_keys=True) + "\n")
