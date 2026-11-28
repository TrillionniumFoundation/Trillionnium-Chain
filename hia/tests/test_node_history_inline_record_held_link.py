"""Same still-live SQLite row, actual original conversion, linked stock HIR1."""
from collections import Counter
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.history_inline_record_original import original


class NodeHistoryInlineRecordHeldLinkTests(unittest.TestCase):
    def test_actual_static_selfhost_call_before_same_statement_advances(self):
        with tempfile.TemporaryDirectory(prefix="trnm-history-held-link-") as tmp:
            raw = original(Path(tmp), held_link=True)
        at = 0
        counts = Counter()
        while at < len(raw):
            input_n, status, n = struct.unpack_from("<III", raw, at)
            at += 12
            sent, observed = raw[at:at+input_n], raw[at+input_n:at+input_n+n]
            at += input_n+n
            self.assertEqual(len(sent),input_n)
            self.assertTrue(sent.startswith(b"HIR1\0\0\0\0"))
            self.assertEqual(len(observed),144 if status==0 else 0)
            counts[status] += 1
        self.assertEqual(at,len(raw))
        self.assertEqual(counts,{0:3,10:3,11:4,12:4,13:4,14:2,30:9,31:5})
