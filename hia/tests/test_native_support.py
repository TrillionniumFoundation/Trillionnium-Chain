"""Prelinked fixture workers retain the standard private buffer boundaries."""
import base64
import json
import subprocess
import unittest
from unittest.mock import patch

from hia.platform.release_pq_shadow.build import ENTRY, LinkedShadow
from hia.tests.native_support import MAX_EXTENT, NativeModule


class PrelinkedNativeExtentTests(unittest.TestCase):
    def test_linked_shadow_and_prelinked_context_inherit_default_extent(self):
        self.assertEqual(MAX_EXTENT, 1 << 20)
        # Neither prelinked path calls NativeModule.__init__.
        for owner, entry in ((LinkedShadow, ENTRY), (NativeModule, "f0")):
            shim = NativeModule.__new__(owner)
            shim.exports = frozenset((entry,))
            shim.byte_exports = (entry,)
            shim.functions = {entry: {"params": [{"type": "readbuf"}, {"type": "mutbuf"}],
                                      "returns": ["u32"]}}
            shim.library = "unused.so"
            shim.artifact_sha256 = "0" * 64

            with self.subTest(owner=owner.__name__):
                with patch("hia.tests.native_support.subprocess.run",
                           side_effect=subprocess.TimeoutExpired("fixture worker", 1)) as worker:
                    for lengths in ((MAX_EXTENT + 1, 1), (1, MAX_EXTENT + 1)):
                        with self.assertRaisesRegex(ValueError, "within the fixture extent"):
                            shim.call(entry, [bytes(n) for n in lengths], timeout=1)
                    worker.assert_not_called()

                    result = shim.call(entry, [bytes(MAX_EXTENT), bytes(MAX_EXTENT)], timeout=1)
                    self.assertEqual(result.status, "timeout")
                    worker.assert_called_once()
                    request = json.loads(worker.call_args.kwargs["input"])
                    [case] = request["cases"]
                    self.assertEqual(case["function"], entry)
                    self.assertEqual([x["type"] for x in case["arguments"]], ["readbuf", "mutbuf"])
                    self.assertEqual([len(base64.b64decode(x["bytes"], validate=True))
                                      for x in case["arguments"]], [MAX_EXTENT, MAX_EXTENT])
