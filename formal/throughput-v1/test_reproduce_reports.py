#!/usr/bin/env python3
"""Regression controls for the reproducer's outside-source output boundary."""
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import reproduce_reports as reader


class OutputBoundaryTests(unittest.TestCase):
    def test_parent_traversal_cannot_enter_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo, outside = root / "repo", root / "outside"
            repo.mkdir(); outside.mkdir()
            output = outside / ".." / "repo" / "result"
            with patch.object(reader, "ROOT", repo), patch("sys.argv", ["reader", "--output", str(output)]), \
                    patch.object(pathlib.Path, "mkdir", side_effect=AssertionError("source write reached")):
                with self.assertRaisesRegex(ValueError, "OUTPUT_MUST_BE_OUTSIDE_SOURCE"):
                    reader.main()

    def test_external_symlink_parent_cannot_enter_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo = root / "repo"; repo.mkdir()
            alias = root / "outside-link"; alias.symlink_to(repo, target_is_directory=True)
            with patch.object(reader, "ROOT", repo), patch("sys.argv", ["reader", "--output", str(alias / "result")]), \
                    patch.object(pathlib.Path, "mkdir", side_effect=AssertionError("source write reached")):
                with self.assertRaisesRegex(ValueError, "OUTPUT_MUST_BE_OUTSIDE_SOURCE"):
                    reader.main()

    def test_canonical_outside_path_reaches_create_only_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo = root / "repo"; repo.mkdir()
            outside = root / "outside"; outside.mkdir()
            target = outside / "unused" / ".." / "result"
            with patch.object(reader, "ROOT", repo), patch("sys.argv", ["reader", "--output", str(target)]), \
                    patch.object(pathlib.Path, "mkdir", autospec=True, side_effect=RuntimeError("outside boundary reached")) as mkdir:
                with self.assertRaisesRegex(RuntimeError, "outside boundary reached"):
                    reader.main()
                mkdir.assert_called_once_with((outside / "result").resolve(), parents=True, exist_ok=False)


if __name__ == "__main__":
    unittest.main()
