"""Ordinary name classification for the research journals' actual SQL filters.

Only SELECT queries over supplied names run here: no journal, keys, triggers,
network operations or witness/custody execution is created.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sqlite3
import unittest


ROOT = Path(__file__).resolve().parent
NAMES = (
    ("sqlite_autoindex_used_1", False),
    ("sqlite_sequence", False),
    ("sqlite_stat1", False),
    ("sqlite_", False),
    ("used", True),
    ("pins", True),
    ("sqlite", True),
    ("sqliteXmetadata", True),
    ("SQLite_local", True),
)


def source_query(filename: str, prefix: str) -> str:
    tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
    matches = [node.value for node in ast.walk(tree)
               if isinstance(node, ast.Constant) and isinstance(node.value, str)
               and node.value.startswith(prefix)]
    if len(matches) != 1:
        raise AssertionError(f"expected one actual source query in {filename}")
    return matches[0]


class SQLiteSchemaNameTests(unittest.TestCase):
    def assert_classification(self, query: str, schema: str, columns: bool) -> None:
        # CTE rows shadow the read-only catalog name for this SELECT only.
        # They exercise the production predicate without creating schema objects.
        if columns:
            prefix = f"WITH {schema}(type,name,sql) AS (VALUES ('table',?,'ddl')) "
        else:
            prefix = f"WITH {schema}(name) AS (VALUES (?)) "
        with sqlite3.connect(":memory:") as connection:
            for name, visible in NAMES:
                with self.subTest(name=name):
                    rows = connection.execute(prefix + query, (name,)).fetchall()
                    expected = [("table", name, "ddl")] if columns else [(name,)]
                    self.assertEqual(rows, expected if visible else [])

    def test_custody_main_names(self):
        query = source_query("pq_cell_custody.py", "SELECT type,name,sql FROM sqlite_master")
        self.assert_classification(query, "sqlite_master", True)

    def test_custody_temp_names(self):
        query = source_query("pq_cell_custody.py", "SELECT name FROM sqlite_temp_master")
        self.assert_classification(query, "sqlite_temp_master", False)

    def test_witness_temp_names(self):
        query = source_query("pq_pql5_quorum.py", "SELECT name FROM sqlite_temp_master")
        self.assert_classification(query, "sqlite_temp_master", False)


if __name__ == "__main__":
    unittest.main()
