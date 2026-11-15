"""Connection cleanup and real SQLite transaction checks for the V2 journal.

These checks cover resource ownership, not signatures, external anchors,
operator independence, root authorization or production qualification.
"""
from contextlib import closing, contextmanager
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import pq_root_recovery_journal_v2 as journal


class ObservedConnection(sqlite3.Connection):
    """Execute actual SQLite operations while observing the owned lifetime."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.close_calls = 0
        self.context_entries = 0
        self.fail_statement = None
        self.setup_error = None

    def execute(self, sql, parameters=(), /):
        if sql == self.fail_statement:
            raise self.setup_error
        return super().execute(sql, parameters)

    def __enter__(self):
        self.context_entries += 1
        return super().__enter__()

    def close(self):
        self.close_calls += 1
        super().close()


@contextmanager
def observe_connections(fail_statement=None, setup_error=None):
    real_connect = sqlite3.connect
    observed = []

    def connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs, factory=ObservedConnection)
        connection.fail_statement = fail_statement
        connection.setup_error = setup_error
        observed.append(connection)
        return connection

    with patch.object(journal.sqlite3, "connect", side_effect=connect):
        yield observed


class RootJournalCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.path = self.directory / "journal.sqlite"

    def assert_closed_once(self, observed):
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0].close_calls, 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            observed[0].execute("SELECT 1")

    def create_items(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("CREATE TABLE items(value TEXT NOT NULL)")
            connection.commit()

    def item_values(self):
        with closing(sqlite3.connect(self.path)) as connection:
            return connection.execute("SELECT value FROM items").fetchall()

    def test_each_setup_failure_closes_without_entering_body(self):
        statements = (
            "PRAGMA journal_mode=DELETE",
            "PRAGMA synchronous=FULL",
            "PRAGMA foreign_keys=ON",
        )
        for index, statement in enumerate(statements):
            with self.subTest(statement=statement):
                path = self.directory / f"setup-{index}.sqlite"
                error = sqlite3.OperationalError("simulated initialization failure")
                with observe_connections(statement, error) as observed:
                    with self.assertRaises(sqlite3.OperationalError) as raised:
                        with journal._database(path, create=True):
                            self.fail("database body entered after setup failure")
                self.assertIs(raised.exception, error)
                self.assertEqual(observed[0].context_entries, 0)
                self.assert_closed_once(observed)

    def test_success_commits_real_transaction_and_closes(self):
        with observe_connections() as observed:
            with journal._database(self.path, create=True) as connection:
                connection.execute("CREATE TABLE items(value TEXT NOT NULL)")
                connection.execute("INSERT INTO items VALUES(?)", ("committed",))
        self.assertEqual(observed[0].context_entries, 1)
        self.assert_closed_once(observed)
        self.assertEqual(self.item_values(), [("committed",)])

    def test_body_failure_rolls_back_and_preserves_exception(self):
        self.create_items()
        error = RuntimeError("ordinary application failure")
        with observe_connections() as observed:
            with self.assertRaises(RuntimeError) as raised:
                with journal._database(self.path) as connection:
                    connection.execute("INSERT INTO items VALUES(?)", ("uncommitted",))
                    raise error
        self.assertIs(raised.exception, error)
        self.assertEqual(observed[0].context_entries, 1)
        self.assert_closed_once(observed)
        self.assertEqual(self.item_values(), [])

    def test_deferred_commit_failure_rolls_back_and_closes(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("CREATE TABLE parent(id INTEGER PRIMARY KEY)")
            connection.execute(
                "CREATE TABLE child(parent_id INTEGER REFERENCES parent(id) "
                "DEFERRABLE INITIALLY DEFERRED)"
            )
            connection.commit()
        body_completed = False
        with observe_connections() as observed:
            with self.assertRaises(sqlite3.IntegrityError):
                with journal._database(self.path) as connection:
                    connection.execute("INSERT INTO child VALUES(1)")
                    body_completed = True
        self.assertTrue(body_completed)
        self.assertEqual(observed[0].context_entries, 1)
        self.assert_closed_once(observed)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT * FROM child").fetchall(), [])


if __name__ == "__main__":
    unittest.main()
