//! The same real owner/SQLite contention controls run for both signed profiles.
//! Channel handshakes hold each blocker until the request has returned; elapsed
//! observations are not used as production latency or WAN acceptance evidence.

// One module definition, expanded against each profile's typed fixture.
macro_rules! declare_tests {
    () => {
        use super::{
            deadline_fixture::{fixture, Directory, Record, META_TABLE, RECORD_TABLE},
            *,
        };
        use rusqlite::types::Value;
        use std::{sync::mpsc, thread, time::Duration};

        const REQUEST_BUDGET: Duration = Duration::from_millis(100);
        const HANDSHAKE_BUDGET: Duration = Duration::from_secs(3);
        // Exaggerate the existing connection wait policy so the failure cannot hide
        // inside a loose elapsed-time assertion. The operation must restore this value.
        const ORIGINAL_SQLITE_WAIT: Duration = Duration::from_secs(10);

        #[derive(Clone, Copy)]
        enum Operation {
            Lookup,
            Publish,
        }

        fn normal_deadline() -> Instant {
            Instant::now() + Duration::from_secs(10)
        }

        fn invoke(
            directory: &Directory,
            record: &Record,
            now: u64,
            operation: Operation,
            deadline: Instant,
        ) -> CellResultV1<()> {
            match operation {
                Operation::Lookup => directory
                    .records(record.statement().request, now, deadline)
                    .map(|_| ()),
                Operation::Publish => {
                    directory.accept_verified(record, "127.0.0.1".parse().unwrap(), now, deadline)
                }
            }
        }

        fn snapshot(directory: &Directory) -> Vec<Vec<Value>> {
            let state = directory.state.lock().unwrap();
            [
                format!("SELECT * FROM {META_TABLE} ORDER BY singleton"),
                format!("SELECT * FROM {RECORD_TABLE} ORDER BY manifest,owner"),
            ]
            .iter()
            .flat_map(|sql| {
                let mut query = state.db.prepare(sql).unwrap();
                let columns = query.column_count();
                let rows = query
                    .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
                    .unwrap();
                rows.collect::<Result<Vec<_>, _>>().unwrap()
            })
            .collect()
        }

        fn refusal_while_held(
            action: impl FnOnce(Instant) -> CellResultV1<()> + Send,
            release: impl FnOnce(),
        ) -> CellErrorV1 {
            thread::scope(|scope| {
                let (ready_tx, ready_rx) = mpsc::sync_channel(0);
                let (start_tx, start_rx) = mpsc::channel();
                let (done_tx, done_rx) = mpsc::channel();
                let worker = scope.spawn(move || {
                    ready_tx.send(()).unwrap();
                    start_rx.recv().unwrap();
                    let result = action(Instant::now() + REQUEST_BUDGET);
                    done_tx.send(result).unwrap();
                });
                let ready = ready_rx.recv_timeout(HANDSHAKE_BUDGET);
                drop(ready_rx);
                // Even a failed assertion must release the real lock before joining.
                let started = ready.is_ok() && start_tx.send(()).is_ok();
                let result = if started {
                    done_rx.recv_timeout(HANDSHAKE_BUDGET)
                } else {
                    Err(mpsc::RecvTimeoutError::Disconnected)
                };
                release();
                drop(start_tx);
                worker.join().unwrap();
                assert!(ready.is_ok(), "request worker did not become ready");
                result
                    .expect("request remained blocked until its owner/SQLite lock was released")
                    .expect_err("contended operation succeeded after its deadline")
            })
        }

        fn require_budget_refusal(error: CellErrorV1) {
            match error {
                CellErrorV1::Invalid("discovery absolute deadline") => (),
                // SQLite rounds its millisecond timeout down. SQLITE_BUSY can therefore
                // be returned just before the absolute deadline and is a valid refusal.
                CellErrorV1::Sql(rusqlite::Error::SqliteFailure(code, _))
                    if code.code == rusqlite::ErrorCode::DatabaseBusy => {}
                other => panic!("unexpected contention result: {other:?}"),
            }
        }

        fn assert_retry_preserves_sequence(
            directory: &Directory,
            first: &Record,
            next: &Record,
            now: u64,
        ) {
            invoke(directory, next, now, Operation::Publish, normal_deadline()).unwrap();
            let records = directory
                .records(next.statement().request, now, normal_deadline())
                .unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].statement().sequence, 2);
            let current = snapshot(directory);
            assert!(invoke(directory, first, now, Operation::Publish, normal_deadline()).is_err());
            assert_eq!(snapshot(directory), current);
        }

        fn owner_contention(operation: Operation) {
            let temp = tempfile::tempdir().unwrap();
            let (directory, first, next, now) = fixture(&temp.path().join("directory.sqlite"));
            invoke(
                &directory,
                &first,
                now,
                Operation::Publish,
                normal_deadline(),
            )
            .unwrap();
            let before = snapshot(&directory);
            let owner = directory.state.lock().unwrap();
            let error = refusal_while_held(
                |deadline| invoke(&directory, &next, now, operation, deadline),
                || drop(owner),
            );
            require_budget_refusal(error);
            assert_eq!(snapshot(&directory), before);
            assert_retry_preserves_sequence(&directory, &first, &next, now);
        }

        fn sqlite_contention(operation: Operation, reader_blocks_commit: bool) {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("directory.sqlite");
            let (directory, first, next, now) = fixture(&path);
            invoke(
                &directory,
                &first,
                now,
                Operation::Publish,
                normal_deadline(),
            )
            .unwrap();
            let before = snapshot(&directory);
            directory
                .state
                .lock()
                .unwrap()
                .db
                .busy_timeout(ORIGINAL_SQLITE_WAIT)
                .unwrap();
            let mut blocker = Connection::open(&path).unwrap();
            blocker.busy_timeout(Duration::ZERO).unwrap();
            let transaction = blocker
                .transaction_with_behavior(if reader_blocks_commit {
                    TransactionBehavior::Deferred
                } else {
                    TransactionBehavior::Immediate
                })
                .unwrap();
            if reader_blocks_commit {
                // BEGIN alone holds no read lock; the real query below does.
                let count: u64 = transaction
                    .query_row(&format!("SELECT count(*) FROM {META_TABLE}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 1);
            }
            let error = refusal_while_held(
                |deadline| invoke(&directory, &next, now, operation, deadline),
                || transaction.rollback().unwrap(),
            );
            require_budget_refusal(error);
            assert_eq!(snapshot(&directory), before);
            let restored: u64 = directory
                .state
                .lock()
                .unwrap()
                .db
                .pragma_query_value(None, "busy_timeout", |row| row.get(0))
                .unwrap();
            assert_eq!(restored, ORIGINAL_SQLITE_WAIT.as_millis() as u64);
            assert_retry_preserves_sequence(&directory, &first, &next, now);
            drop(directory);
            let (reopened, _, _, reopened_now) = fixture(&path);
            let records = reopened
                .records(next.statement().request, reopened_now, normal_deadline())
                .unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].statement().sequence, 2);
        }

        #[test]
        fn lookup_owner_contention_keeps_original_deadline() {
            owner_contention(Operation::Lookup);
        }

        #[test]
        fn publish_owner_contention_keeps_original_deadline() {
            owner_contention(Operation::Publish);
        }

        #[test]
        fn lookup_writer_contention_keeps_original_deadline() {
            sqlite_contention(Operation::Lookup, false);
        }

        #[test]
        fn publish_writer_contention_keeps_original_deadline() {
            sqlite_contention(Operation::Publish, false);
        }

        #[test]
        fn lookup_commit_contention_keeps_original_deadline() {
            sqlite_contention(Operation::Lookup, true);
        }

        #[test]
        fn publish_commit_contention_keeps_original_deadline() {
            sqlite_contention(Operation::Publish, true);
        }
    };
}

pub(super) use declare_tests;
