//! Differential tests against the exact pre-change batched application.
use super::*;
use crate::account_archive_prototype as archive;
use crate::{ErrorCode, ErrorKind};
use rusqlite::params;
use serde_json::json;

// Research only: the fixed 8-cell observation rejected default adoption.
// This whole module is compiled only through native_store's cfg(test) entry.
// Keep the measured candidate independently available without changing normal
// apply, Growth, publish, validation, accounting or resource-policy paths.
mod candidate {
    use super::*;
    /// One application's current-row reader and optional exact-input arithmetic.
    /// The optional arithmetic miss retains the original loader and hash operations.
    /// This owns no row, graph verdict or snapshot: each read executes again and
    /// drops its cursor before the original progress callback or next write.
    struct ApplyNodes<'db, 'cache> {
        db: &'db Connection,
        reader: NodeReader<'db>,
        lifts: Option<&'cache LiftCache>,
    }
    impl<'db, 'cache> ApplyNodes<'db, 'cache> {
        fn new(db: &'db Connection, lifts: Option<&'cache LiftCache>) -> Self {
            Self {
                db,
                reader: NodeReader::new(db),
                lifts,
            }
        }

        fn root(&mut self, root: &Root, empty: &[Hash; 257], maximum: u64) -> Result<Option<Node>> {
            let Some(lifts) = self.lifts else {
                return load_root_bounded(self.db, root, empty, maximum);
            };
            // Keep the actual load before root/count checks, including its original
            // missing/type/corruption error priority. Empty roots prepare nothing.
            let node = root
                .node
                .map(|id| self.reader.load(id, Some(lifts)))
                .transpose()
                .map_err(storage)?;
            crate::ensure(
                root.count <= maximum
                    && root.node.is_none() == (root.count == 0)
                    && node.as_ref().map_or(empty[0], |node| lifts.lift(node, 0)) == root.digest,
                "NATIVE_ACCOUNT_ROOT",
            )
            .map_err(Error::local_integrity)?;
            Ok(node)
        }

        fn child(
            &mut self,
            parent: &Node,
            side: bool,
            empty: &[Hash; 257],
        ) -> archive::Result<Node> {
            match self.lifts {
                Some(lifts) => child_with_lifts(&mut self.reader, parent, side, empty, Some(lifts)),
                None => archive::child(self.db, parent, side, empty),
            }
        }

        fn fork(
            &self,
            depth: usize,
            left: &Node,
            right: &Node,
            empty: &[Hash; 257],
        ) -> archive::Result<Node> {
            match self.lifts {
                Some(lifts) => {
                    Node::fork_with_lift(depth, left, right, &|node, level| lifts.lift(node, level))
                }
                None => Node::fork(depth, left, right, empty),
            }
        }

        fn lift(&self, node: &Node, depth: usize, empty: &[Hash; 257]) -> Hash {
            self.lifts
                .map_or_else(|| node.lift(depth, empty), |lifts| lifts.lift(node, depth))
        }
    }

    fn lookup(
        nodes: &mut ApplyNodes<'_, '_>,
        root: Option<Node>,
        owner: Hash,
        empty: &[Hash; 257],
    ) -> Result<Option<Account>> {
        let key = archive::path(owner);
        let mut current = root;
        for _ in 0..257 {
            let Some(node) = current else { return Ok(None) };
            if archive::common(&key, &node.path) < node.depth {
                return Ok(None);
            }
            match node.kind {
                Kind::Leaf(stored, account) => {
                    crate::ensure(stored == owner, "NATIVE_ACCOUNT_COLLISION")
                        .map_err(Error::local_integrity)?;
                    return Ok(Some(account));
                }
                Kind::Fork { .. } => {
                    current = Some(
                        nodes
                            .child(&node, archive::bit(&key, node.depth), empty)
                            .map_err(storage)?,
                    );
                }
            }
        }
        Err(Error::from("NATIVE_ACCOUNT_PATH").local_integrity())
    }

    /// Merge sorted changed leaves into the compressed parent tree. Every persisted
    /// node belongs to the completed successor: intermediate per-account roots are
    /// never written. Unchanged subtrees and all prior versions remain untouched.
    fn apply_batch(
        nodes: &mut ApplyNodes<'_, '_>,
        existing: Option<Node>,
        updates: &[Node],
        empty: &[Hash; 257],
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<Node>> {
        progress()?;
        let Some(first) = updates.first() else {
            return Ok(existing);
        };
        let last = updates.last().ok_or("NATIVE_ACCOUNT_DELTA")?;
        let changed_depth = archive::common(&first.path, &last.path);
        let depth = existing.as_ref().map_or(changed_depth, |node| {
            changed_depth
                .min(node.depth)
                .min(archive::common(&node.path, &first.path))
        });
        if depth == 256 {
            crate::ensure(updates.len() == 1, "NATIVE_ACCOUNT_DELTA")
                .map_err(Error::local_integrity)?;
            // The original-parent lookup already checked identity and nonce. Keep
            // this structural guard so the merge cannot replace another owner.
            if let Some(node) = existing {
                crate::ensure(
                matches!((node.kind, first.kind), (Kind::Leaf(old, _), Kind::Leaf(new, _)) if old == new),
                "NATIVE_ACCOUNT_COLLISION",
            )
            .map_err(Error::local_integrity)?;
            }
            archive::save_node(nodes.db, first).map_err(storage)?;
            return Ok(Some(first.clone()));
        }
        let split = updates.partition_point(|node| !archive::bit(&node.path, depth));
        let (left_updates, right_updates) = updates.split_at(split);
        let (left, right) = match existing {
            None => (None, None),
            Some(node) if depth < node.depth => {
                if archive::bit(&node.path, depth) {
                    (None, Some(node))
                } else {
                    (Some(node), None)
                }
            }
            Some(node) => {
                crate::ensure(
                    depth == node.depth && matches!(node.kind, Kind::Fork { .. }),
                    "NATIVE_ACCOUNT_GRAPH",
                )
                .map_err(Error::local_integrity)?;
                (
                    Some(nodes.child(&node, false, empty).map_err(storage)?),
                    Some(nodes.child(&node, true, empty).map_err(storage)?),
                )
            }
        };
        let left = apply_batch(nodes, left, left_updates, empty, progress)?
            .ok_or_else(|| Error::from("NATIVE_ACCOUNT_GRAPH").local_integrity())?;
        let right = apply_batch(nodes, right, right_updates, empty, progress)?
            .ok_or_else(|| Error::from("NATIVE_ACCOUNT_GRAPH").local_integrity())?;
        let next = nodes.fork(depth, &left, &right, empty).map_err(storage)?;
        archive::save_node(nodes.db, &next).map_err(storage)?;
        Ok(Some(next))
    }

    /// Reuse only exact-input arithmetic warmed by the current parent check.
    /// Every actual SQL row, parent edge, write and progress checkpoint remains.
    /// Rollback can retain arithmetic, never an account or admission verdict.
    pub(super) fn apply_with_lifts(
        db: &Connection,
        parent: &Root,
        deltas: &[crate::store::Delta],
        progress: &mut dyn FnMut() -> Result<()>,
        lifts: &LiftCache,
    ) -> Result<Root> {
        apply_bounded(db, parent, deltas, progress, 65_536, Some(lifts))
    }

    fn apply_bounded(
        db: &Connection,
        parent: &Root,
        deltas: &[crate::store::Delta],
        progress: &mut dyn FnMut() -> Result<()>,
        maximum: u64,
        lifts: Option<&LiftCache>,
    ) -> Result<Root> {
        let empty = empty_hashes();
        let mut nodes = ApplyNodes::new(db, lifts);
        let original = nodes.root(parent, &empty, maximum)?;
        let mut updates = Vec::new();
        let mut count = parent.count;
        // Canonical key order can visit a credit before its matching debit. Keep a
        // signed wide delta accumulator so an intermediate order cannot reject a
        // conserved u64 total near its boundary.
        let mut balance = i128::from(parent.balance);
        for (key, before, after) in deltas {
            progress()?;
            if !key.starts_with("account:") {
                continue;
            }
            let after = after
                .as_ref()
                .ok_or_else(|| Error::from("NATIVE_ACCOUNT_DELETION").local_integrity())?;
            let (owner, next) = account(key, after)?;
            let prior = before
                .as_ref()
                .map(|bytes| account(key, bytes).map(|row| row.1))
                .transpose()?;
            crate::ensure(
                lookup(&mut nodes, original.clone(), owner, &empty)? == prior
                    && prior.is_none_or(|prior| next.nonce >= prior.nonce),
                "NATIVE_ACCOUNT_DELTA",
            )
            .map_err(Error::local_integrity)?;
            count = count
                .checked_add(u64::from(prior.is_none()))
                .ok_or("NATIVE_ACCOUNT_COUNT")?;
            balance = balance
                .checked_sub(i128::from(prior.map_or(0, |prior| prior.balance)))
                .and_then(|value| value.checked_add(i128::from(next.balance)))
                .ok_or("NATIVE_ACCOUNT_BALANCE")?;
            updates.push(Node::account(owner, next));
        }
        crate::ensure(count <= maximum, "NATIVE_ACCOUNT_COUNT").map_err(Error::local_integrity)?;
        let balance = u64::try_from(balance)
            .map_err(|_| Error::from("NATIVE_ACCOUNT_BALANCE").local_integrity())?;
        updates.sort_unstable_by_key(|node| node.path);
        crate::ensure(
            updates.windows(2).all(|pair| pair[0].path != pair[1].path),
            "NATIVE_ACCOUNT_DELTA",
        )
        .map_err(Error::local_integrity)?;
        let root = apply_batch(&mut nodes, original, &updates, &empty, progress)?;
        Ok(Root {
            node: root.as_ref().map(|node| node.id),
            digest: root
                .as_ref()
                .map_or(empty[0], |node| nodes.lift(node, 0, &empty)),
            count,
            balance,
        })
    }
}

// Frozen f9977c5d implementation. This keeps the original batch SQL and
// callback order, unlike the older serial-insertion reference. It never uses
// candidate::ApplyNodes, NodeReader or the candidate application helpers.
mod reference {
    use super::*;
    fn lookup(
        db: &Connection,
        root: Option<Node>,
        owner: Hash,
        empty: &[Hash; 257],
    ) -> Result<Option<Account>> {
        let key = archive::path(owner);
        let mut current = root;
        for _ in 0..257 {
            let Some(node) = current else { return Ok(None) };
            if archive::common(&key, &node.path) < node.depth {
                return Ok(None);
            }
            match node.kind {
                Kind::Leaf(stored, account) => {
                    crate::ensure(stored == owner, "NATIVE_ACCOUNT_COLLISION")
                        .map_err(Error::local_integrity)?;
                    return Ok(Some(account));
                }
                Kind::Fork { .. } => {
                    current = Some(
                        archive::child(db, &node, archive::bit(&key, node.depth), empty)
                            .map_err(storage)?,
                    );
                }
            }
        }
        Err(Error::from("NATIVE_ACCOUNT_PATH").local_integrity())
    }

    fn apply_batch(
        db: &Connection,
        existing: Option<Node>,
        updates: &[Node],
        empty: &[Hash; 257],
        progress: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Option<Node>> {
        progress()?;
        let Some(first) = updates.first() else {
            return Ok(existing);
        };
        let last = updates.last().ok_or("NATIVE_ACCOUNT_DELTA")?;
        let changed_depth = archive::common(&first.path, &last.path);
        let depth = existing.as_ref().map_or(changed_depth, |node| {
            changed_depth
                .min(node.depth)
                .min(archive::common(&node.path, &first.path))
        });
        if depth == 256 {
            crate::ensure(updates.len() == 1, "NATIVE_ACCOUNT_DELTA")
                .map_err(Error::local_integrity)?;
            // The original-parent lookup already checked identity and nonce. Keep
            // this structural guard so the merge cannot replace another owner.
            if let Some(node) = existing {
                crate::ensure(
                matches!((node.kind, first.kind), (Kind::Leaf(old, _), Kind::Leaf(new, _)) if old == new),
                "NATIVE_ACCOUNT_COLLISION",
            )
            .map_err(Error::local_integrity)?;
            }
            archive::save_node(db, first).map_err(storage)?;
            return Ok(Some(first.clone()));
        }
        let split = updates.partition_point(|node| !archive::bit(&node.path, depth));
        let (left_updates, right_updates) = updates.split_at(split);
        let (left, right) = match existing {
            None => (None, None),
            Some(node) if depth < node.depth => {
                if archive::bit(&node.path, depth) {
                    (None, Some(node))
                } else {
                    (Some(node), None)
                }
            }
            Some(node) => {
                crate::ensure(
                    depth == node.depth && matches!(node.kind, Kind::Fork { .. }),
                    "NATIVE_ACCOUNT_GRAPH",
                )
                .map_err(Error::local_integrity)?;
                (
                    Some(archive::child(db, &node, false, empty).map_err(storage)?),
                    Some(archive::child(db, &node, true, empty).map_err(storage)?),
                )
            }
        };
        let left = apply_batch(db, left, left_updates, empty, progress)?
            .ok_or_else(|| Error::from("NATIVE_ACCOUNT_GRAPH").local_integrity())?;
        let right = apply_batch(db, right, right_updates, empty, progress)?
            .ok_or_else(|| Error::from("NATIVE_ACCOUNT_GRAPH").local_integrity())?;
        let next = Node::fork(depth, &left, &right, empty).map_err(storage)?;
        archive::save_node(db, &next).map_err(storage)?;
        Ok(Some(next))
    }

    pub(super) fn apply_bounded(
        db: &Connection,
        parent: &Root,
        deltas: &[crate::store::Delta],
        progress: &mut dyn FnMut() -> Result<()>,
        maximum: u64,
    ) -> Result<Root> {
        let empty = empty_hashes();
        let original = load_root_bounded(db, parent, &empty, maximum)?;
        let mut updates = Vec::new();
        let mut count = parent.count;
        // Canonical key order can visit a credit before its matching debit. Keep a
        // signed wide delta accumulator so an intermediate order cannot reject a
        // conserved u64 total near its boundary.
        let mut balance = i128::from(parent.balance);
        for (key, before, after) in deltas {
            progress()?;
            if !key.starts_with("account:") {
                continue;
            }
            let after = after
                .as_ref()
                .ok_or_else(|| Error::from("NATIVE_ACCOUNT_DELETION").local_integrity())?;
            let (owner, next) = account(key, after)?;
            let prior = before
                .as_ref()
                .map(|bytes| account(key, bytes).map(|row| row.1))
                .transpose()?;
            crate::ensure(
                lookup(db, original.clone(), owner, &empty)? == prior
                    && prior.is_none_or(|prior| next.nonce >= prior.nonce),
                "NATIVE_ACCOUNT_DELTA",
            )
            .map_err(Error::local_integrity)?;
            count = count
                .checked_add(u64::from(prior.is_none()))
                .ok_or("NATIVE_ACCOUNT_COUNT")?;
            balance = balance
                .checked_sub(i128::from(prior.map_or(0, |prior| prior.balance)))
                .and_then(|value| value.checked_add(i128::from(next.balance)))
                .ok_or("NATIVE_ACCOUNT_BALANCE")?;
            updates.push(Node::account(owner, next));
        }
        crate::ensure(count <= maximum, "NATIVE_ACCOUNT_COUNT").map_err(Error::local_integrity)?;
        let balance = u64::try_from(balance)
            .map_err(|_| Error::from("NATIVE_ACCOUNT_BALANCE").local_integrity())?;
        updates.sort_unstable_by_key(|node| node.path);
        crate::ensure(
            updates.windows(2).all(|pair| pair[0].path != pair[1].path),
            "NATIVE_ACCOUNT_DELTA",
        )
        .map_err(Error::local_integrity)?;
        let root = apply_batch(db, original, &updates, &empty, progress)?;
        Ok(Root {
            node: root.as_ref().map(|node| node.id),
            digest: root.as_ref().map_or(empty[0], |node| node.lift(0, &empty)),
            count,
            balance,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum Arm {
    Reference,
    Uncached,
    Cached,
    Growth,
}

type Verdict = std::result::Result<Root, (ErrorKind, Option<ErrorCode>, String)>;
type Stored = Vec<(Vec<u8>, rusqlite::types::Value)>;

fn verdict(result: Result<Root>) -> Verdict {
    result.map_err(|error| (error.kind(), error.code(), error.to_string()))
}

fn owner(index: u64) -> Hash {
    trnm_protocol::pon_wire::hash(b"native-apply-reader-fixture", &[&index.to_le_bytes()])
}

fn fixture(db: &Connection, count: u64) -> (State, Root) {
    db.execute_batch(crate::store::native_authenticated::DDL)
        .unwrap();
    let state = (0..count)
        .map(|index| {
            (
                format!("account:{}", hex::encode(owner(index))),
                json!({"balance":1_000 + index,"nonce":index % 7}),
            )
        })
        .collect();
    let root = seed(db, &state, &mut || Ok(())).unwrap();
    (state, root)
}

fn change(state: &State, count: usize) -> (State, Vec<crate::store::Delta>) {
    let mut after = state.clone();
    let mut deltas = Vec::new();
    for (key, value) in after.iter_mut().take(count) {
        let before = serde_json::to_vec(value).unwrap();
        value["balance"] = json!(value["balance"].as_u64().unwrap() + 13);
        value["nonce"] = json!(value["nonce"].as_u64().unwrap() + 1);
        deltas.push((
            key.clone(),
            Some(before),
            Some(serde_json::to_vec(value).unwrap()),
        ));
    }
    (after, deltas)
}

fn stored(db: &Connection) -> Stored {
    db.prepare("SELECT id,data FROM archive_nodes ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn run(
    arm: Arm,
    db: &Connection,
    parent: &Root,
    deltas: &[crate::store::Delta],
    progress: &mut dyn FnMut() -> Result<()>,
    cache: &LiftCache,
) -> Result<Root> {
    match arm {
        Arm::Reference => reference::apply_bounded(db, parent, deltas, progress, 65_536),
        Arm::Uncached => apply(db, parent, deltas, progress),
        Arm::Cached => candidate::apply_with_lifts(db, parent, deltas, progress, cache),
        Arm::Growth => apply_growth(db, parent, deltas, progress),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
struct SqlObservation {
    selects: u64,
    writes: u64,
    statements: u64,
    // Actual bound statements are retained in correctness tests only. Timing
    // observations use counters without expansion/allocation on each read.
    sequence: Vec<String>,
}

struct TraceState {
    observation: RefCell<SqlObservation>,
    capture: bool,
    recording: std::cell::Cell<bool>,
    failed: std::cell::Cell<bool>,
}
thread_local! {
    // Test workers are independent threads. Rc also makes a guard !Send, so
    // its callback state and cleanup cannot migrate to another test worker.
    static ACTIVE_SQL_TRACE: RefCell<Option<std::rc::Rc<TraceState>>> = const { RefCell::new(None) };
}

struct SqlTrace<'db> {
    db: &'db mut Connection,
    state: std::rc::Rc<TraceState>,
}
impl<'db> SqlTrace<'db> {
    fn new(db: &'db mut Connection, capture: bool) -> Self {
        let state = std::rc::Rc::new(TraceState {
            observation: RefCell::default(),
            capture,
            recording: std::cell::Cell::new(false),
            failed: std::cell::Cell::new(false),
        });
        ACTIVE_SQL_TRACE.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none(), "only one traced test connection per worker");
            *slot = Some(std::rc::Rc::clone(&state));
        });
        // These test-owned connections never have a TransactionScope observer
        // or Node owner. The dependency's safe wrapper owns the SQLite ABI.
        let guard = Self { db, state };
        guard
            .db
            .trace_v2(
                rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
                Some(sql_trace),
            )
            .expect("install the complete SQL trace");
        guard
    }
    fn start(&self) {
        // Install with exclusive connection ownership before opening a transaction.
        // Record only the original apply interval: BEGIN, fixture changes,
        // post-result inspection and ROLLBACK remain outside the observation.
        assert!(!self.state.recording.replace(true));
        assert!(!self.state.failed.get(), "SQL trace must be complete");
        *self.state.observation.borrow_mut() = SqlObservation::default();
    }
    fn observation(&self) -> SqlObservation {
        assert!(self.state.recording.replace(false));
        assert!(!self.state.failed.get(), "SQL trace must be complete");
        self.state.observation.borrow().clone()
    }
}
impl Drop for SqlTrace<'_> {
    fn drop(&mut self) {
        self.state.recording.set(false);
        let removed = self.db.trace_v2(
            rusqlite::trace::TraceEventCodes::empty(),
            None::<fn(rusqlite::trace::TraceEvent<'_>)>,
        );
        ACTIVE_SQL_TRACE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot
                .as_ref()
                .is_some_and(|state| std::rc::Rc::ptr_eq(state, &self.state))
            {
                slot.take();
            } else {
                self.state.failed.set(true);
            }
        });
        if let Err(error) = removed {
            self.state.failed.set(true);
            if !std::thread::panicking() {
                panic!("remove the SQL trace: {error}");
            }
        }
    }
}
fn sql_trace(event: rusqlite::trace::TraceEvent<'_>) {
    let rusqlite::trace::TraceEvent::Stmt(statement, _) = event else {
        return;
    };
    let state = ACTIVE_SQL_TRACE.with(|slot| slot.borrow().clone());
    let Some(state) = state else {
        return;
    };
    if !state.recording.get() {
        return;
    }
    // The wrapper catches ABI unwinds. Mark our observation failed as well so
    // a swallowed diagnostic failure can never look like complete evidence.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let sql = statement.sql();
        let verb = sql.split_ascii_whitespace().next();
        let mut observation = state.observation.borrow_mut();
        observation.statements += 1;
        // Count actual executed statements, not prepares or expected graph
        // visits. This test corpus contains only these fixed SQL verbs. Unknown
        // statements fail the observation rather than being guessed readonly.
        // Trigger events use the original statement's SQL, not synthetic text.
        match verb {
            Some("SELECT") => observation.selects += 1,
            Some("INSERT" | "UPDATE" | "DELETE" | "ALTER" | "CREATE" | "DROP") => {
                observation.writes += 1
            }
            _ => state.failed.set(true),
        }
        if state.capture {
            match statement.expanded_sql() {
                Some(value) => observation.sequence.push(value),
                None => state.failed.set(true),
            }
        }
    }));
    if result.is_err() {
        state.failed.set(true);
    }
}

fn observed(
    arm: Arm,
    db: &Connection,
    trace: &SqlTrace<'_>,
    root: &Root,
    deltas: &[crate::store::Delta],
    cache: &LiftCache,
    mut checkpoint: impl FnMut(usize) -> Result<()>,
) -> (Verdict, usize, SqlObservation, Stored) {
    let mut calls = 0;
    trace.start();
    let result = verdict(run(
        arm,
        db,
        root,
        deltas,
        &mut || {
            calls += 1;
            checkpoint(calls)
        },
        cache,
    ));
    let sql = trace.observation();
    (result, calls, sql, stored(db))
}

#[test]
fn native_apply_reader_cold_warm_and_fallback_match_original_batch_bytes_and_sql_order() {
    for count in [0, 1, 31, 257] {
        let mut db = Connection::open_in_memory().unwrap();
        let (state, parent) = fixture(&db, count);
        let (mut after, mut changes) = change(&state, (count as usize).div_ceil(3));
        let inserted_key = format!("account:{}", hex::encode(owner(count + 10)));
        let inserted_value = json!({"balance":17,"nonce":0});
        changes.push((
            inserted_key.clone(),
            None,
            Some(serde_json::to_vec(&inserted_value).unwrap()),
        ));
        after.insert(inserted_key, inserted_value);
        changes.sort_by(|a, b| a.0.cmp(&b.0));
        let original = stored(&db);
        let mut expected = None;
        for warm in [false, true] {
            for arm in [Arm::Reference, Arm::Uncached, Arm::Cached, Arm::Growth] {
                let cache = LiftCache::default();
                if warm {
                    verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
                }
                let trace = SqlTrace::new(&mut db, true);
                let transaction = trace.db.unchecked_transaction().unwrap();
                let observed =
                    observed(arm, &transaction, &trace, &parent, &changes, &cache, |_| {
                        Ok(())
                    });
                let next = observed.0.as_ref().unwrap();
                verify(&transaction, next, &after, &mut || Ok(())).unwrap();
                if let Some(expected) = &expected {
                    assert_eq!(&observed, expected, "count={count} {arm:?} warm={warm}");
                } else {
                    expected = Some(observed);
                }
                transaction.rollback().unwrap();
                drop(trace);
                assert_eq!(stored(&db), original);
            }
        }
        // Persist the already-derived successor, then apply the same original
        // parent/deltas again. Every INSERT now conflicts and must reread exact
        // current bytes even while ApplyNodes retains its same-SQL reader.
        let transaction = db.unchecked_transaction().unwrap();
        let next = apply(&transaction, &parent, &changes, &mut || Ok(())).unwrap();
        transaction.commit().unwrap();
        let repeated_rows = stored(&db);
        let cache = LiftCache::default();
        verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
        let mut repeated = None;
        for arm in [Arm::Reference, Arm::Uncached, Arm::Cached, Arm::Growth] {
            let trace = SqlTrace::new(&mut db, true);
            let transaction = trace.db.unchecked_transaction().unwrap();
            let result = observed(arm, &transaction, &trace, &parent, &changes, &cache, |_| {
                Ok(())
            });
            assert_eq!(result.0.as_ref().unwrap(), &next);
            assert_eq!(result.3, repeated_rows);
            assert!(result.2.selects > expected.as_ref().unwrap().2.selects);
            if let Some(expected) = &repeated {
                assert_eq!(&result, expected);
            } else {
                repeated = Some(result);
            }
            transaction.rollback().unwrap();
            drop(trace);
            assert_eq!(stored(&db), repeated_rows);
        }
    }
    // Empty roots still require no table, no SQL or new prepare prerequisite.
    let mut db = Connection::open_in_memory().unwrap();
    let root = Root {
        node: None,
        digest: empty_hashes()[0],
        count: 0,
        balance: 0,
    };
    let cache = LiftCache::default();
    for changes in [
        vec![],
        vec![("meta:only".into(), None, Some(b"1".to_vec()))],
    ] {
        let mut visits = [0; 2];
        for (index, arm) in [Arm::Reference, Arm::Cached].into_iter().enumerate() {
            let trace = SqlTrace::new(&mut db, true);
            trace.start();
            assert_eq!(
                run(
                    arm,
                    trace.db,
                    &root,
                    &changes,
                    &mut || {
                        visits[index] += 1;
                        Ok(())
                    },
                    &cache
                )
                .unwrap(),
                root
            );
            assert_eq!(trace.observation(), SqlObservation::default());
        }
        assert_eq!(visits[0], visits[1]);
    }
}

#[derive(Clone, Copy, Debug)]
enum Damage {
    Missing,
    Changed,
    Text,
    Oversize,
    AddColumn,
    Rename,
}

#[test]
fn native_apply_reader_warm_cache_observes_current_child_mutation_and_missing_rows() {
    for damage in [
        Damage::Missing,
        Damage::Changed,
        Damage::Text,
        Damage::Oversize,
        Damage::AddColumn,
        Damage::Rename,
    ] {
        let mut db = Connection::open_in_memory().unwrap();
        let (state, parent) = fixture(&db, 8);
        let (_, changes) = change(&state, 2);
        let cache = LiftCache::default();
        verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
        let original = stored(&db);
        for cut in [1, 2] {
            let (owner, prior) =
                account(&changes[cut - 1].0, changes[cut - 1].1.as_ref().unwrap()).unwrap();
            let leaf = Node::account(owner, prior);
            let mut expected = None;
            for arm in [Arm::Reference, Arm::Uncached, Arm::Cached] {
                let trace = SqlTrace::new(&mut db, true);
                let transaction = trace.db.unchecked_transaction().unwrap();
                let observed = observed(
                    arm,
                    &transaction,
                    &trace,
                    &parent,
                    &changes,
                    &cache,
                    |call| {
                        if call == cut {
                            match damage {
                                Damage::Missing => {
                                    transaction.execute(
                                        "DELETE FROM archive_nodes WHERE id=?",
                                        [leaf.id.as_slice()],
                                    )?;
                                }
                                Damage::Changed => {
                                    let mut bytes = leaf.encode();
                                    bytes[40] ^= 0x80;
                                    transaction.execute(
                                        "UPDATE archive_nodes SET data=? WHERE id=?",
                                        params![bytes, leaf.id.as_slice()],
                                    )?;
                                }
                                Damage::Text => {
                                    transaction.execute(
                                        "UPDATE archive_nodes SET data='not-a-blob' WHERE id=?",
                                        [leaf.id.as_slice()],
                                    )?;
                                }
                                Damage::Oversize => {
                                    transaction.execute(
                                    "UPDATE archive_nodes SET data=zeroblob(1048576) WHERE id=?",
                                    [leaf.id.as_slice()],
                                )?;
                                }
                                Damage::AddColumn => {
                                    transaction.execute_batch(
                                        "ALTER TABLE archive_nodes ADD COLUMN extra INTEGER",
                                    )?;
                                }
                                // Keep a replacement table so post-result row observations
                                // work while the next current SQL read still sees absence.
                                Damage::Rename => {
                                    transaction.execute_batch("ALTER TABLE archive_nodes RENAME TO removed_nodes; CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB NOT NULL)")?;
                                }
                            }
                        }
                        Ok(())
                    },
                );
                if matches!(damage, Damage::AddColumn) {
                    assert!(observed.0.is_ok());
                } else {
                    assert_eq!(
                        observed.0.as_ref().unwrap_err().0,
                        ErrorKind::LocalStructure
                    );
                }
                if let Some(expected) = &expected {
                    assert_eq!(&observed, expected, "{damage:?} cut={cut} {arm:?}");
                } else {
                    expected = Some(observed);
                }
                transaction.rollback().unwrap();
                drop(trace);
                assert_eq!(stored(&db), original);
            }
        }
        // Same arithmetic remains harmless after rollback restores exact rows.
        verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
    }
}

#[test]
fn native_apply_reader_cancellation_at_every_original_checkpoint_keeps_partial_writes() {
    let mut db = Connection::open_in_memory().unwrap();
    let (state, parent) = fixture(&db, 8);
    let (_, changes) = change(&state, 3);
    let cache = LiftCache::default();
    verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
    let original = stored(&db);
    let trace = SqlTrace::new(&mut db, true);
    let transaction = trace.db.unchecked_transaction().unwrap();
    let (_, checkpoints, _, _) = observed(
        Arm::Reference,
        &transaction,
        &trace,
        &parent,
        &changes,
        &cache,
        |_| Ok(()),
    );
    transaction.rollback().unwrap();
    drop(trace);
    let mut after_write = false;
    for cut in 1..=checkpoints {
        let mut expected = None;
        for arm in [Arm::Reference, Arm::Uncached, Arm::Cached] {
            let trace = SqlTrace::new(&mut db, true);
            let transaction = trace.db.unchecked_transaction().unwrap();
            let result = observed(
                arm,
                &transaction,
                &trace,
                &parent,
                &changes,
                &cache,
                |call| {
                    if call == cut {
                        // A competing next-read failure may not preempt cancellation.
                        transaction.execute_batch(
                            "ALTER TABLE archive_nodes ADD COLUMN cancelled INTEGER",
                        )?;
                        return Err(Error::new(ErrorCode::PublicRequestCancelled));
                    }
                    Ok(())
                },
            );
            assert_eq!(result.1, cut);
            assert_eq!(
                result.0.as_ref().unwrap_err().1,
                Some(ErrorCode::PublicRequestCancelled)
            );
            after_write |= result.3 != original;
            if let Some(expected) = &expected {
                assert_eq!(&result, expected, "cut={cut} {arm:?}");
            } else {
                expected = Some(result);
            }
            transaction.rollback().unwrap();
            drop(trace);
            assert_eq!(stored(&db), original);
        }
    }
    assert!(after_write);
}

#[test]
fn native_apply_reader_preserves_nonce_deletion_duplicate_and_growth_limits() {
    let mut db = Connection::open_in_memory().unwrap();
    let (state, parent) = fixture(&db, 8);
    let (_, good) = change(&state, 2);
    let cache = LiftCache::default();
    verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
    let mut cases = Vec::new();
    let mut deletion = good.clone();
    deletion[0].2 = None;
    cases.push(deletion);
    let mut absent = good.clone();
    absent[0].1 = None;
    cases.push(absent);
    let mut nonce = good.clone();
    nonce[0].2 = Some(br#"{"balance":1,"nonce":0}"#.to_vec());
    // Choose an actual nonzero original nonce to make regression certain.
    let nonzero = state
        .iter()
        .find(|(_, v)| v["nonce"].as_u64().unwrap() > 0)
        .unwrap();
    nonce[0].0 = nonzero.0.clone();
    nonce[0].1 = Some(serde_json::to_vec(nonzero.1).unwrap());
    cases.push(nonce);
    cases.push(vec![good[0].clone(), good[0].clone()]);
    for changes in cases {
        let mut expected = None;
        for arm in [Arm::Reference, Arm::Uncached, Arm::Cached, Arm::Growth] {
            let trace = SqlTrace::new(&mut db, true);
            let transaction = trace.db.unchecked_transaction().unwrap();
            let result = observed(arm, &transaction, &trace, &parent, &changes, &cache, |_| {
                Ok(())
            });
            assert!(result.0.is_err());
            if let Some(expected) = &expected {
                assert_eq!(&result, expected);
            } else {
                expected = Some(result);
            }
            transaction.rollback().unwrap();
        }
    }
    // Synthetic private Root metadata exercises only the unchanged bound check;
    // it is not represented as a valid complete account graph or admitted state.
    let mut oversized = parent.clone();
    oversized.count = 65_537;
    for arm in [Arm::Reference, Arm::Uncached, Arm::Cached] {
        assert_eq!(
            run(arm, &db, &oversized, &[], &mut || Ok(()), &cache)
                .unwrap_err()
                .to_string(),
            "NATIVE_ACCOUNT_ROOT"
        );
    }
    let expected = reference::apply_bounded(
        &db,
        &oversized,
        &[],
        &mut || Ok(()),
        trnm_mvcc_fee::pon_executor::growth::MAX_ACCOUNTS,
    )
    .unwrap();
    assert_eq!(
        apply_growth(&db, &oversized, &[], &mut || Ok(())).unwrap(),
        expected
    );
}

#[test]
fn native_apply_reader_keeps_insert_refusal_collision_rollback_and_cold_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("native-apply.sqlite");
    let mut db = Connection::open(&path).unwrap();
    let (state, parent) = fixture(&db, 8);
    let (after, changes) = change(&state, 3);
    let cache = LiftCache::default();
    verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
    let original = stored(&db);
    for collision in [false, true] {
        let mut expected = None;
        for arm in [Arm::Reference, Arm::Uncached, Arm::Cached] {
            let trace = SqlTrace::new(&mut db, true);
            let transaction = trace.db.unchecked_transaction().unwrap();
            if collision {
                let (owner, value) =
                    account(&changes[0].0, changes[0].2.as_ref().unwrap()).unwrap();
                let next = Node::account(owner, value);
                transaction
                    .execute(
                        "INSERT INTO archive_nodes VALUES(?,?)",
                        params![next.id.as_slice(), b"conflicting-current-bytes".as_slice()],
                    )
                    .unwrap();
            } else {
                transaction.execute_batch("CREATE TEMP TRIGGER refuse_native_apply BEFORE INSERT ON archive_nodes WHEN substr(NEW.data,1,1)=X'01' BEGIN SELECT RAISE(ABORT,'native apply write refused'); END").unwrap();
            }
            let result = observed(arm, &transaction, &trace, &parent, &changes, &cache, |_| {
                Ok(())
            });
            assert_eq!(result.0.as_ref().unwrap_err().0, ErrorKind::LocalStructure);
            if let Some(expected) = &expected {
                assert_eq!(&result, expected);
            } else {
                expected = Some(result);
            }
            transaction.rollback().unwrap();
            drop(trace);
            assert_eq!(stored(&db), original);
        }
    }
    let transaction = db.unchecked_transaction().unwrap();
    let next = candidate::apply_with_lifts(&transaction, &parent, &changes, &mut || Ok(()), &cache)
        .unwrap();
    transaction.commit().unwrap();
    let committed = stored(&db);
    drop(db);
    let reopened = Connection::open(&path).unwrap();
    assert_eq!(stored(&reopened), committed);
    verify(&reopened, &parent, &state, &mut || Ok(())).unwrap();
    verify(&reopened, &next, &after, &mut || Ok(())).unwrap();
}

#[cfg(unix)]
fn thread_cpu_ns() -> Option<u64> {
    let stamp = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(
        rustix::time::ClockId::ThreadCPUTime,
    ))
    .ok()?;
    let nanos = u64::try_from(stamp.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    u64::try_from(stamp.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(nanos)
}

#[cfg(unix)]
struct Sample {
    elapsed_ns: u64,
    cpu_ns: Option<u64>,
    result: Verdict,
    progress: usize,
    sql: SqlObservation,
    rows: Stored,
    decode_before: serde_json::Value,
    decode_after: serde_json::Value,
    diagnostic_equal: bool,
}

#[cfg(unix)]
fn sample(
    arm: Arm,
    db: &mut Connection,
    state: &State,
    root: &Root,
    changes: &[crate::store::Delta],
    warm: bool,
) -> Sample {
    // Every sample starts with a fresh arithmetic cache. "Warm" means exactly
    // the complete parent graph was checked once, as in publish_with_readback;
    // it does not mean a previous successful successor/rollback warmed it.
    let cache = LiftCache::default();
    if warm {
        verify_with_lifts(db, root, state, &mut || Ok(()), Some(&cache)).unwrap();
    }
    let decode_before = cache.decode_observation();
    let transaction = db.unchecked_transaction().unwrap();
    let mut progress = 0;
    let before_cpu = thread_cpu_ns();
    let started = std::time::Instant::now();
    let returned = verdict(run(
        arm,
        &transaction,
        root,
        changes,
        &mut || {
            progress += 1;
            Ok(())
        },
        &cache,
    ));
    std::hint::black_box(&returned);
    // Preserve the complete returned value for equality, then dispose of the
    // call's return before ending its interval. The same small copy is charged
    // in all arms. SQL transaction setup/rollback and inspection are outside.
    let result = returned.clone();
    drop(returned);
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap();
    let cpu_ns = before_cpu
        .zip(thread_cpu_ns())
        .and_then(|(a, b)| b.checked_sub(a));
    let rows = stored(&transaction);
    transaction.rollback().unwrap();
    let decode_after = cache.decode_observation();
    // A separate identical-input pass supplies SQL counts. The main interval
    // installs no SQL trace or new diagnostics beyond the shared callback count.
    // Reset arithmetic to the same declared cold/parent-warmed initial state.
    let diagnostic_cache = LiftCache::default();
    if warm {
        verify_with_lifts(db, root, state, &mut || Ok(()), Some(&diagnostic_cache)).unwrap();
    }
    let trace = SqlTrace::new(db, false);
    let transaction = trace.db.unchecked_transaction().unwrap();
    trace.start();
    let mut diagnostic_progress = 0;
    let diagnostic_result = verdict(run(
        arm,
        &transaction,
        root,
        changes,
        &mut || {
            diagnostic_progress += 1;
            Ok(())
        },
        &diagnostic_cache,
    ));
    let sql = trace.observation();
    let diagnostic_equal = diagnostic_result == result
        && diagnostic_progress == progress
        && stored(&transaction) == rows;
    transaction.rollback().unwrap();
    drop(trace);
    Sample {
        elapsed_ns,
        cpu_ns,
        result,
        progress,
        sql,
        rows,
        decode_before,
        decode_after,
        diagnostic_equal,
    }
}

#[cfg(unix)]
fn quantiles(values: &[u64]) -> (f64, u64) {
    assert_eq!(values.len(), 12);
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    // Even-sample median; nearest-rank p95 is the 12th of twelve observations.
    ((sorted[5] as f64 + sorted[6] as f64) / 2.0, sorted[11])
}

#[cfg(unix)]
#[test]
#[ignore = "fixed 12-pair complete-apply observation; not the original fixed-Host gate"]
fn native_apply_reader_paired_complete_apply_cost_observation() {
    assert!(
        std::hint::black_box(!cfg!(debug_assertions)),
        "release comparison required"
    );
    let mut all_cells_qualified = true;
    for count in [512u64, 1024] {
        let mut db = Connection::open_in_memory().unwrap();
        let (state, parent) = fixture(&db, count);
        let original = stored(&db);
        for changes_count in [1, count as usize / 4] {
            let (_, changes) = change(&state, changes_count);
            for warm in [false, true] {
                let mut elapsed: [Vec<u64>; 3] = std::array::from_fn(|_| Vec::new());
                let mut cpu: [Vec<u64>; 3] = std::array::from_fn(|_| Vec::new());
                let mut equivalent = true;
                for pair in 0..12 {
                    let order = if pair % 2 == 0 { [0, 1, 2] } else { [2, 1, 0] };
                    let mut samples: [Option<Sample>; 3] = std::array::from_fn(|_| None);
                    for (position, index) in order.into_iter().enumerate() {
                        let arm = [Arm::Reference, Arm::Cached, Arm::Uncached][index];
                        let value = sample(arm, &mut db, &state, &parent, &changes, warm);
                        elapsed[index].push(value.elapsed_ns);
                        if let Some(value) = value.cpu_ns {
                            cpu[index].push(value);
                        }
                        // Emit every raw sample before comparisons or summary.
                        // Failed/equal/slower observations are never filtered out.
                        eprintln!(
                            "pon_native_apply_reader_sample_v1 {}",
                            json!({
                                "accounts":count,"changed_accounts":changes_count,
                                "arithmetic_cache":if warm {"parent-graph-warmed"} else {"cold"},
                                "pair":pair,"position":position,"arm":format!("{arm:?}"),
                                "elapsed_ns":value.elapsed_ns,"thread_cpu_ns":value.cpu_ns,
                                "progress_callbacks":value.progress,"sql_from_independent_equivalence_pass":value.sql,
                            "independent_diagnostic_pass_equal":value.diagnostic_equal,
                                "outcome":format!("{:?}",value.result),
                                "decode_before":value.decode_before,"decode_after":value.decode_after,
                                "scope":"complete apply through returned-root disposal; transaction begin/rollback, cache setup and post-call inspection excluded; fresh cache each sample; no SQL trace in primary timed interval; SQL counters from separate equivalent pass",
                                "sql_database":"in-memory; SQLite page/statement caches are not declared cold",
                                "public_service_acceptance_qualified":false
                            })
                        );
                        samples[index] = Some(value);
                    }
                    let reference = samples[0].as_ref().unwrap();
                    let same = samples.iter().flatten().all(|sample| {
                        sample.diagnostic_equal
                            && sample.result == reference.result
                            && sample.result.is_ok()
                            && sample.progress == reference.progress
                            && sample.sql == reference.sql
                            && sample.rows == reference.rows
                    });
                    let restored = stored(&db) == original;
                    equivalent &= same && restored;
                    eprintln!(
                        "pon_native_apply_reader_pair_v1 {}",
                        json!({
                            "accounts":count,"changed_accounts":changes_count,"warm":warm,"pair":pair,
                            "root_all_stored_rows_errors_callbacks_sql_counts_equal":same,
                            "rollback_restored_all_parent_rows":restored,
                            "reference_elapsed_ns":samples[0].as_ref().unwrap().elapsed_ns,
                            "candidate_elapsed_ns":samples[1].as_ref().unwrap().elapsed_ns,
                            "uncached_fallback_elapsed_ns":samples[2].as_ref().unwrap().elapsed_ns,
                            "public_service_acceptance_qualified":false
                        })
                    );
                }
                let wall: [(f64, u64); 3] = std::array::from_fn(|index| quantiles(&elapsed[index]));
                let median_ratio = wall[1].0 / wall[0].0;
                let p95_ratio = wall[1].1 as f64 / wall[0].1 as f64;
                let qualified = equivalent && median_ratio <= 0.95 && p95_ratio <= 1.10;
                all_cells_qualified &= qualified;
                let cpu_quantiles: [Option<(f64, u64)>; 3] = std::array::from_fn(|index| {
                    (cpu[index].len() == 12).then(|| quantiles(&cpu[index]))
                });
                eprintln!(
                    "pon_native_apply_reader_cell_v1 {}",
                    json!({
                        "accounts":count,"changed_accounts":changes_count,"warm":warm,
                        "pairs":12,"arms":["Reference","Cached","Uncached"],
                        "wall_median_and_nearest_rank_p95_ns":wall,
                        "known_complete_cpu_median_and_nearest_rank_p95_ns":cpu_quantiles,
                        "candidate_reference_wall_median_ratio":median_ratio,
                        "candidate_reference_wall_p95_ratio":p95_ratio,
                        "state_and_control_equivalent":equivalent,
                        "finite_component_criterion_met":qualified,
                        "criterion":"every cell median improvement at least 5%, p95 regression at most 10%, complete state/control equivalence; all raw pairs retained",
                        "public_service_acceptance_qualified":false
                    })
                );
            }
        }
    }
    eprintln!(
        "pon_native_apply_reader_summary_v1 {}",
        json!({
            "cells":8,"pairs_per_cell":12,"arms_per_pair":3,
            "all_cells_qualified":all_cells_qualified,
            "failure_action":"retain all observations and do not enable the optimized default path",
            "original_fixed_host_gate_replaced":false,
            "public_service_acceptance_qualified":false
        })
    );
}

#[test]
fn native_apply_reader_pinned_statement_does_not_hide_foreign_wal_commit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("native-apply-wal.sqlite");
    let mut db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL").unwrap();
    let (state, parent) = fixture(&db, 8);
    let (_, changes) = change(&state, 2);
    let (owner, value) = account(&changes[0].0, changes[0].1.as_ref().unwrap()).unwrap();
    let leaf = Node::account(owner, value);
    let cache = LiftCache::default();
    verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
    let original = stored(&db);
    let foreign = Connection::open(&path).unwrap();
    let mut expected = None;
    for arm in [Arm::Reference, Arm::Uncached, Arm::Cached] {
        let mut committed = false;
        let trace = SqlTrace::new(&mut db, true);
        let result = observed(arm, trace.db, &trace, &parent, &changes, &cache, |call| {
            if call == 1 {
                // The current root read has completed, but its first descendant
                // has not been read. A live cursor would hide this WAL commit.
                assert_eq!(
                    foreign
                        .execute("DELETE FROM archive_nodes WHERE id=?", [leaf.id.as_slice()])?,
                    1
                );
                committed = foreign.is_autocommit();
            }
            Ok(())
        });
        drop(trace);
        assert!(committed);
        assert_eq!(result.0.as_ref().unwrap_err().0, ErrorKind::LocalStructure);
        if let Some(expected) = &expected {
            assert_eq!(&result, expected);
        } else {
            expected = Some(result);
        }
        foreign
            .execute(
                "INSERT INTO archive_nodes VALUES(?,?)",
                params![leaf.id.as_slice(), leaf.encode()],
            )
            .unwrap();
        assert_eq!(stored(&db), original);
    }
}

#[test]
fn native_apply_reader_warm_root_read_and_root_binding_precede_progress() {
    let mut db = Connection::open_in_memory().unwrap();
    let (state, parent) = fixture(&db, 8);
    let cache = LiftCache::default();
    verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
    for case in 0..4 {
        let mut expected = None;
        for arm in [Arm::Reference, Arm::Uncached, Arm::Cached] {
            let trace = SqlTrace::new(&mut db, true);
            let transaction = trace.db.unchecked_transaction().unwrap();
            let mut root = parent.clone();
            match case {
                0 => {
                    root.digest[0] ^= 1;
                }
                1 => {
                    root.count = 0;
                }
                2 => {
                    transaction
                        .execute(
                            "DELETE FROM archive_nodes WHERE id=?",
                            [root.node.unwrap().as_slice()],
                        )
                        .unwrap();
                }
                3 => {
                    transaction
                        .execute(
                            "UPDATE archive_nodes SET data=X'00' WHERE id=?",
                            [root.node.unwrap().as_slice()],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let result = observed(arm, &transaction, &trace, &root, &[], &cache, |_| {
                Err(Error::new(ErrorCode::PublicRequestCancelled))
            });
            assert_eq!(result.1, 0, "original root errors precede callbacks");
            assert_eq!(result.0.as_ref().unwrap_err().0, ErrorKind::LocalStructure);
            if let Some(expected) = &expected {
                assert_eq!(&result, expected);
            } else {
                expected = Some(result);
            }
            transaction.rollback().unwrap();
        }
    }
}

#[test]
fn native_apply_reader_cached_valid_bytes_keep_side_prefix_depth_and_edge_hash_checks() {
    let mut db = Connection::open_in_memory().unwrap();
    let (state, parent) = fixture(&db, 64);
    let cache = LiftCache::default();
    verify_with_lifts(&db, &parent, &state, &mut || Ok(()), Some(&cache)).unwrap();
    // A real non-root fork with a fork on its left lets the prefix case alter
    // encoded path bits without changing the child digest or its lifted hash.
    let original = stored(&db)
        .into_iter()
        .find_map(|(id, value)| {
            let rusqlite::types::Value::Blob(bytes) = value else {
                return None;
            };
            let node = Node::decode(id.try_into().unwrap(), &bytes).unwrap();
            let Kind::Fork { left, .. } = node.kind else {
                return None;
            };
            (node.depth > 0
                && matches!(
                    archive::load_node(&db, left).unwrap().kind,
                    Kind::Fork { .. }
                ))
            .then_some(node)
        })
        .unwrap();
    let (key, value) = state
        .iter()
        .find(|(key, value)| {
            let (owner, _) = account(key, &serde_json::to_vec(value).unwrap()).unwrap();
            archive::path(owner) == original.path
        })
        .unwrap();
    let mut next = value.clone();
    next["balance"] = json!(value["balance"].as_u64().unwrap() + 1);
    next["nonce"] = json!(value["nonce"].as_u64().unwrap() + 1);
    let changes = vec![(
        key.clone(),
        Some(serde_json::to_vec(value).unwrap()),
        Some(serde_json::to_vec(&next).unwrap()),
    )];
    let empty = empty_hashes();
    for case in ["side", "prefix", "depth", "edge-hash"] {
        let trace = SqlTrace::new(&mut db, true);
        let transaction = trace.db.unchecked_transaction().unwrap();
        let mut forged = original.clone();
        let Kind::Fork {
            mut left,
            mut right,
            mut left_hash,
            right_hash,
        } = forged.kind
        else {
            unreachable!();
        };
        match case {
            "side" => {
                std::mem::swap(&mut left, &mut right);
            }
            "prefix" => {
                let mut child = archive::load_node(&transaction, left).unwrap();
                child.path[0] ^= 0x80;
                let bytes = child.encode();
                child.id =
                    trnm_protocol::pon_wire::hash(b"account-archive-node-record-v1", &[&bytes]);
                archive::save_node(&transaction, &child).unwrap();
                // Bits before the parent's depth do not enter this lift, so
                // hash equality alone cannot reject the malformed prefix.
                assert_eq!(child.lift(original.depth + 1, &empty), left_hash);
                left = child.id;
                NodeReader::new(&transaction)
                    .load(left, Some(&cache))
                    .unwrap();
            }
            "depth" => {
                forged.depth = 255;
            }
            "edge-hash" => {
                left_hash[0] ^= 1;
            }
            _ => unreachable!(),
        }
        forged.kind = Kind::Fork {
            left,
            right,
            left_hash,
            right_hash,
        };
        let bytes = forged.encode();
        let id = trnm_protocol::pon_wire::hash(b"account-archive-node-record-v1", &[&bytes]);
        // Both original decode and cached decode accept these content-addressed
        // bytes. Only the current edge relationship must reject application.
        let forged = Node::decode(id, &bytes).unwrap();
        archive::save_node(&transaction, &forged).unwrap();
        NodeReader::new(&transaction)
            .load(forged.id, Some(&cache))
            .unwrap();
        let root = Root {
            node: Some(forged.id),
            digest: forged.lift(0, &empty),
            count: parent.count,
            balance: parent.balance,
        };
        let mut expected = None;
        for arm in [Arm::Reference, Arm::Uncached, Arm::Cached] {
            let result = observed(arm, &transaction, &trace, &root, &changes, &cache, |_| {
                Ok(())
            });
            assert_eq!(
                result.1, 1,
                "{case}: must reach original first edge boundary"
            );
            let error = result.0.as_ref().unwrap_err();
            assert_eq!(error.0, ErrorKind::LocalStructure);
            assert_eq!(error.2, "NATIVE_ACCOUNT_STORE:CorruptRecord");
            if let Some(expected) = &expected {
                assert_eq!(&result, expected, "{case} {arm:?}");
            } else {
                expected = Some(result);
            }
        }
        transaction.rollback().unwrap();
    }
}
