//! The original JOIN is an independent executable oracle. Synthetic retained
//! header fixtures exercise this reader only; they do not qualify W1 or State.
//! Cold recovery below separately uses genuinely admitted blocks. The guarded
//! candidate is test-only and has not passed a cost gate; production keeps the
//! original JOIN, even when these semantic/measurement controls pass.
use super::*;
use crate::store::HISTORY_HEADER_BATCH;
use crate::{consensus, development_public, ErrorCode, Packet, Settings};
use rusqlite::{types::Value as SqlValue, Connection, StatementStatus};
use trnm_crypto_primitives::pon_work;
use trnm_protocol::pon_wire::Header;

const REFERENCE_SQL: &str = "WITH RECURSIVE ancestry(id,parent,ordinal) AS (
         SELECT id,parent,0 FROM blocks WHERE id=?1 AND id!=?2
         UNION ALL
         SELECT b.id,b.parent,a.ordinal+1
         FROM ancestry a JOIN blocks b ON b.id=a.parent
         WHERE b.id!=?2 LIMIT ?3
     )
     SELECT b.parent,b.height,b.chainwork,b.state_root,substr(b.packet,1,?4),
         substr(b.packet,-32),length(b.packet),p.height,p.chainwork,p.parent,
         p.state_root,b.id,a.ordinal
     FROM ancestry a JOIN blocks b ON b.id=a.id
     LEFT JOIN blocks p ON p.id=b.parent ORDER BY a.ordinal";

fn reference(
    node: &Node,
    start: Hash,
    maximum: u64,
    visit: &mut impl FnMut(Hash, StoredHeaderLink) -> Result<()>,
) -> Result<(Hash, u64)> {
    ensure(
        (1..=HISTORY_HEADER_BATCH).contains(&maximum),
        "ANCESTRY_LIMIT",
    )?;
    if start == node.settings.genesis() {
        return Ok((start, 0));
    }
    let mut statement = node.db.prepare_cached(REFERENCE_SQL)?;
    node.count_header_query();
    let mut rows = statement.query(params![
        start.as_slice(),
        node.settings.genesis().as_slice(),
        maximum,
        node.settings.packet_header_length(),
    ])?;
    let mut current = start;
    let mut checked = 0;
    while let Some(row) = rows.next()? {
        let id = bytes32(row.get(11)?)?;
        ensure(
            checked < maximum && row.get::<_, u64>(12)? == checked && id == current,
            "ANCESTRY_HEIGHT",
        )
        .map_err(Error::local_integrity)?;
        let link = node.check_header_projection(id, HeaderProjection::read(row)?)?;
        current = link.header.parent;
        visit(id, link)?;
        checked = checked.checked_add(1).ok_or("ANCESTRY_LIMIT")?;
    }
    let complete = ensure(
        checked == maximum || current == node.settings.genesis(),
        "UNKNOWN_PARENT",
    );
    if checked == 0 {
        complete?;
    } else {
        complete.map_err(Error::local_integrity)?;
    }
    Ok((current, checked))
}

struct Fixture {
    node: Node,
    directory: tempfile::TempDir,
    ids: Vec<Hash>,
}

fn append_material(node: &Node, parent: Hash, timestamp: u64, nonce: u64) -> Hash {
    let before = node.record(parent).unwrap();
    let header = Header {
        network: node.settings.network(),
        parameters: node.settings.parameters(),
        parent,
        height: before.height + 1,
        timestamp,
        target: [255; 32],
        miner: [11; 32],
        transactions: [12; 32],
        state: [13; 32],
        receipts: [14; 32],
        work_task: [15; 32],
        nonce,
    };
    // This is deliberately not admitted work: this bounded-reader fixture
    // needs actual canonical header/trace/id/parent/work/root SQL material.
    let packet = Packet {
        header,
        transactions: vec![],
        proof: vec![0; pon_work::PROOF_BYTES],
    };
    let id = packet.id().unwrap();
    let work = before
        .work
        .checked_add(consensus::required_work(packet.header.target).unwrap())
        .unwrap();
    node.db
        .execute(
            "INSERT INTO blocks VALUES(?,?,?,?,?,?)",
            params![
                id.as_slice(),
                parent.as_slice(),
                packet.header.height,
                work.bytes().as_slice(),
                packet.encode().unwrap(),
                packet.header.state.as_slice(),
            ],
        )
        .unwrap();
    id
}

fn fixture(count: u64) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(directory.path(), Settings::development(Some(1)).unwrap(), 1).unwrap();
    node.db.set_prepared_statement_cache_capacity(128);
    let mut ids = vec![node.settings.genesis()];
    for height in 1..=count {
        ids.push(append_material(&node, *ids.last().unwrap(), height + 10, 0));
    }
    Fixture {
        node,
        directory,
        ids,
    }
}

fn same_error(actual: Error, expected: Error) {
    assert_eq!(actual.to_string(), expected.to_string());
    assert_eq!(actual.kind(), expected.kind());
    assert_eq!(actual.requires_owner_stop(), expected.requires_owner_stop());
}

#[derive(Debug, PartialEq, Eq)]
struct Link {
    id: Hash,
    header: Header,
    parent: Option<Hash>,
    height: u64,
    root: Hash,
    work: [u8; 64],
    parent_work: [u8; 64],
}
fn collect(
    node: &Node,
    tip: Hash,
    maximum: u64,
    optimized: bool,
) -> Result<(Hash, u64, Vec<Link>)> {
    let mut links = Vec::new();
    let mut take = |id, link: StoredHeaderLink| {
        links.push(Link {
            id,
            header: link.header,
            parent: link.record.parent,
            height: link.record.height,
            root: link.record.root,
            work: link.record.work.bytes(),
            parent_work: link.parent_work.bytes(),
        });
        Ok(())
    };
    let (next, count) = if optimized {
        ensure((1..=HISTORY_HEADER_BATCH).contains(&maximum), "ANCESTRY_LIMIT")?;
        if tip == node.settings.genesis() {
            (tip, 0)
        } else {
            super::visit(node, tip, maximum, &mut take)?
        }
    } else {
        reference(node, tip, maximum, &mut take)?
    };
    Ok((next, count, links))
}

fn refuses_like_reference(node: &Node, tip: Hash) {
    same_error(
        collect(node, tip, HISTORY_HEADER_BATCH, true).unwrap_err(),
        collect(node, tip, HISTORY_HEADER_BATCH, false).unwrap_err(),
    );
}

#[test]
fn adjacent_material_matches_original_on_forks_and_batch_boundaries() {
    let f = fixture(70);
    let fork = append_material(&f.node, f.ids[40], 900, 7);
    for tip in [
        f.ids[0], f.ids[1], f.ids[63], f.ids[64], f.ids[65], f.ids[70], fork,
    ] {
        for maximum in [1, 2, 11, 16, 63, 64] {
            assert_eq!(
                collect(&f.node, tip, maximum, true).unwrap(),
                collect(&f.node, tip, maximum, false).unwrap()
            );
        }
    }
    refuses_like_reference(&f.node, [99; 32]);
    for maximum in [0, HISTORY_HEADER_BATCH + 1] {
        same_error(
            collect(&f.node, f.ids[70], maximum, true).unwrap_err(),
            collect(&f.node, f.ids[70], maximum, false).unwrap_err(),
        );
    }
}

#[test]
fn adjacent_material_preserves_corruption_types_and_first_error_order() {
    let f = fixture(70);
    for height in [6, 7, 69, 70] {
        for (column, corrupt) in [
            ("height", SqlValue::Integer(-1)),
            ("height", SqlValue::Text("not-an-integer".into())),
            ("parent", SqlValue::Blob(vec![0; 33])),
            ("parent", SqlValue::Integer(1)),
            ("chainwork", SqlValue::Blob(vec![0; 65])),
            ("chainwork", SqlValue::Text("not-a-blob".into())),
            ("state_root", SqlValue::Blob(vec![0; 33])),
            ("state_root", SqlValue::Integer(1)),
            ("packet", SqlValue::Blob(vec![0; 3])),
            ("packet", SqlValue::Text("not-a-packet".into())),
        ] {
            f.node
                .db
                .execute_batch("SAVEPOINT material_corruption")
                .unwrap();
            f.node
                .db
                .execute(
                    &format!("UPDATE blocks SET {column}=? WHERE id=?"),
                    params![corrupt, f.ids[height].as_slice()],
                )
                .unwrap();
            refuses_like_reference(&f.node, f.ids[70]);
            f.node
                .db
                .execute_batch("ROLLBACK TO material_corruption; RELEASE material_corruption")
                .unwrap();
        }
    }
    // Current packet decoding follows all SQL field conversions. An invalid
    // typed parent work column therefore precedes a current header-codec error.
    let raw: Vec<u8> = f
        .node
        .db
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [f.ids[70].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    for parent_work in [
        SqlValue::Text("wrong-type".into()),
        SqlValue::Blob(vec![0; 3]),
    ] {
        f.node.db.execute_batch("SAVEPOINT first_error").unwrap();
        let mut bad = raw.clone();
        bad[0] ^= 255;
        f.node
            .db
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![bad, f.ids[70].as_slice()],
            )
            .unwrap();
        f.node
            .db
            .execute(
                "UPDATE blocks SET chainwork=? WHERE id=?",
                params![parent_work, f.ids[69].as_slice()],
            )
            .unwrap();
        refuses_like_reference(&f.node, f.ids[70]);
        f.node
            .db
            .execute_batch("ROLLBACK TO first_error; RELEASE first_error")
            .unwrap();
    }
    assert_eq!(
        collect(&f.node, f.ids[70], 64, true).unwrap(),
        collect(&f.node, f.ids[70], 64, false).unwrap()
    );
}

#[test]
fn adjacent_material_keeps_boundary_parent_header_outside_the_validation_window() {
    let f = fixture(70);
    let expected = collect(&f.node, f.ids[70], 64, false).unwrap();
    // Height six is only the final header's parent. Its packet is not parsed,
    // while all its original record fields remain mandatory.
    f.node.db.execute_batch("SAVEPOINT boundary").unwrap();
    f.node
        .db
        .execute(
            "UPDATE blocks SET packet=x'00' WHERE id=?",
            [f.ids[6].as_slice()],
        )
        .unwrap();
    assert_eq!(collect(&f.node, f.ids[70], 64, true).unwrap(), expected);
    assert_eq!(collect(&f.node, f.ids[70], 64, false).unwrap(), expected);
    assert!(f.node.check_observed_history(f.ids[70], 100_000).is_err());
    for column in ["chainwork", "state_root", "parent"] {
        f.node.db.execute_batch("SAVEPOINT boundary_shape").unwrap();
        f.node
            .db
            .execute(
                &format!("UPDATE blocks SET {column}=zeroblob(1048576) WHERE id=?"),
                [f.ids[6].as_slice()],
            )
            .unwrap();
        refuses_like_reference(&f.node, f.ids[70]);
        f.node
            .db
            .execute_batch("ROLLBACK TO boundary_shape; RELEASE boundary_shape")
            .unwrap();
    }
    f.node
        .db
        .execute_batch("ROLLBACK TO boundary; RELEASE boundary")
        .unwrap();
    // Missing internal ancestors remain local integrity failures, and even a
    // malformed cycle is bounded by the original 64-header limit.
    f.node.db.execute_batch("SAVEPOINT missing").unwrap();
    f.node
        .db
        .execute("DELETE FROM blocks WHERE id=?", [f.ids[6].as_slice()])
        .unwrap();
    refuses_like_reference(&f.node, f.ids[70]);
    f.node
        .db
        .execute_batch("ROLLBACK TO missing; RELEASE missing")
        .unwrap();
    f.node.db.execute_batch("SAVEPOINT cycle").unwrap();
    f.node
        .db
        .execute(
            "UPDATE blocks SET parent=id WHERE id=?",
            [f.ids[69].as_slice()],
        )
        .unwrap();
    refuses_like_reference(&f.node, f.ids[70]);
    f.node
        .db
        .execute_batch("ROLLBACK TO cycle; RELEASE cycle")
        .unwrap();
}

fn observed_reference(
    node: &Node,
    tip: Hash,
    now: u64,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    progress()?;
    let bound = now as u128 + node.settings.limit("future_skew_seconds")? as u128;
    let mut current = tip;
    while current != node.settings.genesis() {
        progress()?;
        (current, _) = reference(node, current, 64, &mut |_, link| {
            progress()?;
            ensure(link.header.timestamp as u128 <= bound, "TIME_DEFERRED")
        })?;
    }
    progress()
}

#[test]
fn observed_time_rechecks_current_bound_and_each_original_cancellation() {
    let f = fixture(0);
    let first = append_material(&f.node, f.ids[0], 1_000_000, 1);
    let tip = append_material(&f.node, first, 11, 2);
    f.node.check_observed_history(tip, 1_000_000).unwrap();
    // A later narrow bound must still see the older, future-dated ancestor.
    let error = f.node.check_observed_history(tip, 0).unwrap_err();
    assert_eq!(error.to_string(), "TIME_DEFERRED");
    same_error(
        error,
        observed_reference(&f.node, tip, 0, &mut || Ok(())).unwrap_err(),
    );
    let mut total = 0;
    observed_reference(&f.node, tip, 1_000_000, &mut || {
        total += 1;
        Ok(())
    })
    .unwrap();
    for code in [
        ErrorCode::PublicRequestCancelled,
        ErrorCode::PublicMutationCpuBudget,
    ] {
        for cut in 1..=total {
            let mut calls = 0;
            let actual = f
                .node
                .check_observed_history_with_progress(tip, 1_000_000, &mut || {
                    calls += 1;
                    if calls == cut {
                        Err(Error::new(code))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert_eq!(calls, cut);
            calls = 0;
            let expected = observed_reference(&f.node, tip, 1_000_000, &mut || {
                calls += 1;
                if calls == cut {
                    Err(Error::new(code))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            same_error(actual, expected);
            assert!(f.node.db.is_autocommit());
        }
    }
    f.node.check_observed_history(tip, 1_000_000).unwrap();
}

#[test]
fn adjacent_material_is_not_reused_after_write_rollback_or_foreign_commit() {
    let f = fixture(70);
    let expected = collect(&f.node, f.ids[70], 64, false).unwrap();
    assert_eq!(collect(&f.node, f.ids[70], 64, true).unwrap(), expected);
    for control in ["SAVEPOINT changed", "BEGIN IMMEDIATE"] {
        f.node.db.execute_batch(control).unwrap();
        f.node
            .db
            .execute(
                "UPDATE blocks SET state_root=zeroblob(3) WHERE id=?",
                [f.ids[69].as_slice()],
            )
            .unwrap();
        refuses_like_reference(&f.node, f.ids[70]);
        f.node.db.execute_batch("ROLLBACK").unwrap();
        f.node
            .db
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .unwrap();
        assert_eq!(collect(&f.node, f.ids[70], 64, true).unwrap(), expected);
    }
    let foreign = Connection::open(f.directory.path().join("native.sqlite")).unwrap();
    let original: Vec<u8> = foreign
        .query_row(
            "SELECT state_root FROM blocks WHERE id=?",
            [f.ids[69].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    foreign
        .execute(
            "UPDATE blocks SET state_root=zeroblob(3) WHERE id=?",
            [f.ids[69].as_slice()],
        )
        .unwrap();
    refuses_like_reference(&f.node, f.ids[70]);
    foreign
        .execute(
            "UPDATE blocks SET state_root=? WHERE id=?",
            params![original, f.ids[69].as_slice()],
        )
        .unwrap();
    assert_eq!(collect(&f.node, f.ids[70], 64, true).unwrap(), expected);
}

#[test]
fn observed_time_cold_open_reads_real_admitted_history_again() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let mut tip = settings.genesis();
    for height in 1..=3 {
        let packet = node
            .make(
                tip,
                vec![],
                development_public(0).unwrap(),
                1 + height * 10,
                4096,
            )
            .unwrap();
        tip = node.admit(&packet, 100_000).unwrap();
        node.activate_observed(tip, 100_000).unwrap();
    }
    node.check_observed_history(tip, 100_000).unwrap();
    let expected = node.read_active().unwrap();
    drop(node);
    let node = Node::open(directory.path(), settings, 1).unwrap();
    let before = node.history_read_counters();
    node.check_observed_history(tip, 100_000).unwrap();
    let after = node.history_read_counters();
    assert_eq!(after.header_link_queries - before.header_link_queries, 1);
    assert_eq!(
        after.header_trace_bytes - before.header_trace_bytes,
        3 * (node.settings.packet_header_length() as u64 + 32)
    );
    assert_eq!(node.read_active().unwrap(), expected);
    node.db
        .execute(
            "UPDATE blocks SET state_root=zeroblob(3) WHERE id=?",
            [tip.as_slice()],
        )
        .unwrap();
    refuses_like_reference(&node, tip);
}

#[test]
fn adjacent_material_binds_current_profile_and_actual_connection() {
    let mut f = fixture(70);
    let other = fixture(70);
    assert_eq!(
        collect(&f.node, f.ids[70], 64, true).unwrap(),
        collect(&other.node, other.ids[70], 64, true).unwrap()
    );
    other
        .node
        .db
        .execute(
            "UPDATE blocks SET state_root=zeroblob(3) WHERE id=?",
            [other.ids[69].as_slice()],
        )
        .unwrap();
    refuses_like_reference(&other.node, other.ids[70]);
    collect(&f.node, f.ids[70], 64, true).unwrap();
    // Changing the selected packet namespace cannot borrow an earlier classic
    // decode. Every actual projection uses today's Settings/profile again.
    f.node.settings.app.params["native_pq_accounts_profile"] =
        serde_json::json!("unvalidated-profile");
    refuses_like_reference(&f.node, f.ids[70]);
    f.node
        .settings
        .app
        .params
        .as_object_mut()
        .unwrap()
        .remove("native_pq_accounts_profile");
    collect(&f.node, f.ids[70], 64, true).unwrap();
}

fn counters(db: &Connection, sql: &str) -> (i32, i32) {
    let statement = db.prepare_cached(sql).unwrap();
    (
        statement.reset_status(StatementStatus::Run),
        statement.reset_status(StatementStatus::VmStep),
    )
}

#[test]
fn full_batches_report_guarded_candidate_cost_without_promoting_runtime() {
    let f = fixture(130);
    collect(&f.node, f.ids[130], 64, false).unwrap();
    collect(&f.node, f.ids[130], 64, true).unwrap();
    counters(&f.node.db, REFERENCE_SQL);
    counters(&f.node.db, HEADER_MATERIAL_SQL);
    let before = f.node.history_read_counters();
    let original = collect(&f.node, f.ids[130], 64, false).unwrap();
    let reference_reads = f.node.history_read_counters();
    let reference_sql = counters(&f.node.db, REFERENCE_SQL);
    let current = collect(&f.node, f.ids[130], 64, true).unwrap();
    let candidate_reads = f.node.history_read_counters();
    let candidate_sql = counters(&f.node.db, HEADER_MATERIAL_SQL);
    assert_eq!(current, original);
    assert_eq!(reference_sql.0, 1);
    assert_eq!(candidate_sql.0, 1);
    assert!(candidate_sql.1 > 0 && reference_sql.1 > 0);
    assert_eq!(
        reference_reads.header_link_queries - before.header_link_queries,
        1
    );
    assert_eq!(
        candidate_reads.header_link_queries - reference_reads.header_link_queries,
        1
    );
    let bytes = 64 * (f.node.settings.packet_header_length() as u64 + 32);
    assert_eq!(
        reference_reads.header_trace_bytes - before.header_trace_bytes,
        bytes
    );
    assert_eq!(
        candidate_reads.header_trace_bytes - reference_reads.header_trace_bytes,
        bytes
    );
    // A semantic pass cannot activate the candidate. The actual runtime entry
    // still runs its original statement and never executes HEADER_MATERIAL_SQL.
    let mut runtime_ids = Vec::new();
    let runtime = f
        .node
        .visit_header_batch_limited(f.ids[130], 64, &mut |id, _| {
            runtime_ids.push(id);
            Ok(())
        })
        .unwrap();
    assert_eq!(runtime, (original.0, original.1));
    assert_eq!(
        runtime_ids,
        original.2.iter().map(|link| link.id).collect::<Vec<_>>()
    );
    assert_eq!(counters(&f.node.db, HEADER_MATERIAL_SQL).0, 0);
    println!(
        "{}",
        serde_json::json!({
            "schema":"pon-adjacent-header-material-work-v1",
            "fixture":"synthetic retained header/record material, not admitted W1/State",
            "headers":64,"maximum_material_rows":65,"maximum_rust_material_rows":2,
            "reference_sql_runs":reference_sql.0,"candidate_sql_runs":candidate_sql.0,
            "reference_vm_steps":reference_sql.1,"candidate_vm_steps":candidate_sql.1,
            "candidate_vm_reduction_observed":candidate_sql.1 < reference_sql.1,
            "header_trace_bytes_returned_per_arm":bytes,
            "candidate_status":"NO_GO_TEST_ONLY_NOT_IN_RUNTIME",
            "runtime_reader":"original ordered JOIN",
            "host_checkpoints_removed":0,"cross_call_verdicts_retained":0,
            "complete_history_asymptotic_cost":"linear",
            "whole_service_slo_qualified":false,"throughput_qualified":false
        })
    );
}
