use super::*;

pub(super) fn genesis(config: &CellVersionRetentionConfigV3) -> CellVersionCatalogAnchorV3 {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-version-retention-genesis.v3\0");
    hash.update(config.retention.store_id);
    hash.update(config.retention.capacity_bytes.to_be_bytes());
    hash.update(config.retention.maximum_obligations.to_be_bytes());
    hash.update(config.maximum_versions.to_be_bytes());
    hash.update(config.maximum_metadata_bytes.to_be_bytes());
    CellVersionCatalogAnchorV3 {
        generation: 0,
        commitment: hash.finalize().into(),
    }
}

pub(super) fn configure(connection: &Connection) -> CellResultV1<()> {
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    // Logical metadata is capped below 64 MiB. This separate file-size ceiling
    // includes SQLite pages and refuses unexpected growth instead of truncation.
    connection.pragma_update(None, "max_page_count", 32768_u32)?;
    Ok(())
}

pub(super) fn check_directory(directory: &Path) -> CellResultV1<()> {
    let metadata = fs::symlink_metadata(directory)?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "version retention directory",
    )?;
    let metadata = fs::symlink_metadata(directory.join("versions.sqlite"))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "version retention database",
    )
}

pub(super) fn write_catalog_until<T>(
    connection: &mut Connection,
    deadline: Instant,
    write: impl FnOnce(&Connection) -> CellResultV1<T>,
) -> CellResultV1<T> {
    check_deadline(deadline)?;
    let original_ms: u64 = connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    let original = Duration::from_millis(original_ms);
    connection.busy_timeout(original.min(deadline.saturating_duration_since(Instant::now())))?;
    let result = (|| {
        check_deadline(deadline)?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        check_deadline(deadline)?;
        let result = write(&transaction)?;
        check_deadline(deadline)?;
        transaction
            .busy_timeout(original.min(deadline.saturating_duration_since(Instant::now())))?;
        check_deadline(deadline)?;
        transaction.commit()?;
        // A late refusal cannot undo a durable commit. The original operation
        // and this append-only event remain available for target-only recovery.
        check_deadline(deadline)?;
        Ok(result)
    })();
    connection.busy_timeout(original)?;
    result
}

pub(super) fn require_anchor(
    connection: &Connection,
    config: &CellVersionRetentionConfigV3,
    expected: CellVersionCatalogAnchorV3,
    actual: CellVersionCatalogAnchorV3,
) -> CellResultV1<()> {
    require(
        expected.generation <= actual.generation,
        "version retention catalog rollback",
    )?;
    let known = if expected.generation == 0 {
        genesis(config).commitment
    } else {
        digest(connection.query_row(
            "SELECT checksum FROM version_events WHERE generation=?1",
            [expected.generation],
            |row| row.get(0),
        )?)?
    };
    require(
        known == expected.commitment,
        "version retention catalog anchor",
    )
}

pub(super) fn audit(
    connection: &Connection,
    config: &CellVersionRetentionConfigV3,
    deadline: Instant,
) -> CellResultV1<AuditedCatalog> {
    check_deadline(deadline)?;
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let page_size: u32 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    require(
        application == APPLICATION_ID && version == 3 && page_size == 4096,
        "version retention namespace",
    )?;
    for (name, expected) in [
        ("metadata", META_SQL),
        ("version_duties", DUTIES_SQL),
        ("version_events", EVENTS_SQL),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        require(
            actual.as_deref() == Some(expected),
            "version retention schema",
        )?;
    }
    let objects: u64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'",
        [],
        |row| row.get(0),
    )?;
    require(objects == 3, "version retention schema")?;
    let metadata_rows: u64 =
        connection.query_row("SELECT count(*) FROM metadata", [], |row| row.get(0))?;
    require(metadata_rows == 1, "version retention metadata singleton")?;
    let (store_id, maximum, maximum_bytes, generation, tip): (Vec<u8>, u32, u64, u64, Vec<u8>) = connection.query_row(
        "SELECT store_id,maximum_versions,maximum_metadata_bytes,generation,tip FROM metadata WHERE singleton=1", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    require(
        store_id.as_slice() == config.retention.store_id
            && maximum == config.maximum_versions
            && maximum_bytes == config.maximum_metadata_bytes,
        "version retention stored configuration",
    )?;
    let (count, metadata_bytes): (u64, u64) = connection.query_row(
        "SELECT count(*),coalesce(sum(length(wire)),0) FROM version_duties",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    require(
        count <= u64::from(config.maximum_versions)
            && metadata_bytes <= config.maximum_metadata_bytes,
        "version retention catalog capacity",
    )?;
    let mut statement =
        connection.prepare("SELECT operation FROM version_duties ORDER BY operation")?;
    let mut query = statement.query([])?;
    let mut rows = Vec::with_capacity(count as usize);
    while let Some(row) = query.next()? {
        check_deadline(deadline)?;
        rows.push(required_row(connection, config, digest(row.get(0)?)?)?);
    }
    validate_relationships(&rows, config, deadline)?;
    let event_count: u64 =
        connection.query_row("SELECT count(*) FROM version_events", [], |row| row.get(0))?;
    require(
        event_count == generation && generation <= 3 * count,
        "version retention event capacity",
    )?;
    let mut expected = genesis(config);
    let mut states: BTreeMap<CellDigestV1, (u8, u64)> = BTreeMap::new();
    let by_id: BTreeMap<_, _> = rows
        .iter()
        .map(|row| (row.contract.operation, row))
        .collect();
    let mut events = connection.prepare("SELECT generation,operation,contract,status,previous,checksum FROM version_events ORDER BY generation")?;
    let mut query = events.query([])?;
    while let Some(event) = query.next()? {
        check_deadline(deadline)?;
        let current: u64 = event.get(0)?;
        let operation = digest(event.get(1)?)?;
        let commitment = digest(event.get(2)?)?;
        let status: u8 = event.get(3)?;
        let previous = digest(event.get(4)?)?;
        let checksum = digest(event.get(5)?)?;
        require(
            current == expected.generation + 1 && previous == expected.commitment,
            "version retention event chain",
        )?;
        let row = by_id
            .get(&operation)
            .ok_or(CellErrorV1::Invalid("version retention event without duty"))?;
        require(
            commitment == row.contract.commitment(config)?,
            "version retention event contract",
        )?;
        let next_status = states.get(&operation).map_or(0, |(prior, _)| prior + 1);
        require(
            status == next_status && status <= 2,
            "version retention state regression",
        )?;
        if status == 0 {
            if let Some(link) = &row.contract.snapshot {
                require(
                    states
                        .get(&link.predecessor_operation)
                        .is_some_and(|(state, _)| *state >= 1),
                    "version retention snapshot predecessor not previously complete",
                )?;
            }
        }
        require(
            checksum == event_checksum(config, current, operation, commitment, status, previous),
            "version retention event integrity",
        )?;
        states.insert(operation, (status, current));
        expected = CellVersionCatalogAnchorV3 {
            generation: current,
            commitment: checksum,
        };
    }
    require(
        expected.generation == generation && expected.commitment.as_slice() == tip,
        "version retention catalog head",
    )?;
    for row in &rows {
        require(
            states.get(&row.contract.operation) == Some(&(row.status, row.generation)),
            "version retention duty/event disagreement",
        )?;
    }
    check_deadline(deadline)?;
    Ok(AuditedCatalog {
        rows,
        anchor: expected,
        metadata_bytes,
    })
}

pub(super) fn validate_relationships(
    rows: &[DutyRow],
    config: &CellVersionRetentionConfigV3,
    deadline: Instant,
) -> CellResultV1<()> {
    let mut operations: BTreeMap<CellDigestV1, (bool, CellDigestV1)> = BTreeMap::new();
    let mut funding = BTreeMap::new();
    let mut object_terms = BTreeMap::new();
    let mut live_manifests = BTreeMap::new();
    let mut snapshots = BTreeSet::new();
    let mut protected = 0;
    let mut protected_version_bytes = 0_usize;
    for row in rows {
        check_deadline(deadline)?;
        let contract = &row.contract;
        require(
            operations
                .insert(contract.operation, (true, contract.operation))
                .is_none(),
            "version retention operation alias",
        )?;
        require(
            funding
                .insert(contract.funding_operation, (true, contract.operation))
                .is_none(),
            "version retention funding alias",
        )?;
        if row.status != 2 {
            protected += 1;
            protected_version_bytes = protected_version_bytes
                .checked_add(contract.version.encode().len())
                .ok_or(CellErrorV1::Invalid("version retention protected metadata"))?;
        }
        for object in &contract.objects {
            let identity = (false, object.operation);
            if let Some(old) = operations.insert(object.operation, identity) {
                require(old == identity, "version retention operation alias")?;
            }
            if let Some(old) = funding.insert(object.funding_operation, identity) {
                require(old == identity, "version retention funding alias")?;
            }
            let commitment = object.commitment(config.retention.store_id);
            if let Some(old) = object_terms.insert(object.operation, commitment) {
                require(
                    old == commitment,
                    "version retention shared object contract changed",
                )?;
            }
            if row.status != 2 {
                if let Some(old) = live_manifests.insert(object.manifest.id(), object.operation) {
                    require(
                        old == object.operation,
                        "version retention shared object operation alias",
                    )?;
                }
            }
        }
        if let Some(link) = &contract.snapshot {
            require(
                snapshots.insert((link.schedule, link.ordinal)),
                "version retention snapshot identity replay",
            )?;
            let prior = rows
                .iter()
                .find(|candidate| candidate.contract.operation == link.predecessor_operation)
                .ok_or(CellErrorV1::Invalid(
                    "version retention unknown snapshot predecessor",
                ))?;
            require(
                prior.status >= 1
                    && prior.contract.commitment(config)? == link.predecessor_contract
                    && prior.contract.operation != contract.operation,
                "version retention snapshot predecessor",
            )?;
            if link.ordinal > 1 {
                let previous = prior
                    .contract
                    .snapshot
                    .as_ref()
                    .ok_or(CellErrorV1::Invalid(
                        "version retention snapshot cursor gap",
                    ))?;
                require(
                    previous.schedule == link.schedule
                        && previous.ordinal.checked_add(1) == Some(link.ordinal)
                        && previous.due_height < link.due_height,
                    "version retention snapshot cursor gap",
                )?;
            } else {
                require(
                    prior
                        .contract
                        .snapshot
                        .as_ref()
                        .is_none_or(|previous| previous.schedule != link.schedule),
                    "version retention snapshot cursor reset",
                )?;
            }
        }
    }
    require(
        operations.keys().all(|id| !funding.contains_key(id)),
        "version retention operation/funding alias",
    )?;
    require(
        protected <= MAX_PROTECTED_VERSIONS && protected_version_bytes <= 32 * 1024 * 1024,
        "version retention protected capacity",
    )?;
    require(
        object_terms.len() <= config.retention.maximum_obligations as usize,
        "version retention physical history capacity",
    )?;
    Ok(())
}

pub(super) fn read_row(
    connection: &Connection,
    config: &CellVersionRetentionConfigV3,
    operation: CellDigestV1,
) -> CellResultV1<Option<DutyRow>> {
    let raw = connection.query_row("SELECT funding,CASE WHEN length(wire) BETWEEN 1 AND 16777216 THEN wire ELSE NULL END,status,generation,checksum FROM version_duties WHERE operation=?1", [operation.as_slice()], |row| Ok((row.get::<_,Vec<u8>>(0)?, row.get::<_,Option<Vec<u8>>>(1)?, row.get::<_,u8>(2)?, row.get::<_,u64>(3)?, row.get::<_,Vec<u8>>(4)?))).optional()?;
    let Some((funding, wire, status, generation, checksum)) = raw else {
        return Ok(None);
    };
    let wire = wire.ok_or(CellErrorV1::Invalid("version retention contract size"))?;
    let contract = CellVersionRetentionContractV3::decode(&wire, config)?;
    require(
        contract.operation == operation
            && contract.funding_operation.as_slice() == funding
            && status <= 2
            && generation > 0
            && checksum == row_checksum(&wire, status, generation),
        "version retention row integrity",
    )?;
    Ok(Some(DutyRow {
        contract,
        status,
        generation,
    }))
}

pub(super) fn required_row(
    connection: &Connection,
    config: &CellVersionRetentionConfigV3,
    operation: CellDigestV1,
) -> CellResultV1<DutyRow> {
    read_row(connection, config, operation)?
        .ok_or(CellErrorV1::Invalid("version retention unknown duty"))
}

pub(super) fn transition(
    connection: &Connection,
    config: &CellVersionRetentionConfigV3,
    row: &mut DutyRow,
    previous: CellVersionCatalogAnchorV3,
    insert: bool,
) -> CellResultV1<CellVersionCatalogAnchorV3> {
    let generation = previous
        .generation
        .checked_add(1)
        .filter(|value| *value <= 3 * u64::from(config.maximum_versions))
        .ok_or(CellErrorV1::Invalid("version retention event capacity"))?;
    row.generation = generation;
    let wire = row.contract.encode_wire();
    let checksum = row_checksum(&wire, row.status, generation);
    let changed = if insert {
        connection.execute(
            "INSERT INTO version_duties VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                row.contract.operation.as_slice(),
                row.contract.funding_operation.as_slice(),
                wire,
                row.status,
                generation,
                checksum
            ],
        )?
    } else {
        connection.execute("UPDATE version_duties SET status=?2,generation=?3,checksum=?4 WHERE operation=?1 AND wire=?5 AND status=?6", params![row.contract.operation.as_slice(),row.status,generation,checksum,wire,row.status - 1])?
    };
    require(changed == 1, "version retention catalog write")?;
    let commitment = row.contract.commitment(config)?;
    let tip = event_checksum(
        config,
        generation,
        row.contract.operation,
        commitment,
        row.status,
        previous.commitment,
    );
    connection.execute(
        "INSERT INTO version_events VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            generation,
            row.contract.operation.as_slice(),
            commitment.as_slice(),
            row.status,
            previous.commitment.as_slice(),
            tip.as_slice()
        ],
    )?;
    let changed = connection.execute(
        "UPDATE metadata SET generation=?1,tip=?2 WHERE singleton=1 AND generation=?3 AND tip=?4",
        params![
            generation,
            tip.as_slice(),
            previous.generation,
            previous.commitment.as_slice()
        ],
    )?;
    require(changed == 1, "version retention head write")?;
    let durable = required_row(connection, config, row.contract.operation)?;
    require(
        durable.contract == row.contract
            && durable.status == row.status
            && durable.generation == generation,
        "version retention write readback",
    )?;
    Ok(CellVersionCatalogAnchorV3 {
        generation,
        commitment: tip,
    })
}

fn row_checksum(wire: &[u8], status: u8, generation: u64) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-version-retention-row.v3\0");
    hash.update([status]);
    hash.update(generation.to_be_bytes());
    hash.update(wire);
    hash.finalize().to_vec()
}

fn event_checksum(
    config: &CellVersionRetentionConfigV3,
    generation: u64,
    operation: CellDigestV1,
    contract: CellDigestV1,
    status: u8,
    previous: CellDigestV1,
) -> CellDigestV1 {
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-version-retention-event.v3\0");
    hash.update(config.retention.store_id);
    hash.update(generation.to_be_bytes());
    hash.update(operation);
    hash.update(contract);
    hash.update([status]);
    hash.update(previous);
    hash.finalize().into()
}

fn digest(bytes: Vec<u8>) -> CellResultV1<CellDigestV1> {
    bytes
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("version retention digest"))
}
