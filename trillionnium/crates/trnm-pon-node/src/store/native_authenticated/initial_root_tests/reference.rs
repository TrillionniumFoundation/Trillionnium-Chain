//! Exact b73f17051651f24fe2cf357543870464dc48f2ab reference control flow.
//! These six function bodies are copied without semantic changes from the
//! parent native_authenticated.rs. They resolve each other within this module,
//! so the reference does not call the new initial-root implementation.
use super::*;

fn native_block_with_cache(
    db: &Connection,
    settings: &Settings,
    id: Hash,
    cache: Option<&ArithmeticCache>,
) -> Result<NativeBlock> {
    let _measurement = cache.map(|cache| cache.history.observe(HistoryStage::Packet));
    local((|| {
        let (parent, height, work, packet, state): StoredBlockRow = db
            .prepare_cached(NATIVE_BLOCK_SQL)?
            .query_row([id.as_slice()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?;
        let parent = parent.map(bytes32).transpose()?;
        let state = bytes32(state)?;
        let work = consensus::Work::from_bytes(bytes64(work)?);
        if id == settings.genesis() {
            ensure(
                parent.is_none()
                    && height == 0
                    && packet.is_none()
                    && work == consensus::Work::from_bytes([0; 64])
                    && state
                        == match cache {
                            Some(cache) => cache.state_root(settings, &settings.initial)?,
                            None => root(&settings.initial)?,
                        },
                "NATIVE_STATE_GENESIS",
            )?;
            return Ok(NativeBlock {
                parent,
                height,
                root: state,
                packet_digest: None,
            });
        }
        let raw = packet.ok_or("NATIVE_STATE_PACKET")?;
        let cached = cache.and_then(|cache| cache.history.packet(settings, id, &raw));
        let (header, packet_id, transactions, cached_digest) = match cached {
            Some(math) => (math.header, math.id, math.transactions, Some(math.digest)),
            None => {
                let packet = Packet::decode(&raw)?;
                let h = &packet.header;
                let packet_id = packet.id()?;
                // Keep the original short-circuit field order. In particular,
                // invalid context must not move the transaction-root work first.
                ensure(
                    packet_id == id
                        && h.network == settings.network()
                        && h.parameters == settings.parameters()
                        && Some(h.parent) == parent
                        && h.height == height
                        && h.state == state,
                    "NATIVE_STATE_PACKET",
                )?;
                let transactions = sequence_root("transactions", &packet.transactions);
                ensure(h.transactions == transactions, "NATIVE_STATE_PACKET")?;
                (packet.header, packet_id, transactions, None)
            }
        };
        let h = &header;
        ensure(
            packet_id == id
                && h.network == settings.network()
                && h.parameters == settings.parameters()
                && Some(h.parent) == parent
                && h.height == height
                && h.state == state
                && h.transactions == transactions,
            "NATIVE_STATE_PACKET",
        )?;
        let (parent_height, parent_work): (u64, Vec<u8>) = db
            .prepare_cached(NATIVE_PARENT_SQL)?
            .query_row([h.parent.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        ensure(
            parent_height.checked_add(1) == Some(height)
                && consensus::Work::from_bytes(bytes64(parent_work)?)
                    .checked_add(consensus::required_work(h.target)?)?
                    == work,
            "NATIVE_STATE_PARENT",
        )?;
        let digest =
            cached_digest.unwrap_or_else(|| hash(b"native-authenticated-packet-v1", &[&raw]));
        if let Some(cache) = cache {
            cache.history.retain_packet(
                settings,
                id,
                raw,
                history_arithmetic::PacketMath {
                    header,
                    id: packet_id,
                    transactions,
                    digest,
                },
            );
        }
        Ok(NativeBlock {
            parent,
            height,
            root: state,
            packet_digest: Some(digest),
        })
    })())
}

fn verify_record(
    db: &Connection,
    settings: &Settings,
    record: &Record,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: Option<&ArithmeticCache>,
) -> Result<()> {
    let native = native_block_with_cache(db, settings, record.block, cache)?;
    let (delta_count, delta_root) = stored_delta_root_observed(
        db,
        record.block,
        progress,
        cache.map(|cache| (settings, cache)),
    )?;
    local(ensure(
        record.parent == native.parent
            && record.height == native.height
            && record.packet_digest == native.packet_digest
            && record.state.network == settings.network()
            && record.state.parameters == settings.parameters()
            && record.state.genesis == settings.genesis()
            && record.state.state_root == native.root
            && record.delta_count == delta_count as u64
            && record.delta_root == delta_root,
        "NATIVE_STATE_BINDING",
    ))?;
    match record.parent {
        None => local(ensure(
            record.block == settings.genesis()
                && record.parent_commitment.is_none()
                && delta_count == 0,
            "NATIVE_STATE_GENESIS",
        )),
        Some(parent) => {
            let parent = load_observed(db, parent, cache.map(|cache| (settings, cache)))?;
            local(ensure(
                record.parent_commitment == Some(parent.id)
                    && parent.height.checked_add(1) == Some(record.height),
                "NATIVE_STATE_PARENT",
            ))
        }
    }
}

pub(crate) fn verify_state_with_cache(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: Option<&ArithmeticCache>,
) -> Result<()> {
    verify_state_with_readback(db, settings, block, state, progress, cache, None)
}

pub(super) fn verify_state_with_readback(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: Option<&ArithmeticCache>,
    readback: Option<&mut PostWriteReadback<'_>>,
) -> Result<()> {
    verify_state_with_readback_and_calculation(
        db, settings, block, state, progress, cache, readback, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_state_with_readback_and_calculation(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: Option<&ArithmeticCache>,
    mut readback: Option<&mut PostWriteReadback<'_>>,
    calculation: Option<FullRootCalculation<'_>>,
) -> Result<()> {
    let result = (|| {
        let _measurement = cache.map(|cache| cache.history.observe(HistoryStage::VerifyState));
        progress()?;
        if let Some(scope) = readback.as_deref_mut() {
            scope.current(db)?;
        }
        let record = load_observed(db, block, cache.map(|cache| (settings, cache)))?;
        verify_record(db, settings, &record, progress, cache)?;
        local(ensure(
            record.state
                == match cache {
                    Some(cache) => cache.complete_with_calculation(settings, state, calculation)?,
                    None => complete(settings, state)?,
                },
            "NATIVE_STATE_ROOT",
        ))?;
        let reused = match readback.as_deref_mut() {
            Some(scope) => scope.matches(db, settings, &record)?,
            None => false,
        };
        if !reused {
            let _measurement = cache.map(|cache| cache.history.observe(HistoryStage::AccountGraph));
            native_store::verify_with_lifts(
                db,
                &record.accounts,
                state,
                progress,
                cache.map(|c| &c.lifts),
            )?;
        }
        // Keep the original boundary checkpoint. A scoped graph hit creates no
        // synthetic progress events; every real traversal keeps every node check.
        progress()?;
        if let Some(scope) = readback.as_deref_mut() {
            if reused {
                if !scope.matches(db, settings, &record)? {
                    // A final callback wrote after the match. Reuse stays disabled;
                    // repeat the original verifier, never mint a replacement scope.
                    return verify_state_with_cache(db, settings, block, state, progress, cache);
                }
                scope.consumed = true;
                #[cfg(test)]
                {
                    scope.hits += 1;
                }
            } else {
                scope.remember(db, record)?;
            }
        }
        Ok(())
    })();
    match readback {
        Some(scope) => scope.finish(result),
        None => result,
    }
}

pub(super) fn verify_history_with_readback(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: Option<&ArithmeticCache>,
    readback: Option<&mut PostWriteReadback<'_>>,
) -> Result<()> {
    let _measurement = cache.map(|cache| cache.history.observe(HistoryStage::VerifyHistory));
    let mut current = block;
    let mut expected_height = None;
    loop {
        progress()?;
        let record = load_observed(db, current, cache.map(|cache| (settings, cache)))?;
        verify_record(db, settings, &record, progress, cache)?;
        local(ensure(
            expected_height.is_none_or(|height| record.height == height),
            "NATIVE_STATE_HISTORY",
        ))?;
        match record.parent {
            Some(parent) => {
                expected_height = Some(record.height.checked_sub(1).ok_or("NATIVE_STATE_HISTORY")?);
                current = parent;
            }
            None => {
                let bytes: Vec<u8> = db
                    .prepare_cached("SELECT state FROM snapshots WHERE block=?")
                    .map_err(|error| Error::from(error).local_integrity())?
                    .query_row([current.as_slice()], |row| row.get(0))
                    .map_err(|error| Error::from(error).local_integrity())?;
                let state: State = serde_json::from_slice(&bytes)
                    .map_err(|error| Error::from(error).local_integrity())?;
                local(ensure(
                    canonical(&state)? == bytes && state == settings.initial,
                    "NATIVE_STATE_GENESIS",
                ))?;
                return verify_state_with_readback(
                    db, settings, current, &state, progress, cache, readback,
                );
            }
        }
    }
}

pub(super) fn checked_block(
    db: &Connection,
    settings: &Settings,
    id: Hash,
    cache: Option<&ArithmeticCache>,
) -> Result<NativeBlock> {
    native_block_with_cache(db, settings, id, cache)
}

pub(super) fn checked_record(
    db: &Connection,
    settings: &Settings,
    record: &Record,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: Option<&ArithmeticCache>,
) -> Result<()> {
    verify_record(db, settings, record, progress, cache)
}
