//! History replay under the original Node-owned CPU account and crash epoch.
//! Shared ordinary owners release their writer for CPU refill, decoding, W1
//! and bounded M06 execution. The original owner checks the private execution
//! artifact and retains the original transaction/readback publication fences.
use super::{
    ensure, hex_packet_for_settings, history_kernel_work_checkpoint, now, public_v3, Hash, Node,
    Packet, Page, Result, Settings, WorkCheckedPacket, MAX_FRAME,
};
use std::{
    sync::{Mutex, TryLockError},
    thread,
    time::{Duration, Instant},
};

pub(super) const PAGE_BUDGET: Duration = Duration::from_secs(30);
pub(super) const SYNC_BUDGET: Duration = Duration::from_secs(300);

pub(super) struct Control<'a> {
    pub deadline: Instant,
    pub resource: &'a (dyn Fn() -> Result<()> + Sync),
}
impl Control<'_> {
    fn alive(&self) -> Result<()> {
        ensure(Instant::now() < self.deadline, "PUBLIC_REQUEST_DEADLINE")
    }
    fn check(&self) -> Result<()> {
        self.alive()?;
        (self.resource)()
    }
}

pub(super) enum Owner<'a> {
    Exclusive(&'a mut Node),
    Shared(&'a Mutex<Node>),
}
impl Owner<'_> {
    fn with<T>(
        &mut self,
        control: &Control<'_>,
        action: impl FnOnce(&mut Node) -> Result<T>,
    ) -> Result<T> {
        control.check()?;
        match self {
            Self::Exclusive(node) => action(node),
            Self::Shared(node) => loop {
                control.check()?;
                match node.try_lock() {
                    Ok(mut guard) => return action(&mut guard),
                    Err(TryLockError::Poisoned(_)) => return Err("OWNER_POISONED".into()),
                    Err(TryLockError::WouldBlock) => thread::sleep(
                        Duration::from_millis(1)
                            .min(control.deadline.saturating_duration_since(Instant::now())),
                    ),
                }
            },
        }
    }

    fn finish(
        &mut self,
        control: &Control<'_>,
        cpu: &public_v3::ServiceMutationCpuDomain,
    ) -> Result<()> {
        // Closing an already settled scope is cleanup, never new proof work.
        // Try once even after cancellation. Do not wait beyond the original
        // deadline for a busy writer: Drop then fences the original account,
        // and the persisted active marker prevents restart from erasing debt.
        match self {
            Self::Exclusive(node) => node.finish_remote_history_cpu_epoch(cpu),
            Self::Shared(node) => loop {
                match node.try_lock() {
                    Ok(mut guard) => return guard.finish_remote_history_cpu_epoch(cpu),
                    Err(TryLockError::Poisoned(_)) => return Err("OWNER_POISONED".into()),
                    Err(TryLockError::WouldBlock) => {
                        ensure(
                            Instant::now() < control.deadline,
                            "PUBLIC_MUTATION_CPU_UNAVAILABLE",
                        )?;
                        thread::sleep(
                            Duration::from_millis(1)
                                .min(control.deadline.saturating_duration_since(Instant::now())),
                        );
                    }
                }
            },
        }
    }
}

struct EpochGuard {
    cpu: public_v3::ServiceMutationCpuDomain,
    closed: bool,
}
impl Drop for EpochGuard {
    fn drop(&mut self) {
        if !self.closed {
            self.cpu.abandon_history_epoch();
        }
    }
}

fn scoped<T>(
    owner: &mut Owner<'_>,
    control: &Control<'_>,
    native: impl FnOnce(&mut Owner<'_>, &public_v3::ServiceMutationCpuDomain) -> Result<T>,
) -> Result<T> {
    let cpu = owner.with(control, |node| {
        // #498's continuous-mode deny gate remains before any paid work.
        // Generic scalar begin is not the continuous durable-operation journal.
        let cpu = node.remote_history_cpu_domain()?;
        node.begin_remote_history_cpu_epoch()?;
        Ok(cpu)
    })?;
    let mut guard = EpochGuard { cpu, closed: false };
    cut("epoch");
    let result = native(owner, &guard.cpu);
    let close = owner.finish(control, &guard.cpu);
    if close.is_ok() {
        guard.closed = true;
    }
    close?;
    result
}

fn begin_cpu(
    cpu: &public_v3::ServiceMutationCpuDomain,
    control: &Control<'_>,
) -> Result<public_v3::ServiceMutationCpuOperation> {
    // Keep a depleted peer from owning the poller's entire (possibly long)
    // runtime. This local wait ceiling can only shorten the original end.
    let wait_end = control
        .deadline
        .min(Instant::now() + Duration::from_secs(2));
    loop {
        control.check()?;
        ensure(Instant::now() < wait_end, "PUBLIC_MUTATION_CPU_BUDGET")?;
        match cpu.begin() {
            Ok(operation) => return Ok(operation),
            Err(error) if error.is(crate::ErrorCode::PublicMutationCpuBudget) => {
                // No Node guard; the fixed business deadline never advances.
                cut("cpu_wait");
                thread::sleep(
                    Duration::from_millis(2)
                        .min(wait_end.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn metered<T>(
    cpu: &public_v3::ServiceMutationCpuDomain,
    control: &Control<'_>,
    native: impl FnOnce(&public_v3::ServiceMutationCpuOperation) -> Result<T>,
) -> Result<T> {
    let operation = begin_cpu(cpu, control)?;
    let result = operation
        .bind_history_request(control.deadline)
        .and_then(|()| native(&operation));
    let receipt = operation.finish();
    ensure(
        !receipt.accounting_unavailable,
        "PUBLIC_MUTATION_CPU_UNAVAILABLE",
    )?;
    result
}

fn validate_page(settings: &Settings, page: &Page, tip: Hash, after: Hash) -> Result<()> {
    let schema = if settings.is_native_pq_application_v6() {
        "pon-native-pq-history-v6"
    } else {
        "pon-native-history-v1"
    };
    ensure(
        page.schema == schema
            && page.network == hex::encode(settings.network())
            && page.parameters == hex::encode(settings.parameters())
            && page.genesis == hex::encode(settings.genesis()),
        "PAGE_CONTEXT",
    )?;
    ensure(
        page.tip == hex::encode(tip)
            && page.after == hex::encode(after)
            && page.packets.len() <= 16,
        "PAGE_CURSOR",
    )?;
    ensure(
        !page.packets.is_empty() || (after == tip && page.complete),
        "EMPTY_PAGE",
    )?;
    let mut total = 0usize;
    for packet in &page.packets {
        total = total.checked_add(packet.len()).ok_or("PAGE_LIMIT")?;
        ensure(total <= MAX_FRAME - 1024, "PAGE_LIMIT")?;
    }
    Ok(())
}

fn admit_packet(
    owner: &mut Owner<'_>,
    cpu: &public_v3::ServiceMutationCpuDomain,
    packet: Packet,
    clock: u64,
    control: &Control<'_>,
    activate: Option<Hash>,
) -> Result<(Hash, bool, Option<Hash>)> {
    if let Some(tip) = activate {
        ensure(tip == packet.id()?, "PAGE_COMPLETE")?;
    }
    let owns_node_mutex = matches!(owner, Owner::Shared(_));
    metered(cpu, control, |operation| {
        let progress = operation.checkpoint_handle();
        // history_checkpoint checks the original deadline and actual Host
        // before its CPU observation, then again throughout every refill wait.
        // Keep that check at every native progress boundary; a second adjacent
        // control.check() performed no ledger work and duplicated Host reads.
        let check = || progress.history_checkpoint(owns_node_mutex, &|| control.check());
        check()?;
        let (existing, permit, settings) = owner.with(control, |node| {
            let existing =
                node.precheck_public_admission_context_with_progress(&packet, clock, &mut || {
                    check()
                })?;
            let permit = if existing.is_none() {
                node.begin_owner_work(&packet)?
            } else {
                None
            };
            Ok((existing, permit, node.settings().clone()))
        })?;
        if let Some(id) = existing {
            let active = activate
                .map(|tip| activate_packet(owner, tip, clock, control, operation))
                .transpose()?;
            return Ok((id, false, active));
        }
        let checked = WorkCheckedPacket::verify_with_progress(packet, &mut |point| {
            control.alive()?;
            progress.history_checkpoint(owns_node_mutex, &|| control.check())?;
            if history_kernel_work_checkpoint(point) {
                (control.resource)()?;
            }
            if matches!(
                point,
                trnm_crypto_primitives::pon_work::VerificationProgress::TranscriptTile {
                    row: 4,
                    column: 0,
                    inner: 0,
                }
            ) {
                // Noise/matrix preparation and half the real transcript have
                // already executed. This is not a pre-verification mock cut.
                cut("w1");
            }
            Ok(())
        })?;
        operation.history_work_verified_for_settings(&checked, &settings)?;
        // Promotion changes only scheduling for this complete, unique W1.
        // Shared owners retain nonwaiting checkpoints while holding Node;
        // exclusive embedding has no Node mutex and keeps its exact stack.
        check()?;
        let execution_progress = |point| {
            check()?;
            if point == trnm_mvcc_fee::pon_executor::ExecutionProgress::AfterMandatory {
                cut("m06");
            }
            Ok(())
        };
        let execution = trnm_mvcc_fee::pon_executor::ExecutionControl::new(
            &execution_progress,
            operation.worker_accounting(),
        );
        let id = match owner {
            Owner::Shared(node) => {
                let (guard, id, _) = super::admit_shared_checked(
                    node,
                    checked,
                    permit,
                    &mut |_| check(),
                    &execution,
                    || Ok(clock),
                    None,
                )?;
                drop(guard);
                id
            }
            Owner::Exclusive(_) => owner.with(control, |node| {
                let checked = node.attach_owner_work(checked, permit)?;
                node.admit_work_checked_with_control(checked, clock, &execution)
            })?,
        };
        // Test-only cut is after the actual native COMMIT, before CPU settle.
        cut("admitted");
        let active = if let Some(tip) = activate {
            // Final activation keeps the original admission operation and
            // deadline. It does not start a new reservation after paid W1.
            Some(activate_packet(owner, tip, clock, control, operation)?)
        } else {
            None
        };
        Ok((id, true, active))
    })
}

fn activate_packet(
    owner: &mut Owner<'_>,
    tip: Hash,
    clock: u64,
    control: &Control<'_>,
    operation: &public_v3::ServiceMutationCpuOperation,
) -> Result<Hash> {
    let owns_node_mutex = matches!(owner, Owner::Shared(_));
    let checkpoint = || operation.history_checkpoint(owns_node_mutex, &|| control.check());
    checkpoint()?;
    let active = owner.with(control, |node| {
        node.activate_observed_with_termination(
            tip,
            clock,
            &mut || {
                cut("activation_progress");
                checkpoint()
            },
            Some(&operation.checkpoint_handle()),
        )
    })?;
    cut("activated");
    checkpoint()?;
    Ok(active)
}

pub(super) fn receive(
    mut owner: Owner<'_>,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
    control: Control<'_>,
) -> Result<Hash> {
    let (settings, continuous) = owner.with(&control, |node| {
        validate_page(node.settings(), &page, tip, after)?;
        Ok((node.settings().clone(), node.is_continuous()))
    })?;
    if continuous {
        // The exclusive owner may use its exact signed receiver pair for one
        // complete extension. General pages and the shared discovery poller
        // still need their own durable History authority and remain closed.
        ensure(
            matches!(owner, Owner::Exclusive(_))
                && page.complete
                && page.packets.len() == 1
                && page.next == hex::encode(tip),
            "OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED",
        )?;
        let text = &page.packets[0];
        ensure(
            text.len() <= 2_097_152
                && text.len().is_multiple_of(2)
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "PACKET_HEX",
        )?;
        let raw = hex::decode(text).map_err(|_| crate::Error::from("PACKET_HEX"))?;
        return owner.with(&control, |node| {
            node.receive_owned_continuous_history_packet(&raw, tip, after, clock, &|| {
                control.check()
            })
        });
    }
    scoped(&mut owner, &control, |owner, cpu| {
        let (packets, next) = metered(cpu, &control, |operation| {
            let mut packets = Vec::with_capacity(page.packets.len());
            let mut next = after;
            for raw in &page.packets {
                control.check()?;
                operation.checkpoint()?;
                let packet = hex_packet_for_settings(raw, &settings)?;
                ensure(packet.header.parent == next, "PAGE_PARENT")?;
                next = packet.id()?;
                packets.push(packet);
            }
            ensure(
                page.next == hex::encode(next) && page.complete == (next == tip),
                "PAGE_COMPLETE",
            )?;
            control.check()?;
            operation.checkpoint()?;
            Ok((packets, next))
        })?;
        cut("decoded");
        let count = packets.len();
        for (index, packet) in packets.into_iter().enumerate() {
            let activate = (page.complete && index + 1 == count).then_some(tip);
            admit_packet(owner, cpu, packet, clock, &control, activate)?;
        }
        if page.complete && count == 0 {
            metered(cpu, &control, |operation| {
                activate_packet(owner, tip, clock, &control, operation)
            })?;
        }
        Ok(next)
    })
}

/// The pinned public poller uses the same short-owner importer and durable
/// epoch. Its packet is already bounded/decoded, but all native checks and W1
/// remain charged to the original account, including ordinary standalone use.
pub(crate) fn admit_shared_packet(
    node: &Mutex<Node>,
    packet: Packet,
    deadline: Instant,
    resource: &(dyn Fn() -> Result<()> + Sync),
    activate: Option<Hash>,
) -> Result<(bool, Option<Hash>)> {
    if let Some(tip) = activate {
        ensure(tip == packet.id()?, "PAGE_COMPLETE")?;
    }
    let control = Control { deadline, resource };
    let mut owner = Owner::Shared(node);
    owner.with(&control, |node| {
        ensure(
            !node.is_continuous(),
            "OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED",
        )?;
        node.public_service_cpu_domain()?;
        Ok(())
    })?;
    scoped(&mut owner, &control, |owner, cpu| {
        admit_packet(owner, cpu, packet, now()?, &control, activate)
            .map(|(_, inserted, active)| (inserted, active))
    })
}

/// Complete a previously admitted locator using the original service account,
/// durable History epoch and caller deadline. No proof work or new CPU domain
/// is created for an empty page or a known Head response.
pub(crate) fn complete_shared(
    node: &Mutex<Node>,
    tip: Hash,
    deadline: Instant,
    resource: &(dyn Fn() -> Result<()> + Sync),
) -> Result<Hash> {
    let control = Control { deadline, resource };
    let mut owner = Owner::Shared(node);
    owner.with(&control, |node| {
        ensure(
            !node.is_continuous(),
            "OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED",
        )?;
        node.public_service_cpu_domain()?;
        Ok(())
    })?;
    scoped(&mut owner, &control, |owner, cpu| {
        metered(cpu, &control, |operation| {
            activate_packet(owner, tip, now()?, &control, operation)
        })
    })
}

#[cfg(all(test, target_os = "linux"))]
fn cut(stage: &'static str) {
    tests::cut(stage);
}
#[cfg(not(all(test, target_os = "linux")))]
fn cut(_stage: &'static str) {}

#[cfg(all(test, target_os = "linux"))]
#[path = "history_import_tests.rs"]
mod tests;
