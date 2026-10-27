//! History replay under the original Node-owned CPU account and crash epoch.
//! Shared owners are held for context, M06/commit and epoch metadata only;
//! CPU refill, canonical packet decoding and full W1 run outside their mutex.
//! M06 remains under the writer until a separately verified execution/commit
//! split exists. No snapshot, clock verdict or peer statement is trusted here.
use super::{
    ensure, hex_packet, history_kernel_work_checkpoint, now, public_v3, Hash, Node, Packet, Page,
    Result, Settings, WorkCheckedPacket, MAX_FRAME,
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
    let result = native(&operation);
    let receipt = operation.finish();
    ensure(
        !receipt.accounting_unavailable,
        "PUBLIC_MUTATION_CPU_UNAVAILABLE",
    )?;
    result
}

fn validate_page(settings: &Settings, page: &Page, tip: Hash, after: Hash) -> Result<()> {
    ensure(
        page.schema == "pon-native-history-v1"
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
) -> Result<(Hash, bool)> {
    metered(cpu, control, |operation| {
        let progress = operation.checkpoint_handle();
        let check = || {
            control.check()?;
            progress.checkpoint()
        };
        check()?;
        let (existing, permit) = owner.with(control, |node| {
            let existing =
                node.precheck_public_admission_context_with_progress(&packet, clock, &mut || {
                    check()
                })?;
            let permit = if existing.is_none() {
                node.begin_owner_work(&packet)?
            } else {
                None
            };
            Ok((existing, permit))
        })?;
        if let Some(id) = existing {
            return Ok((id, false));
        }
        let checked = WorkCheckedPacket::verify_with_progress(packet, &mut |point| {
            control.alive()?;
            progress.checkpoint()?;
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
        check()?;
        let id = owner.with(control, |node| {
            let checked = node.attach_owner_work(checked, permit)?;
            let execution_progress = |_| check();
            let execution = trnm_mvcc_fee::pon_executor::ExecutionControl::new(
                &execution_progress,
                operation.worker_accounting(),
            );
            // Full parent/state/clock/permit checks repeat in native admission.
            // A valid competing branch need not be the current active tip.
            node.admit_work_checked_with_control(checked, clock, &execution)
        })?;
        // Test-only cut is after the actual native COMMIT, before CPU settle.
        cut("admitted");
        Ok((id, true))
    })
}

pub(super) fn receive(
    mut owner: Owner<'_>,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
    control: Control<'_>,
) -> Result<Hash> {
    owner.with(&control, |node| {
        validate_page(node.settings(), &page, tip, after)
    })?;
    scoped(&mut owner, &control, |owner, cpu| {
        let (packets, next) = metered(cpu, &control, |operation| {
            let mut packets = Vec::with_capacity(page.packets.len());
            let mut next = after;
            for raw in &page.packets {
                control.check()?;
                operation.checkpoint()?;
                let packet = hex_packet(raw)?;
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
        for packet in packets {
            admit_packet(owner, cpu, packet, clock, &control)?;
        }
        if page.complete {
            metered(cpu, &control, |operation| {
                operation.checkpoint()?;
                owner.with(&control, |node| node.activate_observed(tip, clock))?;
                cut("activated");
                control.check()?;
                operation.checkpoint()
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
) -> Result<bool> {
    let control = Control { deadline, resource };
    let mut owner = Owner::Shared(node);
    scoped(&mut owner, &control, |owner, cpu| {
        admit_packet(owner, cpu, packet, now()?, &control).map(|(_, inserted)| inserted)
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
