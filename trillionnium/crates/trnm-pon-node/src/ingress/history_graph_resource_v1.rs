//! Explicit ordinary-History graph resource policy. This is a new bounded-work
//! observation schedule, not a cached KernelBudget verdict or a V6 signature.
use crate::account_archive_prototype::native_store::AccountGraphKind;
use crate::native_progress::{NativeProgress, NativeProgressPoint};
use crate::{ensure, Result};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const PROFILE: &str = "history-account-graph-resource-fence-v1";
pub const MAX_NODE_BODIES: u32 = 8;

pub(crate) fn policy_digest() -> String {
    hex::encode(trnm_protocol::pon_wire::hash(b"ordinary-history-graph-resource-policy-v1", &[
        PROFILE.as_bytes(), &MAX_NODE_BODIES.to_le_bytes(),
        b"sealed-graph-ordinal;every-node-cpu-cancel-sql;full-enter-first-final-exit-commit-settlement;ordinary-only",
    ]))
}

#[derive(Default, Serialize)]
pub(crate) struct Counters {
    pub(crate) imports: u64,
    pub(crate) imports_closed: u64,
    pub(crate) imports_failed: u64,
    native_cpu_checkpoints: u64,
    graph_entries: u64,
    graph_exits: u64,
    graph_aborts: u64,
    graph_node_checkpoints: u64,
    graph_completed_node_bodies: u64,
    graph_full_resource_checks: u64,
    graph_max_node_window: u32,
    before_commit_checks: u64,
    scope_failures: u64,
    unfinished_scopes: u64,
    kernel_checks: u64,
    kernel_failed_checks: u64,
    kernel_cpu_known_calls: u64,
    kernel_cpu_unknown_calls: u64,
    kernel_cpu_ns: u64,
    kernel_wall_ns: u64,
    binding_checks: u64,
    binding_failed_checks: u64,
}

pub(crate) type SharedCounters = Arc<Mutex<Counters>>;

pub(crate) fn count(
    counters: &SharedCounters,
    update: impl FnOnce(&mut Counters) -> Result<()>,
) -> Result<()> {
    let mut counters = counters
        .lock()
        .map_err(|_| "HISTORY_GRAPH_RESOURCE_OBSERVATION_V1")?;
    update(&mut counters)
}

fn add(value: &mut u64, amount: u64) -> Result<()> {
    *value = value
        .checked_add(amount)
        .ok_or("HISTORY_GRAPH_RESOURCE_OBSERVATION_V1")?;
    Ok(())
}

pub(crate) fn observe(counters: &SharedCounters) -> Result<serde_json::Value> {
    let counters = counters
        .lock()
        .map_err(|_| "HISTORY_GRAPH_RESOURCE_OBSERVATION_V1")?;
    Ok(serde_json::json!({
        "schema":"ordinary-history-graph-resource-observation-v1",
        "profile":PROFILE,"maximum_node_bodies_between_full_checks":MAX_NODE_BODIES,
        "counters":&*counters,
        "scope":"cumulative explicit v1 imports on this actual Node; kernel counts/CPU cover instrumented INNER fresh KernelBudget::verify calls only, not all checker executions; excludes entry open/identity, outer final checks, epoch open/final-close checks, binding SQL and timing overhead; nested in import CPU",
        "strict_path_is_separate":true,"observation_is_authority":false,
        "wall_clock_revocation_bound_claimed":false,
    }))
}

pub(crate) fn measured_kernel(
    counters: &SharedCounters,
    verify: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let wall = Instant::now();
    let before = super::calling_thread_cpu_ns();
    let result = verify();
    let cpu = before
        .zip(super::calling_thread_cpu_ns())
        .and_then(|(a, b)| b.checked_sub(a));
    let elapsed = u64::try_from(wall.elapsed().as_nanos())
        .map_err(|_| "HISTORY_GRAPH_RESOURCE_OBSERVATION_V1")?;
    count(counters, |c| {
        add(&mut c.kernel_checks, 1)?;
        add(&mut c.kernel_failed_checks, u64::from(result.is_err()))?;
        add(&mut c.kernel_wall_ns, elapsed)?;
        if let Some(cpu) = cpu {
            add(&mut c.kernel_cpu_known_calls, 1)?;
            add(&mut c.kernel_cpu_ns, cpu)?;
        } else {
            add(&mut c.kernel_cpu_unknown_calls, 1)?;
        }
        Ok(())
    })?;
    result
}

pub(crate) fn measured_binding(
    counters: &SharedCounters,
    verify: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let result = verify();
    count(counters, |c| {
        add(&mut c.binding_checks, 1)?;
        add(&mut c.binding_failed_checks, u64::from(result.is_err()))
    })?;
    result
}

#[derive(Default)]
struct Graph {
    next: u32,
    last_full: u32,
    final_relation: bool,
}

/// The scope belongs to one actual Node operation and is never shared with a
/// worker or another import. Only the private verifier can construct graph
/// points. Every ordinary checkpoint and commit always invokes the full check.
pub(crate) struct GraphProgress<'a> {
    cpu: &'a dyn Fn() -> Result<()>,
    full: &'a (dyn Fn() -> Result<()> + Sync),
    counters: SharedCounters,
    graph: Option<Graph>,
    invalid_sequence: bool,
    refused: bool,
    #[cfg(test)]
    before_commit_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl<'a> GraphProgress<'a> {
    pub(crate) fn new(
        cpu: &'a dyn Fn() -> Result<()>,
        full: &'a (dyn Fn() -> Result<()> + Sync),
        counters: SharedCounters,
    ) -> Self {
        Self {
            cpu,
            full,
            counters,
            graph: None,
            invalid_sequence: false,
            refused: false,
            #[cfg(test)]
            before_commit_hook: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_before_commit_hook(&mut self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        self.before_commit_hook = hook;
    }

    pub(crate) fn complete(&self) -> Result<()> {
        ensure(
            self.graph.is_none() && !self.invalid_sequence && !self.refused,
            "HISTORY_GRAPH_RESOURCE_SCOPE_V1",
        )
    }

    fn edge(&mut self, kind: AccountGraphKind) -> Result<bool> {
        match kind {
            AccountGraphKind::Enter => {
                ensure(self.graph.is_none(), "HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                self.graph = Some(Graph::default());
                count(&self.counters, |c| add(&mut c.graph_entries, 1))?;
                Ok(true)
            }
            AccountGraphKind::BeforeNode { ordinal } => {
                let graph = self
                    .graph
                    .as_mut()
                    .ok_or("HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                ensure(
                    !graph.final_relation && ordinal == graph.next && ordinal < 131_071,
                    "HISTORY_GRAPH_RESOURCE_SCOPE_V1",
                )?;
                graph.next = graph
                    .next
                    .checked_add(1)
                    .ok_or("HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                let full = ordinal.is_multiple_of(MAX_NODE_BODIES);
                if full {
                    let window = ordinal
                        .checked_sub(graph.last_full)
                        .ok_or("HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                    ensure(window <= MAX_NODE_BODIES, "HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                    count(&self.counters, |c| {
                        c.graph_max_node_window = c.graph_max_node_window.max(window);
                        Ok(())
                    })?;
                    graph.last_full = ordinal;
                }
                count(&self.counters, |c| add(&mut c.graph_node_checkpoints, 1))?;
                Ok(full)
            }
            AccountGraphKind::BeforeFinalRelation { completed } => {
                let graph = self
                    .graph
                    .as_mut()
                    .ok_or("HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                ensure(
                    !graph.final_relation && completed == graph.next,
                    "HISTORY_GRAPH_RESOURCE_SCOPE_V1",
                )?;
                let window = completed
                    .checked_sub(graph.last_full)
                    .ok_or("HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                ensure(window <= MAX_NODE_BODIES, "HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                graph.final_relation = true;
                graph.last_full = completed;
                count(&self.counters, |c| {
                    c.graph_max_node_window = c.graph_max_node_window.max(window);
                    Ok(())
                })?;
                Ok(true)
            }
            AccountGraphKind::Exit {
                completed,
                succeeded,
            } => {
                let graph = self.graph.take().ok_or("HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                ensure(
                    completed <= graph.next
                        && graph.next - completed <= 1
                        && (!succeeded || (graph.final_relation && completed == graph.next)),
                    "HISTORY_GRAPH_RESOURCE_SCOPE_V1",
                )?;
                let window = completed
                    .checked_sub(graph.last_full)
                    .ok_or("HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                ensure(window <= MAX_NODE_BODIES, "HISTORY_GRAPH_RESOURCE_SCOPE_V1")?;
                count(&self.counters, |c| {
                    c.graph_max_node_window = c.graph_max_node_window.max(window);
                    add(&mut c.graph_exits, 1)?;
                    add(&mut c.graph_aborts, u64::from(!succeeded))?;
                    add(&mut c.graph_completed_node_bodies, u64::from(completed))
                })?;
                Ok(true)
            }
        }
    }

    pub(crate) fn point(&mut self, point: NativeProgressPoint) -> Result<()> {
        let previously_refused = self.refused;
        let aborted = matches!(&point, NativeProgressPoint::AccountGraph(point)
            if matches!(point.kind(), AccountGraphKind::Exit { succeeded: false, .. }));
        let result = self.attempt(point);
        self.refused |= result.is_err() || aborted;
        // Even if an internal caller accidentally ignores a refusal, later
        // successful reads cannot qualify this same operation. The real Exit
        // is still attempted so aborts retain their full resource observation.
        preserve_native(
            result,
            ensure(!previously_refused, "HISTORY_GRAPH_RESOURCE_SCOPE_V1"),
        )
    }

    fn attempt(&mut self, point: NativeProgressPoint) -> Result<()> {
        count(&self.counters, |c| add(&mut c.native_cpu_checkpoints, 1))?;
        // The CPU/cancel attempt runs at EVERY node, including nodes for which
        // the new resource policy does not need another kernel read.
        let cpu = (self.cpu)();
        let is_graph = matches!(&point, NativeProgressPoint::AccountGraph(_));
        let full = match point {
            NativeProgressPoint::Boundary => self.complete().map(|()| true),
            NativeProgressPoint::BeforeCommit => {
                #[cfg(test)]
                if let Some(hook) = &self.before_commit_hook {
                    hook();
                }
                count(&self.counters, |c| add(&mut c.before_commit_checks, 1))?;
                self.complete().map(|()| true)
            }
            NativeProgressPoint::AccountGraph(point) => self.edge(point.kind()),
        };
        if full.is_err() {
            self.invalid_sequence = true;
            count(&self.counters, |c| add(&mut c.scope_failures, 1))?;
        }
        // Even an aborted Exit gets its complete resource check. No successful
        // prefix or earlier check is used to qualify this graph or operation.
        let resource = if full.as_ref().copied().unwrap_or(true) {
            if is_graph {
                count(&self.counters, |c| {
                    add(&mut c.graph_full_resource_checks, 1)
                })?;
            }
            (self.full)()
        } else {
            Ok(())
        };
        cpu.and(full.map(|_| ())).and(resource)
    }
}

impl NativeProgress for GraphProgress<'_> {
    fn checkpoint(&mut self) -> Result<()> {
        self.point(NativeProgressPoint::Boundary)
    }
    fn before_commit(&mut self) -> Result<()> {
        self.point(NativeProgressPoint::BeforeCommit)
    }
    fn account_graph(
        &mut self,
        point: crate::account_archive_prototype::native_store::AccountGraphPoint,
    ) -> Result<()> {
        self.point(NativeProgressPoint::AccountGraph(point))
    }
}

impl Drop for GraphProgress<'_> {
    fn drop(&mut self) {
        if self.graph.is_some() {
            // No fallible I/O and no clean receipt on unwind. The enclosing
            // original durable epoch survives until real known settlement.
            if let Ok(mut counters) = self.counters.lock() {
                counters.unfinished_scopes = counters.unfinished_scopes.saturating_add(1);
            }
        }
    }
}

pub(crate) fn preserve_native<T>(native: Result<T>, boundary: Result<()>) -> Result<T> {
    match (native, boundary) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod native_tests;
