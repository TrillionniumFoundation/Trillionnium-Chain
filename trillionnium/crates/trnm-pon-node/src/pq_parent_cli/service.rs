use super::*;
use serde_json::json;
use std::{
    io::Write,
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use trnm_pon_node::{
    ingress::{
        pq_network::{serve_pq_tls13_shared, tls::PqTlsServer, TLS_PROFILE},
        public_v3::{serve_public_protected_v3, PublicServer, PQ_HISTORY_PROFILE},
    },
    public_submit::pq::PQ_RECOVERY_HISTORY_TRANSPORT,
};

struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(super) fn run(
    args: &BTreeMap<String, String>,
    native: SocketAddr,
    history: SocketAddr,
    workers: usize,
) -> Result<Value> {
    let seconds = number(args, "--seconds", 30)?;
    ensure((1..=3600).contains(&seconds), "PQ_NETWORK_SERVER_BUDGET")?;
    let material = config::load(args)?;
    let native_server = PqTlsServer::new(
        material.policy.clone(),
        material.signer()?,
        material.tls_identity()?,
    )?;
    let history_server =
        PublicServer::new_pq_history(material.history_identity()?, material.history)?;
    let policy = material.policy.clone();
    let history_policy = material.history.pq_history_id();
    let witness_selected = material.witness_selected();
    // Preserve the ordinary V3 process slot and all library intake, CPU,
    // crash-fence, owner-lock and request limits. There is ONE actual Node.
    let _host = crate::host_public_guard::Guard::acquire()?;
    let node = Arc::new(Mutex::new(material.open_node(args, workers)?));
    let native = TcpListener::bind(native)?;
    let history = TcpListener::bind(history)?;
    ensure(
        native.local_addr()? != history.local_addr()?,
        "PQ_PARENT_ENDPOINTS_DISTINCT",
    )?;
    // This event reports bound sockets, not a completed handshake or a granted
    // request. Both original services still perform their own startup checks.
    println!(
        "{}",
        json!({"event":"pq-parent-pair-bound",
        "native_listen":native.local_addr()?.to_string(),
        "history_listen":history.local_addr()?.to_string(),
        "native_profile":TLS_PROFILE,"native_policy":hex::encode(policy.id()),
        "history_profile":PQ_HISTORY_PROFILE,"history_policy":hex::encode(history_policy),
        "history_transport":PQ_RECOVERY_HISTORY_TRANSPORT,
        "configured_group":"X25519MLKEM768","group_evidence":"single-configured-group-inference",
        "pnq2_rollback_witness_selected":witness_selected,
        "whole_node_rollback_protection":false,"private_task_qualification":false,
        "production_activation":false,"consensus_authority":false})
    );
    std::io::stdout().flush()?;
    let stop = Arc::new(AtomicBool::new(false));
    let lifetime = Duration::from_secs(seconds);
    let (native_result, history_result) = std::thread::scope(|scope| {
        let _stop_on_exit = StopOnDrop(stop.clone());
        let owner = node.clone();
        let stopped = stop.clone();
        let worker = scope.spawn(move || {
            let _stop_on_exit = StopOnDrop(stopped.clone());
            let result = serve_public_protected_v3(
                history,
                owner,
                lifetime,
                stopped.clone(),
                history_server,
            );
            stopped.store(true, Ordering::Release);
            result
        });
        let result = serve_pq_tls13_shared(native, node, lifetime, stop.clone(), native_server);
        stop.store(true, Ordering::Release);
        let joined = worker
            .join()
            .map_err(|_| trnm_pon_node::Error::from("PQ_PARENT_HISTORY_THREAD"))
            .and_then(|result| result);
        (result, joined)
    });
    Ok(json!({"schema":"pq-parent-pair-service-v1","ok":true,
        "native_metrics":native_result?,"history_metrics":history_result?,
        "history_transport":PQ_RECOVERY_HISTORY_TRANSPORT,
        "pnq2_rollback_witness_selected":witness_selected,
        "whole_node_rollback_protection":false,"private_task_qualification":false,
        "production_activation":false,"consensus_authority":false}))
}
