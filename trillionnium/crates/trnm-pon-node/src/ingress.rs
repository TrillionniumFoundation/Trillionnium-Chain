//! Bounded native socket ingress. Development loopback only; not Sybil-safe public P2P.
use crate::{digest, ensure, store::WorkCheckedPacket, Error, Node, Packet, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, TryLockError,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trnm_protocol::pon_wire::{hash, Hash};
use trnm_transport::proof_admission::bounded_ingress;
const MAX_FRAME: usize = 2 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Head,
    Submit { packet: String },
    History { tip: String, after: String },
    Confirm { transaction: String, block: String },
    ConfirmMany { queries: Vec<ConfirmationQuery> },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationQuery {
    pub transaction: String,
    pub block: String,
}
pub fn confirmation_queries(queries: &[ConfirmationQuery]) -> Result<Vec<(Hash, Hash)>> {
    ensure((1..=256).contains(&queries.len()), "CONFIRMATION_LIMIT")?;
    queries
        .iter()
        .map(|q| Ok((digest(&q.transaction)?, digest(&q.block)?)))
        .collect()
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub schema: String,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    pub tip: String,
    pub after: String,
    pub packets: Vec<String>,
    pub next: String,
    pub complete: bool,
}
#[derive(Default, Debug, Serialize)]
pub struct Metrics {
    pub completed_requests: u64,
    pub rejected_requests: u64,
    pub busy_requests: u64,
    pub malformed_requests: u64,
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::from("CLOCK"))?
        .as_secs())
}
fn read_exact_deadline(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or("FRAME_DEADLINE")?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(bytes) {
            Ok(0) => return Err("FRAME_EOF".into()),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn read_frame_budget(stream: &mut TcpStream, budget: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + budget;
    let mut prefix = [0; 4];
    read_exact_deadline(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    ensure((1..=MAX_FRAME).contains(&length), "FRAME_LIMIT")?;
    let mut bytes = vec![0; length];
    read_exact_deadline(stream, &mut bytes, deadline)?;
    Ok(bytes)
}
fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    read_frame_budget(stream, Duration::from_secs(5))
}
fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    ensure((1..=MAX_FRAME).contains(&bytes.len()), "FRAME_LIMIT")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let prefix = (bytes.len() as u32).to_be_bytes();
    for mut part in [prefix.as_slice(), bytes] {
        while !part.is_empty() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|v| !v.is_zero())
                .ok_or("FRAME_DEADLINE")?;
            stream.set_write_timeout(Some(remaining))?;
            match stream.write(part) {
                Ok(0) => return Err("FRAME_EOF".into()),
                Ok(n) => part = &part[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}
fn hex_packet(text: &str) -> Result<Packet> {
    ensure(
        text.len() <= 2_097_152
            && text.len().is_multiple_of(2)
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "PACKET_HEX",
    )?;
    Packet::decode(&hex::decode(text).map_err(|_| Error::from("PACKET_HEX"))?)
}
fn dispatch(
    node: &mut Node,
    request: Request,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Value> {
    progress(0)?;
    match request {
        Request::Head => node.stats(),
        Request::Submit { .. } => Err("SUBMIT_REQUIRES_WORK_CHECK".into()),
        Request::History { tip, after } => {
            let packets =
                node.history_with_progress(digest(&tip)?, digest(&after)?, 16, progress)?;
            let next = packets
                .last()
                .map(|p| p.id().map(hex::encode))
                .transpose()?
                .unwrap_or_else(|| after.clone());
            Ok(serde_json::to_value(Page {
                schema: "pon-native-history-v1".into(),
                network: hex::encode(node.settings().network()),
                parameters: hex::encode(node.settings().parameters()),
                genesis: hex::encode(node.settings().genesis()),
                complete: next == tip,
                tip,
                after,
                next,
                packets: packets
                    .iter()
                    .map(|p| p.encode().map(hex::encode))
                    .collect::<Result<_>>()?,
            })?)
        }
        Request::Confirm { transaction, block } => {
            let batch = node.confirmations_with_progress(
                &[(digest(&transaction)?, digest(&block)?)],
                now()?,
                progress,
            )?;
            Ok(serde_json::to_value(
                batch
                    .observations
                    .into_iter()
                    .next()
                    .ok_or("EMPTY_CONFIRMATION")?,
            )?)
        }
        Request::ConfirmMany { queries } => Ok(serde_json::to_value(
            node.confirmations_with_progress(&confirmation_queries(&queries)?, now()?, progress)?,
        )?),
    }
}
fn lock_owner<'a>(
    node: &'a Mutex<Node>,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<MutexGuard<'a, Node>> {
    loop {
        progress(0)?;
        match node.try_lock() {
            Ok(owner) => return Ok(owner),
            Err(TryLockError::Poisoned(_)) => return Err("OWNER_POISONED".into()),
            Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(2)),
        }
    }
}

fn submit_result(node: &mut Node, id: Hash, clock: u64) -> Result<Value> {
    let active = node.activate_observed(id, clock)?;
    Ok(json!({"block":hex::encode(id),"active":hex::encode(active),
        "generation":node.active()?.1,"physical_execution":false}))
}

/// The verifier runs outside the only durable owner's lock. It cannot commit a block.
/// The injected verifier is private and used only to schedule deterministic unit tests.
fn dispatch_shared_with(
    node: &Mutex<Node>,
    request: Request,
    progress: &mut dyn FnMut(u64) -> Result<()>,
    verify: impl FnOnce(Packet) -> Result<WorkCheckedPacket>,
) -> Result<Value> {
    match request {
        Request::Submit { packet } => {
            let packet = hex_packet(&packet)?;
            {
                let mut owner = lock_owner(node, progress)?;
                let clock = now()?;
                if let Some(id) = owner.check_admission_context(&packet, clock)? {
                    return submit_result(&mut owner, id, clock);
                }
            }
            progress(0)?;
            let checked = verify(packet)?;
            // Cancellation after work must not turn into a durable admission.
            progress(0)?;
            let mut owner = lock_owner(node, progress)?;
            let clock = now()?;
            let id = owner.admit_work_checked(checked, clock)?;
            submit_result(&mut owner, id, clock)
        }
        other => {
            let mut owner = lock_owner(node, progress)?;
            dispatch(&mut owner, other, progress)
        }
    }
}

pub fn serve(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
) -> Result<Metrics> {
    ensure(
        listener.local_addr()?.ip().is_loopback(),
        "DEVELOPMENT_LOOPBACK_ONLY",
    )?;
    ensure(
        lifetime > Duration::ZERO && lifetime <= Duration::from_secs(3600),
        "SERVER_BUDGET",
    )?;
    listener.set_nonblocking(true)?;
    let listeners = (0..3)
        .map(|_| listener.try_clone())
        .collect::<std::io::Result<Vec<_>>>()?;
    let node = Arc::new(Mutex::new(node));
    let metrics = Arc::new(Mutex::new(Metrics::default()));
    let (public, _local_recovery) = bounded_ingress();
    let deadline = Instant::now() + lifetime;
    thread::scope(|scope| -> Result<()> {
        let mut workers = Vec::new();
        for listener in listeners {
            let node = node.clone();
            let metrics = metrics.clone();
            let public = public.clone();
            let stop = stop.clone();
            workers.push(scope.spawn(move || -> Result<()> {
                while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                    let (mut socket, address) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(e) => return Err(e.into()),
                    };
                    let request_deadline = deadline.min(Instant::now() + Duration::from_secs(10));
                    socket.set_nonblocking(false)?;
                    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
                    let bytes = match read_frame(&mut socket) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?
                                .malformed_requests += 1;
                            let _ = write_frame(
                                &mut socket,
                                &serde_json::to_vec(&json!({"error":e.to_string()}))?,
                            );
                            continue;
                        }
                    };
                    let peer = hash(b"native-peer-ip", &[address.ip().to_string().as_bytes()]);
                    let _permit = match public.try_acquire(peer, hash(b"native-request", &[&bytes]))
                    {
                        Ok(p) => p,
                        Err(e) => {
                            metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?
                                .busy_requests += 1;
                            let _ = write_frame(
                                &mut socket,
                                &serde_json::to_vec(&json!({"error":format!("BUSY:{e:?}")}))?,
                            );
                            continue;
                        }
                    };
                    let result = (|| -> Result<Value> {
                        let request: Request = serde_json::from_slice(&bytes)?;
                        let mut progress = |_: u64| -> Result<()> {
                            ensure(!stop.load(Ordering::Acquire), "CANCELLED")?;
                            ensure(Instant::now() < request_deadline, "REQUEST_DEADLINE")
                        };
                        dispatch_shared_with(
                            &node,
                            request,
                            &mut progress,
                            WorkCheckedPacket::verify,
                        )
                    })();
                    let reply = match result {
                        Ok(value) => {
                            metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?
                                .completed_requests += 1;
                            value
                        }
                        Err(e) => {
                            metrics
                                .lock()
                                .map_err(|_| Error::from("METRICS_POISONED"))?
                                .rejected_requests += 1;
                            json!({"error":e.to_string()})
                        }
                    };
                    let _ = write_frame(&mut socket, &serde_json::to_vec(&reply)?);
                }
                Ok(())
            }));
        }
        for worker in workers {
            worker.join().map_err(|_| Error::from("WORKER_PANIC"))??;
        }
        Ok(())
    })?;
    let metrics = Arc::try_unwrap(metrics).map_err(|_| Error::from("METRICS_LIFETIME"))?;
    metrics.into_inner().map_err(|_| "METRICS_POISONED".into())
}
pub fn call(address: SocketAddr, request: &Request) -> Result<Value> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write_frame(&mut stream, &serde_json::to_vec(request)?)?;
    let bytes = read_frame(&mut stream)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if let Some(error) = value.get("error") {
        return Err(format!("REMOTE:{error}").into());
    }
    Ok(value)
}
pub fn receive_page(
    node: &mut Node,
    page: Page,
    tip: Hash,
    after: Hash,
    clock: u64,
) -> Result<Hash> {
    ensure(
        page.schema == "pon-native-history-v1"
            && page.network == hex::encode(node.settings().network())
            && page.parameters == hex::encode(node.settings().parameters())
            && page.genesis == hex::encode(node.settings().genesis()),
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
    ensure(
        page.packets.iter().map(String::len).sum::<usize>() <= MAX_FRAME - 1024,
        "PAGE_LIMIT",
    )?;
    let packets = page
        .packets
        .iter()
        .map(|s| hex_packet(s))
        .collect::<Result<Vec<_>>>()?;
    let mut next = after;
    for packet in &packets {
        ensure(packet.header.parent == next, "PAGE_PARENT")?;
        next = packet.id()?;
    }
    ensure(
        page.next == hex::encode(next) && page.complete == (next == tip),
        "PAGE_COMPLETE",
    )?;
    for packet in &packets {
        node.admit(packet, clock)?;
    }
    if page.complete {
        node.activate_observed(tip, clock)?;
    }
    Ok(next)
}
pub fn sync_from(
    node: &mut Node,
    address: SocketAddr,
    tip: Hash,
    mut after: Hash,
    page_budget: usize,
) -> Result<Hash> {
    ensure((1..=4096).contains(&page_budget), "SYNC_BUDGET")?;
    for _ in 0..page_budget {
        let request = Request::History {
            tip: hex::encode(tip),
            after: hex::encode(after),
        };
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        write_frame(&mut stream, &serde_json::to_vec(&request)?)?;
        let page: Page = serde_json::from_slice(&read_frame(&mut stream)?)?;
        let complete = page.complete;
        after = receive_page(node, page, tip, after, now()?)?;
        if complete {
            return Ok(after);
        }
    }
    Err(format!(
        "INCOMPLETE_HISTORY:page_budget:after={}",
        hex::encode(after)
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slow_partial_frame_cannot_extend_the_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sender = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&1000u32.to_be_bytes()).unwrap();
            for _ in 0..40 {
                if stream.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let (mut stream, _) = listener.accept().unwrap();
        assert!(read_frame_budget(&mut stream, Duration::from_millis(100)).is_err());
        drop(stream);
        sender.join().unwrap();
    }

    fn pending_packet() -> (tempfile::TempDir, Mutex<Node>, Packet) {
        let dir = tempfile::tempdir().unwrap();
        let clock = now().unwrap();
        let settings = crate::Settings::development(Some(clock - 100)).unwrap();
        let node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let packet = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                clock - 90,
                4096,
            )
            .unwrap();
        (dir, Mutex::new(node), packet)
    }

    #[test]
    fn work_replay_does_not_hold_the_durable_owner_lock() {
        let (_dir, node, packet) = pending_packet();
        let expected = packet.id().unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let reply = dispatch_shared_with(&node, request, &mut |_| Ok(()), |packet| {
            // Schedule a genuine status read while the verifier is in flight.
            assert!(node.try_lock().is_ok());
            let head = dispatch_shared_with(&node, Request::Head, &mut |_| Ok(()), |_| {
                panic!("read requests cannot ask for work verification")
            })
            .unwrap();
            assert_eq!(head["height"], 0);
            WorkCheckedPacket::verify(packet)
        })
        .unwrap();
        assert_eq!(reply["block"], hex::encode(expected));
        assert_eq!(node.lock().unwrap().stats().unwrap()["height"], 1);
    }

    #[test]
    fn cancellation_after_actual_work_verification_has_no_commit() {
        let (_dir, node, packet) = pending_packet();
        let before = node.lock().unwrap().stats().unwrap();
        let cancelled = AtomicBool::new(false);
        let mut progress = |_| ensure(!cancelled.load(Ordering::Acquire), "CANCELLED");
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let error = dispatch_shared_with(&node, request, &mut progress, |packet| {
            let checked = WorkCheckedPacket::verify(packet)?;
            cancelled.store(true, Ordering::Release);
            Ok(checked)
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "CANCELLED");
        assert_eq!(node.lock().unwrap().stats().unwrap(), before);
    }

    #[test]
    fn context_reject_and_exact_duplicate_do_not_replay_work() {
        let (_dir, node, packet) = pending_packet();
        let mut wrong = packet.clone();
        wrong.header.network[0] ^= 1;
        let request = Request::Submit {
            packet: hex::encode(wrong.encode().unwrap()),
        };
        assert_eq!(
            dispatch_shared_with(&node, request, &mut |_| Ok(()), |_| panic!(
                "bad context reached work verifier"
            ))
            .unwrap_err()
            .to_string(),
            "NETWORK"
        );
        let encoded = hex::encode(packet.encode().unwrap());
        dispatch_shared_with(
            &node,
            Request::Submit {
                packet: encoded.clone(),
            },
            &mut |_| Ok(()),
            WorkCheckedPacket::verify,
        )
        .unwrap();
        let before = node.lock().unwrap().stats().unwrap();
        dispatch_shared_with(
            &node,
            Request::Submit { packet: encoded },
            &mut |_| Ok(()),
            |_| panic!("exact stored duplicate repeated work"),
        )
        .unwrap();
        assert_eq!(node.lock().unwrap().stats().unwrap(), before);
    }

    #[test]
    fn verified_work_cannot_bypass_destination_context_or_clock() {
        let (_dir, node, packet) = pending_packet();
        let checked = WorkCheckedPacket::verify(packet.clone()).unwrap();
        let before = node.lock().unwrap().stats().unwrap();
        assert_eq!(
            node.lock()
                .unwrap()
                .admit_work_checked(checked, 1)
                .unwrap_err()
                .to_string(),
            "TIME_DEFERRED"
        );
        assert_eq!(node.lock().unwrap().stats().unwrap(), before);
        let other_dir = tempfile::tempdir().unwrap();
        let mut other = Node::open(
            other_dir.path(),
            crate::Settings::development(None).unwrap(),
            1,
        )
        .unwrap();
        let before = other.stats().unwrap();
        assert_eq!(
            other
                .admit_work_checked(WorkCheckedPacket::verify(packet).unwrap(), now().unwrap())
                .unwrap_err()
                .to_string(),
            "NETWORK"
        );
        assert_eq!(other.stats().unwrap(), before);
    }

    #[test]
    fn owner_lock_wait_remains_cooperatively_cancellable() {
        let (_dir, node, _packet) = pending_packet();
        let held = node.lock().unwrap();
        let mut calls = 0;
        let mut progress = |_| {
            calls += 1;
            ensure(calls < 3, "CANCELLED")
        };
        assert!(matches!(lock_owner(&node, &mut progress), Err(e) if e.to_string() == "CANCELLED"));
        assert_eq!(calls, 3);
        drop(held);
        assert!(lock_owner(&node, &mut |_| Ok(())).is_ok());
    }

    #[test]
    fn intervening_heavier_branch_does_not_promote_the_verified_stale_candidate() {
        let (_dir, node, packet) = pending_packet();
        let original = packet.id().unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let reply = dispatch_shared_with(&node, request, &mut |_| Ok(()), |packet| {
            {
                let mut owner = node.lock().unwrap();
                let base = owner.settings().genesis_time();
                for height in 1..=2 {
                    let other = owner.make(
                        owner.active()?.0,
                        vec![],
                        crate::development_public(1)?,
                        base + height * 10,
                        4096,
                    )?;
                    let id = owner.admit(&other, now()?)?;
                    owner.activate_observed(id, now()?)?;
                }
            }
            WorkCheckedPacket::verify(packet)
        })
        .unwrap();
        assert_eq!(reply["block"], hex::encode(original));
        assert_ne!(reply["active"], reply["block"]);
        let owner = node.lock().unwrap();
        assert_eq!(owner.stats().unwrap()["height"], 2);
        assert_eq!(owner.stats().unwrap()["stored_blocks"], 4);
    }
}
