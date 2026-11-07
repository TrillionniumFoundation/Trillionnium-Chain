use super::*;
use std::io::Write;

/// Faults affect only this real loopback test peer. No production hook, fake
/// signature, policy override or claim about a real CPU bucket is introduced.
pub(super) enum Fault {
    LostAckThenMalformedFrame,
    EofBeforeEveryAdmission,
    SignedRemoteLabel {
        server: Box<PqServer>,
        label: &'static str,
    },
}
pub(super) struct Proxy {
    pub address: SocketAddr,
    pub seen: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}
impl Proxy {
    pub fn start(target: SocketAddr, policy: Arc<PqNetworkPolicy>, fault: Fault) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let observed = seen.clone();
        let worker = thread::spawn(move || -> Result<()> {
            let end = Instant::now() + Duration::from_secs(30);
            let mut ordinal = 0;
            while !stopping.load(Ordering::Acquire) && Instant::now() < end {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let deadline = end.min(Instant::now() + Duration::from_secs(10));
                        let wire = crate::ingress::read_frame_deadline(&mut stream, deadline)?;
                        observed.lock().unwrap().push(wire.clone());
                        let index = ordinal;
                        ordinal += 1;
                        match &fault {
                            Fault::EofBeforeEveryAdmission => continue,
                            Fault::SignedRemoteLabel { server, label } => {
                                let verified =
                                    policy.verify_request(&wire, crate::ingress::now()?)?;
                                let response =
                                    server.response(&verified, Err(crate::Error::from(*label)))?;
                                crate::ingress::write_frame_deadline(
                                    &mut stream,
                                    &response,
                                    deadline,
                                )?;
                                continue;
                            }
                            Fault::LostAckThenMalformedFrame if index == 1 => {
                                // A complete invalid length is a terminal local
                                // framing failure, distinct from the prior EOF.
                                stream.write_all(&u32::MAX.to_be_bytes())?;
                                continue;
                            }
                            _ => {}
                        }
                        let budget = deadline
                            .checked_duration_since(Instant::now())
                            .ok_or("FRAME_DEADLINE")?;
                        let mut upstream = TcpStream::connect_timeout(&target, budget)?;
                        crate::ingress::write_frame_deadline(&mut upstream, &wire, deadline)?;
                        let response =
                            crate::ingress::read_frame_deadline(&mut upstream, deadline)?;
                        if matches!(&fault, Fault::LostAckThenMalformedFrame) && index == 0 {
                            // The actual Node completed and returned its signed
                            // receipt, but no byte of that receipt reaches caller.
                            continue;
                        }
                        crate::ingress::write_frame_deadline(&mut stream, &response, deadline)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        });
        Self {
            address,
            seen,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if thread::panicking() {
                if !matches!(&result, Ok(Ok(_))) {
                    eprintln!("proxy join during panic: {result:?}");
                }
            } else {
                result.unwrap().unwrap();
            }
        }
    }
}
