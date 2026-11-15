use super::*;

fn cancelled(error: &CellErrorV1) -> bool {
    matches!(error, CellErrorV1::Io(error)
        if error.kind() == io::ErrorKind::Interrupted
            && error.to_string().contains("CELL_OPERATION_CANCELLED"))
}

fn accept_before(listener: &TcpListener, deadline: Instant) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("cancellation provider accept: {error}"),
        }
    }
}

#[test]
fn observed_cancellation_remains_with_original_session_after_flag_reset() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let flag = AtomicBool::new(true);
    let requests_left = AtomicU64::new(4);
    let responses = ResponseBudget::new(64);
    let transport = RequestContext {
        timeout: Duration::from_secs(1),
        overall: Instant::now() + Duration::from_secs(2),
        requests_left: &requests_left,
        responses: &responses,
        cancelled: Some(&flag),
    };
    let peer = listener.local_addr().unwrap();
    assert!(cancelled(
        &request(peer, 2, [1; 32], 64, &transport).unwrap_err()
    ));
    flag.store(false, Ordering::Release);
    assert!(cancelled(
        &request(peer, 2, [1; 32], 64, &transport).unwrap_err()
    ));
    assert_eq!(requests_left.load(Ordering::Relaxed), 4);
    assert_eq!(responses.received().unwrap(), 0);
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(!responses.is_quarantined(peer).unwrap());
}

#[test]
fn cancellation_keeps_partial_response_charge_without_retry_or_peer_quarantine() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let flag = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    let requests_left = AtomicU64::new(4);
    let responses = ResponseBudget::new(64);
    let deadline = Instant::now() + Duration::from_secs(3);
    let transport = RequestContext {
        timeout: Duration::from_secs(2),
        overall: deadline,
        requests_left: &requests_left,
        responses: &responses,
        cancelled: Some(&flag),
    };
    let (result, attempts) = thread::scope(|scope| {
        let provider = scope.spawn(|| {
            let mut stream = accept_before(&listener, deadline);
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut query = [0; 37];
            stream.read_exact(&mut query).unwrap();
            stream.write_all(b"TCS1").unwrap();
            // The actual client counter, not the server write, establishes
            // that these bytes were received before cancellation.
            while responses.received().unwrap() != 4 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            let before_cancel = responses.received().unwrap();
            flag.store(true, Ordering::Release);
            while !done.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            before_cancel
        });
        let result = request_with_retry(peer, 2, [1; 32], 64, &transport);
        done.store(true, Ordering::Release);
        assert_eq!(provider.join().unwrap(), 4);
        result
    });
    assert!(cancelled(&result.unwrap_err()));
    assert_eq!(attempts, 1);
    assert_eq!(requests_left.load(Ordering::Relaxed), 3);
    assert_eq!(responses.received().unwrap(), 4);
    assert!(!responses.is_quarantined(peer).unwrap());
    flag.store(false, Ordering::Release);
    assert!(cancelled(
        &request(peer, 2, [1; 32], 64, &transport).unwrap_err()
    ));
    assert_eq!(requests_left.load(Ordering::Relaxed), 3);
    assert_eq!(responses.received().unwrap(), 4);
}

#[test]
fn cancellation_poll_timeouts_keep_original_partial_frame_and_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let flag = AtomicBool::new(false);
    let requests_left = AtomicU64::new(1);
    let responses = ResponseBudget::new(11);
    let deadline = Instant::now() + Duration::from_secs(3);
    let transport = RequestContext {
        timeout: Duration::from_secs(2),
        overall: deadline,
        requests_left: &requests_left,
        responses: &responses,
        cancelled: Some(&flag),
    };
    let (result, attempts) = thread::scope(|scope| {
        let provider = scope.spawn(|| {
            let mut stream = accept_before(&listener, deadline);
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut query = [0; 37];
            stream.read_exact(&mut query).unwrap();
            stream.write_all(b"TCS1").unwrap();
            // Deliberately span several cancellation polls without expiring
            // the original request or returning a complete frame yet.
            thread::sleep(Duration::from_millis(50));
            stream.write_all(&[0, 0, 0, 0, 2, b'o', b'k']).unwrap();
        });
        let result = request_with_retry(peer, 2, [1; 32], 2, &transport);
        provider.join().unwrap();
        result
    });
    assert_eq!(result.unwrap(), b"ok");
    assert_eq!(attempts, 1);
    assert_eq!(requests_left.load(Ordering::Relaxed), 0);
    assert_eq!(responses.received().unwrap(), 11);
}

#[test]
fn cancelled_budget_wait_preserves_unused_capacity_without_reviving_session() {
    let responses = ResponseBudget::new(9);
    let deadline = Instant::now() + Duration::from_secs(2);
    let reserved = responses.reserve(9, deadline).unwrap();
    let flag = AtomicBool::new(false);
    let result = thread::scope(|scope| {
        let (started, observed) = mpsc::channel();
        let responses = &responses;
        let flag = &flag;
        let waiter = scope.spawn(move || {
            started.send(()).unwrap();
            responses.reserve_controlled(4, deadline, Some(flag))
        });
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        flag.store(true, Ordering::Release);
        waiter.join().unwrap()
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    responses.complete(reserved, 0).unwrap();
    flag.store(false, Ordering::Release);
    assert_eq!(
        responses.reserve(9, deadline).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(responses.received().unwrap(), 0);
    let state = responses.state.lock().unwrap();
    assert_eq!(state.available, 9);
    assert_eq!(state.reserved, 0);
}
