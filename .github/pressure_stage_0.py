from pathlib import Path
root=Path.cwd()
p=root/'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs'
s=p.read_text()
def rep(a,b):
 global s
 assert s.count(a)==1, (s.count(a),a[:80])
 s=s.replace(a,b)
rep('impl Client {\n    fn call(&self, lane: &str, who: u8, request: Request) -> Value {\n        let start = Instant::now();', '''fn call_deadline(start: Instant, outer: Option<Instant>) -> Instant {
    let local = start + Duration::from_millis(CALL_MS);
    outer.map(|deadline| deadline.min(local)).unwrap_or(local)
}
impl Client {
    fn call(&self, lane: &str, who: u8, request: Request) -> Value {
        self.call_before(lane, who, request, None)
    }
    fn call_before(
        &self,
        lane: &str,
        who: u8,
        request: Request,
        outer: Option<Instant>,
    ) -> Value {
        let start = Instant::now();
        let deadline = call_deadline(start, outer);''')
rep('let started_ns = ns(self.epoch);','let started_ns: u64 = start.duration_since(self.epoch).as_nanos().try_into().unwrap();')
rep('Some(start + Duration::from_millis(CALL_MS)),','Some(deadline),')
rep('''        let ended_ns = ns(self.epoch);
        let elapsed_ns = ns(start);
        let late = elapsed_ns > CALL_MS * 1_000_000;''','''        let end = Instant::now();
        let ended_ns: u64 = end.duration_since(self.epoch).as_nanos().try_into().unwrap();
        let elapsed_ns: u64 = end.duration_since(start).as_nanos().try_into().unwrap();
        let deadline_at_ns: u64 = deadline.duration_since(self.epoch).as_nanos().try_into().unwrap();
        let outer_at_ns = outer.map(|value| {
            u64::try_from(value.duration_since(self.epoch).as_nanos()).unwrap()
        });
        let late = end > deadline;''')
rep('''            "elapsed_wall_ns": elapsed_ns, "deadline_ms": CALL_MS,
            "client_thread_cpu_ns": client_thread_cpu_ns,''','''            "elapsed_wall_ns": elapsed_ns, "deadline_ms": CALL_MS,
            "effective_deadline_at_ns": deadline_at_ns, "outer_deadline_at_ns": outer_at_ns,
            "client_thread_cpu_ns": client_thread_cpu_ns,''')
rep('''fn caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct() {
    assert_eq!''','''fn caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct() {
    // Expiry is exercised through the actual client, not a timer-only mock.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let epoch = Instant::now();
    let client = Client {
        address: listener.local_addr().unwrap(),
        settings: Settings::development(Some(1_750_000_000)).unwrap(),
        epoch,
    };
    let start = Instant::now();
    assert_eq!(call_deadline(start, None), start + Duration::from_millis(CALL_MS));
    assert_eq!(call_deadline(start, Some(start)), start);
    assert_eq!(call_deadline(start, Some(epoch)), epoch);
    assert_eq!(
        call_deadline(start, Some(start + Duration::from_secs(4))),
        start + Duration::from_millis(CALL_MS)
    );
    let row = client.call_before("expired_pressure", 72, Request::Head, Some(epoch));
    assert_eq!(row["status"], "error");
    assert_eq!(row["error"], "PUBLIC_CLIENT_DEADLINE");
    assert_eq!(row["effective_deadline_at_ns"], 0);
    assert_eq!(row["metrics"]["solution_trials"], 0);
    assert_eq!(row["metrics"]["failed_stage"], "construction");
    assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!''')
rep('''    // One common wall window. Request construction, negotiation, backpressure,
    // ticket search and failures all consume it; no retry renews that window.''','''    // One common attacker window, passed into every actual TCP call. Honest
    // probes retain their original two-second SLO and are reported separately;
    // joined cleanup is not credited as additional offered attack time.''')
rep('''                    let call = client.call(
                        "sustained_from_zero",''','''                    let call = client.call_before(
                        "sustained_from_zero",''')
rep('''                            packet: packet.clone(),
                        },
                    );''','''                            packet: packet.clone(),
                        },
                        Some(window_end),
                    );''')
rep('''    let budget_depletion_observed =
        below_start_reserve_observed || observed_debt || mutation_cpu_refusals > 0;''','''    // Raw credit includes outstanding start reservations, and reserve refusals
    // can mean occupied workers. Neither is a causal public-depletion witness.
    let budget_pressure_observed =
        below_start_reserve_observed || observed_debt || mutation_cpu_refusals > 0;''')
rep('''    (
        node,
        json!({
            "phase": number, "target": hex::encode(target), "initial_meter": initial_budget,''','''    let mut observation = json!({
            "phase": number, "target": hex::encode(target), "initial_meter": initial_budget,''')
rep('''            "budget_depletion_observed": budget_depletion_observed,''','''            "budget_pressure_observed": budget_pressure_observed,''')
rep('''            "work_profile_qualified": false, "production_activation": false,
        }),
    )
}

fn sustained_observation''','''            "work_profile_qualified": false, "production_activation": false,
        });
    observation["window_started_ns"] = json!(u64::try_from(window_start.duration_since(epoch).as_nanos()).unwrap());
    observation["window_ended_ns"] = json!(u64::try_from(window_end.duration_since(epoch).as_nanos()).unwrap());
    (node, observation)
}

fn sustained_observation''')
rep('"schema": "public-v3-sustained-local-from-zero-v1"','"schema": "public-v3-sustained-local-from-zero-v2"')
rep('''        "budget_depletion_demonstrated": first["budget_depletion_observed"] == true
            || second["budget_depletion_observed"] == true,''','''        "budget_pressure_observed": first["budget_pressure_observed"] == true
            || second["budget_pressure_observed"] == true,
        "budget_depletion_demonstrated": false,''')
p.write_text(s)
