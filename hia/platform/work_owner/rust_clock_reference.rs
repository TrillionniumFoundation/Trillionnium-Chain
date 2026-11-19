// Private observer inside the original resource_tests child. Production methods
// and their error ordering remain unchanged. This parent-owned observation lives
// until its actual scoped child has been joined, including a child panic.
mod clock_fault_observation {
    use super::*;
    use std::io::Write;

    const CLOCK_MARKER: &str = "HIA_WORK_OWNER_CLOCK:";

    #[derive(Default)]
    struct Observed {
        worker_tid: u32,
        progress: Vec<[u64; 5]>,
        host_calls: u64,
        host_checks: u64,
        work_code: u64,
        ordinary_finish_returned: bool,
        paid_checkpoints: u64,
        paid: Option<Value>,
        live: Option<crate::ingress::public_v3::hia_work_owner_bridge::PaidLive>,
    }

    fn role(tid: u32, kind: u64) {
        let mut marker = [0u8; 32];
        marker[..8].copy_from_slice(b"PCROLE01");
        marker[8..16].copy_from_slice(&u64::from(tid).to_le_bytes());
        marker[16..24].copy_from_slice(&kind.to_le_bytes());
        io::stderr().lock().write_all(&marker).unwrap();
    }

    fn checked(owner: &FixtureOwner, observed: &mut Observed) -> crate::Result<()> {
        observed.host_calls += 1;
        let parent = owner.checked()?;
        observed.host_checks += 1;
        drop(parent);
        Ok(())
    }

    fn evaluate(case: &Value) -> Value {
        assert_eq!(case["gate_stage"].as_u64(), Some(0));
        assert_eq!(case["gate_sequence"].as_u64(), Some(0));
        assert_eq!(case["signal"].as_u64(), Some(0));
        assert_eq!(case["delay_ms"].as_u64(), Some(0));
        assert!(case["actions"].as_array().unwrap().is_empty());
        let input = decoded(case["request_hex"].as_str().unwrap());
        assert_eq!(input.len(), 49_284);
        let challenge: [u8; 32] = input[0..32].try_into().unwrap();
        let task: [u8; 32] = input[32..64].try_into().unwrap();
        let target: [u8; 32] = input[64..96].try_into().unwrap();
        let temp = tempfile::tempdir().unwrap();
        provision(temp.path());
        let main_tid = actual_tid();
        role(main_tid, 1);
        // The same four-second Instant is created before acquire and initial
        // sampling, exactly as in the original ordinary-method observer.
        let deadline = Instant::now() + Duration::from_secs(4);
        let paid_domain = PaidDomain::new();
        let cancel = AtomicBool::new(false);
        let stop = AtomicBool::new(false);
        let owner = FixtureOwner::acquire(temp.path()).unwrap();
        let before_checks = Cell::new(0u64);
        let parent = owner.checked().unwrap();
        drop(parent);
        before_checks.set(1);
        let before = owner
            .sample(0, &[], &before_checks, &Cell::new(false))
            .unwrap();
        let mut observed = Observed::default();
        let joined = thread::scope(|scope| {
            let retained = &mut observed;
            let owner = &owner;
            let input = &input;
            let stop = &stop;
            let cancel = &cancel;
            let paid_domain = &paid_domain;
            let child = scope.spawn(move || {
                retained.worker_tid = actual_tid();
                assert_ne!(main_tid, retained.worker_tid);
                role(retained.worker_tid, 3);
                let operation = paid_domain.begin()?;
                retained.live = Some(operation.live());
                let native = (|| -> crate::Result<pon_work::VerifiedWork> {
                    checked(owner, retained)?;
                    crate::ingress::public_v3::hia_work_owner_bridge::alive(
                        deadline, stop, cancel,
                    )?;
                    retained.paid_checkpoints += 1;
                    operation.checkpoint()?;
                    let checked_work = pon_work::verify_with_progress(
                        challenge,
                        task,
                        target,
                        &input[96..],
                        &mut |point| {
                            let sequence = u64::try_from(retained.progress.len()).unwrap() + 1;
                            retained.progress.push(progress_row(point, sequence));
                            crate::ingress::public_v3::hia_work_owner_bridge::alive(
                                deadline, stop, cancel,
                            )?;
                            checked(owner, retained)?;
                            crate::ingress::public_v3::hia_work_owner_bridge::alive(
                                deadline, stop, cancel,
                            )?;
                            retained.paid_checkpoints += 1;
                            operation.checkpoint()
                        },
                    );
                    match checked_work {
                        Ok(value) => Ok(value),
                        Err(VerificationError::Cancelled(error)) => Err(error),
                        Err(VerificationError::Relation(error)) => {
                            retained.work_code = relation_code(error);
                            Err(format!("HIA_WORK_RELATION_{}", retained.work_code).into())
                        }
                    }
                })();
                let result = crate::ingress::public_v3::hia_work_owner_bridge::finish(
                    native,
                    deadline,
                    || checked(owner, retained),
                );
                retained.paid = Some(operation.finish());
                retained.ordinary_finish_returned = true;
                result
            });
            // This consumes the actual original std join handle. A panic is
            // observed after join, never converted into a returned Work value.
            child.join()
        });
        // The private diagnostic marker follows the consumed real join result.
        // The tracer also reads the actual clone child-clear-TID word here.
        let mut join_marker = [0u8; 32];
        join_marker[..8].copy_from_slice(b"PCJOIN01");
        join_marker[8..16].copy_from_slice(&u64::from(main_tid).to_le_bytes());
        join_marker[16..24].copy_from_slice(&u64::from(observed.worker_tid).to_le_bytes());
        join_marker[24..32].copy_from_slice(&u64::from(joined.is_err()).to_le_bytes());
        io::stderr().lock().write_all(&join_marker).unwrap();
        let mut after_sample_attempts = 0u64;
        let mut after_checks = 0u64;
        let mut after_values = None;
        let mut delta_values = None;
        let mut product = None;
        let mut returned_domain = None;
        let mut returned_code = None;
        let mut panic_payload = None;
        let panicked = match joined {
            Err(payload) => {
                panic_payload = Some(
                    payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                        .expect("the actual std clock panic must retain its string payload"),
                );
                true
            }
            Ok(mut outcome) => {
                after_sample_attempts += 1;
                let checks = Cell::new(before_checks.get());
                match owner.sample(0, &[], &checks, &Cell::new(false)) {
                    Err(error) => outcome = Err(error),
                    Ok(after) => match after.cpu_delta_since(before) {
                        Err(error) => outcome = Err(error),
                        Ok(delta) => {
                            after_values = Some(values(after));
                            delta_values = Some([
                                delta.usage_usec,
                                delta.nr_periods,
                                delta.nr_throttled,
                                delta.throttled_usec,
                            ]);
                        }
                    },
                }
                after_checks = checks.get();
                match outcome {
                    Ok(value) => {
                        returned_domain = Some(0u64);
                        returned_code = Some(0u64);
                        product = Some(hex::encode(
                            value
                                .product()
                                .iter()
                                .flat_map(|word| word.to_le_bytes())
                                .collect::<Vec<_>>(),
                        ));
                    }
                    Err(error) => {
                        let (domain, code) = outcome_code(&error);
                        returned_domain = Some(domain);
                        returned_code = Some(code);
                    }
                }
                false
            }
        };
        json!({
            "schema": "trnm.hia.work-owner-original-clock-observation.v2",
            "name": case["name"],
            "input_sha256": hex::encode(Sha256::digest(&input)),
            "main_tid": main_tid,
            "worker_tid": observed.worker_tid,
            "joined": true,
            "worker_panicked": panicked,
            "panic_payload": panic_payload,
            "progress": observed.progress,
            "host_calls": observed.host_calls,
            "host_checks": observed.host_checks,
            "before_checks": before_checks.get(),
            "before_values": values(before),
            "after_sample_attempts": after_sample_attempts,
            "after_checks": after_checks,
            "after_values": after_values,
            "delta_values": delta_values,
            "product_hex": product,
            "returned_domain": returned_domain,
            "returned_code": returned_code,
            "work_code": observed.work_code,
            "ordinary_finish_returned": observed.ordinary_finish_returned,
            "paid": observed.paid,
            "paid_checkpoints": observed.paid_checkpoints,
            "paid_live": observed.live.map(|live| live.snapshot()),
            "paid_global": paid_domain.snapshot(),
            "actual_original_finite_paid_work_checkpoints": true,
            "actual_original_W1": true,
            "actual_original_Host_primitives": true,
            "actual_original_task_alive_and_final_resource": true,
            "actual_original_std_scoped_spawn_and_join": true,
            "parent_retained_observation_after_actual_join": true,
            "production_fixed_parent_authority": false,
            "complete_Node_or_paid_checkpoint": false,
            "original_deadline_seconds": 4,
        })
    }

    #[test]
    fn actual_controlled_clock() {
        let path = std::env::var_os("TRNM_HIA_WORK_OWNER_CORPUS")
            .expect("mandatory exact baseline corpus required");
        let input = fs::File::open(path).unwrap();
        let lines: Vec<_> = io::BufReader::new(input)
            .lines()
            .map(|line| line.unwrap())
            .collect();
        assert_eq!(lines.len(), 1);
        let case: Value = serde_json::from_str(&lines[0]).unwrap();
        println!("{CLOCK_MARKER}{}", evaluate(&case));
    }
}
