    // Component-only experiment. This module is added to a byte-bound copy of
    // the actual production reader; it is not inserted into the repository.
    fn probe_open(path: &std::ffi::CStr) -> io::Result<fs::File> {
        loop {
            match rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                Ok(fd) => return Ok(fd.into()),
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn fresh_open_component_probe() -> Result<()> {
        use std::hint::black_box;
        use std::os::unix::ffi::OsStrExt;
        use std::time::Instant;
        const ROUNDS: usize = 16;
        const REPEATS: usize = 128;
        let names = [
            "/proc/sys/kernel/random/boot_id",
            "/proc/thread-self/cgroup",
            "/sys/fs/cgroup/cpu.max",
            "/sys/fs/cgroup/cpu.max.burst",
            "/sys/fs/cgroup/memory.max",
            "/sys/fs/cgroup/memory.swap.max",
            "/sys/fs/cgroup/pids.max",
        ];
        let paths = names.map(Path::new);
        let c_paths = paths.map(|p| std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap());
        let expected = paths.map(|p| fs::read_to_string(p).unwrap());
        let cpu_now = || {
            let t = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
            (t.tv_sec as u128) * 1_000_000_000 + (t.tv_nsec as u128)
        };
        let mut samples = Vec::new();
        for round in 0..ROUNDS {
            for (slot, candidate) in [false, true, true, false].into_iter().enumerate() {
                let cpu_before = cpu_now();
                let wall_before = Instant::now();
                let mut equal = true;
                let mut observed_bytes = 0usize;
                for _ in 0..REPEATS {
                    for (index, ((path, c_path), expected)) in
                        paths.iter().zip(&c_paths).zip(&expected).enumerate()
                    {
                        if index < 2 {
                            let mut bytes = [0; CONTEXT_STACK_BYTES + 1];
                            let text = if candidate {
                                let mut file = probe_open(c_path)
                                    .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?;
                                read_context_text(&mut file, &mut bytes)
                                    .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?
                            } else {
                                read_context(path, &mut bytes)?
                            };
                            equal &= black_box(text.as_bytes()) == expected.as_bytes();
                            observed_bytes += text.len();
                        } else {
                            let mut bytes = [0; MAX_LIMIT_BYTES + 1];
                            let text = if candidate {
                                let mut file = probe_open(c_path)
                                    .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_UNAVAILABLE"))?;
                                read_limit_text(&mut file, &mut bytes)?
                            } else {
                                read_limit(path, &mut bytes)?
                            };
                            equal &= black_box(text.as_bytes()) == expected.as_bytes();
                            observed_bytes += text.len();
                        }
                    }
                }
                let wall_ns = wall_before.elapsed().as_nanos();
                let cpu_ns = cpu_now() - cpu_before;
                equal &= observed_bytes == REPEATS * expected.iter().map(String::len).sum::<usize>();
                samples.push(serde_json::json!({"round": round, "slot": slot,
                    "candidate": candidate, "fresh_opens": REPEATS * paths.len(),
                    "observed_bytes": observed_bytes, "all_bytes_equal": equal,
                    "thread_cpu_ns": cpu_ns, "wall_ns": wall_ns}));
            }
        }
        let all_equal = samples.iter().all(|r| r["all_bytes_equal"] == true);
        println!("{}", serde_json::json!({
            "schema": "fresh-open-cstr-component-probe-v1", "samples": samples,
            "rounds": ROUNDS, "abba_slots_per_round": 4, "repeats_per_slot": REPEATS,
            "paths": names, "all_bytes_equal": all_equal,
            "predeclared_selection": "consider further production testing only if median paired thread-CPU B/A <= 0.95 and empirical p95 <= 1.0; preserve every sample",
            "scope": "fresh open plus original complete bounded/unbounded readers; immutable pathname spelling only; no descriptor/content/verdict retained; current container root is NOT the approved public Host parent",
            "full_host_verified": false, "original_service_gate_passed": false,
            "production_candidate_accepted": false
        }));
        if !all_equal {
            return Err("component source changed during observation".into());
        }
        Ok(())
    }

