//! R11 whole-controller-cgroup evidence. These are real kernel observations,
//! never per-actor RSS, a physical reservation, work credit, or service authority.
//! The old public-phase RSS samples remain untouched, including their nulls.
use super::*;

pub(super) const SCHEMA: &str = "fixed-host-root-controller-resources-v1";
const SAMPLE_SCHEMA: &str = "fixed-host-root-controller-resource-sample-v1";
const MEMORY_CEILING: u64 = 17_179_869_184;
const SCOPE: &str = "whole original controller cgroup and all descendants; includes controller, broker, launcher and external producer processes; excludes separately systemd-owned public phase; not per-actor RSS";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct Counters {
    cpu_usage_usec: u64,
    memory_current_bytes: u64,
    memory_peak_lifetime_bytes: u64,
}

fn unsigned(raw: &str) -> Result<u64, String> {
    let text = raw.trim();
    require(
        raw.is_ascii() && !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
        "RESOURCE_UNSIGNED_INTEGER_REQUIRED",
    )?;
    text.parse::<u64>().map_err(|error| error.to_string())
}

fn parse(cpu: &str, current: &str, peak: &str) -> Result<Counters, String> {
    require(
        cpu.is_ascii() && cpu.len() <= 2048 && current.len() <= 128 && peak.len() <= 128,
        "BOUNDED_ACTUAL_CONTROLLER_COUNTERS",
    )?;
    let mut fields = BTreeMap::new();
    for line in cpu.lines() {
        let mut parts = line.split_ascii_whitespace();
        let key = parts.next().ok_or("COMPLETE_CPU_STAT_FIELD")?;
        let value = unsigned(parts.next().ok_or("COMPLETE_CPU_STAT_FIELD")?)?;
        require(
            parts.next().is_none() && fields.insert(key, value).is_none(),
            "UNIQUE_COMPLETE_CPU_STAT_FIELDS",
        )?;
    }
    let result = Counters {
        cpu_usage_usec: *fields
            .get("usage_usec")
            .ok_or("ACTUAL_USAGE_USEC_REQUIRED")?,
        memory_current_bytes: unsigned(current)?,
        memory_peak_lifetime_bytes: unsigned(peak)?,
    };
    require(
        result.cpu_usage_usec > 0
            && result.memory_current_bytes > 0
            && result.memory_current_bytes <= result.memory_peak_lifetime_bytes
            && result.memory_peak_lifetime_bytes <= MEMORY_CEILING,
        "ACTIVE_CONTROLLER_COUNTER_GEOMETRY",
    )?;
    Ok(result)
}

fn identity(controller: &VerifiedController) -> Result<ControllerIdentity, String> {
    let process = observe_process(controller.identity.process.pid)?;
    let cgroup = group_identity(&process.cgroup)?;
    let actual = ControllerIdentity { process, cgroup };
    require(
        actual == controller.identity,
        "RESOURCE_CONTROLLER_IDENTITY_CHANGED",
    )?;
    Ok(actual)
}

fn actor_rows(controller: &VerifiedController, actors: &[Actor]) -> Vec<Value> {
    actors
        .iter()
        .enumerate()
        .map(|(ordinal, actor)| {
            let pid = actor.pid();
            json!({"ordinal":ordinal,"pid":pid,"identity":controller.actor(pid)})
        })
        .collect()
}

pub(super) fn sample(
    controller: &VerifiedController,
    stage: &str,
    actors: &[Actor],
    expected: usize,
) -> Value {
    let started = support::monotonic();
    let controller_before = identity(controller);
    let actors_before = actor_rows(controller, actors);
    let read = |name: &str, limit| -> Result<String, String> {
        controller_before.as_ref().map_err(Clone::clone)?;
        kernel_text(
            &external_group(&controller.identity.process.cgroup)?.join(name),
            limit,
        )
    };
    // Attempt all three independently after the same actual identity was checked.
    // Err/raw bytes remain in the report; no zero, RSS, or RUSAGE substitute.
    let cpu = read("cpu.stat", 2048);
    let current = read("memory.current", 128);
    let peak = read("memory.peak", 128);
    let counters = (|| {
        parse(
            cpu.as_ref().map_err(Clone::clone)?,
            current.as_ref().map_err(Clone::clone)?,
            peak.as_ref().map_err(Clone::clone)?,
        )
    })();
    let actors_after = actor_rows(controller, actors);
    let controller_after = identity(controller);
    let ended = support::monotonic();
    let validation = (|| -> Result<(), String> {
        require(
            matches!(stage, "before_launch" | "actors_ready" | "after_reap")
                && matches!(expected, 0 | ATTACKERS)
                && actors.len() == expected
                && started > 0
                && started <= ended,
            "EXACT_CONTROLLER_RESOURCE_SAMPLE_SCOPE",
        )?;
        controller_before.as_ref().map_err(Clone::clone)?;
        controller_after.as_ref().map_err(Clone::clone)?;
        counters.as_ref().map_err(Clone::clone)?;
        let mut pids = BTreeSet::new();
        for (before, after) in actors_before.iter().zip(&actors_after) {
            let pid = before["pid"].as_u64().ok_or("RESOURCE_ACTOR_PID")?;
            require(
                pid > 1
                    && pids.insert(pid)
                    && before == after
                    && before["identity"].get("Ok").is_some(),
                "RESOURCE_ACTOR_IDENTITY_CHANGED",
            )?;
        }
        require(pids.len() == expected, "ALL_RESOURCE_ACTORS_REQUIRED")
    })();
    json!({"schema":SAMPLE_SCHEMA,"stage":stage,"scope":SCOPE,
        "controller_identity":controller.identity,"controller_before":controller_before,
        "controller_after":controller_after,"expected_live_actors":expected,
        "actors_before":actors_before,"actors_after":actors_after,
        "started_monotonic_ns":started,"ended_monotonic_ns":ended,
        "reads":{"cpu_stat":cpu,"memory_current":current,"memory_peak":peak},
        "counters":counters,"complete":validation.is_ok(),"validation":validation})
}

fn known(sample: &Value) -> Result<Counters, String> {
    require(
        sample["schema"] == SAMPLE_SCHEMA
            && sample["scope"] == SCOPE
            && sample["complete"] == true
            && sample["validation"] == json!({"Ok":null}),
        "KNOWN_ACTUAL_CONTROLLER_SAMPLE_REQUIRED",
    )?;
    let raw = |name: &str| {
        sample["reads"][name]["Ok"]
            .as_str()
            .ok_or("ACTUAL_CONTROLLER_RAW_READ_REQUIRED")
    };
    let counters = parse(
        raw("cpu_stat")?,
        raw("memory_current")?,
        raw("memory_peak")?,
    )?;
    require(
        sample["counters"] == json!({"Ok":counters}),
        "RAW_AND_PARSED_CONTROLLER_COUNTERS_MUST_AGREE",
    )?;
    Ok(counters)
}

fn interval(before: Counters, ready: Counters, after: Counters) -> Result<u64, String> {
    require(
        before.cpu_usage_usec <= ready.cpu_usage_usec
            && ready.cpu_usage_usec <= after.cpu_usage_usec
            && before.memory_peak_lifetime_bytes <= ready.memory_peak_lifetime_bytes
            && ready.memory_peak_lifetime_bytes <= after.memory_peak_lifetime_bytes,
        "CONTROLLER_COUNTER_REWIND",
    )?;
    let delta = after
        .cpu_usage_usec
        .checked_sub(before.cpu_usage_usec)
        .ok_or("CONTROLLER_COUNTER_REWIND")?;
    require(delta > 0, "OBSERVED_CONTROLLER_CPU_DELTA_REQUIRED")?;
    Ok(delta)
}

pub(super) fn finish(
    controller: &ControllerIdentity,
    phase: &str,
    before: Value,
    ready: Value,
    after: Value,
    spawned: &[Value],
    children: &[Value],
) -> Value {
    let expected = if phase == "valid-work-root" {
        ATTACKERS
    } else {
        0
    };
    let reaped: Vec<_> = children.iter().map(|row| row["pid"].clone()).collect();
    let validation = (|| -> Result<u64, String> {
        require(
            matches!(phase, "baseline" | "valid-work-root"),
            "EXACT_RESOURCE_PHASE",
        )?;
        require(
            spawned.len() == expected && reaped.len() == expected,
            "ALL_SPAWNED_AND_REAPED_RESOURCE_ACTORS_REQUIRED",
        )?;
        let expected_controller = json!(controller);
        let samples = [
            (&before, "before_launch", 0),
            (&ready, "actors_ready", expected),
            (&after, "after_reap", 0),
        ];
        let mut previous_end = 0;
        for (sample, stage, count) in samples {
            require(
                sample["stage"] == stage
                    && sample["controller_identity"] == expected_controller
                    && sample["controller_before"] == json!({"Ok":controller})
                    && sample["controller_after"] == json!({"Ok":controller})
                    && sample["expected_live_actors"] == count,
                "EXACT_CONTROLLER_RESOURCE_IDENTITY",
            )?;
            let start = sample["started_monotonic_ns"]
                .as_u64()
                .ok_or("RESOURCE_CLOCK")?;
            let end = sample["ended_monotonic_ns"]
                .as_u64()
                .ok_or("RESOURCE_CLOCK")?;
            require(
                previous_end <= start && start <= end,
                "ORDERED_CONTROLLER_RESOURCE_CLOCKS",
            )?;
            previous_end = end;
            for field in ["actors_before", "actors_after"] {
                let rows = sample[field].as_array().ok_or("RESOURCE_ACTOR_ROWS")?;
                require(rows.len() == count, "COMPLETE_CONTROLLER_RESOURCE_ACTORS")?;
                for (ordinal, row) in rows.iter().enumerate() {
                    let actual = &spawned[ordinal];
                    require(
                        row["ordinal"] == ordinal
                            && row["pid"] == actual["pid"]
                            && row["identity"] == json!({"Ok":actual["identity"]}),
                        "CONTROLLER_RESOURCE_ACTOR_BINDING",
                    )?;
                }
            }
        }
        let mut pids = BTreeSet::new();
        for (ordinal, (spawn, reap)) in spawned.iter().zip(&reaped).enumerate() {
            let pid = spawn["pid"].as_u64().ok_or("RESOURCE_ACTOR_PID")?;
            require(
                pid > 1 && pids.insert(pid) && spawn["ordinal"] == ordinal && reap == &json!(pid),
                "DISTINCT_REAPED_RESOURCE_ACTORS_REQUIRED",
            )?;
        }
        interval(known(&before)?, known(&ready)?, known(&after)?)
    })();
    json!({"schema":SCHEMA,"scope":SCOPE,"phase":phase,"controller_identity":controller,
        "expected_phase_actors":expected,"actor_manifest":spawned,"reaped_actor_pids":reaped,
        "before_launch":before,"actors_ready":ready,"after_reap":after,
        "cpu_interval_scope":"before phase launcher spawn through actual actor reaping and phase exit; excludes earlier honest-miner preparation",
        "memory_peak_scope":"whole original controller service lifetime, including earlier preparation and previous phases; never a memory delta or per-actor peak",
        "per_actor_rss_qualified":false,"old_public_rss_diagnostics_preserved":true,
        "cpu_usage_delta_usec":validation.as_ref().ok(),"complete":validation.is_ok(),
        "validation":validation})
}

pub(super) fn campaign_complete(phases: &[Value]) -> bool {
    let validate = || -> Result<(), String> {
        require(phases.len() == 2, "BOTH_RESOURCE_PHASES_REQUIRED")?;
        let mut previous: Option<Counters> = None;
        let mut previous_end = 0;
        for (phase, expected) in phases.iter().zip(["baseline", "valid-work-root"]) {
            let group = &phase["external_controller_resources"];
            require(
                group["schema"] == SCHEMA
                    && group["phase"] == expected
                    && group["complete"] == true,
                "ALL_CONTROLLER_RESOURCE_PHASES_REQUIRED",
            )?;
            for name in ["before_launch", "actors_ready", "after_reap"] {
                let sample = &group[name];
                let counters = known(sample)?;
                let start = sample["started_monotonic_ns"]
                    .as_u64()
                    .ok_or("RESOURCE_CLOCK")?;
                let end = sample["ended_monotonic_ns"]
                    .as_u64()
                    .ok_or("RESOURCE_CLOCK")?;
                require(
                    previous_end <= start && start <= end,
                    "CAMPAIGN_RESOURCE_CLOCK_REWIND",
                )?;
                if let Some(prior) = previous {
                    require(
                        prior.cpu_usage_usec <= counters.cpu_usage_usec
                            && prior.memory_peak_lifetime_bytes
                                <= counters.memory_peak_lifetime_bytes,
                        "CAMPAIGN_CONTROLLER_COUNTER_REWIND",
                    )?;
                }
                previous = Some(counters);
                previous_end = end;
            }
        }
        Ok(())
    };
    validate().is_ok()
}

#[test]
fn fixed_root_controller_resource_parser_rejects_missing_duplicate_and_unknown_counters() {
    assert_eq!(
        parse("usage_usec 42\nuser_usec 20\n", "128\n", "256\n").unwrap(),
        Counters {
            cpu_usage_usec: 42,
            memory_current_bytes: 128,
            memory_peak_lifetime_bytes: 256
        }
    );
    for cpu in [
        "",
        "user_usec 1\n",
        "usage_usec 1\nusage_usec 2\n",
        "usage_usec -1\n",
        "usage_usec 1 extra\n",
        "usage_usec 18446744073709551616\n",
        "usage_usec 0\n",
    ] {
        assert!(parse(cpu, "128", "256").is_err(), "{cpu}");
    }
    for (current, peak) in [
        ("0", "256"),
        ("256", "128"),
        ("128", "max"),
        ("128", ""),
        ("128", "17179869185"),
        ("true", "256"),
    ] {
        assert!(parse("usage_usec 42\n", current, peak).is_err());
    }
}

#[test]
fn fixed_root_controller_resource_interval_rejects_rewind_and_lifetime_peak_as_delta() {
    let before = parse("usage_usec 42\n", "128", "512").unwrap();
    let ready = parse("usage_usec 43\n", "256", "512").unwrap();
    let after = parse("usage_usec 44\n", "64", "512").unwrap();
    assert_eq!(interval(before, ready, after).unwrap(), 2);
    assert!(interval(ready, before, after).is_err());
    assert!(interval(before, ready, before).is_err());
    assert!(interval(before, before, before).is_err());
    let decreased_peak = parse("usage_usec 44\n", "64", "256").unwrap();
    assert!(interval(before, ready, decreased_peak).is_err());
}
