// Private cfg(test) child of the unchanged original request_observation module.
// This adapter calls the actual original methods. Its finite command scheduler
// is test infrastructure, not a replacement original paid account or executor.
use super::ThreadCpuStamp;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle, ThreadId};

#[derive(Clone, Deserialize)]
struct Command {
    op: u64,
    target: u64,
    stamp: Option<String>,
    save: Option<String>,
    argument: u64,
    positive: bool,
}
#[derive(Deserialize)]
struct ClockFixture {
    expected: Option<u64>,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    commands: Vec<Command>,
    fixture: bool,
    injection: Option<String>,
    controlled_timespec: Option<ClockFixture>,
}
struct State {
    stamps: HashMap<String, ThreadCpuStamp>,
    checksum: u64,
    original_calls: u64,
}
struct Observed {
    comparison: Value,
    original: Value,
}
enum Message {
    Execute(Command, mpsc::Sender<Observed>),
    Stop,
}
struct Worker {
    sender: mpsc::Sender<Message>,
    join: JoinHandle<ThreadId>,
    identity: ThreadId,
}

fn work(mut value: u64, count: u64) -> u64 {
    for index in 0..count {
        value = std::hint::black_box(
            value.wrapping_mul(1_664_525)
                 .wrapping_add(1_013_904_223)
                 .wrapping_add(index),
        );
    }
    value
}

fn execute(
    command: &Command,
    state: &Arc<Mutex<State>>,
    fixture: bool,
    expected: ThreadId,
    clock_fixture: Option<Option<u64>>,
) -> Observed {
    let actual = thread::current().id();
    assert_eq!(actual, expected, "private scheduler did not enter the real target thread");
    let mut state = state.lock().expect("private reference registry poisoned");
    let mut some = false;
    let mut consumed = false;
    let mut owner_same = None;
    let mut before = None;
    let mut after = None;
    let mut elapsed = None;
    let mut controlled_value = None;
    let method;
    match command.op {
        1 => {
            method = "original ThreadCpuStamp::start";
            state.original_calls += 1;
            let stamp = ThreadCpuStamp::start();
            after = stamp.as_ref().map(|value| value.ns);
            if let Some(expected_value) = clock_fixture {
                assert_eq!(after, expected_value, "original full syscall timespec conversion differs");
                controlled_value = after;
            }
            if let Some(stamp) = stamp {
                assert_eq!(stamp.thread, actual);
                let name = command.save.as_ref().expect("start requires output label");
                assert!(!state.stamps.contains_key(name));
                state.stamps.insert(name.clone(), stamp);
                some = true;
            }
        }
        2 => {
            method = "original ThreadCpuStamp::clone";
            state.original_calls += 1;
            let old = state.stamps
                .get(command.stamp.as_ref().expect("clone requires a label"))
                .expect("missing original stamp");
            before = Some(old.ns);
            owner_same = Some(old.thread == actual);
            let cloned = old.clone();
            assert_eq!(cloned.ns, old.ns);
            assert_eq!(cloned.thread, old.thread);
            after = Some(cloned.ns);
            let name = command.save.as_ref().expect("clone requires output label");
            assert!(!state.stamps.contains_key(name));
            state.stamps.insert(name.clone(), cloned);
            some = true;
        }
        3 => {
            method = "original ThreadCpuStamp::checkpoint";
            state.original_calls += 1;
            let stamp = state.stamps
                .get_mut(command.stamp.as_ref().expect("checkpoint requires a label"))
                .expect("missing original stamp");
            before = Some(stamp.ns);
            owner_same = Some(stamp.thread == actual);
            elapsed = stamp.checkpoint();
            after = Some(stamp.ns);
            some = elapsed.is_some();
            if let Some(value) = elapsed {
                assert_eq!(owner_same, Some(true));
                assert_eq!(after.unwrap().checked_sub(before.unwrap()), Some(value));
            } else {
                assert_eq!(after, before, "failed original checkpoint reset its baseline");
            }
        }
        4 => {
            method = "original ThreadCpuStamp::finish";
            state.original_calls += 1;
            let stamp = state.stamps
                .remove(command.stamp.as_ref().expect("finish requires a label"))
                .expect("missing original stamp");
            before = Some(stamp.ns);
            owner_same = Some(stamp.thread == actual);
            // The actual original self-consuming method is invoked on this thread.
            elapsed = stamp.finish();
            consumed = true;
            some = elapsed.is_some();
            if some {
                assert_eq!(owner_same, Some(true));
            }
        }
        8 => {
            method = "original ThreadCpuStamp value drop, no CPU sampling";
            state.original_calls += 1;
            let stamp = state.stamps
                .remove(command.stamp.as_ref().expect("drop requires a label"))
                .expect("missing original stamp");
            before = Some(stamp.ns);
            owner_same = Some(stamp.thread == actual);
            drop(stamp);
            consumed = true;
        }
        5 => {
            method = "private native arithmetic workload, not original Node work";
            assert!((1..=1_000_000).contains(&command.argument));
            state.checksum = work(state.checksum, command.argument);
        }
        129 => {
            method = "private fixture baseline edit followed by original methods";
            assert!(fixture, "baseline fixture is not a production primitive");
            let stamp = state.stamps
                .get_mut(command.stamp.as_ref().expect("fixture requires a label"))
                .expect("missing original stamp");
            before = Some(stamp.ns);
            owner_same = Some(stamp.thread == actual);
            stamp.ns = command.argument;
            after = Some(stamp.ns);
        }
        _ => panic!("unhandled private primitive operation"),
    }
    let positive_requirement_met = if command.positive {
        assert!(elapsed.is_some_and(|value| value > 0), "mandatory actual Linux CPU interval was not positive");
        Some(true)
    } else {
        None
    };
    Observed {
        comparison: json!({
            "op":command.op,"target":command.target,"some":some,
            "active":state.stamps.len(),"consumed":consumed,"owner_same":owner_same,
            "baseline_invariant":true,"positive_requirement_met":positive_requirement_met,
            "checksum":state.checksum,"controlled_value":controlled_value
        }),
        original: json!({
            "method":method,"actual_thread_id":format!("{actual:?}"),
            "before":before,"after":after,"elapsed":elapsed,
            "original_calls_so_far":state.original_calls
        }),
    }
}

fn run(case: &Case) -> Value {
    let main = thread::current().id();
    let state = Arc::new(Mutex::new(State {
        stamps: HashMap::new(),
        checksum: 1,
        original_calls: 0,
    }));
    let mut worker: Option<Worker> = None;
    let mut thread_ids = vec![main];
    let mut births = 0_u64;
    let mut joins = 0_u64;
    let mut comparison = Vec::new();
    let mut observations = Vec::new();
    for command in &case.commands {
        assert!(command.target <= 1);
        let mut observed = if command.op == 6 {
            assert_eq!(command.target, 0);
            assert!(worker.is_none());
            let (sender, receiver) = mpsc::channel();
            let (ready_send, ready_receive) = mpsc::channel();
            let registry = state.clone();
            let fixture = case.fixture;
            let join = thread::Builder::new()
                .name("hia-original-thread-cpu".into())
                .spawn(move || {
                    let current = thread::current().id();
                    ready_send.send(current).unwrap();
                    while let Ok(message) = receiver.recv() {
                        match message {
                            Message::Execute(command, reply) => {
                                reply.send(execute(&command, &registry, fixture, current, None)).unwrap();
                            }
                            Message::Stop => break,
                        }
                    }
                    assert_eq!(thread::current().id(), current);
                    current
                })
                .expect("mandatory real original worker creation failed");
            let identity = ready_receive.recv().expect("real child readiness missing");
            assert!(identity != main && !thread_ids.contains(&identity), "Rust ThreadId was reused");
            thread_ids.push(identity);
            worker = Some(Worker { sender, join, identity });
            births += 1;
            let locked = state.lock().unwrap();
            Observed {
                comparison: json!({
                    "op":command.op,"target":0,"some":false,"active":locked.stamps.len(),
                    "consumed":false,"owner_same":null,"baseline_invariant":true,
                    "positive_requirement_met":null,"checksum":locked.checksum,
                    "controlled_value":null
                }),
                original: json!({"method":"actual std::thread::Builder spawn and child readiness",
                                 "actual_thread_id":format!("{main:?}"),
                                 "child_thread_id":format!("{identity:?}")}),
            }
        } else if command.op == 7 {
            assert_eq!(command.target, 0);
            let old = worker.take().expect("no actual child to join");
            old.sender.send(Message::Stop).expect("actual child stop failed");
            let finished = old.join.join().expect("actual child panicked");
            assert_eq!(finished, old.identity);
            joins += 1;
            let locked = state.lock().unwrap();
            Observed {
                comparison: json!({
                    "op":command.op,"target":0,"some":false,"active":locked.stamps.len(),
                    "consumed":false,"owner_same":null,"baseline_invariant":true,
                    "positive_requirement_met":null,"checksum":locked.checksum,
                    "controlled_value":null
                }),
                original: json!({"method":"actual std::thread::JoinHandle::join",
                                 "actual_thread_id":format!("{main:?}"),
                                 "joined_thread_id":format!("{finished:?}")}),
            }
        } else if command.target == 0 {
            execute(command, &state, case.fixture, main,
                    case.controlled_timespec.as_ref().map(|value| value.expected))
        } else {
            let live = worker.as_ref().expect("worker command has no actual child");
            let (reply, returned) = mpsc::channel();
            live.sender.send(Message::Execute(command.clone(), reply)).unwrap();
            returned.recv().expect("actual worker did not execute the original method")
        };
        observed.comparison["births"] = json!(births);
        observed.comparison["joins"] = json!(joins);
        comparison.push(observed.comparison);
        observations.push(observed.original);
    }
    if let Some(old) = worker {
        old.sender.send(Message::Stop).unwrap();
        assert_eq!(old.join.join().unwrap(), old.identity);
        joins += 1;
    }
    assert_eq!(births, joins, "every actual original child must be joined");
    let locked = state.lock().unwrap();
    json!({
        "name":case.name,"comparison":comparison,"observations":observations,
        "original_calls":locked.original_calls,
        "actual_thread_ids":thread_ids.into_iter().map(|id|format!("{id:?}")).collect::<Vec<_>>(),
        "actual_births":births,"actual_joins":joins,
        "fixture_baseline_edit_enabled":case.fixture,
        "controlled_syscall_result_fixture":case.injection.is_some(),
        "original_shared_paid_account_executed":false,
        "original_scoped_executor_executed":false
    })
}

#[test]
fn linux_clock_is_mandatory() {
    assert_eq!(std::env::consts::OS, "linux");
    let stamp = ThreadCpuStamp::start().expect("mandatory original Linux thread CPU clock unavailable");
    let value = work(1, 100_000);
    std::hint::black_box(value);
    let elapsed = stamp.finish().expect("mandatory original Linux finish unavailable");
    assert!(elapsed > 0, "mandatory original Linux CPU interval was not positive");
    println!("HIA_THREAD_CPU_LINUX_AVAILABLE:{elapsed}");
}

#[test]
fn evaluate() {
    assert_eq!(std::env::consts::OS, "linux");
    let path = std::env::var("TRNM_HIA_THREAD_CPU_CORPUS").expect("missing exact corpus");
    let selection = std::env::var("TRNM_HIA_THREAD_CPU_CASE").ok();
    let raw = std::fs::read_to_string(path).expect("cannot read exact corpus");
    let cases = raw.lines().map(|line| serde_json::from_str::<Case>(line).unwrap()).collect::<Vec<_>>();
    let mut executed = 0;
    for case in &cases {
        let selected = match &selection {
            Some(name) => &case.name == name,
            None => case.injection.is_none(),
        };
        if !selected {
            continue;
        }
        println!("HIA_THREAD_CPU_ORACLE:{}", run(case));
        executed += 1;
    }
    assert!(executed > 0, "no exact original case executed");
    if selection.is_some() {
        assert_eq!(executed, 1, "ambiguous exact original case");
    }
}
