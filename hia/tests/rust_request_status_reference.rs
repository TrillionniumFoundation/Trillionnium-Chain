//! Test transport for the unchanged original RequestStatus implementation.
use std::io::{self, BufRead, Write};
use trnm_types::{RequestStateError, RequestStatus};

const STATES: [RequestStatus; 7] = [
    RequestStatus::Open,
    RequestStatus::Assigned,
    RequestStatus::CommitQueued,
    RequestStatus::RevealSubmitted,
    RequestStatus::Rejected,
    RequestStatus::FailedAdapter,
    RequestStatus::FailedSubmission,
];

fn index(state: RequestStatus) -> u64 {
    STATES
        .iter()
        .position(|candidate| *candidate == state)
        .unwrap() as u64
}

fn record(
    kind: u64,
    from: u64,
    to: u64,
    flags: u64,
    display: &str,
    detail: &str,
    code: &str,
) -> Vec<u8> {
    let mut output = b"RQSR0001".to_vec();
    for word in [
        kind,
        from,
        to,
        flags,
        display.len() as u64,
        detail.len() as u64,
        code.len() as u64,
    ] {
        output.extend_from_slice(&word.to_le_bytes());
    }
    for value in [display, detail, code] {
        output.extend_from_slice(value.as_bytes());
    }
    output
}

fn flags(from: RequestStatus, to: RequestStatus) -> u64 {
    u64::from(from.is_terminal())
        | (u64::from(from.can_transition_to(to)) << 1)
        | (u64::from(to.is_terminal()) << 2)
}

fn state_record(from: RequestStatus, to: RequestStatus) -> Vec<u8> {
    assert_eq!(to.to_string(), to.as_str());
    record(
        0,
        index(from),
        index(to),
        flags(from, to),
        &to.to_string(),
        "",
        "",
    )
}

fn error_record(error: RequestStateError) -> Vec<u8> {
    let display = error.to_string();
    let code = error.stable_code();
    match &error {
        RequestStateError::UnknownState { input } => record(1, 255, 255, 0, &display, input, code),
        RequestStateError::InvalidTransition { from, to } => record(
            2,
            index(*from),
            index(*to),
            flags(*from, *to),
            &display,
            "",
            code,
        ),
    }
}

fn run(input: &[u8]) -> Vec<u8> {
    assert!(input.len() >= 16);
    assert_eq!(&input[..4], b"RQS1");
    assert_eq!(input[7], 0);
    let body_size = u64::from_le_bytes(input[8..16].try_into().unwrap());
    assert_eq!(body_size as usize, input.len() - 16);
    match input[4] {
        0 => {
            assert_eq!(&input[5..7], &[0, 0]);
            match RequestStatus::parse(std::str::from_utf8(&input[16..]).unwrap()) {
                Ok(state) => state_record(state, state),
                Err(error) => error_record(error),
            }
        }
        1 => {
            assert_eq!(body_size, 0);
            assert_eq!(input[6], 0);
            let state = STATES[usize::from(input[5])];
            state_record(state, state)
        }
        2 => {
            assert_eq!(body_size, 0);
            let from = STATES[usize::from(input[5])];
            let to = STATES[usize::from(input[6])];
            match from.transition(to) {
                Ok(state) => {
                    assert_eq!(state, to);
                    state_record(from, state)
                }
                Err(error) => error_record(error),
            }
        }
        _ => panic!("unsupported test operation"),
    }
}

fn main() {
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        assert_eq!(line.len() % 2, 0);
        let input: Vec<u8> = (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            .collect();
        for byte in run(&input) {
            write!(output, "{byte:02x}").unwrap();
        }
        writeln!(output).unwrap();
    }
}
