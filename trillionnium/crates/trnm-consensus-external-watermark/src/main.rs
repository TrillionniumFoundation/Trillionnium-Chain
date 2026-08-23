use std::{env, process::ExitCode};

use trnm_consensus_external_watermark::{
    run_daemon, run_per_reservation_daemon, run_semantic_daemon, ExternalWatermarkSemanticBindingV1,
};

fn usage() -> ! {
    eprintln!("usage: trnm-external-watermark-v0 semantic --socket ABS_PATH --log ABS_PATH --scope HEX32 --journal-id HEX32 --capability HEX32 [--per-reservation]");
    eprintln!("       opaque --fixture-opaque --socket ABS_PATH --log ABS_PATH");
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut raw_args: Vec<String> = env::args().skip(1).collect();
    let first = raw_args.first().cloned();
    let (mode, explicit_mode) = match first.as_deref() {
        Some("opaque") => (false, None),
        Some("semantic") => (true, None),
        Some(flag) if flag.starts_with('-') => (false, Some(())),
        _ => usage(),
    };
    if explicit_mode.is_none() {
        raw_args.remove(0);
    }
    let mut args = raw_args.into_iter();
    let mut socket = None;
    let mut log = None;
    let mut scope = None;
    let mut journal_id = None;
    let mut capability = None;
    let mut per_reservation = false;
    let mut fixture_opaque = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => set_once(&mut socket, args.next(), "--socket"),
            "--log" => set_once(&mut log, args.next(), "--log"),
            "--scope" => {
                let value = args.next().unwrap_or_else(|| usage());
                set_once(
                    &mut scope,
                    Some(decode_hex32(&value).unwrap_or_else(|_| usage())),
                    "--scope",
                );
            }
            "--journal-id" => {
                let value = args.next().unwrap_or_else(|| usage());
                set_once(
                    &mut journal_id,
                    Some(decode_hex32(&value).unwrap_or_else(|_| usage())),
                    "--journal-id",
                );
            }
            "--capability" => {
                let value = args.next().unwrap_or_else(|| usage());
                set_once(
                    &mut capability,
                    Some(decode_hex32(&value).unwrap_or_else(|_| usage())),
                    "--capability",
                );
            }
            "--per-reservation" => {
                if per_reservation {
                    usage();
                }
                per_reservation = true;
            }
            "--fixture-opaque" => {
                if fixture_opaque {
                    usage();
                }
                fixture_opaque = true;
            }
            "--help" => usage(),
            _ => usage(),
        }
    }
    let socket = socket.unwrap_or_else(|| usage());
    let log = log.unwrap_or_else(|| usage());
    let result = if mode {
        if fixture_opaque {
            usage();
        }
        let binding = ExternalWatermarkSemanticBindingV1::new(
            scope.unwrap_or_else(|| usage()),
            journal_id.unwrap_or_else(|| usage()),
            capability.unwrap_or_else(|| usage()),
        )
        .unwrap_or_else(|| usage());
        if per_reservation {
            run_per_reservation_daemon(socket, log, binding)
        } else {
            run_semantic_daemon(socket, log, binding)
        }
    } else {
        if !fixture_opaque
            || per_reservation
            || scope.is_some()
            || journal_id.is_some()
            || capability.is_some()
        {
            usage();
        }
        run_daemon(socket, log)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("external watermark authority failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn set_once<T>(slot: &mut Option<T>, value: Option<T>, flag: &str) {
    if slot.is_some() || value.is_none() {
        eprintln!("duplicate or missing value for {flag}");
        usage();
    }
    *slot = value;
}

fn decode_hex32(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64 {
        return Err(());
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        let high = nibble(value.as_bytes()[index * 2]).ok_or(())?;
        let low = nibble(value.as_bytes()[index * 2 + 1]).ok_or(())?;
        *slot = (high << 4) | low;
    }
    if output == [0; 32] {
        return Err(());
    }
    Ok(output)
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
