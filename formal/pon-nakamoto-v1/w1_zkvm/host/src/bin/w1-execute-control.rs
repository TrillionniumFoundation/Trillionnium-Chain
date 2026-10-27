//! Execute the pinned full guest for positive/negative controls and cycle counts.
//! This produces NO cryptographic receipt and cannot qualify the proof experiment.
use anyhow::{ensure, Context, Result};
use risc0_zkvm::{Executor, ExecutorEnv, ExitCode, ExternalProver};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::Instant};
use trnm_w1_zk_methods::{TRNM_W1_FULL_GUEST_ELF, TRNM_W1_FULL_GUEST_ID};
use trnm_w1_zk_relation::{check_complete_relation, fixture};

fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn main() -> Result<()> {
    for key in [
        "RISC0_DEV_MODE",
        "BONSAI_API_URL",
        "BONSAI_API_KEY",
        "RISC0_PROVER",
    ] {
        ensure!(
            std::env::var_os(key).is_none(),
            "unexpected proof-selection environment"
        );
    }
    let mut args = std::env::args().skip(1);
    let r0vm = PathBuf::from(args.next().context("absolute pinned r0vm path")?);
    let mode = args
        .next()
        .context("valid | wrong-task | wrong-product | wrong-transcript")?;
    ensure!(args.next().is_none(), "unexpected arguments");
    ensure!(
        r0vm.is_absolute() && r0vm.is_file(),
        "absolute pinned r0vm required"
    );
    ensure!(
        sha(&fs::read(&r0vm)?)
            == "2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6",
        "local prover digest mismatch"
    );
    let mut input = fixture(0);
    match mode.as_str() {
        "valid" => {}
        "wrong-task" => input[318 + 4] ^= 1,
        "wrong-product" => input[318 + 4 + 2 * 4096 * 4] ^= 1,
        "wrong-transcript" => *input.last_mut().unwrap() ^= 1,
        _ => anyhow::bail!("unknown control"),
    }
    let expected = check_complete_relation(&input);
    ensure!(
        expected.is_ok() == (mode == "valid"),
        "native control did not match declared class"
    );
    let executor = ExternalProver::new("pinned-local-execution-control", r0vm);
    let env = ExecutorEnv::builder()
        .segment_limit_po2(18)
        .session_limit(Some(1 << 30))
        .write_slice(&input)
        .build()?;
    let start = Instant::now();
    let observed = executor.execute(env, TRNM_W1_FULL_GUEST_ELF);
    let elapsed = start.elapsed().as_nanos();
    let result = match observed {
        Ok(session) => {
            if let Ok(journal) = &expected {
                ensure!(
                    session.exit_code == ExitCode::Halted(0),
                    "valid guest did not halt successfully"
                );
                ensure!(
                    session.journal.bytes == *journal,
                    "guest/native output mismatch"
                );
            } else {
                ensure!(
                    session.exit_code != ExitCode::Halted(0),
                    "invalid witness accepted by guest"
                );
            }
            json!({"exit_code":format!("{:?}",session.exit_code),"segments":session.segments.len(),"user_cycles":session.cycles(),"journal_bytes":session.journal.bytes.len(),"journal_sha256":sha(&session.journal.bytes)})
        }
        Err(error) => {
            ensure!(expected.is_err(), "valid guest execution failed: {error}");
            // The error text is retained; callers must distinguish a guest
            // assertion from infrastructure failure in their evidence review.
            json!({"executor_error":error.to_string(),"guest_rejection_requires_error_readback":true})
        }
    };
    println!(
        "{}",
        json!({"schema":"trnm-w1-real-guest-execution-control-v1","mode":mode,"native_result":format!("{:?}",expected.as_ref().map(|_| ())),"input_sha256":sha(&input),"guest_image_id":TRNM_W1_FULL_GUEST_ID,"execution_ns":elapsed,"result":result,"cryptographic_proof_generated":false,"consensus_admission":false,"production_activation":false})
    );
    Ok(())
}
