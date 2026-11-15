//! Real confirmations, repeated starts and two genuine process-exit cuts.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Output;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::native_owner_journal::{
    JournalCheckpoint, JournalMakeRequest, JournaledNativeOwner, NativeJournalOptions,
};
use trnm_pon_node::native_risk_ledger::{
    NativeRiskOwner, RiskConfirmationRequest, RiskLedgerCheckpoint, RiskLedgerOptions,
};
use trnm_pon_node::{development_public, Error, Result, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

pub const BEFORE_DISPATCH_EXIT: i32 = 31;
pub const AFTER_NATIVE_EXIT: i32 = 32;
const NOW: u64 = 100;
const SCOPE: Hash = [42; 32];

#[derive(Serialize, Deserialize)]
struct Plan {
    root: PathBuf,
    bank_checkpoint: RiskLedgerCheckpoint,
    native_checkpoint: JournalCheckpoint,
    transaction: Hash,
    included: Hash,
    allowance_units: u64,
    after_native: bool,
}
fn options(pin: Option<RiskLedgerCheckpoint>) -> RiskLedgerOptions {
    RiskLedgerOptions {
        unit_denominator: 1000,
        budget_units: 40,
        law_scope_sha256: SCOPE,
        expected_checkpoint: pin,
        ..RiskLedgerOptions::default()
    }
}
fn open(
    root: &Path,
    bank: Option<RiskLedgerCheckpoint>,
    native: Option<JournalCheckpoint>,
) -> Result<NativeRiskOwner> {
    NativeRiskOwner::open(
        &root.join("store"),
        &root.join("native"),
        &root.join("bank"),
        Settings::development(Some(1))?,
        NativeJournalOptions {
            expected_checkpoint: native,
            ..NativeJournalOptions::default()
        },
        options(bank),
    )
}
fn request(transaction: Hash, included: Hash, allowance_units: u64) -> RiskConfirmationRequest {
    RiskConfirmationRequest {
        transaction,
        included,
        observed_now: NOW,
        allowance_units,
        law_scope_sha256: SCOPE,
        statement_sha256: hash(b"risk-ledger-example-claim-v1", &[&transaction, &included]),
    }
}
fn write_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target.join(entry.file_name()))?;
        } else if entry.file_type()?.is_file() {
            fs::copy(entry.path(), target.join(entry.file_name()))?;
        } else {
            return Err("RISK_EXAMPLE_SPECIAL_FILE".into());
        }
    }
    Ok(())
}
fn transfer(settings: &Settings) -> Result<Vec<u8>> {
    let mut payload = development_public(1)?.to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transaction = Envelope {
        network: settings.network(),
        sender: development_public(0)?,
        nonce: 1,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
        .map_err(|e| Error::from(format!("RISK_EXAMPLE_KEY:{e:?}")))?;
    transaction.signature = hex::decode(sign_hex(
        &key,
        &transaction
            .signing_digest()
            .map_err(|e| Error::from(format!("RISK_EXAMPLE_SIGN:{e:?}")))?,
    ))
    .map_err(|e| Error::from(format!("RISK_EXAMPLE_HEX:{e}")))?
    .try_into()
    .map_err(|_| "RISK_EXAMPLE_SIGNATURE")?;
    transaction
        .encode()
        .map_err(|e| Error::from(format!("RISK_EXAMPLE_TRANSACTION:{e:?}")))
}

/// This function must execute in a child. Both cuts preserve a fsynced charge;
/// the second actually invokes the original native confirmation before exit.
pub fn crash_child(path: &Path) -> Result<()> {
    let plan: Plan = serde_json::from_slice(&fs::read(path)?)?;
    let mut owner = open(
        &plan.root,
        Some(plan.bank_checkpoint),
        Some(plan.native_checkpoint),
    )?;
    let pending = owner.start_confirmation(request(
        plan.transaction,
        plan.included,
        plan.allowance_units,
    ))?;
    let registration = pending.registration_sequence();
    if plan.after_native {
        let outcome = pending.execute()?;
        if !outcome.wrapper_succeeded() {
            return Err("RISK_EXAMPLE_CONFIRMATION_FAILED".into());
        }
        println!(
            "{}",
            json!({"start_durable":true,"registration_sequence":registration,
            "native_confirmation_returned_success":true,"risk_outcome_written":false})
        );
        std::io::stdout().flush()?;
        std::process::exit(AFTER_NATIVE_EXIT)
    }
    println!(
        "{}",
        json!({"start_durable":true,"registration_sequence":registration,
        "native_confirmation_invoked":false,"risk_outcome_written":false})
    );
    std::io::stdout().flush()?;
    std::process::exit(BEFORE_DISPATCH_EXIT)
}

pub fn run(root: &Path, mut spawn: impl FnMut(&Path) -> Result<Output>) -> Result<Value> {
    fs::create_dir(root)?;
    let root = root.canonicalize()?;
    let settings = Settings::development(Some(1))?;
    let tx = transfer(&settings)?;
    let transaction = hash(b"tx-id", &[&tx]);
    let mut owner = open(&root, None, None)?;
    let mut tip = settings.genesis();
    let mut included = None;
    let mut early = None;
    for height in 1..=7 {
        let packet = owner.make(
            JournalMakeRequest {
                parent: tip,
                transactions: if height == 1 {
                    vec![tx.clone()]
                } else {
                    vec![]
                },
                miner: development_public(0)?,
                timestamp: height * 10 + 1,
                max_attempts: 4096,
            },
            NOW,
        )?;
        tip = owner.admit(&packet, NOW)?;
        owner.activate_observed(tip, NOW)?;
        if height == 1 {
            included = Some(tip);
            let observation = owner.confirmation(request(transaction, tip, 1))?;
            if observation.confirmed {
                return Err("RISK_EXAMPLE_EARLY_CONFIRMATION".into());
            }
            early = Some(serde_json::to_value(observation)?);
        }
    }
    let included = included.ok_or("RISK_EXAMPLE_MISSING_TARGET")?;
    let confirmed = owner.confirmation(request(transaction, included, 2))?;
    if !confirmed.confirmed {
        return Err("RISK_EXAMPLE_SIX_SUCCESSORS".into());
    }
    let repeated = owner.confirmation(request(transaction, included, 3))?;
    if !repeated.confirmed {
        return Err("RISK_EXAMPLE_REPEATED_CONFIRMATION".into());
    }
    let failed = owner.confirmation(request([99; 32], included, 4));
    let error = match failed {
        Ok(_) => return Err("RISK_EXAMPLE_MISSING_MEMBERSHIP_REFUSAL".into()),
        Err(e) => e.to_string(),
    };
    if error != "MEMBERSHIP" {
        return Err("RISK_EXAMPLE_UNEXPECTED_NATIVE_ERROR".into());
    }
    let before_children = owner.status()?;
    let (mut bank_pin, mut native_pin) = owner.finish(NOW)?;
    copy_tree(&root.join("bank"), &root.join("old-bank"))?;
    copy_tree(&root.join("native"), &root.join("old-native"))?;
    let mut children = Vec::new();
    let mut recoveries = Vec::new();
    for (index, after_native, allowance, following) in [(1, false, 5, 6), (2, true, 7, 8)] {
        let plan = Plan {
            root: root.clone(),
            bank_checkpoint: bank_pin,
            native_checkpoint: native_pin,
            transaction,
            included,
            allowance_units: allowance,
            after_native,
        };
        let path = root.join(format!("child-{index}-plan.json"));
        write_new(&path, &plan)?;
        let output = spawn(&path)?;
        let expected = if after_native {
            AFTER_NATIVE_EXIT
        } else {
            BEFORE_DISPATCH_EXIT
        };
        if output.status.code() != Some(expected) {
            return Err(format!(
                "RISK_EXAMPLE_CHILD_EXIT:{:?}:{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        children.push(json!({"after_native":after_native,"exit_code":output.status.code(),
            "stdout":String::from_utf8_lossy(&output.stdout),"stderr":String::from_utf8_lossy(&output.stderr)}));
        let mut recovered = open(
            &root,
            Some(plan.bank_checkpoint),
            Some(plan.native_checkpoint),
        )?;
        let before = recovered.status()?;
        let observation = recovered.confirmation(request(transaction, included, following))?;
        if !observation.confirmed {
            return Err("RISK_EXAMPLE_RECOVERED_CONFIRMATION".into());
        }
        let after = recovered.status()?;
        recoveries.push(json!({"before":before,"after":after}));
        if after_native {
            let native_before = recovered.native_checkpoint()?;
            let cap_refusal = match recovered.start_confirmation(request(transaction, included, 5))
            {
                Ok(_) => return Err("RISK_EXAMPLE_BUDGET_BYPASS".into()),
                Err(e) => e.to_string(),
            };
            if cap_refusal != "RISK_LEDGER_BUDGET"
                || recovered.native_checkpoint()? != native_before
            {
                return Err("RISK_EXAMPLE_BUDGET_NATIVE_EFFECT".into());
            }
        }
        (bank_pin, native_pin) = recovered.finish(NOW)?;
    }
    let final_status = recoveries.last().ok_or("RISK_EXAMPLE_RECOVERY")?["after"].clone();
    let stale_refusal = match NativeRiskOwner::open(
        &root.join("store"),
        &root.join("native"),
        &root.join("old-bank"),
        settings,
        NativeJournalOptions::default(),
        options(Some(bank_pin.clone())),
    ) {
        Ok(_) => return Err("RISK_EXAMPLE_STALE_PIN_ACCEPTED".into()),
        Err(e) => e.to_string(),
    };
    if stale_refusal != "RISK_LEDGER_CHECKPOINT" {
        return Err("RISK_EXAMPLE_STALE_PIN_REASON".into());
    }
    let foreign = JournaledNativeOwner::open(
        &root.join("foreign-store"),
        &root.join("foreign-native"),
        Settings::development(Some(1))?,
        NativeJournalOptions::default(),
    )?;
    foreign.finish(NOW)?;
    let report = json!({"schema":"pon-native-risk-ledger-run-v1","bank_directory":"bank","native_directory":"native",
        "foreign_native_directory":"foreign-native",
        "old_bank_directory":"old-bank","old_native_directory":"old-native","bank_checkpoint":bank_pin,"native_checkpoint":native_pin,
        "transaction":hex::encode(transaction),"included":hex::encode(included),"early":early,"confirmed":confirmed,"repeated":repeated,
        "native_membership_error":error,"before_children":before_children,"children":children,"recoveries":recoveries,
        "final_status":final_status,"stale_bank_refusal":stale_refusal,"actual_probability_law_authenticated":false,
        "native_conditional_risk_certified":false,"global_failure_probability":null});
    write_new(&root.join("run.json"), &report)?;
    Ok(report)
}
