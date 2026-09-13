/// Linux-only subprocess entry used by the finalization-intent SIGKILL test.
///
/// This is re-exported only by `lab-validator-runtime-test-support`.  The
/// helper owns one deterministic synthetic marker and one fresh regular store
/// file; no caller can supply Core proof fields or use this entry to clear a
/// production marker.
#[cfg(feature = "lab-validator-runtime-test-support")]
#[doc(hidden)]
pub fn run_finalization_intent_kill_helper_v1() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "missing finalization-intent helper command".to_owned())?;
    let root = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| "missing finalization-intent helper root".to_owned())?,
    );
    let phase_text = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "missing finalization-intent checkpoint phase".to_owned())?;
    if arguments.next().is_some() {
        return Err("unexpected finalization-intent helper arguments".to_owned());
    }
    let phase = FinalizationIntentProcessCheckpointV1::parse(&phase_text)?;
    let marker = process_fixture_marker_v1();

    match command.as_str() {
        "prepare-write" => {
            if !phase.is_write() {
                return Err("prepare-write received a clear checkpoint".to_owned());
            }
            let store_path = process_store_v1(&root, true)?;
            SELECTED_PROCESS_CHECKPOINT_V1
                .set(phase)
                .map_err(|_| "process checkpoint was already selected".to_owned())?;
            write_marker_v0(&store_path, marker).map_err(|error| error.to_owned())?;
            Err(format!(
                "write returned without holding selected checkpoint {}",
                phase.as_str()
            ))
        }
        "recover-write" => {
            if !phase.is_write() {
                return Err("recover-write received a clear checkpoint".to_owned());
            }
            let store_path = process_store_v1(&root, false)?;
            recover_marker_publication_v1(&store_path, marker).map_err(|error| error.to_owned())?;
            print_process_state_v1("recovered_write", phase, &store_path, marker)
        }
        "verify-write" => {
            if !phase.is_write() {
                return Err("verify-write received a clear checkpoint".to_owned());
            }
            let store_path = process_store_v1(&root, false)?;
            if residue_exists_v1(&marker_temp_path_v0(&store_path))
                .map_err(|error| error.to_owned())?
                || load_marker_v0(&store_path).map_err(|error| error.to_owned())? != Some(marker)
            {
                return Err("verified write is not the exact stable marker".to_owned());
            }
            print_process_state_v1("verified_write", phase, &store_path, marker)
        }
        "prepare-clear" => {
            if !phase.is_clear() {
                return Err("prepare-clear received a write checkpoint".to_owned());
            }
            let store_path = process_store_v1(&root, true)?;
            write_marker_v0(&store_path, marker).map_err(|error| error.to_owned())?;
            SELECTED_PROCESS_CHECKPOINT_V1
                .set(phase)
                .map_err(|_| "process checkpoint was already selected".to_owned())?;
            clear_marker_v0(&store_path, marker).map_err(|error| error.to_owned())?;
            Err(format!(
                "clear returned without holding selected checkpoint {}",
                phase.as_str()
            ))
        }
        "recover-clear" => {
            if !phase.is_clear() {
                return Err("recover-clear received a write checkpoint".to_owned());
            }
            let store_path = process_store_v1(&root, false)?;
            if residue_exists_v1(&marker_temp_path_v0(&store_path))
                .map_err(|error| error.to_owned())?
            {
                return Err("clear recovery found an impossible temporary marker".to_owned());
            }
            match load_marker_v0(&store_path).map_err(|error| error.to_owned())? {
                Some(observed) if observed == marker => {
                    clear_marker_v0(&store_path, marker).map_err(|error| error.to_owned())?;
                }
                Some(_) => return Err("clear recovery found a foreign marker".to_owned()),
                None => {}
            }
            print_process_state_v1("recovered_clear", phase, &store_path, marker)
        }
        "verify-clear" => {
            if !phase.is_clear() {
                return Err("verify-clear received a write checkpoint".to_owned());
            }
            let store_path = process_store_v1(&root, false)?;
            if residue_exists_v1(&marker_temp_path_v0(&store_path))
                .map_err(|error| error.to_owned())?
                || load_marker_v0(&store_path)
                    .map_err(|error| error.to_owned())?
                    .is_some()
            {
                return Err("verified clear retained a finalization-intent residue".to_owned());
            }
            print_process_state_v1("verified_clear", phase, &store_path, marker)
        }
        _ => Err(format!(
            "unknown finalization-intent helper command: {command}"
        )),
    }
}
