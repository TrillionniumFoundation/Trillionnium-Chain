
#[cfg(feature = "lab-validator-runtime-test-support")]
const PROCESS_FIXTURE_SEED_V1: u8 = 61;
#[cfg(feature = "lab-validator-runtime-test-support")]
const PROCESS_STORE_NAME_V1: &str = "validation.sqlite3";

/// Exact durability cuts exposed only to the Linux process-test helper.
///
/// The production marker API does not accept a phase, callback, or caller-
/// supplied marker.  This enum exists only in the explicitly named test-
/// support feature so the helper can stop after a real filesystem operation
/// and be killed by an independent parent process.
#[cfg(feature = "lab-validator-runtime-test-support")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalizationIntentProcessCheckpointV1 {
    WriteTempFsyncedBeforePublish,
    WritePublishedBeforeTempCleanup,
    WriteCompleteBeforeReturn,
    ClearUnlinkedBeforeParentFsync,
    ClearCompleteBeforeReturn,
}

#[cfg(feature = "lab-validator-runtime-test-support")]
impl FinalizationIntentProcessCheckpointV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::WriteTempFsyncedBeforePublish => "write_temp_fsynced_before_publish",
            Self::WritePublishedBeforeTempCleanup => "write_published_before_temp_cleanup",
            Self::WriteCompleteBeforeReturn => "write_complete_before_return",
            Self::ClearUnlinkedBeforeParentFsync => "clear_unlinked_before_parent_fsync",
            Self::ClearCompleteBeforeReturn => "clear_complete_before_return",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "write_temp_fsynced_before_publish" => Ok(Self::WriteTempFsyncedBeforePublish),
            "write_published_before_temp_cleanup" => Ok(Self::WritePublishedBeforeTempCleanup),
            "write_complete_before_return" => Ok(Self::WriteCompleteBeforeReturn),
            "clear_unlinked_before_parent_fsync" => Ok(Self::ClearUnlinkedBeforeParentFsync),
            "clear_complete_before_return" => Ok(Self::ClearCompleteBeforeReturn),
            _ => Err(format!("unknown finalization-intent checkpoint phase: {value}")),
        }
    }

    const fn is_write(self) -> bool {
        matches!(
            self,
            Self::WriteTempFsyncedBeforePublish
                | Self::WritePublishedBeforeTempCleanup
                | Self::WriteCompleteBeforeReturn
        )
    }

    const fn is_clear(self) -> bool {
        !self.is_write()
    }
}

#[cfg(feature = "lab-validator-runtime-test-support")]
static SELECTED_PROCESS_CHECKPOINT_V1: OnceLock<FinalizationIntentProcessCheckpointV1> =
    OnceLock::new();
