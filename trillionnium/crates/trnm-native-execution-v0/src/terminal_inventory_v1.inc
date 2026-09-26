/// Immutable ordinary-store inventory for a consumed terminal owner's audit.
/// This value has no execution or finality authority.
#[derive(Debug)]
pub struct ConfirmedNativeTerminalInventoryV1 {
    owner_affinity: Arc<()>,
    store_id: [u8; 32],
    head: ApplicationHeadV0,
    durable_sequence: u64,
    prepared_count: u64,
}

impl ConfirmedNativeTerminalInventoryV1 {
    pub const fn head_v1(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn durable_sequence_v1(&self) -> u64 {
        self.durable_sequence
    }
    pub const fn prepared_count_v1(&self) -> u64 {
        self.prepared_count
    }
    pub fn belongs_to_application_at_path_v1(
        &self,
        application: &DurableNativeApplicationV0,
        path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &application.owner_affinity)
            && self.store_id == application.config.store_id
            && path == application.path()
            && application.confirm_namespace_identity_v1().is_ok()
    }
}

impl DurableNativeApplicationV0 {
    /// Full immutable schema3 inventory readback; no recovery or capability minting.
    pub fn confirm_ordinary_terminal_inventory_v1(
        &self,
    ) -> DurableResult<ConfirmedNativeTerminalInventoryV1> {
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        connection.execute_batch("BEGIN DEFERRED").map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "terminal_inventory.begin",
            )
        })?;
        verify_schema_v0(&connection)?;
        if epoch_durable::schema_version(&connection)? != APPLICATION_SCHEMA_VERSION_V0 {
            return Err(error(
                NativeApplicationExecutionErrorCodeV0::InvalidConfiguration,
                "terminal_inventory.exact_schema3",
            ));
        }
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let prepared_count = count_prepared_p_v0(&connection)?;
        connection.execute_batch("ROLLBACK").map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::CorruptStore,
                "terminal_inventory.rollback",
            )
        })?;
        self.confirm_namespace_identity_v1()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        Ok(ConfirmedNativeTerminalInventoryV1 {
            owner_affinity: Arc::clone(&self.owner_affinity),
            store_id: self.config.store_id,
            head: metadata.head,
            durable_sequence: metadata.durable_sequence,
            prepared_count,
        })
    }
}
