use super::*;

impl CellVersionRetentionStoreV3 {
    fn seal_ack(
        &mut self,
        mut row: DutyRow,
        objects: Vec<CellRetentionReadbackV1>,
        deadline: Instant,
    ) -> CellResultV1<CellVersionRetentionReadbackV3> {
        require(
            objects.len() == row.contract.objects.len()
                && objects
                    .iter()
                    .all(|object| object.acknowledged && !object.retired),
            "version retention incomplete readback",
        )?;
        let minimum = self.observed.get();
        write_catalog_until(&mut self.catalog, deadline, |tx| {
            let current = audit(tx, &self.config, deadline)?;
            require_anchor(tx, &self.config, minimum, current.anchor)?;
            let prior = required_row(tx, &self.config, row.contract.operation)?;
            require(
                prior.contract == row.contract && prior.status != 2,
                "version retention ACK prior changed",
            )?;
            if prior.status == 0 {
                row.status = 1;
                transition(tx, &self.config, &mut row, current.anchor, false)?;
            }
            audit(tx, &self.config, deadline)?;
            Ok(())
        })?;
        let current = self.check(deadline)?;
        let durable = required_row(&self.catalog, &self.config, row.contract.operation)?;
        require(
            durable.status == 1 && durable.contract == row.contract,
            "version retention ACK readback",
        )?;
        self.readback(&durable, current.anchor, objects)
    }

    pub(super) fn check(&self, deadline: Instant) -> CellResultV1<AuditedCatalog> {
        check_deadline(deadline)?;
        check_directory(&self.directory)?;
        let current = audit(&self.catalog, &self.config, deadline)?;
        require_anchor(
            &self.catalog,
            &self.config,
            self.observed.get(),
            current.anchor,
        )?;
        check_deadline(deadline)?;
        self.observed.set(current.anchor);
        Ok(current)
    }

    fn readback(
        &self,
        row: &DutyRow,
        anchor: CellVersionCatalogAnchorV3,
        objects: Vec<CellRetentionReadbackV1>,
    ) -> CellResultV1<CellVersionRetentionReadbackV3> {
        Ok(CellVersionRetentionReadbackV3 {
            operation: row.contract.operation,
            version: row.contract.version.commitment(),
            contract_commitment: row.contract.commitment(&self.config)?,
            anchor,
            acknowledged: row.status == 1,
            retired: row.status == 2,
            objects,
        })
    }

    /// Expiry alone never removes a reference. Unknown Pending/repair effects
    /// require original target reconciliation before this explicit transition.
    pub fn retire_version(
        &mut self,
        operation: CellDigestV1,
        current_height: u64,
        deadline: Instant,
    ) -> CellResultV1<()> {
        self.check(deadline)?;
        let mut row = required_row(&self.catalog, &self.config, operation)?;
        if row.status == 2 {
            return check_deadline(deadline);
        }
        require(row.status == 1, "version retention pending duty")?;
        require(
            current_height >= row.contract.retain_until_height,
            "version retention lease not expired",
        )?;
        let minimum = self.observed.get();
        write_catalog_until(&mut self.catalog, deadline, |tx| {
            let current = audit(tx, &self.config, deadline)?;
            require_anchor(tx, &self.config, minimum, current.anchor)?;
            let prior = required_row(tx, &self.config, operation)?;
            require(
                prior.contract == row.contract && prior.status == 1,
                "version retention retirement prior changed",
            )?;
            let physical = self.retention.catalog_inventory(deadline)?;
            projection(&current.rows, &physical, &self.config, deadline)?;
            for object in &prior.contract.objects {
                let actual = physical
                    .iter()
                    .find(|actual| actual.operation == object.operation)
                    .ok_or(CellErrorV1::Invalid(
                        "version retention missing acknowledged object",
                    ))?;
                require(
                    actual.acknowledged
                        && !actual.retired
                        && actual.contract_commitment
                            == object.commitment(self.config.retention.store_id),
                    "version retention retirement object state",
                )?;
                self.retention
                    .require_settled_repairs(object.operation, deadline)?;
            }
            row.status = 2;
            transition(tx, &self.config, &mut row, current.anchor, false)?;
            audit(tx, &self.config, deadline)?;
            Ok(())
        })?;
        self.check(deadline)?;
        let durable = required_row(&self.catalog, &self.config, operation)?;
        require(
            durable.status == 2 && durable.contract == row.contract,
            "version retention retirement readback",
        )?;
        check_deadline(deadline)
    }

    /// Hold the complete catalog writer through physical retirement. Every
    /// reference, including Pending and expired-unretired roots, must be retired.
    pub fn retire_object(
        &mut self,
        object_operation: CellDigestV1,
        current_height: u64,
        mut successor: Option<&mut CellVersionRetentionStoreV3>,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.check(deadline)?;
        if let Some(next) = successor.as_mut() {
            next.check(deadline)?;
        }
        let minimum = self.observed.get();
        let result = write_catalog_until(&mut self.catalog, deadline, |tx| {
            let current = audit(tx, &self.config, deadline)?;
            require_anchor(tx, &self.config, minimum, current.anchor)?;
            let mut expected = None;
            for row in &current.rows {
                check_deadline(deadline)?;
                if let Some(object) = row
                    .contract
                    .objects
                    .iter()
                    .find(|object| object.operation == object_operation)
                {
                    require(
                        row.status == 2,
                        "version retention object reachable from protected duty",
                    )?;
                    expected = Some(object.clone());
                }
            }
            let expected =
                expected.ok_or(CellErrorV1::Invalid("version retention unknown object"))?;
            require(
                self.retention.contract(object_operation)? == expected,
                "version retention physical contract changed",
            )?;
            let next = successor.map(|store| &mut store.retention);
            let result = self
                .retention
                .retire(object_operation, current_height, next, deadline)?;
            check_deadline(deadline)?;
            audit(tx, &self.config, deadline)?;
            Ok(result)
        })?;
        self.check(deadline)?;
        Ok(result)
    }
}

impl CellVersionRetentionStoreV3 {
    pub fn acknowledge_version(
        &mut self,
        operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<CellVersionRetentionReadbackV3> {
        self.check(deadline)?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "version retention retired duty")?;
        for object in &row.contract.objects {
            check_deadline(deadline)?;
            require(
                self.retention.contract(object.operation)? == *object,
                "version retention physical contract changed",
            )?;
            self.retention
                .acknowledge(object.operation, cache, deadline)?;
        }
        let objects = self.verify_objects(&row, deadline)?;
        self.seal_ack(row, objects, deadline)
    }

    /// Admit one member's original initial copy through the complete root.
    /// The funding owner must choose this only for its new member intent;
    /// pending/done effects use reconcile_member, which has no source handle.
    pub fn acknowledge_member(
        &mut self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.check_member(operation, object_operation, deadline)?;
        let result = self
            .retention
            .acknowledge(object_operation, cache, deadline)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Recover one original member from its retained target only. A complete
    /// root intent cannot turn an unknown member effect into another copy.
    pub fn reconcile_member(
        &mut self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.check_member(operation, object_operation, deadline)?;
        let result = self
            .retention
            .reconcile_acknowledgement(object_operation, deadline)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    fn check_member(
        &self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<()> {
        self.check(deadline)?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "version retention retired duty")?;
        let object = row
            .contract
            .objects
            .iter()
            .find(|object| object.operation == object_operation)
            .ok_or(CellErrorV1::Invalid("version retention member dependency"))?;
        require(
            self.retention.contract(object_operation)? == *object,
            "version retention physical contract changed",
        )?;
        check_deadline(deadline)
    }

    /// Read the exact persisted terms for recovery without caller reconstruction
    /// or changing any original operation, funding, dependency or lease identity.
    pub fn contract(
        &self,
        operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellVersionRetentionContractV3> {
        self.check(deadline)?;
        let result = required_row(&self.catalog, &self.config, operation)?.contract;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Resolve a lost release ACK from actual targets only. The absence of a
    /// source/cache parameter prevents this recovery entry point from copying
    /// bytes. Missing/partial targets remain pending until a distinct repair.
    pub fn reconcile_version(
        &mut self,
        operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellVersionRetentionReadbackV3> {
        checkpoint()?;
        self.check(deadline)?;
        checkpoint()?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "version retention retired duty")?;
        let mut objects = Vec::with_capacity(row.contract.objects.len());
        for object in &row.contract.objects {
            checkpoint()?;
            require(
                self.retention.contract(object.operation)? == *object,
                "version retention physical contract changed",
            )?;
            objects.push(self.retention.reconcile_acknowledgement_controlled(
                object.operation,
                deadline,
                checkpoint,
            )?);
        }
        checkpoint()?;
        let readback = self.seal_ack(row, objects, deadline)?;
        checkpoint()?;
        Ok(readback)
    }

    pub fn verify_version(
        &mut self,
        operation: CellDigestV1,
        deadline: Instant,
    ) -> CellResultV1<CellVersionRetentionReadbackV3> {
        self.check(deadline)?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status == 1, "version retention release unavailable")?;
        let objects = self.verify_objects(&row, deadline)?;
        let result = self.readback(&row, self.observed.get(), objects)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Repair one exact dependency with the original retention byte accounting.
    /// The caller supplies the current verified height and separately admitted
    /// repair operation. A late attempt refuses without freeing the duty.
    #[allow(clippy::too_many_arguments)]
    pub fn repair_member(
        &mut self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        repair_operation: CellDigestV1,
        current_height: u64,
        cache: &CellStoreV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        self.check(deadline)?;
        checkpoint()?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "version retention retired duty")?;
        require(
            current_height >= row.contract.retain_from_height
                && current_height <= row.contract.repair_deadline_height,
            "version retention repair height deadline",
        )?;
        let object = row
            .contract
            .objects
            .iter()
            .find(|object| object.operation == object_operation)
            .ok_or(CellErrorV1::Invalid("version retention repair dependency"))?;
        require(
            self.retention.contract(object_operation)? == *object,
            "version retention physical contract changed",
        )?;
        let result = self.retention.repair_controlled(
            object_operation,
            repair_operation,
            cache,
            deadline,
            checkpoint,
        )?;
        checkpoint()?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Resolve an original repair from its actual physical target, including
    /// after the immutable dispatch deadline. No source/cache, replacement
    /// operation or new copy is permitted through this recovery entry point.
    pub fn reconcile_repair_member(
        &mut self,
        operation: CellDigestV1,
        object_operation: CellDigestV1,
        repair_operation: CellDigestV1,
        deadline: Instant,
        checkpoint: &mut impl FnMut() -> CellResultV1<()>,
    ) -> CellResultV1<CellRetentionReadbackV1> {
        checkpoint()?;
        self.check(deadline)?;
        checkpoint()?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status != 2, "version retention retired duty")?;
        let object = row
            .contract
            .objects
            .iter()
            .find(|object| object.operation == object_operation)
            .ok_or(CellErrorV1::Invalid("version retention repair dependency"))?;
        require(
            self.retention.contract(object_operation)? == *object,
            "version retention physical contract changed",
        )?;
        let result = self.retention.reconcile_repair_controlled(
            object_operation,
            repair_operation,
            deadline,
            checkpoint,
        )?;
        checkpoint()?;
        check_deadline(deadline)?;
        Ok(result)
    }

    /// Rehydrate the existing disposable chunk cache; no new serving/CAS path.
    pub fn populate_cache(
        &mut self,
        operation: CellDigestV1,
        cache: &CellStoreV1,
        deadline: Instant,
    ) -> CellResultV1<CellVersionRetentionReadbackV3> {
        self.check(deadline)?;
        let row = required_row(&self.catalog, &self.config, operation)?;
        require(row.status == 1, "version retention release unavailable")?;
        let mut objects = Vec::with_capacity(row.contract.objects.len());
        for object in &row.contract.objects {
            check_deadline(deadline)?;
            require(
                self.retention.contract(object.operation)? == *object,
                "version retention physical contract changed",
            )?;
            objects.push(
                self.retention
                    .populate_cache(object.operation, cache, deadline)?,
            );
        }
        let result = self.readback(&row, self.observed.get(), objects)?;
        check_deadline(deadline)?;
        Ok(result)
    }

    fn verify_objects(
        &mut self,
        row: &DutyRow,
        deadline: Instant,
    ) -> CellResultV1<Vec<CellRetentionReadbackV1>> {
        let mut objects = Vec::with_capacity(row.contract.objects.len());
        for object in &row.contract.objects {
            check_deadline(deadline)?;
            require(
                self.retention.contract(object.operation)? == *object,
                "version retention physical contract changed",
            )?;
            objects.push(self.retention.verify(object.operation, deadline)?);
        }
        Ok(objects)
    }
}

impl CellVersionRetentionStoreV3 {
    pub fn store_id(&self) -> CellDigestV1 {
        self.config.retention.store_id
    }

    pub fn configuration(&self) -> &CellVersionRetentionConfigV3 {
        &self.config
    }

    pub fn contract_commitment(
        &self,
        contract: &CellVersionRetentionContractV3,
    ) -> CellResultV1<CellDigestV1> {
        contract.commitment(&self.config)
    }

    pub fn create(directory: &Path, config: CellVersionRetentionConfigV3) -> CellResultV1<Self> {
        validate_config(&config)?;
        fs::create_dir(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let retention =
            CellRetentionStoreV1::create(&directory.join("objects"), config.retention.clone())?;
        let mut catalog = Connection::open_with_flags(
            directory.join("versions.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        catalog.pragma_update(None, "page_size", 4096_u32)?;
        configure(&catalog)?;
        let initial = genesis(&config);
        let tx = catalog.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(META_SQL)?;
        tx.execute_batch(DUTIES_SQL)?;
        tx.execute_batch(EVENTS_SQL)?;
        tx.execute(
            "INSERT INTO metadata VALUES (1,?1,?2,?3,0,?4)",
            params![
                config.retention.store_id.as_slice(),
                config.maximum_versions,
                config.maximum_metadata_bytes,
                initial.commitment.as_slice()
            ],
        )?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", 3)?;
        tx.commit()?;
        File::open(directory)?.sync_all()?;
        if let Some(parent) = directory.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            config,
            catalog,
            retention,
            observed: Cell::new(initial),
        })
    }

    /// The minimum anchor is retained independently by the caller's owner.
    /// A newer valid prefix is allowed after an unknown commit response.
    pub fn open(
        directory: &Path,
        config: CellVersionRetentionConfigV3,
        minimum: CellVersionCatalogAnchorV3,
    ) -> CellResultV1<Self> {
        validate_config(&config)?;
        check_directory(directory)?;
        let retention =
            CellRetentionStoreV1::open(&directory.join("objects"), config.retention.clone())?;
        let catalog = Connection::open_with_flags(
            directory.join("versions.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        catalog.pragma_update(None, "trusted_schema", false)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let current = audit(&catalog, &config, deadline)?;
        require_anchor(&catalog, &config, minimum, current.anchor)?;
        let physical = retention.catalog_inventory(deadline)?;
        projection(&current.rows, &physical, &config, deadline)?;
        configure(&catalog)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            config,
            catalog,
            retention,
            observed: Cell::new(current.anchor),
        })
    }

    pub fn anchor(&self, deadline: Instant) -> CellResultV1<CellVersionCatalogAnchorV3> {
        Ok(self.check(deadline)?.anchor)
    }

    /// One atomic complete Pending intent precedes every physical reservation.
    /// A new intent requires the current generation; exact replay may use an
    /// older authenticated prefix after a lost response.
    pub fn reserve_version(
        &mut self,
        contract: CellVersionRetentionContractV3,
        expected: CellVersionCatalogAnchorV3,
        deadline: Instant,
    ) -> CellResultV1<CellVersionRetentionReadbackV3> {
        self.check(deadline)?;
        contract.validate(&self.config)?;
        let minimum = self.observed.get();
        write_catalog_until(&mut self.catalog, deadline, |tx| {
            let current = audit(tx, &self.config, deadline)?;
            require_anchor(tx, &self.config, minimum, current.anchor)?;
            require_anchor(tx, &self.config, expected, current.anchor)?;
            let physical = self.retention.catalog_inventory(deadline)?;
            if let Some(prior) = current
                .rows
                .iter()
                .find(|row| row.contract.operation == contract.operation)
            {
                require(
                    prior.contract == contract && prior.status != 2,
                    "version retention original operation changed/retired",
                )?;
                projection(&current.rows, &physical, &self.config, deadline)?;
            } else {
                require(
                    expected == current.anchor,
                    "version retention stale admission generation",
                )?;
                require(
                    current.rows.len() < self.config.maximum_versions as usize,
                    "version retention catalog capacity",
                )?;
                let size = contract.encode_wire().len() as u64;
                require(
                    current
                        .metadata_bytes
                        .checked_add(size)
                        .is_some_and(|bytes| bytes <= self.config.maximum_metadata_bytes),
                    "version retention catalog capacity",
                )?;
                let mut proposed = current.rows;
                let mut row = DutyRow {
                    contract: contract.clone(),
                    status: 0,
                    generation: current.anchor.generation + 1,
                };
                proposed.push(row.clone());
                validate_relationships(&proposed, &self.config, deadline)?;
                projection(&proposed, &physical, &self.config, deadline)?;
                transition(tx, &self.config, &mut row, current.anchor, true)?;
            }
            audit(tx, &self.config, deadline)?;
            Ok(())
        })?;
        let current = self.check(deadline)?;
        let durable = current
            .rows
            .iter()
            .find(|row| row.contract.operation == contract.operation)
            .ok_or(CellErrorV1::Invalid("version retention intent readback"))?;
        require(
            durable.contract == contract && durable.status != 2,
            "version retention intent readback",
        )?;
        let mut objects = Vec::with_capacity(contract.objects.len());
        for object in &contract.objects {
            check_deadline(deadline)?;
            let readback = self.retention.reserve_until(object.clone(), deadline)?;
            require(
                !readback.retired,
                "version retention physical object retired",
            )?;
            objects.push(readback);
        }
        let result = self.readback(durable, current.anchor, objects)?;
        check_deadline(deadline)?;
        Ok(result)
    }
}
