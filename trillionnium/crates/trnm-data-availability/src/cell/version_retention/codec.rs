use super::*;

pub(super) fn pin_size(pin: &CellVersionLoaderPinV3) -> usize {
    32 + 1 + pin.context.family.len() + 5 * 32 + 8 + 32 + 1 + pin.required_roles.len() + 16
}

fn encode_pin(pin: &CellVersionLoaderPinV3, out: &mut Vec<u8>) {
    out.extend(pin.closure_id);
    out.push(pin.context.family.len() as u8);
    out.extend(pin.context.family.as_bytes());
    for digest in [
        pin.context.base,
        pin.context.parent,
        pin.context.tokenizer,
        pin.context.layout,
        pin.context.runtime,
    ] {
        out.extend(digest);
    }
    out.extend(pin.selected_generation.to_be_bytes());
    out.extend(pin.loader_profile);
    out.push(pin.required_roles.len() as u8);
    out.extend(pin.required_roles.iter().map(|role| *role as u8));
    out.extend(pin.max_payload_bytes.to_be_bytes());
    out.extend(pin.max_chunks.to_be_bytes());
}

fn decode_pin(input: &mut Input<'_>) -> CellResultV1<CellVersionLoaderPinV3> {
    let closure_id = input.array()?;
    let family_len = usize::from(input.array::<1>()?[0]);
    require(
        (1..=64).contains(&family_len),
        "version retention family size",
    )?;
    let family = std::str::from_utf8(input.take(family_len)?)
        .map_err(|_| CellErrorV1::Invalid("version retention family encoding"))?
        .to_owned();
    let context = CellContextV1 {
        family,
        base: input.array()?,
        parent: input.array()?,
        tokenizer: input.array()?,
        layout: input.array()?,
        runtime: input.array()?,
    };
    let selected_generation = u64::from_be_bytes(input.array()?);
    let loader_profile = input.array()?;
    let roles_len = usize::from(input.array::<1>()?[0]);
    require((1..=6).contains(&roles_len), "version retention role size")?;
    let mut required_roles = Vec::with_capacity(roles_len);
    for _ in 0..roles_len {
        required_roles.push(match input.array::<1>()?[0] {
            1 => CellFileRoleV1::Base,
            2 => CellFileRoleV1::Tokenizer,
            3 => CellFileRoleV1::Preprocessor,
            4 => CellFileRoleV1::Adapter,
            5 => CellFileRoleV1::Router,
            6 => CellFileRoleV1::Configuration,
            _ => return Err(CellErrorV1::Invalid("version retention role encoding")),
        });
    }
    let result = CellVersionLoaderPinV3 {
        closure_id,
        context,
        selected_generation,
        loader_profile,
        required_roles,
        max_payload_bytes: u64::from_be_bytes(input.array()?),
        max_chunks: u64::from_be_bytes(input.array()?),
    };
    result.validate()?;
    Ok(result)
}

impl CellVersionRetentionContractV3 {
    pub fn encode(&self, config: &CellVersionRetentionConfigV3) -> CellResultV1<Vec<u8>> {
        self.validate(config)?;
        Ok(self.encode_wire())
    }

    pub(super) fn encode_wire(&self) -> Vec<u8> {
        let mut out = b"TCA3".to_vec();
        for id in [
            self.operation,
            self.funding_operation,
            self.responsible_owner,
            self.failure_domain,
        ] {
            out.extend(id);
        }
        out.extend(self.replica_index.to_be_bytes());
        out.extend(self.required_replicas.to_be_bytes());
        for value in [
            self.retain_from_height,
            self.retain_until_height,
            self.repair_deadline_height,
        ] {
            out.extend(value.to_be_bytes());
        }
        let version = self.version.encode();
        out.extend((version.len() as u32).to_be_bytes());
        out.extend(version);
        encode_pin(&self.model, &mut out);
        encode_pin(&self.environment, &mut out);
        if let Some(plan) = &self.tensor_model {
            out.push(1);
            let wire = plan.encode();
            out.extend((wire.len() as u32).to_be_bytes());
            out.extend(wire);
        } else {
            out.push(0);
        }
        if let Some(link) = &self.snapshot {
            out.push(1);
            out.extend(link.schedule);
            out.extend(link.ordinal.to_be_bytes());
            out.extend(link.due_height.to_be_bytes());
            out.extend(link.predecessor_operation);
            out.extend(link.predecessor_contract);
        } else {
            out.push(0);
        }
        out.extend((self.objects.len() as u16).to_be_bytes());
        for object in &self.objects {
            out.extend(object.operation);
            out.extend(object.funding_operation);
            for value in [
                object.retain_from_height,
                object.retain_until_height,
                object.maximum_repair_bytes,
            ] {
                out.extend(value.to_be_bytes());
            }
            if let Some((store, operation)) = object.successor {
                out.push(1);
                out.extend(store);
                out.extend(operation);
            } else {
                out.push(0);
            }
            let wire = object.manifest.encode();
            out.extend((wire.len() as u32).to_be_bytes());
            out.extend(wire);
        }
        out
    }

    pub fn decode(wire: &[u8], config: &CellVersionRetentionConfigV3) -> CellResultV1<Self> {
        require(
            wire.len() <= MAX_CELL_VERSION_RETENTION_CONTRACT_BYTES_V3,
            "version retention contract size",
        )?;
        let mut input = Input(wire);
        require(
            input.array::<4>()? == *b"TCA3",
            "version retention contract namespace",
        )?;
        let operation = input.array()?;
        let funding_operation = input.array()?;
        let responsible_owner = input.array()?;
        let failure_domain = input.array()?;
        let replica_index = u16::from_be_bytes(input.array()?);
        let required_replicas = u16::from_be_bytes(input.array()?);
        let retain_from_height = u64::from_be_bytes(input.array()?);
        let retain_until_height = u64::from_be_bytes(input.array()?);
        let repair_deadline_height = u64::from_be_bytes(input.array()?);
        let version = CellVersionManifestV1::decode(input.sized()?)?;
        let model = decode_pin(&mut input)?;
        let environment = decode_pin(&mut input)?;
        let tensor_model = match input.array::<1>()?[0] {
            0 => None,
            1 => Some(CellTensorModelManifestV1::decode(input.sized()?)?),
            _ => return Err(CellErrorV1::Invalid("version retention tensor plan tag")),
        };
        let snapshot = match input.array::<1>()?[0] {
            0 => None,
            1 => Some(CellVersionSnapshotLinkV3 {
                schedule: input.array()?,
                ordinal: u64::from_be_bytes(input.array()?),
                due_height: u64::from_be_bytes(input.array()?),
                predecessor_operation: input.array()?,
                predecessor_contract: input.array()?,
            }),
            _ => return Err(CellErrorV1::Invalid("version retention snapshot tag")),
        };
        let count = usize::from(u16::from_be_bytes(input.array()?));
        require(
            count == version.manifests().len() && count <= 512,
            "version retention complete dependency set",
        )?;
        let mut objects = Vec::with_capacity(count);
        for _ in 0..count {
            let operation = input.array()?;
            let funding_operation = input.array()?;
            let retain_from_height = u64::from_be_bytes(input.array()?);
            let retain_until_height = u64::from_be_bytes(input.array()?);
            let maximum_repair_bytes = u64::from_be_bytes(input.array()?);
            let successor = match input.array::<1>()?[0] {
                0 => None,
                1 => Some((input.array()?, input.array()?)),
                _ => return Err(CellErrorV1::Invalid("version retention successor tag")),
            };
            let manifest = CellManifestV1::decode(input.sized()?)?;
            objects.push(CellRetentionContractV1 {
                operation,
                funding_operation,
                manifest,
                retain_from_height,
                retain_until_height,
                maximum_repair_bytes,
                successor,
            });
        }
        require(input.0.is_empty(), "version retention trailing contract")?;
        let result = Self {
            operation,
            funding_operation,
            responsible_owner,
            failure_domain,
            replica_index,
            required_replicas,
            retain_from_height,
            retain_until_height,
            repair_deadline_height,
            version,
            model,
            environment,
            tensor_model,
            snapshot,
            objects,
        };
        result.validate(config)?;
        require(
            result.encode_wire() == wire,
            "version retention noncanonical contract",
        )?;
        Ok(result)
    }
}

pub(super) struct Input<'a>(pub(super) &'a [u8]);
impl<'a> Input<'a> {
    pub(super) fn take(&mut self, count: usize) -> CellResultV1<&'a [u8]> {
        require(
            count <= self.0.len(),
            "version retention truncated contract",
        )?;
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }
    pub(super) fn array<const N: usize>(&mut self) -> CellResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| CellErrorV1::Invalid("version retention field"))
    }
    pub(super) fn sized(&mut self) -> CellResultV1<&'a [u8]> {
        let count = u32::from_be_bytes(self.array()?) as usize;
        self.take(count)
    }
}
