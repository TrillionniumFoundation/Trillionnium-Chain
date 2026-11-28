//! Unchanged original public value validation on owned synthetic metadata.
//! Never constructs a store, loads content or executes any retention action.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{
    CellClosureFileV1, CellErrorV1, CellFileRoleV1,
    CellManifestV1, CellModelReleaseRootV1, CellReleaseClosureV1, CellRetentionConfigV1,
    CellRetentionContractV1, CellVersionLoaderPinV3, CellVersionManifestV1,
    CellVersionRetentionConfigV3, CellVersionRetentionContractV3, CellVersionSnapshotLinkV3,
};

fn read<const N: usize>(b: &[u8], p: usize) -> [u8; N] {
    b[p..p + N].try_into().unwrap()
}

fn fixture() -> CellVersionRetentionContractV3 {
    fn manifest(runtime: [u8; 32], data_byte: u8) -> CellManifestV1 {
        let family = b"CVA3-outer-fixture";
        let mut wire = b"TCM1".to_vec();
        wire.push(family.len().try_into().unwrap());
        wire.extend_from_slice(family);
        for id in [[1;32], [2;32], [3;32], [4;32], runtime] {
            wire.extend_from_slice(&id);
        }
        wire.extend_from_slice(&17_u64.to_be_bytes());
        wire.extend_from_slice(&[data_byte;32]);
        for value in [16384_u32, 1, 17] {
            wire.extend_from_slice(&value.to_be_bytes());
        }
        wire.extend_from_slice(&[data_byte;32]);
        CellManifestV1::decode(&wire).unwrap()
    }
    fn closure(manifest: &CellManifestV1, role: CellFileRoleV1, generation: u64)
        -> (CellReleaseClosureV1, CellVersionLoaderPinV3)
    {
        let data = CellClosureFileV1 {
            path: if role == CellFileRoleV1::Base { "model.bin" } else { "environment.bin" }.into(),
            role, manifest: manifest.id(), payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(), dependencies: vec![],
        };
        let value = CellReleaseClosureV1::new(
            manifest.context().clone(), generation, [51;32], vec![0], vec![data],
        ).unwrap();
        let pin = CellVersionLoaderPinV3 {
            closure_id: value.id(), context: value.release().context().clone(),
            selected_generation: value.selected_generation(), loader_profile: value.loader_profile(),
            required_roles: vec![role], max_payload_bytes: 4096, max_chunks: 4,
        };
        (value, pin)
    }
    let env = manifest([70;32], 11);
    let (environment, env_pin) = closure(&env, CellFileRoleV1::Configuration, 11);
    let model = manifest(environment.id(), 12);
    let (model_closure, model_pin) = closure(&model, CellFileRoleV1::Base, 17);
    let mut manifests = vec![model, env];
    manifests.sort_by_key(CellManifestV1::id);
    let version = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(model_closure, vec![]).unwrap(), environment, manifests,
    ).unwrap();
    let objects = version.manifests().iter().enumerate().map(|(i, manifest)| {
        CellRetentionContractV1 {
            operation: [0xe1+i as u8;32], funding_operation: [0xf1+i as u8;32],
            manifest: manifest.clone(), retain_from_height: 0, retain_until_height: i64::MAX as u64,
            maximum_repair_bytes: 4*manifest.size(), successor: None,
        }
    }).collect();
    CellVersionRetentionContractV3 {
        operation: [0x71;32], funding_operation: [0x72;32],
        responsible_owner: [0x73;32], failure_domain: [0x74;32],
        replica_index: 0, required_replicas: 1, retain_from_height: 0, retain_until_height: 20,
        repair_deadline_height: 4, version, model: model_pin, environment: env_pin,
        tensor_model: None, snapshot: None, objects,
    }
}

fn main() -> io::Result<()> {
    let base = fixture();
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let mut output = io::stdout().lock();
    let mut rows = input.as_slice();
    while !rows.is_empty() {
        let size = u32::from_le_bytes(read(rows,0)) as usize;
        let (r, tail) = rows[4..].split_at(size);
        rows = tail;
        assert_eq!(&r[..8], b"NVT30001");
        let config = CellVersionRetentionConfigV3 {
            retention: CellRetentionConfigV1 {
                store_id: read(r,8), capacity_bytes: u64::from_be_bytes(read(r,40)),
                maximum_obligations: u32::from_be_bytes(read(r,48)),
            },
            maximum_versions: u32::from_be_bytes(read(r,52)),
            maximum_metadata_bytes: u64::from_be_bytes(read(r,56)),
        };
        let mut v = base.clone();
        v.operation = read(r,64);
        v.funding_operation = read(r,96);
        v.responsible_owner = read(r,128);
        v.failure_domain = read(r,160);
        v.replica_index = u16::from_be_bytes(read(r,192));
        v.required_replicas = u16::from_be_bytes(read(r,194));
        v.retain_from_height = u64::from_be_bytes(read(r,196));
        v.retain_until_height = u64::from_be_bytes(read(r,204));
        v.repair_deadline_height = u64::from_be_bytes(read(r,212));
        if r[220] == 1 {
            v.snapshot = Some(CellVersionSnapshotLinkV3 {
                schedule: read(r,221), ordinal: u64::from_be_bytes(read(r,253)),
                due_height: u64::from_be_bytes(read(r,261)), predecessor_operation: read(r,269),
                predecessor_contract: read(r,301),
            });
        }
        let observed = match v.validate(&config) {
            Ok(()) => [0,0],
            Err(CellErrorV1::Invalid(reason)) => match reason {
                "retention configuration" => [20,20],
                "version retention configuration" => [21,21],
                "version retention identity" => [22,22],
                "version retention replica declaration" => [23,23],
                "version retention lease/repair deadline" => [24,24],
                "version retention snapshot link" => [25,25],
                // These proven later rejects are recorded separately. They
                // must never be mistaken for a successful full original.
                "version retention physical capacity" => [0,30],
                "version retention object identity alias" => [0,31],
                "version retention operation/funding alias" => [0,32],
                _ => panic!("unexpected original TCA3 value predicate: {reason}"),
            },
            Err(other) => panic!("unexpected original TCA3 data error: {other:?}"),
        };
        output.write_all(&observed)?;
    }
    Ok(())
}
