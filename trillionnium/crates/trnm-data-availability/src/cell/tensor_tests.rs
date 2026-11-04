//! Real bounded safetensors byte streams, including valid-hash hostile files.

use std::{
    fs,
    io::{self, Cursor, Read, Seek, SeekFrom},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::*;

const HEADER: &str = r#"{"__metadata__":{"format":"pt"},"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"b":{"dtype":"F16","shape":[2],"data_offsets":[8,12]},"c":{"dtype":"BF16","shape":[],"data_offsets":[12,14]}}"#;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn specs() -> Vec<CellTensorSpecV1> {
    vec![
        CellTensorSpecV1 {
            name: "a".into(),
            dtype: CellTensorDTypeV1::F32,
            shape: vec![2],
        },
        CellTensorSpecV1 {
            name: "b".into(),
            dtype: CellTensorDTypeV1::F16,
            shape: vec![2],
        },
        CellTensorSpecV1 {
            name: "c".into(),
            dtype: CellTensorDTypeV1::Bf16,
            shape: vec![],
        },
    ]
}

fn data() -> Vec<u8> {
    // F32 [1.0, -2.0], F16 [1.0, -2.0], scalar BF16 0.5.
    [
        1.0f32.to_le_bytes().as_slice(),
        (-2.0f32).to_le_bytes().as_slice(),
        0x3c00u16.to_le_bytes().as_slice(),
        0xc000u16.to_le_bytes().as_slice(),
        0x3f00u16.to_le_bytes().as_slice(),
    ]
    .concat()
}

fn container(header: &str, data: &[u8]) -> Vec<u8> {
    let mut header = header.as_bytes().to_vec();
    header.resize(header.len().next_multiple_of(8), b' ');
    [
        (header.len() as u64).to_le_bytes().as_slice(),
        &header,
        data,
    ]
    .concat()
}

fn root_with_files(files: &[(&str, CellFileRoleV1, &[u8])]) -> CellModelReleaseRootV1 {
    let context = CellContextV1 {
        family: "tensor-container-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let entries = files
        .iter()
        .map(|(path, role, bytes)| {
            let payload_sha256: CellDigestV1 = Sha256::digest(bytes).into();
            let manifest = CellManifestV1::new(
                context.clone(),
                bytes.len() as u64,
                payload_sha256,
                16_384,
                bytes
                    .chunks(16_384)
                    .map(|chunk| CellChunkV1 {
                        size: chunk.len() as u32,
                        sha256: Sha256::digest(chunk).into(),
                    })
                    .collect(),
            )
            .unwrap();
            CellClosureFileV1 {
                path: (*path).into(),
                role: *role,
                manifest: manifest.id(),
                payload_sha256,
                payload_bytes: bytes.len() as u64,
                dependencies: vec![],
            }
        })
        .collect();
    CellModelReleaseRootV1::new(
        CellReleaseClosureV1::new(
            context,
            7,
            [6; 32],
            (0..files.len() as u16).collect(),
            entries,
        )
        .unwrap(),
        vec![],
    )
    .unwrap()
}

fn admitted(
    bytes: &[u8],
    tensors: Vec<CellTensorSpecV1>,
) -> (CellModelReleaseRootV1, CellTensorContractV1) {
    let root = root_with_files(&[("base.safetensors", CellFileRoleV1::Base, bytes)]);
    let contract = CellTensorContractV1::new(
        root.id(),
        vec![CellTensorFileV1 {
            file_index: 0,
            tensors,
        }],
    )
    .unwrap();
    (root, contract)
}

fn verify_hostile_bytes(bytes: &[u8]) -> CellResultV1<CellTensorReadbackV1> {
    // Rebind the TCM1, TCD1, TMR1 and TMT1 pins to each hostile file. Failure
    // therefore demonstrates parsing/roster protection, not a stale file hash.
    let (root, contract) = admitted(bytes, specs());
    contract.verify_reader(&root, contract.id(), 0, &mut Cursor::new(bytes), deadline())
}

#[test]
fn tensor_real_file_all_supported_dtypes_scalar_and_metadata_hash_are_verified() {
    let raw = container(HEADER, &data());
    let (root, contract) = admitted(&raw, specs());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("weights.safetensors");
    fs::write(&path, &raw).unwrap();
    let report = contract
        .verify_reader(
            &root,
            contract.id(),
            0,
            &mut fs::File::open(path).unwrap(),
            deadline(),
        )
        .unwrap();
    assert_eq!(report.contract_id, contract.id());
    assert_eq!(report.model_root, root.id());
    assert_eq!(report.tensor_count, 3);
    assert_eq!(report.file_index, 0);
    assert_eq!(report.payload_bytes, raw.len() as u64);
    assert_eq!(
        report.payload_sha256,
        <CellDigestV1>::from(Sha256::digest(&raw))
    );

    // Correct container metadata cannot excuse different actual tensor bytes.
    let mut changed = raw.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(matches!(
        contract.verify_reader(
            &root,
            contract.id(),
            0,
            &mut Cursor::new(changed),
            deadline()
        ),
        Err(CellErrorV1::Invalid("tensor payload digest"))
    ));
    for changed in [
        raw[..raw.len() - 1].to_vec(),
        [raw.as_slice(), &[0]].concat(),
    ] {
        assert!(matches!(
            contract.verify_reader(
                &root,
                contract.id(),
                0,
                &mut Cursor::new(changed),
                deadline()
            ),
            Err(CellErrorV1::Invalid("tensor actual file length"))
        ));
    }
}

#[test]
fn tensor_correct_hash_garbage_and_oversized_or_invalid_header_are_refused() {
    assert!(verify_hostile_bytes(&[7; 64]).is_err());
    let raw = container(HEADER, &data());
    for length in [0u64, 1, 1_048_577, u64::MAX] {
        let mut changed = raw.clone();
        changed[..8].copy_from_slice(&length.to_le_bytes());
        assert!(matches!(
            verify_hostile_bytes(&changed),
            Err(CellErrorV1::Invalid("tensor header length"))
        ));
    }
    for header in [
        format!(" {HEADER}"),
        format!("{HEADER}\n"),
        format!("{HEADER}{{}}"),
        "{}".into(),
    ] {
        assert!(verify_hostile_bytes(&container(&header, &data())).is_err());
    }
}

#[test]
fn tensor_duplicate_names_escaped_aliases_fields_and_metadata_are_refused() {
    let entry = r#""a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}"#;
    for header in [
        HEADER.replacen(entry, &format!("{entry},{entry}"), 1),
        HEADER.replacen(
            entry,
            &format!("{entry},{}", entry.replacen("\"a\"", r#""\u0061""#, 1)),
            1,
        ),
        HEADER.replacen(
            "\"dtype\":\"F32\"",
            "\"dtype\":\"F16\",\"dtype\":\"F32\"",
            1,
        ),
        HEADER.replacen(
            "\"format\":\"pt\"",
            "\"format\":\"pt\",\"format\":\"pt\"",
            1,
        ),
        HEADER.replacen(
            "{\"__metadata__\":",
            "{\"__metadata__\":{},\"__metadata__\":",
            1,
        ),
        HEADER.replacen("\"shape\":[2]", "\"shape\":[2],\"strides\":[1]", 1),
        HEADER.replacen("\"format\":\"pt\"", "\"format\":42", 1),
        HEADER.replacen("\"dtype\":\"F32\"", "\"dtype\":{\"F32\":null}", 1),
        HEADER.replacen("\"shape\":[2]", "\"shape\":[2.0]", 1),
    ] {
        assert!(
            matches!(
                verify_hostile_bytes(&container(&header, &data())),
                Err(CellErrorV1::Invalid("tensor header JSON"))
            ),
            "accepted malformed header: {header}"
        );
    }
}

#[test]
fn tensor_exact_roster_dtype_and_shape_cannot_be_replaced_by_equal_sized_data() {
    for header in [
        HEADER.replacen("\"F32\"", "\"F16\"", 1),
        HEADER.replacen("\"BF16\"", "\"I16\"", 1),
        HEADER.replacen("\"shape\":[2]", "\"shape\":[1,2]", 1),
        HEADER.replacen("\"a\":", "\"renamed\":", 1),
    ] {
        assert!(matches!(
            verify_hostile_bytes(&container(&header, &data())),
            Err(CellErrorV1::Invalid("tensor roster metadata"))
        ));
    }
    let mut missing: serde_json::Value = serde_json::from_str(HEADER).unwrap();
    missing.as_object_mut().unwrap().remove("c");
    assert!(matches!(
        verify_hostile_bytes(&container(&missing.to_string(), &data())),
        Err(CellErrorV1::Invalid("tensor roster coverage"))
    ));
    let mut extra: serde_json::Value = serde_json::from_str(HEADER).unwrap();
    extra["d"] = serde_json::json!({"dtype":"F32","shape":[],"data_offsets":[14,18]});
    assert!(matches!(
        verify_hostile_bytes(&container(
            &extra.to_string(),
            &[data(), vec![0; 4]].concat()
        )),
        Err(CellErrorV1::Invalid("tensor roster coverage"))
    ));
}

#[test]
fn tensor_offsets_reject_overlap_holes_trailing_and_wrong_element_bytes() {
    for (header, payload, expected) in [
        (
            HEADER
                .replace("[8,12]", "[6,10]")
                .replace("[12,14]", "[10,12]"),
            vec![0; 12],
            "tensor overlap or hole",
        ),
        (
            HEADER
                .replace("[8,12]", "[10,14]")
                .replace("[12,14]", "[14,16]"),
            vec![0; 16],
            "tensor overlap or hole",
        ),
        (HEADER.into(), vec![0; 16], "tensor trailing data"),
        (
            HEADER.replace("[0,8]", "[0,7]"),
            data(),
            "tensor data range",
        ),
        (
            HEADER.replace("[12,14]", "[12,18446744073709551615]"),
            data(),
            "tensor data range",
        ),
    ] {
        assert!(
            matches!(
                verify_hostile_bytes(&container(&header, &payload)),
                Err(CellErrorV1::Invalid(reason)) if reason == expected
            ),
            "wrong outcome for {expected}: {header}"
        );
    }
}

#[test]
fn tensor_contract_rejects_shape_overflow_dimension_rank_and_noncanonical_rosters() {
    for shape in [
        vec![u64::from(u32::MAX); 3],
        vec![u64::MAX],
        vec![0],
        vec![1; 9],
    ] {
        let mut tensors = specs();
        tensors[0].shape = shape;
        assert!(CellTensorContractV1::new(
            [1; 32],
            vec![CellTensorFileV1 {
                file_index: 0,
                tensors
            }]
        )
        .is_err());
    }
    for name in ["", "__metadata__", "a\0"] {
        let mut tensors = specs();
        tensors[0].name = name.into();
        assert!(CellTensorContractV1::new(
            [1; 32],
            vec![CellTensorFileV1 {
                file_index: 0,
                tensors
            }]
        )
        .is_err());
    }
    let mut names = specs();
    names.swap(0, 1);
    let duplicate = CellTensorFileV1 {
        file_index: 0,
        tensors: specs(),
    };
    assert!(CellTensorContractV1::new([1; 32], vec![duplicate.clone(), duplicate]).is_err());
    assert!(CellTensorContractV1::new(
        [1; 32],
        vec![CellTensorFileV1 {
            file_index: 0,
            tensors: names
        }]
    )
    .is_err());
}

#[test]
fn tensor_contract_and_model_wire_reject_downgrades_suffixes_and_source_transplants() {
    let raw = container(HEADER, &data());
    let (root, contract) = admitted(&raw, specs());
    let wire = contract.encode();
    assert_eq!(CellTensorContractV1::decode(&wire).unwrap(), contract);
    for end in 0..wire.len() {
        assert!(CellTensorContractV1::decode(&wire[..end]).is_err());
    }
    for offset in [3, 4, 5] {
        let mut changed = wire.clone();
        changed[offset] = if offset == 3 { b'2' } else { 2 };
        assert!(CellTensorContractV1::decode(&changed).is_err());
    }
    assert!(CellTensorContractV1::decode(&[wire.as_slice(), &[0]].concat()).is_err());
    assert!(contract.verify_for_model(&root, [77; 32]).is_err());
    let unrelated = CellTensorContractV1::new([8; 32], contract.files().to_vec()).unwrap();
    assert!(unrelated.verify_for_model(&root, unrelated.id()).is_err());
    assert!(CellTensorModelManifestV1::new(root.clone(), unrelated).is_err());

    let model = CellTensorModelManifestV1::new(root, contract).unwrap();
    let wire = model.encode();
    assert_eq!(CellTensorModelManifestV1::decode(&wire).unwrap(), model);
    for end in 0..wire.len() {
        assert!(CellTensorModelManifestV1::decode(&wire[..end]).is_err());
    }
    let mut changed = wire.clone();
    changed[..4].copy_from_slice(b"TMA2");
    assert!(CellTensorModelManifestV1::decode(&changed).is_err());
    changed = wire.clone();
    changed[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CellTensorModelManifestV1::decode(&changed).is_err());
    assert!(CellTensorModelManifestV1::decode(&[wire.as_slice(), &[0]].concat()).is_err());
}

#[test]
fn tensor_contract_requires_all_base_and_adapter_files_but_not_tokenizer_bytes() {
    let base = container(HEADER, &data());
    let mut other_data = data();
    other_data[0] ^= 1;
    let adapter = container(HEADER, &other_data);
    let root = root_with_files(&[
        ("a-base.safetensors", CellFileRoleV1::Base, &base),
        ("b-adapter.safetensors", CellFileRoleV1::Adapter, &adapter),
        ("tokenizer.json", CellFileRoleV1::Tokenizer, b"{}"),
    ]);
    for index in [0u16, 1] {
        let contract = CellTensorContractV1::new(
            root.id(),
            vec![CellTensorFileV1 {
                file_index: index,
                tensors: specs(),
            }],
        )
        .unwrap();
        assert!(matches!(
            contract.verify_for_model(&root, contract.id()),
            Err(CellErrorV1::Invalid("tensor missing required file"))
        ));
    }
    let contract = CellTensorContractV1::new(
        root.id(),
        (0..2)
            .map(|index| CellTensorFileV1 {
                file_index: index,
                tensors: specs(),
            })
            .collect(),
    )
    .unwrap();
    contract.verify_for_model(&root, contract.id()).unwrap();
    for (index, bytes) in [&base, &adapter].into_iter().enumerate() {
        contract
            .verify_reader(
                &root,
                contract.id(),
                index as u16,
                &mut Cursor::new(bytes),
                deadline(),
            )
            .unwrap();
    }
    let out_of_bounds = CellTensorContractV1::new(
        root.id(),
        vec![CellTensorFileV1 {
            file_index: 3,
            tensors: specs(),
        }],
    )
    .unwrap();
    assert!(matches!(
        out_of_bounds.verify_for_model(&root, out_of_bounds.id()),
        Err(CellErrorV1::Invalid("tensor closure file index"))
    ));
}

struct FragmentedReader {
    bytes: Cursor<Vec<u8>>,
    largest_request: usize,
    total_read: usize,
}

impl Read for FragmentedReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.largest_request = self.largest_request.max(bytes.len());
        let bound = bytes.len().min(1024);
        let read = self.bytes.read(&mut bytes[..bound])?;
        self.total_read += read;
        Ok(read)
    }
}

impl Seek for FragmentedReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(position)
    }
}

#[test]
fn tensor_streams_whole_payload_in_bounded_chunks_and_expired_calls_read_nothing() {
    let raw = container(
        r#"{"weight":{"dtype":"F32","shape":[100000],"data_offsets":[0,400000]}}"#,
        &vec![0; 400000],
    );
    let (root, contract) = admitted(
        &raw,
        vec![CellTensorSpecV1 {
            name: "weight".into(),
            dtype: CellTensorDTypeV1::F32,
            shape: vec![100000],
        }],
    );
    let mut reader = FragmentedReader {
        bytes: Cursor::new(raw.clone()),
        largest_request: 0,
        total_read: 0,
    };
    contract
        .verify_reader(&root, contract.id(), 0, &mut reader, deadline())
        .unwrap();
    assert!(reader.largest_request <= 64 * 1024);
    assert_eq!(reader.total_read, raw.len());
    reader.total_read = 0;
    assert!(matches!(
        contract.verify_reader(&root, contract.id(), 0, &mut reader, Instant::now()),
        Err(CellErrorV1::Invalid("tensor deadline"))
    ));
    assert_eq!(reader.total_read, 0);
}
