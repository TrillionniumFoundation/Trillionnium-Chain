use std::io::Cursor;

use trnm_protocol::crypto_profile::{
    BoundCryptoProfile, CryptoProfile, ProfileBinding, ProfileScope,
};

use super::*;

fn profile() -> BoundCryptoProfile {
    CryptoProfile::CandidateMlDsa65V1
        .bind(ProfileBinding {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            protocol_version: 1,
            scope: ProfileScope::WholeSystemCandidate,
            activation_height: 10,
            retirement_height: Some(100),
        })
        .unwrap()
}

fn context(kind: ContentKind, instance: u8, generation: u64) -> ContentContextV1 {
    ContentContextV1::new(&profile(), kind, [instance; 64], generation).unwrap()
}

fn budget() -> ContentReadBudget {
    ContentReadBudget::new(100, 1_000_000).unwrap()
}

fn limits() -> CellContentGraphLimitsV3 {
    CellContentGraphLimitsV3 {
        max_nodes: 32,
        max_objects: 100,
        max_edges: 192,
        max_depth: 16,
        max_object_bytes: 65_536,
        max_total_bytes: 1_000_000,
    }
}

#[derive(Default)]
struct Objects {
    bytes: BTreeMap<ClaimKey, Vec<u8>>,
}

impl Objects {
    fn leaf(&mut self, instance: u8, bytes: &[u8]) -> ObservedContentV1 {
        let observation = observe_bytes(
            &context(ContentKind::ModelPayload, instance, 1),
            &mut budget(),
            bytes,
        )
        .unwrap();
        self.bytes
            .insert(claim_key(observation.claim()), bytes.to_vec());
        observation
    }

    fn node(
        &mut self,
        instance: u8,
        base: Option<&CellContentGraphNodeObservationV3>,
        parent: Option<&CellContentGraphNodeObservationV3>,
        shared: &[ObservedContentV1; 3],
    ) -> CellContentGraphNodeObservationV3 {
        let payload = self.leaf(instance, format!("payload-{instance}").as_bytes());
        let node = CellContentGraphNodeV3::from_observed_contents(
            "test-cell".to_owned(),
            &payload,
            [
                base.map(CellContentGraphLinkV3::from_observed_node)
                    .unwrap_or_else(CellContentGraphLinkV3::absent),
                parent
                    .map(CellContentGraphLinkV3::from_observed_node)
                    .unwrap_or_else(CellContentGraphLinkV3::absent),
                CellContentGraphLinkV3::from_observed_leaf(&shared[0]).unwrap(),
                CellContentGraphLinkV3::from_observed_leaf(&shared[1]).unwrap(),
                CellContentGraphLinkV3::from_observed_leaf(&shared[2]).unwrap(),
            ],
        )
        .unwrap();
        let observation = node
            .observe_node(
                &context(ContentKind::ModelManifest, instance, 1),
                &mut budget(),
            )
            .unwrap();
        self.bytes
            .insert(claim_key(observation.claim()), node.encode());
        observation
    }

    fn repin(&mut self, original: &ContentClaimV1, bytes: &[u8]) -> ContentClaimV1 {
        let observed = observe_bytes(original.context(), &mut budget(), bytes).unwrap();
        self.bytes
            .insert(claim_key(observed.claim()), bytes.to_vec());
        observed.claim().clone()
    }

    fn verify(
        &self,
        root: &ContentClaimV1,
        caps: CellContentGraphLimitsV3,
        read_budget: &mut ContentReadBudget,
        opened: &mut Vec<ClaimKey>,
    ) -> Result<CellContentGraphReadbackV3> {
        verify_cell_content_graph_v3(root, caps, read_budget, &mut |claim| {
            let key = claim_key(claim);
            opened.push(key);
            self.bytes
                .get(&key)
                .cloned()
                .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn Read>)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing fixture object"))
        })
    }
}

struct Fixture {
    objects: Objects,
    root: ContentClaimV1,
    deepest_node: ContentClaimV1,
    deepest_payload: ContentClaimV1,
}

fn shared(objects: &mut Objects) -> [ObservedContentV1; 3] {
    [
        objects.leaf(101, b"tokenizer"),
        objects.leaf(102, b"layout"),
        objects.leaf(103, b"runtime"),
    ]
}

fn fixture() -> Fixture {
    let mut objects = Objects::default();
    let shared = shared(&mut objects);
    let first = objects.node(1, None, None, &shared);
    let deepest_node = first.claim().clone();
    let deepest_payload = CellContentGraphNodeV3::decode(&objects.bytes[&claim_key(first.claim())])
        .unwrap()
        .payload
        .clone();
    let second = objects.node(2, Some(&first), None, &shared);
    let root = objects.node(3, Some(&second), Some(&first), &shared);
    Fixture {
        objects,
        root: root.claim().clone(),
        deepest_node,
        deepest_payload,
    }
}

#[test]
fn three_level_dag_reads_all_content_once_and_binds_canonical_roles() {
    let f = fixture();
    let mut b = budget();
    let mut opened = Vec::new();
    let result = f
        .objects
        .verify(&f.root, limits(), &mut b, &mut opened)
        .unwrap();
    let total: u64 = f
        .objects
        .bytes
        .values()
        .map(|bytes| bytes.len() as u64)
        .sum();
    assert_eq!(result.root_observation().claim(), &f.root);
    assert_eq!(
        result.usage(),
        CellContentGraphUsageV3 {
            nodes: 3,
            objects: 9,
            edges: 15,
            content_bytes: total,
            maximum_node_depth: 3,
        }
    );
    assert_eq!(opened.len(), 9);
    assert_eq!(opened.iter().collect::<BTreeSet<_>>().len(), 9);
    assert_eq!(result.observations().count(), 9);
    assert_eq!(b.reads_reserved(), 9);
    assert_eq!(b.bytes_reserved(), total + 9);
    for (claim, bytes) in &f.objects.bytes {
        if claim[68] == ContentKind::ModelManifest as u8 {
            let node = CellContentGraphNodeV3::decode(bytes).unwrap();
            assert_eq!(node.encode(), *bytes);
        }
    }
}

#[test]
fn deep_node_or_payload_substitution_cannot_reuse_the_root_pin() {
    for change_node in [false, true] {
        let mut f = fixture();
        let claim = if change_node {
            &f.deepest_node
        } else {
            &f.deepest_payload
        };
        let bytes = f.objects.bytes.get_mut(&claim_key(claim)).unwrap();
        let at = bytes.len() - 1;
        bytes[at] ^= 1;
        assert!(matches!(
            f.objects
                .verify(&f.root, limits(), &mut budget(), &mut Vec::new()),
            Err(CellContentGraphErrorV3::Commitment(
                ContentCommitmentError::Mismatch
            ))
        ));
    }
}

#[test]
fn absent_or_extra_bytes_and_eof_errors_refuse_deep_readback() {
    for tail in [false, true] {
        let mut f = fixture();
        let bytes = f
            .objects
            .bytes
            .get_mut(&claim_key(&f.deepest_payload))
            .unwrap();
        if tail {
            bytes.push(0);
        } else {
            bytes.pop();
        }
        let result = f
            .objects
            .verify(&f.root, limits(), &mut budget(), &mut Vec::new());
        if tail {
            assert!(matches!(
                result,
                Err(CellContentGraphErrorV3::Commitment(
                    ContentCommitmentError::TrailingBytes
                ))
            ));
        } else {
            assert!(matches!(
                result,
                Err(CellContentGraphErrorV3::Commitment(
                    ContentCommitmentError::Truncated
                ))
            ));
        }
    }
    struct EofError(Cursor<Vec<u8>>);
    impl Read for EofError {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.0.position() == self.0.get_ref().len() as u64 {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled EOF"));
            }
            self.0.read(out)
        }
    }
    let f = fixture();
    let mut b = budget();
    let result = verify_cell_content_graph_v3(&f.root, limits(), &mut b, &mut |claim| {
        let bytes = f.objects.bytes[&claim_key(claim)].clone();
        if claim == &f.deepest_payload {
            Ok(Box::new(EofError(Cursor::new(bytes))) as Box<dyn Read>)
        } else {
            Ok(Box::new(Cursor::new(bytes)) as Box<dyn Read>)
        }
    });
    assert!(matches!(result,
        Err(CellContentGraphErrorV3::Commitment(ContentCommitmentError::Io(error)))
        if error.kind() == io::ErrorKind::Interrupted));
    assert!(b.reads_reserved() > 0);
}

#[test]
fn decoder_refuses_role_type_version_length_and_required_slot_substitution() {
    let f = fixture();
    let original = &f.objects.bytes[&claim_key(&f.root)];
    let slots = 5 + "test-cell".len() + CONTENT_CLAIM_BYTES;
    let mut cases = Vec::new();
    let mut changed = original.clone();
    changed[3] = b'4';
    cases.push(changed);
    let mut changed = original.clone();
    changed[slots] = CellContentDependencyV2::Runtime as u8;
    cases.push(changed);
    let mut changed = original.clone();
    changed[slots + 1] = 255;
    cases.push(changed);
    let mut changed = original.clone();
    changed[slots + 1] = CellContentGraphLinkKindV3::Leaf as u8;
    cases.push(changed); // A ModelManifest claim cannot be typed as a leaf.
    let mut changed = original.clone();
    changed.push(0);
    cases.push(changed);
    for bytes in cases {
        assert!(CellContentGraphNodeV3::decode(&bytes).is_err());
    }
    for size in 0..original.len() {
        assert!(CellContentGraphNodeV3::decode(&original[..size]).is_err());
    }
    let mut node = CellContentGraphNodeV3::decode(original).unwrap();
    node.dependencies[2] = CellContentGraphLinkV3::absent();
    assert!(matches!(
        CellContentGraphNodeV3::decode(&node.encode()),
        Err(CellContentGraphErrorV3::Invalid(
            "required dependency absent"
        ))
    ));
}

#[test]
fn even_newly_pinned_malformed_nodes_cannot_supply_unparsed_edges() {
    let mut f = fixture();
    let original = f.objects.bytes[&claim_key(&f.root)].clone();
    let slots = 5 + "test-cell".len() + CONTENT_CLAIM_BYTES;
    for change in 0..4 {
        let mut bytes = original.clone();
        match change {
            0 => bytes[3] = b'4',
            1 => bytes[slots] = 2,
            2 => bytes[slots + 1] = 1,
            _ => bytes.push(0),
        }
        let repinned = f.objects.repin(&f.root, &bytes);
        let mut opened = Vec::new();
        assert!(f
            .objects
            .verify(&repinned, limits(), &mut budget(), &mut opened)
            .is_err());
        assert_eq!(opened, vec![claim_key(&repinned)]);
    }
}

#[test]
fn structured_payloads_cannot_hide_legacy_or_nested_dependencies_as_leaves() {
    for magic in [
        b"TCM1", b"TCM2", b"TCC2", b"TCG3", b"TCG4", b"TCV2", b"TMR1", b"TCX1", b"TMA1", b"TMT1",
        b"TCA2", b"TCA3", b"CCH1", b"CHB1", b"CRP1", b"CSP1", b"CRC1", b"CRS1", b"CDP1", b"CBP1",
        b"CPS1", b"CVA3", b"TCR1", b"TCD1",
    ] {
        let mut objects = Objects::default();
        let shared = shared(&mut objects);
        let payload = objects.leaf(
            1,
            &[magic.as_slice(), b" opaque fallback forbidden"].concat(),
        );
        let node = CellContentGraphNodeV3::from_observed_contents(
            "test-cell".into(),
            &payload,
            [
                CellContentGraphLinkV3::absent(),
                CellContentGraphLinkV3::absent(),
                CellContentGraphLinkV3::from_observed_leaf(&shared[0]).unwrap(),
                CellContentGraphLinkV3::from_observed_leaf(&shared[1]).unwrap(),
                CellContentGraphLinkV3::from_observed_leaf(&shared[2]).unwrap(),
            ],
        )
        .unwrap();
        let pin = node
            .observe_node(&context(ContentKind::ModelManifest, 1, 1), &mut budget())
            .unwrap();
        objects.bytes.insert(claim_key(pin.claim()), node.encode());
        assert!(
            matches!(
                objects.verify(pin.claim(), limits(), &mut budget(), &mut Vec::new()),
                Err(CellContentGraphErrorV3::Invalid(
                    "structured content declared as leaf"
                ))
            ),
            "reserved prefix {magic:?}"
        );
    }
}

#[test]
fn exact_profile_instance_and_generation_bind_node_to_payload() {
    let f = fixture();
    let bytes = f.objects.bytes[&claim_key(&f.root)].clone();
    let node = CellContentGraphNodeV3::decode(&bytes).unwrap();
    for changed_context in [
        context(ContentKind::ModelManifest, 4, 1),
        context(ContentKind::ModelManifest, 3, 2),
        context(ContentKind::ModelPayload, 3, 1),
    ] {
        assert!(node.observe_node(&changed_context, &mut budget()).is_err());
        let pin = observe_bytes(&changed_context, &mut budget(), &bytes).unwrap();
        let mut objects = Objects::default();
        objects.bytes.insert(claim_key(pin.claim()), bytes.clone());
        assert!(objects
            .verify(pin.claim(), limits(), &mut budget(), &mut Vec::new())
            .is_err());
    }
    let mut foreign = node.payload.encode();
    foreign[4] ^= 1;
    let mut changed = node;
    changed.dependencies[2].claim = Some(ContentClaimV1::decode(&foreign).unwrap());
    assert!(matches!(
        changed.validate(),
        Err(CellContentGraphErrorV3::Invalid("dependency profile"))
    ));
}

#[test]
fn conflicting_contents_for_one_object_identity_are_not_aliases() {
    let mut f = fixture();
    let root_bytes = f.objects.bytes[&claim_key(&f.root)].clone();
    let mut node = CellContentGraphNodeV3::decode(&root_bytes).unwrap();
    let original = node.dependencies[2].claim.as_ref().unwrap();
    let changed =
        observe_bytes(original.context(), &mut budget(), b"conflicting tokenizer").unwrap();
    f.objects.bytes.insert(
        claim_key(changed.claim()),
        b"conflicting tokenizer".to_vec(),
    );
    node.dependencies[3] = CellContentGraphLinkV3::from_observed_leaf(&changed).unwrap();
    let root = f.objects.repin(&f.root, &node.encode());
    assert!(matches!(
        f.objects
            .verify(&root, limits(), &mut budget(), &mut Vec::new()),
        Err(CellContentGraphErrorV3::Invalid(
            "ambiguous object identity"
        ))
    ));
}

#[test]
fn shared_subtree_height_cannot_bypass_longest_path_bound() {
    let mut objects = Objects::default();
    let shared = shared(&mut objects);
    let tail = objects.node(1, None, None, &shared);
    let reused = objects.node(2, Some(&tail), None, &shared);
    let deep_b = objects.node(3, Some(&reused), None, &shared);
    let deep_a = objects.node(4, Some(&deep_b), None, &shared);
    let root = objects.node(5, Some(&reused), Some(&deep_a), &shared);
    let mut caps = limits();
    caps.max_depth = 4;
    assert!(matches!(
        objects.verify(root.claim(), caps, &mut budget(), &mut Vec::new()),
        Err(CellContentGraphErrorV3::Invalid("graph depth"))
    ));
    caps.max_depth = 5;
    let result = objects
        .verify(root.claim(), caps, &mut budget(), &mut Vec::new())
        .unwrap();
    assert_eq!(result.usage().nodes, 5);
    assert_eq!(result.usage().maximum_node_depth, 5);
}

#[test]
fn structural_limits_reject_one_over_and_exact_limits_succeed() {
    let f = fixture();
    let total: u64 = f
        .objects
        .bytes
        .values()
        .map(|bytes| bytes.len() as u64)
        .sum();
    let exact = CellContentGraphLimitsV3 {
        max_nodes: 3,
        max_objects: 9,
        max_edges: 15,
        max_depth: 3,
        max_object_bytes: f.root.content_len(),
        max_total_bytes: total,
    };
    f.objects
        .verify(&f.root, exact, &mut budget(), &mut Vec::new())
        .unwrap();
    for selector in 0..6 {
        let mut cap = exact;
        match selector {
            0 => cap.max_nodes -= 1,
            1 => cap.max_objects -= 1,
            2 => cap.max_edges -= 1,
            3 => cap.max_depth -= 1,
            4 => cap.max_object_bytes -= 1,
            _ => cap.max_total_bytes -= 1,
        }
        assert!(f
            .objects
            .verify(&f.root, cap, &mut budget(), &mut Vec::new())
            .is_err());
    }
    let mut cap = exact;
    cap.max_nodes = 0;
    assert!(cap.validate().is_err());
    cap = exact;
    cap.max_depth = MAX_CELL_CONTENT_GRAPH_DEPTH_V3 + 1;
    assert!(cap.validate().is_err());
}

#[test]
fn cumulative_read_exhaustion_opens_no_unreserved_source_and_cannot_retry_for_free() {
    let f = fixture();
    let mut b = ContentReadBudget::new(8, 1_000_000).unwrap();
    let mut opened = Vec::new();
    assert!(matches!(
        f.objects.verify(&f.root, limits(), &mut b, &mut opened),
        Err(CellContentGraphErrorV3::Commitment(
            ContentCommitmentError::Budget
        ))
    ));
    assert_eq!(opened.len(), 8);
    assert_eq!(b.reads_reserved(), 8);
    assert!(b.exhausted());
    assert!(f
        .objects
        .verify(&f.root, limits(), &mut b, &mut opened)
        .is_err());
    assert_eq!(opened.len(), 8);
    let mut b = ContentReadBudget::new(100, f.root.content_len()).unwrap();
    opened.clear();
    assert!(f
        .objects
        .verify(&f.root, limits(), &mut b, &mut opened)
        .is_err());
    assert!(opened.is_empty()); // The root also needs one reserved EOF byte.
}

#[test]
fn missing_object_open_failures_are_charged_before_the_resolver_runs() {
    let f = fixture();
    let mut b = ContentReadBudget::new(1, f.root.content_len() + 1).unwrap();
    let empty = Objects::default();
    let mut opened = Vec::new();
    assert!(
        matches!(empty.verify(&f.root, limits(), &mut b, &mut opened),
        Err(CellContentGraphErrorV3::Commitment(ContentCommitmentError::Io(error)))
        if error.kind() == io::ErrorKind::NotFound)
    );
    assert_eq!(b.reads_reserved(), 1);
    assert_eq!(b.bytes_reserved(), f.root.content_len() + 1);
    assert!(empty
        .verify(&f.root, limits(), &mut b, &mut opened)
        .is_err());
    assert_eq!(opened.len(), 1);
}

#[test]
fn partial_reads_preserve_prefix_checks_and_exact_bytes() {
    struct OneByte(Cursor<Vec<u8>>);
    impl Read for OneByte {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let count = out.len().min(1);
            self.0.read(&mut out[..count])
        }
    }
    let f = fixture();
    let result = verify_cell_content_graph_v3(&f.root, limits(), &mut budget(), &mut |claim| {
        Ok(Box::new(OneByte(Cursor::new(
            f.objects.bytes[&claim_key(claim)].clone(),
        ))) as Box<dyn Read>)
    })
    .unwrap();
    assert_eq!(result.usage().objects, 9);
}

#[test]
fn direct_content_or_node_declarations_cannot_be_verified_as_a_graph() {
    let f = fixture();
    let mut opened = Vec::new();
    assert!(f
        .objects
        .verify(&f.deepest_payload, limits(), &mut budget(), &mut opened)
        .is_err());
    assert!(opened.is_empty());
    // Even a complete observation of valid TCC2/TCM2-sized literal bytes under
    // ModelManifest does not get a graph readback: the new namespace is exact.
    let mut bytes = f.objects.bytes[&claim_key(&f.root)].clone();
    bytes[..4].copy_from_slice(b"TCC2");
    let observed = observe_bytes(f.root.context(), &mut budget(), &bytes).unwrap();
    let mut objects = Objects::default();
    objects.bytes.insert(claim_key(observed.claim()), bytes);
    assert!(matches!(
        objects.verify(observed.claim(), limits(), &mut budget(), &mut Vec::new()),
        Err(CellContentGraphErrorV3::Invalid("node version"))
    ));
}

#[test]
fn equal_length_legacy_digest_cannot_replace_actual_leaf_content() {
    use sha2::{Digest, Sha256};

    let mut objects = Objects::default();
    let shared = shared(&mut objects);
    let actual = [0x55; 32];
    let payload = objects.leaf(1, &actual);
    let node = CellContentGraphNodeV3::from_observed_contents(
        "test-cell".into(),
        &payload,
        [
            CellContentGraphLinkV3::absent(),
            CellContentGraphLinkV3::absent(),
            CellContentGraphLinkV3::from_observed_leaf(&shared[0]).unwrap(),
            CellContentGraphLinkV3::from_observed_leaf(&shared[1]).unwrap(),
            CellContentGraphLinkV3::from_observed_leaf(&shared[2]).unwrap(),
        ],
    )
    .unwrap();
    let root = node
        .observe_node(&context(ContentKind::ModelManifest, 1, 1), &mut budget())
        .unwrap();
    objects.bytes.insert(claim_key(root.claim()), node.encode());
    objects
        .verify(root.claim(), limits(), &mut budget(), &mut Vec::new())
        .unwrap();
    objects
        .bytes
        .insert(claim_key(payload.claim()), Sha256::digest(actual).to_vec());
    // The original and digest both contain 32 bytes: rejection depends on the
    // actual CCH1 content, not a length-based guess about whether bytes are a hash.
    assert!(matches!(
        objects.verify(root.claim(), limits(), &mut budget(), &mut Vec::new()),
        Err(CellContentGraphErrorV3::Commitment(
            ContentCommitmentError::Mismatch
        ))
    ));
}

#[test]
fn independent_python_graph_vector_matches_native_readback() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/fixtures/cell-content-graph-v3/vectors.json"
    )))
    .unwrap();
    assert_eq!(fixture["schema"], "trnm-cell-content-graph-v3-vectors");
    assert_eq!(fixture["profile_ids_are_synthetic_test_labels"], true);
    let mut objects = Objects::default();
    for object in fixture["objects"].as_array().unwrap() {
        let record = hex::decode(object["claim_hex"].as_str().unwrap()).unwrap();
        let bytes = hex::decode(object["content_hex"].as_str().unwrap()).unwrap();
        let claim = ContentClaimV1::decode(&record).unwrap();
        let observed = observe_bytes(claim.context(), &mut budget(), &bytes).unwrap();
        claim.verify(&observed).unwrap();
        if claim.context().kind() == ContentKind::ModelManifest {
            assert_eq!(
                CellContentGraphNodeV3::decode(&bytes).unwrap().encode(),
                bytes
            );
        }
        assert!(objects.bytes.insert(claim_key(&claim), bytes).is_none());
    }
    let root =
        ContentClaimV1::decode(&hex::decode(fixture["root_claim_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let mut b = budget();
    let result = objects
        .verify(&root, limits(), &mut b, &mut Vec::new())
        .unwrap();
    assert_eq!(
        result.usage().nodes,
        fixture["expected"]["nodes"].as_u64().unwrap() as u32
    );
    assert_eq!(
        result.usage().objects,
        fixture["expected"]["objects"].as_u64().unwrap() as u32
    );
    assert_eq!(
        result.usage().edges,
        fixture["expected"]["edges"].as_u64().unwrap() as u32
    );
    assert_eq!(
        result.usage().maximum_node_depth,
        fixture["expected"]["maximum_node_depth"].as_u64().unwrap() as u16
    );
    assert_eq!(
        b.bytes_reserved(),
        fixture["expected"]["reserved_bytes"].as_u64().unwrap()
    );
}
