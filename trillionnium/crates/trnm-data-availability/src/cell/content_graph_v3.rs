//! TCG3 verifies the complete, explicitly declared graph of model content.
//!
//! Every edge is decoded from a node's actual bytes *after* its complete CCH1
//! claim matches. There is no separately supplied edge list, short-ID lookup or
//! promotion from the TCM2/TCC2 direct-content observations. TCG3 is a fresh
//! format; it changes no existing format, cache, loader or authorization owner.
//!
//! The graph is closed over this format's declared edges. It does not discover
//! undeclared executable/library dependencies, prove that an absent ancestor
//! never existed, or establish historical provenance, custody or compatibility.
//! A successful observation grants no installation, CURRENT or FinalUse right.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Read},
};

use trnm_protocol::content_commitment::{
    observe_bytes, observe_reader, ContentClaimV1, ContentCommitmentError, ContentContextV1,
    ContentKind, ContentReadBudget, ObservedContentV1, CONTENT_CLAIM_BYTES,
};

use super::{CellContentDependencyV2, MAX_CELL_BYTES};

const MAGIC: &[u8; 4] = b"TCG3";
const ROLES: [CellContentDependencyV2; 5] = CellContentDependencyV2::ALL;
const FIXED_BYTES: usize = 5 + CONTENT_CLAIM_BYTES + 2 * ROLES.len();
const MIN_NODE_BYTES: usize = FIXED_BYTES + 1 + 3 * CONTENT_CLAIM_BYTES;
pub const MAX_CELL_CONTENT_GRAPH_NODE_BYTES_V3: usize =
    FIXED_BYTES + 64 + ROLES.len() * CONTENT_CLAIM_BYTES;
pub const MAX_CELL_CONTENT_GRAPH_NODES_V3: u32 = 256;
pub const MAX_CELL_CONTENT_GRAPH_OBJECTS_V3: u32 = 7 * MAX_CELL_CONTENT_GRAPH_NODES_V3;
pub const MAX_CELL_CONTENT_GRAPH_EDGES_V3: u32 = 6 * MAX_CELL_CONTENT_GRAPH_NODES_V3;
pub const MAX_CELL_CONTENT_GRAPH_DEPTH_V3: u16 = 32;

type ClaimKey = [u8; CONTENT_CLAIM_BYTES];
// CCH1 through generation: profile, kind, instance and generation, without
// content length/digest. One graph cannot give this identity two meanings.
type ObjectIdentity = [u8; 141];
type Result<T> = std::result::Result<T, CellContentGraphErrorV3>;

#[derive(Debug)]
pub enum CellContentGraphErrorV3 {
    Invalid(&'static str),
    Commitment(ContentCommitmentError),
}

impl fmt::Display for CellContentGraphErrorV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "cell content graph v3 rejected: {reason}"),
            Self::Commitment(error) => write!(f, "cell content graph v3: {error}"),
        }
    }
}

impl std::error::Error for CellContentGraphErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::Commitment(error) => Some(error),
        }
    }
}

impl From<ContentCommitmentError> for CellContentGraphErrorV3 {
    fn from(error: ContentCommitmentError) -> Self {
        Self::Commitment(error)
    }
}

fn require(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(CellContentGraphErrorV3::Invalid(reason))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CellContentGraphLinkKindV3 {
    Absent = 0,
    Leaf = 1,
    Node = 2,
}

/// A typed declaration, never proof that the referenced bytes were read. Leaf
/// construction requires an actual observation; verification still re-reads it
/// and refuses reserved model-container prefixes. Only Base/Parent may be absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellContentGraphLinkV3 {
    kind: CellContentGraphLinkKindV3,
    claim: Option<ContentClaimV1>,
}

impl CellContentGraphLinkV3 {
    pub fn absent() -> Self {
        Self {
            kind: CellContentGraphLinkKindV3::Absent,
            claim: None,
        }
    }

    pub fn from_observed_leaf(observation: &ObservedContentV1) -> Result<Self> {
        check_claim(observation.claim(), CellContentGraphLinkKindV3::Leaf)?;
        Ok(Self {
            kind: CellContentGraphLinkKindV3::Leaf,
            claim: Some(observation.claim().clone()),
        })
    }

    pub fn from_observed_node(observation: &CellContentGraphNodeObservationV3) -> Self {
        Self {
            kind: CellContentGraphLinkKindV3::Node,
            claim: Some(observation.claim().clone()),
        }
    }

    pub fn kind(&self) -> CellContentGraphLinkKindV3 {
        self.kind
    }

    pub fn claim(&self) -> Option<&ContentClaimV1> {
        self.claim.as_ref()
    }
}

/// A canonical TCG3 node declaration. All five role tags are present, even for
/// an explicitly absent Base or Parent. Absence is owner-committed metadata,
/// not evidence that old ancestry has been reconstructed or retired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellContentGraphNodeV3 {
    family: String,
    payload: ContentClaimV1,
    dependencies: [CellContentGraphLinkV3; 5],
}

impl CellContentGraphNodeV3 {
    pub fn from_observed_contents(
        family: String,
        payload: &ObservedContentV1,
        dependencies: [CellContentGraphLinkV3; 5],
    ) -> Result<Self> {
        let value = Self {
            family,
            payload: payload.claim().clone(),
            dependencies,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn family(&self) -> &str {
        &self.family
    }

    pub fn payload_claim(&self) -> &ContentClaimV1 {
        &self.payload
    }

    pub fn dependency(&self, role: CellContentDependencyV2) -> &CellContentGraphLinkV3 {
        &self.dependencies[role as usize - 1]
    }

    pub fn validate(&self) -> Result<()> {
        require(
            (1..=64).contains(&self.family.len())
                && self
                    .family
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "node family",
        )?;
        check_claim(&self.payload, CellContentGraphLinkKindV3::Leaf)?;
        for (role, link) in ROLES.into_iter().zip(&self.dependencies) {
            match (link.kind, &link.claim) {
                (CellContentGraphLinkKindV3::Absent, None) => require(
                    matches!(
                        role,
                        CellContentDependencyV2::Base | CellContentDependencyV2::Parent
                    ),
                    "required dependency absent",
                )?,
                (
                    CellContentGraphLinkKindV3::Leaf | CellContentGraphLinkKindV3::Node,
                    Some(claim),
                ) => {
                    check_claim(claim, link.kind)?;
                    require(
                        claim.context().profile_id() == self.payload.context().profile_id(),
                        "dependency profile",
                    )?;
                }
                _ => return Err(CellContentGraphErrorV3::Invalid("link declaration")),
            }
        }
        Ok(())
    }

    /// Exact wire: TCG3, U8 family length, ASCII family, payload CCH1, then
    /// Base/Parent/Tokenizer/Layout/Runtime slots, each U8 role + U8 link kind.
    /// Present links contain one full CCH1 record; absent links contain no bytes.
    /// No sorting, ignored tail, short locator or alternate version is accepted.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_CELL_CONTENT_GRAPH_NODE_BYTES_V3);
        out.extend_from_slice(MAGIC);
        out.push(self.family.len() as u8);
        out.extend_from_slice(self.family.as_bytes());
        out.extend_from_slice(&self.payload.encode());
        for (role, link) in ROLES.into_iter().zip(&self.dependencies) {
            out.push(role as u8);
            out.push(link.kind as u8);
            if let Some(claim) = &link.claim {
                out.extend_from_slice(&claim.encode());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require(
            (MIN_NODE_BYTES..=MAX_CELL_CONTENT_GRAPH_NODE_BYTES_V3).contains(&bytes.len()),
            "node length",
        )?;
        require(&bytes[..4] == MAGIC, "node version")?;
        let family_len = usize::from(bytes[4]);
        require((1..=64).contains(&family_len), "node family length")?;
        let family_end = 5 + family_len;
        let family = std::str::from_utf8(&bytes[5..family_end])
            .map_err(|_| CellContentGraphErrorV3::Invalid("node family encoding"))?
            .to_owned();
        let payload_end = family_end + CONTENT_CLAIM_BYTES;
        let payload = ContentClaimV1::decode(&bytes[family_end..payload_end])?;
        let mut at = payload_end;
        let mut dependencies = Vec::with_capacity(ROLES.len());
        for role in ROLES {
            let tags = bytes
                .get(at..at + 2)
                .ok_or(CellContentGraphErrorV3::Invalid("node truncated role"))?;
            require(tags[0] == role as u8, "canonical role order")?;
            at += 2;
            let kind = match tags[1] {
                0 => CellContentGraphLinkKindV3::Absent,
                1 => CellContentGraphLinkKindV3::Leaf,
                2 => CellContentGraphLinkKindV3::Node,
                _ => return Err(CellContentGraphErrorV3::Invalid("link kind")),
            };
            let claim = if kind == CellContentGraphLinkKindV3::Absent {
                None
            } else {
                let record = bytes
                    .get(at..at + CONTENT_CLAIM_BYTES)
                    .ok_or(CellContentGraphErrorV3::Invalid("node truncated claim"))?;
                at += CONTENT_CLAIM_BYTES;
                Some(ContentClaimV1::decode(record)?)
            };
            dependencies.push(CellContentGraphLinkV3 { kind, claim });
        }
        require(at == bytes.len(), "node exact coverage")?;
        let value = Self {
            family,
            payload,
            dependencies: dependencies
                .try_into()
                .map_err(|_| CellContentGraphErrorV3::Invalid("node role coverage"))?,
        };
        value.validate()?;
        require(value.encode() == bytes, "canonical node encoding")?;
        Ok(value)
    }

    /// Observe only this declaration, not any referenced payload/dependency.
    /// The distinct result cannot be promoted to a complete graph observation.
    pub fn observe_node(
        &self,
        context: &ContentContextV1,
        budget: &mut ContentReadBudget,
    ) -> Result<CellContentGraphNodeObservationV3> {
        self.validate()?;
        self.check_context(context)?;
        Ok(CellContentGraphNodeObservationV3 {
            observation: observe_bytes(context, budget, &self.encode())?,
        })
    }

    fn check_context(&self, context: &ContentContextV1) -> Result<()> {
        let payload = self.payload.context();
        require(
            context.kind() == ContentKind::ModelManifest
                && context.profile_id() == payload.profile_id()
                && context.instance() == payload.instance()
                && context.generation() == payload.generation(),
            "node/payload context",
        )
    }
}

/// Only the complete canonical node bytes were observed, not its descendants.
#[derive(Debug)]
pub struct CellContentGraphNodeObservationV3 {
    observation: ObservedContentV1,
}

impl CellContentGraphNodeObservationV3 {
    pub fn observation(&self) -> &ObservedContentV1 {
        &self.observation
    }

    pub fn claim(&self) -> &ContentClaimV1 {
        self.observation.claim()
    }
}

fn check_claim(claim: &ContentClaimV1, kind: CellContentGraphLinkKindV3) -> Result<()> {
    let (purpose, maximum) = match kind {
        CellContentGraphLinkKindV3::Leaf => (ContentKind::ModelPayload, MAX_CELL_BYTES),
        CellContentGraphLinkKindV3::Node => (
            ContentKind::ModelManifest,
            MAX_CELL_CONTENT_GRAPH_NODE_BYTES_V3 as u64,
        ),
        CellContentGraphLinkKindV3::Absent => {
            return Err(CellContentGraphErrorV3::Invalid("absent content"));
        }
    };
    require(claim.context().kind() == purpose, "content kind")?;
    require((1..=maximum).contains(&claim.content_len()), "content size")?;
    if kind == CellContentGraphLinkKindV3::Node {
        require(
            claim.content_len() >= MIN_NODE_BYTES as u64,
            "node claim size",
        )?;
    }
    Ok(())
}

/// Per-traversal structural caps. The caller's separate ContentReadBudget is
/// cumulative across traversals and failures and charges each actual read plus
/// EOF. Counts here cover unique objects and their actual declared edge slots.
#[derive(Clone, Copy, Debug)]
pub struct CellContentGraphLimitsV3 {
    pub max_nodes: u32,
    pub max_objects: u32,
    pub max_edges: u32,
    /// Longest node path, including the root. Leaf edges add no node depth.
    pub max_depth: u16,
    pub max_object_bytes: u64,
    pub max_total_bytes: u64,
}

impl CellContentGraphLimitsV3 {
    pub fn validate(&self) -> Result<()> {
        require(
            (1..=MAX_CELL_CONTENT_GRAPH_NODES_V3).contains(&self.max_nodes)
                && (1..=MAX_CELL_CONTENT_GRAPH_OBJECTS_V3).contains(&self.max_objects)
                && (1..=MAX_CELL_CONTENT_GRAPH_EDGES_V3).contains(&self.max_edges)
                && (1..=MAX_CELL_CONTENT_GRAPH_DEPTH_V3).contains(&self.max_depth)
                && (1..=MAX_CELL_BYTES).contains(&self.max_object_bytes)
                && (1..=MAX_CELL_BYTES).contains(&self.max_total_bytes),
            "finite graph limits",
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellContentGraphUsageV3 {
    pub nodes: u32,
    pub objects: u32,
    pub edges: u32,
    pub content_bytes: u64,
    pub maximum_node_depth: u16,
}

#[derive(Debug)]
struct CompletedObject {
    observation: ObservedContentV1,
    // A leaf has height zero; a terminal node has height one. Retaining the
    // full subtree height prevents shared-node reuse from bypassing depth caps.
    node_height: u16,
}

/// All declared edges from the independently pinned root were traversed; each
/// unique full claim matched a complete actual read. No public constructor or
/// deserializer exists. This is neither a stable snapshot nor authorization.
///
/// ```compile_fail
/// use trnm_data_availability::cell::{
///     CellContentGraphNodeObservationV3, CellContentGraphReadbackV3,
/// };
/// fn promote(node: CellContentGraphNodeObservationV3) -> CellContentGraphReadbackV3 {
///     node
/// }
/// ```
#[derive(Debug)]
pub struct CellContentGraphReadbackV3 {
    root: ClaimKey,
    completed: BTreeMap<ClaimKey, CompletedObject>,
    usage: CellContentGraphUsageV3,
}

impl CellContentGraphReadbackV3 {
    pub fn root_observation(&self) -> &ObservedContentV1 {
        &self.completed[&self.root].observation
    }

    pub fn observations(&self) -> impl Iterator<Item = &ObservedContentV1> {
        self.completed.values().map(|value| &value.observation)
    }

    pub fn usage(&self) -> CellContentGraphUsageV3 {
        self.usage
    }
}

/// Resolve complete claims to owned readers. The callback is invoked lazily,
/// only after ContentReadBudget reserves the declared bytes and EOF probe. A
/// missing object/open error is charged and cannot reset the caller's budget.
/// Readers may be files or owned bounded transports; the caller must supply
/// cancellation/deadlines and custody. No claim learned from this same source
/// can replace the independently authenticated expected_root.
pub fn verify_cell_content_graph_v3<F>(
    expected_root: &ContentClaimV1,
    limits: CellContentGraphLimitsV3,
    budget: &mut ContentReadBudget,
    resolve: &mut F,
) -> Result<CellContentGraphReadbackV3>
where
    F: FnMut(&ContentClaimV1) -> io::Result<Box<dyn Read>>,
{
    limits.validate()?;
    check_claim(expected_root, CellContentGraphLinkKindV3::Node)?;
    let mut walker = Walker {
        profile: expected_root.context().profile_id(),
        limits,
        budget,
        resolve,
        completed: BTreeMap::new(),
        active: BTreeSet::new(),
        identities: BTreeMap::new(),
        usage: CellContentGraphUsageV3::default(),
    };
    walker.visit(expected_root, CellContentGraphLinkKindV3::Node, 1)?;
    Ok(CellContentGraphReadbackV3 {
        root: claim_key(expected_root),
        completed: walker.completed,
        usage: walker.usage,
    })
}

fn claim_key(claim: &ContentClaimV1) -> ClaimKey {
    claim.encode().try_into().expect("CCH1 fixed record")
}

struct Walker<'a, F> {
    profile: trnm_protocol::crypto_profile::CryptoProfileId,
    limits: CellContentGraphLimitsV3,
    budget: &'a mut ContentReadBudget,
    resolve: &'a mut F,
    completed: BTreeMap<ClaimKey, CompletedObject>,
    active: BTreeSet<ClaimKey>,
    identities: BTreeMap<ObjectIdentity, ClaimKey>,
    usage: CellContentGraphUsageV3,
}

impl<F> Walker<'_, F>
where
    F: FnMut(&ContentClaimV1) -> io::Result<Box<dyn Read>>,
{
    fn depth(&mut self, start: u16, height: u16) -> Result<()> {
        let deepest = start
            .checked_add(height - 1)
            .ok_or(CellContentGraphErrorV3::Invalid("graph depth"))?;
        require(deepest <= self.limits.max_depth, "graph depth")?;
        self.usage.maximum_node_depth = self.usage.maximum_node_depth.max(deepest);
        Ok(())
    }

    fn visit(
        &mut self,
        claim: &ContentClaimV1,
        kind: CellContentGraphLinkKindV3,
        depth: u16,
    ) -> Result<u16> {
        check_claim(claim, kind)?;
        require(
            claim.context().profile_id() == self.profile,
            "graph profile",
        )?;
        require(
            claim.content_len() <= self.limits.max_object_bytes,
            "graph object size",
        )?;
        if kind == CellContentGraphLinkKindV3::Node {
            self.depth(depth, 1)?;
        }
        let key = claim_key(claim);
        let identity: ObjectIdentity = key[..141].try_into().expect("CCH1 context prefix");
        require(
            self.identities
                .get(&identity)
                .is_none_or(|prior| prior == &key),
            "ambiguous object identity",
        )?;
        require(!self.active.contains(&key), "graph cycle")?;
        if let Some(previous) = self.completed.get(&key) {
            let height = previous.node_height;
            if kind == CellContentGraphLinkKindV3::Node {
                self.depth(depth, height)?;
            }
            return Ok(height);
        }
        require(
            self.usage.objects < self.limits.max_objects,
            "graph object count",
        )?;
        if kind == CellContentGraphLinkKindV3::Node {
            require(self.usage.nodes < self.limits.max_nodes, "graph node count")?;
            self.usage.nodes += 1;
        }
        let content_bytes = self
            .usage
            .content_bytes
            .checked_add(claim.content_len())
            .ok_or(CellContentGraphErrorV3::Invalid("graph byte overflow"))?;
        require(
            content_bytes <= self.limits.max_total_bytes,
            "graph total bytes",
        )?;
        self.usage.objects += 1;
        self.usage.content_bytes = content_bytes;
        self.identities.insert(identity, key);

        // Capturing only the small node encoding, or four bytes of a leaf,
        // avoids buffering complete model payloads. Reservation happens inside
        // observe_reader before DeferredReader can open or read its source.
        let mut reader = DeferredReader {
            resolve: &mut *self.resolve,
            claim,
            reader: None,
            captured: Vec::with_capacity(if kind == CellContentGraphLinkKindV3::Node {
                claim.content_len() as usize + 1
            } else {
                4
            }),
            capture_limit: if kind == CellContentGraphLinkKindV3::Node {
                claim.content_len() as usize + 1
            } else {
                4
            },
        };
        let observation = observe_reader(
            claim.context(),
            self.budget,
            claim.content_len(),
            &mut reader,
        )?;
        claim.verify(&observation)?;
        let captured = reader.captured;
        // Drop the resolved reader before asking the source for any successor.
        drop(reader.reader);

        let height = if kind == CellContentGraphLinkKindV3::Node {
            let node = CellContentGraphNodeV3::decode(&captured)?;
            node.check_context(claim.context())?;
            let edges = 1 + node
                .dependencies
                .iter()
                .filter(|link| link.claim.is_some())
                .count() as u32;
            let total_edges = self
                .usage
                .edges
                .checked_add(edges)
                .ok_or(CellContentGraphErrorV3::Invalid("graph edge overflow"))?;
            require(total_edges <= self.limits.max_edges, "graph edge count")?;
            self.usage.edges = total_edges;
            self.active.insert(key);
            self.visit(&node.payload, CellContentGraphLinkKindV3::Leaf, depth)?;
            let mut height = 1;
            for link in &node.dependencies {
                if let Some(dependency) = &link.claim {
                    let child_height = self.visit(dependency, link.kind, depth + 1)?;
                    height = height.max(child_height + 1);
                }
            }
            self.depth(depth, height)?;
            self.active.remove(&key);
            height
        } else {
            require(
                !reserved_container_prefix(&captured),
                "structured content declared as leaf",
            )?;
            0
        };
        self.completed.insert(
            key,
            CompletedObject {
                observation,
                node_height: height,
            },
        );
        Ok(height)
    }
}

fn reserved_container_prefix(bytes: &[u8]) -> bool {
    // These known Cell containers, claims and storage metadata carry references
    // that the raw-leaf variant does not traverse. Reserve their entire version
    // families instead of silently treating an unsupported version as a leaf.
    // This finite guard does not discover references in arbitrary JSON, ELF,
    // scripts, model payloads or other unknown encodings.
    bytes.len() >= 4
        && [
            b"TCM", b"TCC", b"TCG", b"TCR", b"TCD", b"TMR", b"TCV", b"TCX", b"TMA", b"TMT", b"TCA",
            b"CCH", b"CHB", b"CRP", b"CSP", b"CRC", b"CRS", b"CDP", b"CBP", b"CPS", b"CVA",
        ]
        .iter()
        .any(|prefix| &bytes[..3] == prefix.as_slice())
}

struct DeferredReader<'a, F> {
    resolve: &'a mut F,
    claim: &'a ContentClaimV1,
    reader: Option<Box<dyn Read>>,
    captured: Vec<u8>,
    capture_limit: usize,
}

impl<F> Read for DeferredReader<'_, F>
where
    F: FnMut(&ContentClaimV1) -> io::Result<Box<dyn Read>>,
{
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.reader.is_none() {
            self.reader = Some((self.resolve)(self.claim)?);
        }
        let count = self.reader.as_mut().expect("opened reader").read(bytes)?;
        if count > bytes.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "reader overrun"));
        }
        let retained = count.min(self.capture_limit - self.captured.len());
        self.captured.extend_from_slice(&bytes[..retained]);
        Ok(count)
    }
}

#[cfg(test)]
mod tests;
