"""Closed NPQ selector contract for the original legacy evidence reader.

These are fixed reviewed source contracts from 969150c1f1ad1821ee5ac3c11f0535677e9bb8e9
with the explicit NPQ4 task and NPQ5 renewal selector extensions. They are not templates derived
from evidence or the source currently being inspected.
Recognizing these joins grants no PQ, shared-state or growth evidence authority.
"""
import re
from rust_source_tokens import rust_tokens as tokens

BACKEND_IMPLEMENTATION = r'''
    fn ddl(self) -> String {
        match self {
            Self::Legacy => ddl(),
            Self::AuthenticatedV1 => format!("{}{}", ddl(), native_authenticated::DDL),
            Self::PermanentAccountGrowthV2 => format!("{}{}", ddl(), growth::DDL),
        }
    }
    fn selected_ddl(self, settings: &Settings) -> String {
        if settings.is_native_pq_v5() {
            pq_tasks_v5::ddl(self.ddl())
        } else if settings.is_native_pq_v4() {
            pq_tasks_v4::ddl(self.ddl())
        } else if settings.is_native_pq_v3() {
            pq_quota_v3::ddl(self.ddl())
        } else if settings.is_native_pq_v2() {
            pq_accounts_v2::ddl(self.ddl())
        } else if settings.is_native_pq_v1() {
            pq_native_v1::ddl(self.ddl())
        } else {
            self.ddl()
        }
    }
    fn selected_schema_id(self, settings: &Settings) -> Hash {
        if settings.is_native_pq_v5() {
            return hash(
                b"native-pq-task-branch-schema-v5",
                &[self.selected_ddl(settings).as_bytes()],
            );
        }
        if settings.is_native_pq_v4() {
            return hash(
                b"native-pq-task-branch-schema-v4",
                &[self.selected_ddl(settings).as_bytes()],
            );
        }
        if settings.is_native_pq_v3() {
            return hash(
                b"native-pq-quota-branch-schema-v3",
                &[self.selected_ddl(settings).as_bytes()],
            );
        }
        if settings.is_native_pq_v2() {
            return hash(
                b"native-pq-accounts-branch-schema-v2",
                &[self.selected_ddl(settings).as_bytes()],
            );
        }
        if settings.is_native_pq_v1() {
            return hash(
                b"native-pq-transfer-branch-schema-v1",
                &[self.selected_ddl(settings).as_bytes()],
            );
        }
        if growth_profile_v2::enabled(&settings.app) {
            hash(
                b"native-growth-reference-branch-schema-v2",
                &[self.ddl().as_bytes()],
            )
        } else {
            self.schema_id()
        }
    }
    fn schema_id(self) -> Hash {
        let domain: &[u8] = match self {
            Self::Legacy => b"native-branch-schema-v2",
            Self::AuthenticatedV1 => b"native-authenticated-branch-schema-v1",
            Self::PermanentAccountGrowthV2 => b"native-permanent-account-growth-schema-v2",
        };
        hash(domain, &[self.ddl().as_bytes()])
    }
'''

OPENING_FIELDS = r'''
    pq_explicit: Option<crate::native_packet::Profile>,
    state_backend: StateBackend,
    growth_observation_only: bool,
    native_io: Option<NativeIoLease>,
'''

OPENING_PREFIX = r'''
        let NativeStoreOpening {
            pq_explicit,
            state_backend,
            growth_observation_only,
            native_io,
        } = opening;
        ensure(
            settings.packet_profile()
                == pq_explicit.unwrap_or(crate::native_packet::Profile::Legacy),
            "PQ_EXPLICIT_CONSTRUCTOR_REQUIRED",
        )?;
        ensure(
            pq_explicit.is_none()
                || (state_backend == StateBackend::AuthenticatedV1
                    && native_io.is_none()
                    && !growth_observation_only
                    && owners.policy.is_none()
                    && owners.mining.is_none()
                    && owners.continuous.is_none()),
            "PQ_OPEN_PROFILE",
        )?;
'''

BRIDGE = r'''
        Self::open_selected_with_io(
            path,
            settings,
            workers,
            hook,
            owners,
            NativeStoreOpening {
                pq_explicit: None,
                state_backend,
                growth_observation_only,
                native_io: None,
            },
        )
    '''

PACKET_SOURCE = r'''//! Internal exact selected packet grammar; no automatic profile negotiation.
use crate::{ensure, Packet, Result, Settings};
use trnm_protocol::pon_wire::{Header, HEADER_BYTES};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Profile {
    Legacy,
    Pq1,
    Pq2,
    Pq3,
    Pq4,
    Pq5,
}
impl Settings {
    pub(crate) fn packet_profile(&self) -> Profile {
        if self.is_native_pq_v5() {
            Profile::Pq5
        } else if self.is_native_pq_v4() {
            Profile::Pq4
        } else if self.is_native_pq_v3() {
            Profile::Pq3
        } else if self.is_native_pq_v2() {
            Profile::Pq2
        } else if self.is_native_pq_v1() {
            Profile::Pq1
        } else {
            Profile::Legacy
        }
    }
    pub(crate) fn is_native_pq(&self) -> bool {
        self.packet_profile() != Profile::Legacy
    }
}
pub(crate) fn header_prefix_bytes(profile: Profile) -> usize {
    match profile {
        Profile::Legacy => crate::pq_native_v1::header_prefix_bytes(false),
        Profile::Pq1 => crate::pq_native_v1::header_prefix_bytes(true),
        Profile::Pq2 | Profile::Pq3 | Profile::Pq4 | Profile::Pq5 => HEADER_BYTES + 8,
    }
}
pub(crate) fn decode_header_projection(bytes: &[u8], profile: Profile) -> Result<Header> {
    match profile {
        Profile::Legacy => crate::pq_native_v1::decode_header_projection(bytes, false),
        Profile::Pq1 => crate::pq_native_v1::decode_header_projection(bytes, true),
        Profile::Pq2 | Profile::Pq3 | Profile::Pq4 | Profile::Pq5 => {
            ensure(
                bytes.len() == HEADER_BYTES + 8
                    && bytes.starts_with(match profile {
                        Profile::Pq2 => {
                            trnm_protocol::pq_native_accounts_v2::AccountProfile::AccountsV2
                                .packet_prefix()
                        }
                        Profile::Pq3 => {
                            trnm_protocol::pq_native_accounts_v2::AccountProfile::QuotaV3
                                .packet_prefix()
                        }
                        Profile::Pq4 => {
                            trnm_protocol::pq_native_accounts_v2::AccountProfile::TasksV4
                                .packet_prefix()
                        }
                        Profile::Pq5 => {
                            trnm_protocol::pq_native_accounts_v2::AccountProfile::TasksV5
                                .packet_prefix()
                        }
                        _ => unreachable!(),
                    }),
                "PQ2_HEADER_PROFILE",
            )?;
            Header::decode(&bytes[8..]).map_err(|_| "HEADER_CODEC".into())
        }
    }
}
pub(crate) fn encode(packet: &Packet, profile: Profile) -> Result<Vec<u8>> {
    match profile {
        Profile::Legacy => packet.encode_for_native_profile(false),
        Profile::Pq1 => packet.encode_for_native_profile(true),
        Profile::Pq2 => crate::pq_accounts_v2::encode_packet(packet),
        Profile::Pq4 => crate::pq_accounts_v2::encode_packet_for_profile(
            packet,
            trnm_protocol::pq_native_accounts_v2::AccountProfile::TasksV4,
        ),
        Profile::Pq5 => crate::pq_accounts_v2::encode_packet_for_profile(
            packet,
            trnm_protocol::pq_native_accounts_v2::AccountProfile::TasksV5,
        ),
        Profile::Pq3 => crate::pq_accounts_v2::encode_packet_for_profile(
            packet,
            trnm_protocol::pq_native_accounts_v2::AccountProfile::QuotaV3,
        ),
    }
}
pub(crate) fn decode(raw: &[u8], profile: Profile) -> Result<Packet> {
    match profile {
        Profile::Legacy => Packet::decode(raw),
        Profile::Pq1 => Ok(crate::pq_native_v1::PqPacketV1::decode(raw)?.inner),
        Profile::Pq2 => Ok(crate::pq_accounts_v2::PqPacketV2::decode(raw)?.inner),
        Profile::Pq3 => Ok(crate::pq_quota_v3::PqPacketV3::decode(raw)?.inner),
        Profile::Pq4 => Ok(crate::pq_tasks_v4::PqPacketV4::decode(raw)?.inner),
        Profile::Pq5 => Ok(crate::pq_tasks_v5::PqPacketV5::decode(raw)?.inner),
    }
}
'''

ANCESTRY_CONTEXT = r'''
        crate::ancestry_index::Context {
            pq_packet: self.settings.packet_profile(),
            network: self.settings.network(),
            parameters: self.settings.parameters(),
            genesis: self.settings.genesis(),
        }
    '''

ANCESTRY_READ_HEADER = r'''fn read_header(
    db: &Connection,
    id: Hash,
    pq: crate::native_packet::Profile,
) -> rusqlite::Result<Option<HeaderProjection>> {
    db.query_row("SELECT parent,state_root,substr(packet,1,?),substr(packet,-32) FROM blocks WHERE id=? AND length(parent)=32 AND length(state_root)=32 AND length(packet)<=?",
        params![crate::native_packet::header_prefix_bytes(pq),id.as_slice(),MAX_PACKET], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()
}'''

ANCESTRY_METADATA = r'''fn metadata(db: &Connection, ctx: Context, id: Hash, budget: &mut Budget<'_>) -> Result<Metadata> {
    budget.charge()?;
    let shape = read_shape(db, id)?;
    #[cfg(test)]
    budget.observe(ReadKey::Shape(id), || shape_digest(&shape))?;
    let (height, parent_len, root_len, packet_len) = shape.ok_or("ANCESTRY_INDEX_UNKNOWN_BLOCK")?;
    ensure(
        root_len == 32 && height <= i64::MAX as u64,
        "ANCESTRY_INDEX_METADATA",
    )?;
    if id == ctx.genesis {
        ensure(
            height == 0 && parent_len.is_none() && packet_len.is_none(),
            "ANCESTRY_INDEX_GENESIS",
        )?;
        return Ok(Metadata {
            parent: None,
            height: 0,
        });
    }
    ensure(
        height > 0
            && parent_len == Some(32)
            && packet_len.is_some_and(|n| {
                (crate::native_packet::header_prefix_bytes(ctx.pq_packet)
                    + 2
                    + pon_work::PROOF_BYTES..=MAX_PACKET)
                    .contains(&n)
            }),
        "ANCESTRY_INDEX_PACKET_BYTES",
    )?;
    budget.charge()?;
    // Predicates precede prefix/trace extraction: even corrupt oversized BLOBs
    // never enter the projection or Rust Vec allocation.
    let row = read_header(db, id, ctx.pq_packet)?;
    #[cfg(test)]
    budget.observe(ReadKey::Header(id, ctx.pq_packet), || header_digest(&row))?;
    let (parent, root, prefix, trace) = row.ok_or("ANCESTRY_INDEX_METADATA")?;
    let parent = bytes32(parent)?;
    let root = bytes32(root)?;
    let trace = bytes32(trace)?;
    let header = crate::native_packet::decode_header_projection(&prefix, ctx.pq_packet)
        .map_err(|_| Error::from("ANCESTRY_INDEX_HEADER"))?;
    ensure(
        header.block_id(trace) == id
            && header.network == ctx.network
            && header.parameters == ctx.parameters
            && header.parent == parent
            && header.height == height
            && header.state == root,
        "ANCESTRY_INDEX_HEADER",
    )?;
    Ok(Metadata {
        parent: Some(parent),
        height,
    })
}'''

PQ1_HEADER_PREFIX = r'''fn header_prefix_bytes(pq: bool) -> usize {
    HEADER_BYTES + if pq { 8 } else { 0 }
}'''

PQ1_HEADER_DECODE = r'''fn decode_header_projection(bytes: &[u8], pq: bool) -> Result<Header> {
    if pq {
        ensure(
            bytes.len() == HEADER_BYTES + 8 && bytes.starts_with(wire::PACKET_PREFIX),
            "PQ_HEADER_PROFILE",
        )?;
        Header::decode(&bytes[8..]).map_err(|_| "HEADER_CODEC".into())
    } else {
        Header::decode(bytes).map_err(|_| "HEADER_CODEC".into())
    }
}'''

SETTINGS_SELECTORS = {
    'pq_native_v1': ('is_native_pq_v1', 'pq_native_v1::enabled(&self.app)'),
    'pq_accounts_v2': ('is_native_pq_v2', 'pq::enabled(&self.app) && !pq::quota_v3_enabled(&self.app) && !pq::tasks_v4_enabled(&self.app) && !pq::tasks_v5_enabled(&self.app)'),
    'pq_quota_v3': ('is_native_pq_v3', 'pq::quota_v3_enabled(&self.app)'),
    'pq_tasks_v4': ('is_native_pq_v4', 'pq::tasks_v4_enabled(&self.app)'),
    'pq_tasks_v5': ('is_native_pq_v5', 'pq::tasks_v5_enabled(&self.app)'),
}

EXECUTOR_SELECTORS = {
    'pq_native_v1': {
        'enabled': '''pub fn enabled(cfg: &Config) -> bool {
            cfg.native_pq.is_some() || cfg.params.get("native_pq_profile").is_some()
        }''',
    },
    'pq_accounts_v2': {
        'enabled': '''pub fn enabled(cfg: &Config) -> bool {
            cfg.native_pq_v2.is_some() || cfg.params.get(SELECTOR).is_some()
        }''',
        'quota_v3_enabled': '''pub fn quota_v3_enabled(cfg: &Config) -> bool {
            cfg.native_pq_v2.as_ref().is_some_and(|p| p.wire_profile == wire::AccountProfile::QuotaV3)
        }''',
        'tasks_v4_enabled': '''pub fn tasks_v4_enabled(cfg: &Config) -> bool {
            cfg.native_pq_v2.as_ref().is_some_and(|p| p.wire_profile == wire::AccountProfile::TasksV4)
        }''',
        'tasks_v5_enabled': '''pub fn tasks_v5_enabled(cfg: &Config) -> bool {
            cfg.native_pq_v2.as_ref().is_some_and(|p| p.wire_profile == wire::AccountProfile::TasksV5)
        }''',
    },
}

def exact(actual, expected, message):
    if tokens(actual) != tokens(expected):
        raise ValueError(message)


def opening_prefix_end(text, code, unpack_end, group_end, require):
    end = unpack_end
    for _ in range(2):
        start = re.match(r'\s*ensure\s*\(', code[end:])
        require(start is not None, 'durable PQ opening guard')
        close = group_end(code, end + start.end() - 1)
        require(close is not None, 'durable PQ opening guard')
        tail = re.match(r'\s*\?\s*;', code[close:])
        require(tail is not None, 'durable PQ opening guard propagation')
        end = close + tail.end()
    exact(text[:end], OPENING_PREFIX, 'durable PQ opening guard')
    return end


def verify_packet_contract(root, source, node, *, safe, body, header, item_prefix, require):
    """Recognize the Legacy arm only; never return a PQ schema or packet kind."""
    folder = 'trillionnium/crates/trnm-pon-node/src/'
    lib = safe(root, folder + 'lib.rs').read_text()
    for name, expected in [('native_packet', 'mod native_packet'),
                           ('pq_native_v1', 'pub mod pq_native_v1'),
                           ('pq_accounts_v2', 'pub mod pq_accounts_v2'),
                           ('pq_quota_v3', 'pub mod pq_quota_v3'),
                           ('pq_tasks_v4', 'pub mod pq_tasks_v4'),
                           ('pq_tasks_v5', 'pub mod pq_tasks_v5')]:
        exact(item_prefix(lib, 'mod', name, ';'), expected, 'durable PQ packet module owner')
    packet = safe(root, folder + 'native_packet.rs').read_text()
    exact(packet, PACKET_SOURCE, 'durable PQ packet selection/legacy header contract')
    for module, (method, expected_body) in SETTINGS_SELECTORS.items():
        text = safe(root, folder + module + '.rs').read_text()
        expected_import = ('use trnm_mvcc_fee::pon_executor::pq_native_v1' if module == 'pq_native_v1'
                           else 'use trnm_mvcc_fee::pon_executor::pq_accounts_v2 as pq')
        exact(item_prefix(text, 'use', 'trnm_mvcc_fee', ';'),expected_import,
              'durable PQ selector provider owner')
        exact(item_prefix(text, 'impl', 'Settings', '{'), 'impl Settings',
              'durable PQ settings selector owner')
        settings = body(text, 'impl', 'Settings')
        exact(item_prefix(settings, 'fn', method, '{'),
              'pub(crate) fn ' + method + '(&self) -> bool',
              'durable PQ settings selector owner')
        exact(body(settings, 'fn', method), expected_body, 'durable PQ settings selector')
    for module, methods in EXECUTOR_SELECTORS.items():
        text = safe(root, 'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/' + module + '.rs').read_text()
        for method, expected in methods.items():
            actual = item_prefix(text, 'fn', method, '{') + '{' + body(text, 'fn', method) + '}'
            exact(actual, expected, 'durable PQ executor selector')
        if module == 'pq_accounts_v2':
            # The selector literal is a direct immutable item, not a cfg/path
            # decoy or an unconstrained imported value.
            prefix = item_prefix(text, 'const', 'SELECTOR', ';')
            exact(prefix, 'const SELECTOR: &str = "native_pq_accounts_profile"',
                  'durable PQ executor selector literal')
    pq1 = safe(root, folder + 'pq_native_v1.rs').read_text()
    for name, expected in [('header_prefix_bytes', PQ1_HEADER_PREFIX),
                           ('decode_header_projection', PQ1_HEADER_DECODE)]:
        declaration = header(pq1, name)
        exact(item_prefix(pq1, 'fn', name, '{'), 'pub(crate) ' + declaration,
              'durable PQ legacy header owner')
        exact(declaration + '{' + body(pq1, 'fn', name) + '}', expected,
              'durable PQ original legacy header')
    exact(header(node, 'ancestry_context'),
          'fn ancestry_context(&self) -> crate::ancestry_index::Context',
          'durable PQ ancestry context owner')
    exact(body(node, 'fn', 'ancestry_context'), ANCESTRY_CONTEXT,
          'durable PQ ancestry context selection')
    ancestry = safe(root, folder + 'ancestry_index.rs').read_text()
    for name, expected in [('read_header', ANCESTRY_READ_HEADER), ('metadata', ANCESTRY_METADATA)]:
        declaration = header(ancestry, name)
        exact(item_prefix(ancestry, 'fn', name, '{'), declaration,
              'durable PQ ancestry header owner')
        exact(declaration + '{' + body(ancestry, 'fn', name) + '}', expected,
              'durable PQ ancestry header selection')
