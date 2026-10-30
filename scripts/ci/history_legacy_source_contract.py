"""Closed History V6 join for the original legacy evidence reader.

These fixed contracts describe the explicit owner join in 39b2d4cbc4f34d549c21fd1e4cefd54ba146462f.
They are not learned from the source under inspection. Recognizing this join
does not validate History effects, startup accounting or a History database.
The result of the caller remains only the original Legacy schema.
"""
import re

import pq_legacy_source_contract as pq_contract


# Extend only the two reviewed arms of the unchanged closed NPQ selector.
# A change to that fixed contract must be reviewed here too, not silently ignored.
_DDL_ARM = 'Self::PermanentAccountGrowthV2 => format!("{}{}", ddl(), growth::DDL),'
_DOMAIN_ARM = 'Self::PermanentAccountGrowthV2 => b"native-permanent-account-growth-schema-v2",'
assert pq_contract.BACKEND_IMPLEMENTATION.count(_DDL_ARM) == 1
assert pq_contract.BACKEND_IMPLEMENTATION.count(_DOMAIN_ARM) == 1
BACKEND_IMPLEMENTATION = pq_contract.BACKEND_IMPLEMENTATION.replace(
    _DDL_ARM, _DDL_ARM + '\nSelf::HistoryEffectV6 => format!("{}{}", ddl(), history_effect_v6::DDL),', 1
).replace(
    _DOMAIN_ARM, _DOMAIN_ARM + '\nSelf::HistoryEffectV6 => b"native-history-effect-schema-v6",', 1
)

OWNERS = r'''struct NativeOwners<'a> {
    policy: Option<OwnerPolicy>,
    mining: Option<operator_mining_owner::MiningOwner>,
    continuous: Option<operator_continuous_owner::ContinuousOwner>,
    history_effect: Option<history_effect_v6::Owner>,
    startup_material: Option<history_effect_v6::StartupMaterial<'a>>,
}'''

STARTUP_MATERIAL = r'''pub(super) struct StartupMaterial<'a> {
    pub(super) seal: crate::operator_checkpoint_tile::StartupMaterialSeal,
    pub(super) progress: &'a dyn Fn(StartupProgress) -> Result<()>,
}'''

DDL = 'CREATE TABLE history_effect_v6(operation TEXT PRIMARY KEY NOT NULL CHECK(length(operation)=64),intent BLOB UNIQUE NOT NULL CHECK(length(intent)=32),marker BLOB NOT NULL CHECK(length(marker)>0 AND length(marker)<=16384));'

# The complete next prefix after the two original PQ guards. In particular the
# backend/owner equivalence and consumed startup seal cannot be skipped, nested,
# reordered or supplied by an unrelated same-spelled scope.
OPENING_PREFIX = r'''
    if let Some(io) = &native_io {
        io.check().map_err(|e| Error::from(e.to_string()))?;
        ensure(path == io.directory(), "NATIVE_IO_HELD_ROOT")?;
    }
    ensure(!authenticated_migration_pending(path)?, "NATIVE_STATE_MIGRATION_PENDING",)?;
    ensure(
        settings.is_permanent_account_growth_v2()
            == (state_backend == StateBackend::PermanentAccountGrowthV2),
        "GROWTH_PROFILE_BACKEND",
    )?;
    if growth_observation_only {
        ensure(
            state_backend == StateBackend::PermanentAccountGrowthV2
                && path.join("native.sqlite").is_file(),
            "GROWTH_PACKET_STATUS_EXISTING_STORE_REQUIRED",
        )?;
    }
    let NativeOwners {
        policy: owner_policy,
        mining: mining_owner,
        continuous: continuous_owner,
        history_effect: history_effect_owner,
        startup_material,
    } = owners;
    if growth_profile_v2::enabled(&settings.app) {
        ensure(state_backend == StateBackend::Legacy, "GROWTH_REFERENCE_BACKEND",)?;
        ensure(
            owner_policy.is_none() && mining_owner.is_none()
                && continuous_owner.is_none() && history_effect_owner.is_none(),
            "GROWTH_REFERENCE_OWNER",
        )?;
    }
    ensure(
        usize::from(owner_policy.is_some()) + usize::from(mining_owner.is_some())
            + usize::from(continuous_owner.is_some()) + usize::from(history_effect_owner.is_some())
            <= 1,
        "OWNER_MODE_AMBIGUOUS",
    )?;
    let required_owner_marker = owner_policy.as_ref().map(|p| p.required_marker.as_slice())
        .or_else(|| mining_owner.as_ref().map(|p| p.marker.as_slice()))
        .or_else(|| continuous_owner.as_ref().map(|p| p.marker.as_slice()))
        .or_else(|| history_effect_owner.as_ref().map(|p| p.marker.as_slice()));
    ensure(
        (state_backend == StateBackend::HistoryEffectV6) == history_effect_owner.is_some(),
        "HISTORY_V6_OWNER_REQUIRED",
    )?;
    if let Some(owner) = &history_effect_owner { owner.checkpoint()?; }
    ensure([1, 2, 4, 8].contains(&workers), "WORKERS")?;
    let startup_progress = startup_material.as_ref().map(|material| material.progress);
    if let Some(material) = startup_material {
        let history_owner = history_effect_owner.as_ref().ok_or("HISTORY_V6_OWNER_REQUIRED")?;
        history_owner.consume_startup_material(material.seal, &settings, material.progress)?;
    } else {
        ensure(history_effect_owner.is_none(), "HISTORY_V6_STARTUP_SEAL_REQUIRED",)?;
        settings.replay_checkpoint_tile_material()?;
    }
    let history_owner = history_effect_owner.clone();
    let startup_check = |stage| -> Result<()> {
        if let Some(owner) = &history_owner { owner.checkpoint()?; }
        if let Some(progress) = startup_progress { progress(stage)?; }
        if let Some(owner) = &history_owner { owner.checkpoint()?; }
        Ok(())
    };
'''


def struct_contract(text, name, expected, *, masked, direct, item_prefix, group_end, require):
    """One direct declaration, including its exact lifetime and visibility."""
    code = masked(text)
    matches = [m for m in re.finditer(r'\bstruct\s+' + name + r'\b', code)
               if direct(code, m.start())]
    require(len(matches) == 1, 'durable History owner declaration ' + name)
    start = code.find('{', matches[0].end())
    require(start >= 0, 'durable History owner declaration ' + name)
    end = group_end(code, start)
    require(end is not None, 'durable History owner declaration ' + name)
    declaration = item_prefix(text, 'struct', name, '{') + text[start:end]
    pq_contract.exact(declaration, expected, 'durable History owner declaration ' + name)


def opening_prefix_end(text, code, pq_end, *, direct, group_end, require):
    matches = [m for m in re.finditer(r'\blet\s+startup_check\s*=', code)
               if direct(code, m.start())]
    require(len(matches) == 1, 'durable History opening owner contract')
    start = code.find('{', matches[0].end())
    require(start >= 0, 'durable History opening owner contract')
    end = group_end(code, start)
    require(end is not None, 'durable History opening owner contract')
    tail = re.match(r'\s*;', code[end:])
    require(tail is not None, 'durable History opening owner contract')
    end += tail.end()
    pq_contract.exact(text[pq_end:end], OPENING_PREFIX, 'durable History opening owner contract')
    remaining = code[end:]
    names = (r'\b(?:owners|owner_policy|mining_owner|continuous_owner|history_effect_owner|'
             r'startup_material|startup_progress|history_owner|startup_check|required_owner_marker)\b')
    places = names + r'(?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])*'
    require(not re.search(r'\blet\s+[^;=]*' + names + r'[^;=]*=', remaining)
            and not re.search(places + r'\s*[+*/%&|^\-]?=(?!=)', remaining)
            and not re.search(r'&\s*mut\s*\(*\s*' + names, remaining),
            'durable History opening owner rebound')
    return end
