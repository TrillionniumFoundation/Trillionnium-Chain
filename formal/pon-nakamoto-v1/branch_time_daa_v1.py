"""Versioned, branch-derived time/DAA reference; never native block admission.

The temporal records below are a NEW research namespace, not PNH1/PGH2 packets.
Their hashes bind only this module's declared fields. No W1 proof, signature,
transaction, chain selection, durable database or trusted wall clock is supplied
by this component. The existing production owners and their rules are unchanged.

An immutable schedule selects either the retained periodic rule or integer ASERT
at an explicitly committed height. Each ASERT epoch derives its anchor from the
selected parent's own ancestry. Warm cache inputs and persisted anchor claims are
checked against that derivation; neither is an authority. Replay uses archived
clock inputs, and current-clock eligibility is a separate, mandatory owner hook.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re


SCHEMA = "trnm-branch-time-daa-reference-v1"
ASERT_ALGORITHM = "aserti3-raw-u256-monotone-v1"
U64_MAX = (1 << 64) - 1
U256_MAX = (1 << 256) - 1
MAX_UPGRADES = 16
MAX_RECORDS = 32768
MAX_SNAPSHOT_BYTES = 32 << 20
ZERO_ID = "0" * 64
_HEX256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_DECIMAL64 = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z", re.ASCII)


class DaaError(ValueError):
    """A bounded-input or deterministic temporal-rule refusal."""


class TimeDeferred(DaaError):
    """This observer's supplied clock is too early; no state is appended."""


def _uint(value: int, name: str, maximum: int = U64_MAX) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise DaaError(name + "_RANGE")
    return value


def _positive(value: int, name: str, maximum: int = U64_MAX) -> int:
    _uint(value, name, maximum)
    if value == 0:
        raise DaaError(name + "_ZERO")
    return value


def _id(value: str, name: str) -> str:
    if type(value) is not str or _HEX256.fullmatch(value) is None:
        raise DaaError(name + "_ENCODING")
    return value


def _u64(value: int) -> bytes:
    return _uint(value, "U64").to_bytes(8, "little")


def _u256(value: int) -> bytes:
    return _uint(value, "U256", U256_MAX).to_bytes(32, "big")


def _hash(domain: bytes, *parts: bytes) -> str:
    return hashlib.sha256(domain + b"".join(parts)).hexdigest()


def _keys(value: object, expected: set[str], name: str) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise DaaError(name + "_FIELDS")
    return value


def _decimal64(value: str, name: str) -> int:
    if type(value) is not str or _DECIMAL64.fullmatch(value) is None:
        raise DaaError(name + "_ENCODING")
    return _uint(int(value), name)


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DaaError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def snapshot_id(snapshot: bytes) -> str:
    """Identity to retain outside the snapshot before permitting cold replay."""
    if type(snapshot) is not bytes or not 0 < len(snapshot) <= MAX_SNAPSHOT_BYTES:
        raise DaaError("SNAPSHOT_BYTE_BUDGET")
    return _hash(b"TRNM-BRANCH-TIME-SNAPSHOT1\0", snapshot)


def trunc_div(numerator: int, denominator: int) -> int:
    """Signed division toward zero, without any floating-point conversion."""
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise DaaError("SIGNED_DIVISION_INPUT")
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def asert_target(anchor_target: int, time_delta: int, intervals: int,
                 spacing: int, half_life: int, pow_limit: int) -> int:
    """Integer ASERT on RAW u256 targets, with the specified signed rounding.

    intervals = evaluation_parent.height - anchor.height + 1.
    time_delta = evaluation_parent.time - anchor.parent.time.

    Polynomial coefficients follow the BCHN ASERT specification. This function
    does not import quantum_daa_model or BCHN code. Compact nBits conversion and
    BCH's testnet reset are deliberately absent from this new candidate profile.
    """
    _positive(pow_limit, "POW_LIMIT", U256_MAX)
    _positive(anchor_target, "ANCHOR_TARGET", pow_limit)
    _positive(intervals, "INTERVALS")
    _positive(spacing, "SPACING")
    _positive(half_life, "HALF_LIFE")
    if type(time_delta) is not int or not -U64_MAX <= time_delta <= U64_MAX:
        raise DaaError("TIME_DELTA_RANGE")
    scaled_error = (time_delta - spacing * intervals) * 65536
    if not -(1 << 127) <= scaled_error < (1 << 127):
        raise DaaError("ASERT_I128_RANGE")
    exponent = trunc_div(scaled_error, half_life)
    shifts = exponent >> 16
    fraction = exponent - shifts * 65536
    factor = 65536 + ((195766423245049 * fraction
                       + 971821376 * fraction**2
                       + 5127 * fraction**3 + (1 << 47)) >> 48)
    # These thresholds avoid constructing a huge shifted Python integer. They
    # have the same clamped result for every permitted positive u256 target.
    if shifts >= 256:
        return pow_limit
    if shifts <= -512:
        return 1
    scaled_target = anchor_target * factor
    if shifts < 0:
        scaled_target >>= -shifts
    else:
        scaled_target <<= shifts
    return max(1, min(pow_limit, scaled_target >> 16))


@dataclass(frozen=True)
class LegacyParameters:
    interval: int
    spacing: int
    future_skew: int

    def __post_init__(self) -> None:
        _positive(self.interval, "LEGACY_INTERVAL")
        _positive(self.spacing, "LEGACY_SPACING")
        _uint(self.future_skew, "LEGACY_FUTURE_SKEW")
        if self.interval < 16 or (self.interval - 1) * self.spacing * 4 > U64_MAX:
            raise DaaError("LEGACY_PARAMETERS")

    def encoding(self) -> bytes:
        return _u64(self.interval) + _u64(self.spacing) + _u64(self.future_skew)


@dataclass(frozen=True)
class Upgrade:
    first_height: int
    spacing: int
    half_life: int
    future_skew: int
    algorithm: str = ASERT_ALGORITHM

    def __post_init__(self) -> None:
        _uint(self.first_height, "UPGRADE_HEIGHT")
        _positive(self.spacing, "UPGRADE_SPACING")
        _positive(self.half_life, "UPGRADE_HALF_LIFE")
        _uint(self.future_skew, "UPGRADE_FUTURE_SKEW")
        if self.first_height < 2:
            raise DaaError("ANCHOR_PARENT_REQUIRED")
        if type(self.algorithm) is not str or self.algorithm != ASERT_ALGORITHM:
            raise DaaError("UNSUPPORTED_DAA_ALGORITHM")

    def encoding(self) -> bytes:
        return (b"ASR1" + _u64(self.first_height) + _u64(self.spacing)
                + _u64(self.half_life) + _u64(self.future_skew))


@dataclass(frozen=True)
class Schedule:
    """A precommitted experiment schedule, not a governance authorization."""
    network_id: str
    genesis_timestamp: int
    genesis_target: int
    pow_limit: int
    legacy: LegacyParameters
    upgrades: tuple[Upgrade, ...]

    def __post_init__(self) -> None:
        _id(self.network_id, "NETWORK_ID")
        _uint(self.genesis_timestamp, "GENESIS_TIME")
        _positive(self.pow_limit, "POW_LIMIT", U256_MAX)
        _positive(self.genesis_target, "GENESIS_TARGET", self.pow_limit)
        if type(self.legacy) is not LegacyParameters:
            raise DaaError("LEGACY_PARAMETERS_TYPE")
        if type(self.upgrades) is not tuple or len(self.upgrades) > MAX_UPGRADES:
            raise DaaError("UPGRADE_SCHEDULE_BOUNDS")
        previous = 1
        for upgrade in self.upgrades:
            if type(upgrade) is not Upgrade or upgrade.first_height <= previous:
                raise DaaError("UPGRADE_SCHEDULE_ORDER")
            previous = upgrade.first_height

    @property
    def commitment(self) -> str:
        return _hash(b"TRNM-BRANCH-TIME-SCHEDULE1\0",
                     bytes.fromhex(self.network_id), _u64(self.genesis_timestamp),
                     _u256(self.genesis_target), _u256(self.pow_limit),
                     self.legacy.encoding(), len(self.upgrades).to_bytes(2, "little"),
                     *(upgrade.encoding() for upgrade in self.upgrades))

    def epoch(self, height: int) -> int:
        _uint(height, "HEIGHT")
        return sum(upgrade.first_height <= height for upgrade in self.upgrades)

    def rule_id(self, height: int) -> str:
        return _hash(b"TRNM-BRANCH-TIME-RULE1\0",
                     bytes.fromhex(self.commitment), self.epoch(height).to_bytes(2, "little"))

    def future_skew(self, height: int) -> int:
        index = self.epoch(height)
        return (self.legacy.future_skew if index == 0
                else self.upgrades[index - 1].future_skew)


@dataclass(frozen=True)
class TemporalHeader:
    """A committed arithmetic record, NOT a native or work-verified block."""
    schedule_id: str
    rule_id: str
    parent_id: str
    height: int
    timestamp: int
    target: int
    body_id: str

    def __post_init__(self) -> None:
        for value, name in ((self.schedule_id, "SCHEDULE_ID"), (self.rule_id, "RULE_ID"),
                            (self.parent_id, "PARENT_ID"), (self.body_id, "BODY_ID")):
            _id(value, name)
        _uint(self.height, "HEIGHT")
        _uint(self.timestamp, "TIMESTAMP")
        _positive(self.target, "TARGET", U256_MAX)

    @property
    def record_id(self) -> str:
        return _hash(b"TRNM-BRANCH-TIME-HEADER1\0", bytes.fromhex(self.schedule_id),
                     bytes.fromhex(self.rule_id), bytes.fromhex(self.parent_id),
                     _u64(self.height), _u64(self.timestamp), _u256(self.target),
                     bytes.fromhex(self.body_id))

    def fields(self) -> dict:
        return {"schedule_id": self.schedule_id, "rule_id": self.rule_id,
                "parent_id": self.parent_id, "height": str(self.height),
                "timestamp": str(self.timestamp), "target_hex": f"{self.target:064x}",
                "body_id": self.body_id, "record_id": self.record_id}


@dataclass(frozen=True)
class BranchAnchor:
    schedule_id: str
    rule_id: str
    activation_height: int
    anchor_id: str
    anchor_height: int
    anchor_timestamp: int
    anchor_target: int
    anchor_parent_id: str
    anchor_parent_timestamp: int

    def __post_init__(self) -> None:
        for value, name in ((self.schedule_id, "SCHEDULE_ID"), (self.rule_id, "RULE_ID"),
                            (self.anchor_id, "ANCHOR_ID"),
                            (self.anchor_parent_id, "ANCHOR_PARENT_ID")):
            _id(value, name)
        for value, name in ((self.activation_height, "ACTIVATION_HEIGHT"),
                            (self.anchor_height, "ANCHOR_HEIGHT"),
                            (self.anchor_timestamp, "ANCHOR_TIME"),
                            (self.anchor_parent_timestamp, "ANCHOR_PARENT_TIME")):
            _uint(value, name)
        _positive(self.anchor_target, "ANCHOR_TARGET", U256_MAX)
        if self.activation_height < 2 or self.anchor_height != self.activation_height - 1:
            raise DaaError("ANCHOR_HEIGHT_BINDING")

    @property
    def commitment(self) -> str:
        return _hash(b"TRNM-BRANCH-TIME-ANCHOR1\0", bytes.fromhex(self.schedule_id),
                     bytes.fromhex(self.rule_id), _u64(self.activation_height),
                     bytes.fromhex(self.anchor_id), _u64(self.anchor_height),
                     _u64(self.anchor_timestamp), _u256(self.anchor_target),
                     bytes.fromhex(self.anchor_parent_id), _u64(self.anchor_parent_timestamp))


@dataclass(frozen=True)
class Requirement:
    schedule_id: str
    rule_id: str
    next_height: int
    target: int
    minimum_timestamp: int
    future_skew: int
    anchor: BranchAnchor | None

    @property
    def required_work(self) -> int:
        # This is only the retained arithmetic convention, never an award.
        return (1 << 256) // (self.target + 1)


@dataclass(frozen=True)
class TemporalReceipt:
    record_id: str
    rule_id: str
    anchor_commitment: str | None
    required_work: int


class BranchTimeDaa:
    """Bounded branch graph for reference replay; no fork-choice authority."""

    def __init__(self, schedule: Schedule):
        if type(schedule) is not Schedule:
            raise DaaError("SCHEDULE_TYPE")
        self.schedule = schedule
        genesis = TemporalHeader(schedule.commitment, schedule.rule_id(0), ZERO_ID,
                                 0, schedule.genesis_timestamp,
                                 schedule.genesis_target, schedule.network_id)
        self.genesis_id = genesis.record_id
        self._headers = {self.genesis_id: genesis}
        self._observed: dict[str, int] = {}
        self._receipts: dict[str, TemporalReceipt] = {}

    def header(self, record_id: str) -> TemporalHeader:
        _id(record_id, "RECORD_ID")
        try:
            return self._headers[record_id]
        except KeyError as exc:
            raise DaaError("UNKNOWN_PARENT") from exc

    def ancestry(self, record_id: str) -> tuple[TemporalHeader, ...]:
        """Parent-first, terminating at the schedule's exact genesis record."""
        current = self.header(record_id)
        result = [current]
        while current.height:
            parent = self.header(current.parent_id)
            if parent.height != current.height - 1:
                raise DaaError("ANCESTRY_HEIGHT")
            result.append(parent)
            if len(result) > MAX_RECORDS:
                raise DaaError("ANCESTRY_BUDGET")
            current = parent
        if current.record_id != self.genesis_id:
            raise DaaError("GENESIS_IDENTITY")
        return tuple(result)

    def requirement(self, parent_id: str,
                    cached_anchor: BranchAnchor | None = None) -> Requirement:
        history = self.ancestry(parent_id)
        parent = history[0]
        if parent.height == U64_MAX:
            raise DaaError("HEIGHT_OVERFLOW")
        height = parent.height + 1
        epoch = self.schedule.epoch(height)
        rule_id = self.schedule.rule_id(height)
        median = sorted(header.timestamp for header in history[:11])[min(11, len(history)) // 2]
        minimum = median + 1
        anchor = None
        if epoch == 0:
            if cached_anchor is not None:
                raise DaaError("LEGACY_HAS_NO_ASERT_ANCHOR")
            parameters = self.schedule.legacy
            target = parent.target
            if height % parameters.interval == 0:
                if len(history) < parameters.interval:
                    raise DaaError("UNKNOWN_RETARGET_ANCESTOR")
                first = history[parameters.interval - 1].timestamp
                desired = (parameters.interval - 1) * parameters.spacing
                span = min(4 * desired, max((desired + 3) // 4,
                                           max(1, parent.timestamp - first)))
                target = max(1, min(self.schedule.pow_limit, parent.target * span // desired))
        else:
            parameters = self.schedule.upgrades[epoch - 1]
            anchor_height = parameters.first_height - 1
            offset = parent.height - anchor_height
            if not 0 <= offset < len(history) - 1:
                raise DaaError("UNKNOWN_ANCHOR_ANCESTRY")
            ancestor, ancestor_parent = history[offset:offset + 2]
            anchor = BranchAnchor(self.schedule.commitment, rule_id,
                                  parameters.first_height, ancestor.record_id,
                                  ancestor.height, ancestor.timestamp, ancestor.target,
                                  ancestor_parent.record_id, ancestor_parent.timestamp)
            if cached_anchor is not None:
                if type(cached_anchor) is not BranchAnchor or cached_anchor != anchor:
                    raise DaaError("ANCHOR_CACHE_MISMATCH")
            target = asert_target(anchor.anchor_target,
                                  parent.timestamp - anchor.anchor_parent_timestamp,
                                  parent.height - anchor.anchor_height + 1,
                                  parameters.spacing, parameters.half_life,
                                  self.schedule.pow_limit)
            minimum = max(minimum, parent.timestamp)
        if minimum > U64_MAX:
            raise DaaError("TIME_RANGE_EXHAUSTED")
        return Requirement(self.schedule.commitment, rule_id, height, target,
                           minimum, parameters.future_skew, anchor)

    def candidate(self, parent_id: str, timestamp: int, body_id: str) -> TemporalHeader:
        """Construct fields only; this can construct a time-invalid candidate."""
        required = self.requirement(parent_id)
        return TemporalHeader(required.schedule_id, required.rule_id, parent_id,
                              required.next_height, timestamp, required.target, body_id)

    def append(self, candidate: TemporalHeader, observed_now: int,
               cached_anchor: BranchAnchor | None = None) -> TemporalReceipt:
        """Check temporal fields, then atomically append one reference record."""
        if type(candidate) is not TemporalHeader:
            raise DaaError("TEMPORAL_HEADER_TYPE")
        _uint(observed_now, "OBSERVED_NOW")
        if candidate.schedule_id != self.schedule.commitment:
            raise DaaError("SCHEDULE_IDENTITY")
        parent = self.header(candidate.parent_id)
        required = self.requirement(candidate.parent_id, cached_anchor)
        if candidate.height != required.next_height:
            raise DaaError("HEIGHT_BINDING")
        if candidate.rule_id != required.rule_id:
            raise DaaError("RULE_IDENTITY")
        if candidate.target != required.target:
            raise DaaError("REQUIRED_TARGET")
        if required.anchor is not None and candidate.timestamp < parent.timestamp:
            raise DaaError("TIME_NONDECREASING")
        if candidate.timestamp < required.minimum_timestamp:
            raise DaaError("TIME_MTP")
        if candidate.timestamp > observed_now + required.future_skew:
            raise TimeDeferred("TIME_DEFERRED")
        record_id = candidate.record_id
        if record_id in self._headers:
            # Duplicate transport is not another record or another credit.
            return self._receipts[record_id]
        if len(self._headers) >= MAX_RECORDS:
            raise DaaError("RECORD_BUDGET")
        receipt = TemporalReceipt(record_id, required.rule_id,
                                  None if required.anchor is None else required.anchor.commitment,
                                  required.required_work)
        self._headers[record_id] = candidate
        self._observed[record_id] = observed_now
        self._receipts[record_id] = receipt
        return receipt

    def check_activation_clock(self, tip_id: str, observed_now: int) -> None:
        """Identical explicit clock hook for warm use and restored use.

        Successful replay does not activate a tip. The native owner must also
        perform this check with its current clock before considering a branch,
        plus all native work, authorization, admission and fork-choice checks.
        """
        _uint(observed_now, "OBSERVED_NOW")
        for header in self.ancestry(tip_id):
            if header.timestamp > observed_now + self.schedule.future_skew(header.height):
                raise TimeDeferred("ACTIVATION_TIME_DEFERRED")

    def snapshot(self) -> bytes:
        records = []
        for record_id, observed in self._observed.items():
            fields = self._headers[record_id].fields()
            fields.update(observed_now=str(observed),
                          anchor_commitment=self._receipts[record_id].anchor_commitment)
            records.append(fields)
        result = _canonical({"schema": SCHEMA, "schedule_id": self.schedule.commitment,
                             "genesis_id": self.genesis_id, "records": records})
        if len(result) > MAX_SNAPSHOT_BYTES:
            raise DaaError("SNAPSHOT_BYTE_BUDGET")
        return result

    @classmethod
    def restore(cls, snapshot: bytes, schedule: Schedule,
                expected_snapshot_id: str) -> BranchTimeDaa:
        """Replay canonical records under an independently supplied schedule.

        expected_snapshot_id MUST come from the caller's independently retained
        recovery identity, never from the snapshot being restored. This module
        cannot establish that caller's custody or prevent rollback of that
        external identity. Archived clocks are untrusted experiment inputs.
        A restored view has no active tip and creates no effects.
        """
        if type(snapshot) is not bytes or not 0 < len(snapshot) <= MAX_SNAPSHOT_BYTES:
            raise DaaError("SNAPSHOT_BYTE_BUDGET")
        _id(expected_snapshot_id, "EXPECTED_SNAPSHOT_ID")
        if snapshot_id(snapshot) != expected_snapshot_id:
            raise DaaError("RECOVERY_IDENTITY_MISMATCH")
        try:
            value = json.loads(snapshot.decode("ascii"), object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise DaaError("SNAPSHOT_ENCODING") from exc
        value = _keys(value, {"schema", "schedule_id", "genesis_id", "records"}, "SNAPSHOT")
        if value["schema"] != SCHEMA or type(value["schema"]) is not str:
            raise DaaError("SNAPSHOT_SCHEMA")
        if _canonical(value) != snapshot:
            raise DaaError("SNAPSHOT_NONCANONICAL")
        replay = cls(schedule)
        if value["schedule_id"] != schedule.commitment or value["genesis_id"] != replay.genesis_id:
            raise DaaError("SNAPSHOT_SCHEDULE_BINDING")
        records = value["records"]
        if type(records) is not list or len(records) >= MAX_RECORDS:
            raise DaaError("SNAPSHOT_RECORD_BUDGET")
        for row in records:
            row = _keys(row, {"schedule_id", "rule_id", "parent_id", "height", "timestamp",
                              "target_hex", "body_id", "record_id", "observed_now",
                              "anchor_commitment"}, "RECORD")
            _id(row["target_hex"], "TARGET_HEX")
            header = TemporalHeader(row["schedule_id"], row["rule_id"], row["parent_id"],
                                    _decimal64(row["height"], "HEIGHT"),
                                    _decimal64(row["timestamp"], "TIMESTAMP"),
                                    int(row["target_hex"], 16), row["body_id"])
            if type(row["record_id"]) is not str or row["record_id"] != header.record_id:
                raise DaaError("RECORD_COMMITMENT")
            if header.record_id in replay._headers:
                raise DaaError("DUPLICATE_RECORD")
            if row["anchor_commitment"] is not None:
                _id(row["anchor_commitment"], "ANCHOR_COMMITMENT")
            receipt = replay.append(header, _decimal64(row["observed_now"], "OBSERVED_NOW"))
            if receipt.anchor_commitment != row["anchor_commitment"]:
                raise DaaError("PERSISTED_ANCHOR_MISMATCH")
        return replay


def qualification() -> dict:
    return {"schema": SCHEMA,
            "scope": "versioned_temporal_reference_and_deterministic_branch_replay",
            "native_admission_executed": False,
            "complete_work_relation_verified": False,
            "native_database_recovery_executed": False,
            "independent_recovery_anchor_established": False,
            "trusted_clock_established": False,
            "mixed_consensus_security_proved": False,
            "production_activation": False}
