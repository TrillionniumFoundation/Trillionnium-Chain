"""Five-lane funding/resource planner; no issuance, proof verifier or payment adapter.

Funding/evaluation/capacity facts are independently verified owner inputs. This
reference checks their finite accounting consequences, not their authenticity.
Branch checkpoints exclude the monotonic external-intent journal. All identifiers
belong to this fresh reference namespace, never historical ledger storage.
"""
import copy
from dataclasses import dataclass, field

from contract_wire import H, read_config

LANES = {
    'mining': ('verified_work_units', 'cpu_ns'),
    'contribution': ('training_cpu_ns', 'parameter_bytes'),
    'evaluation': ('evaluation_cpu_ns', 'evaluated_examples'),
    'storage': ('retained_byte_blocks', 'repair_bytes'),
    'serving': ('inference_cpu_ns', 'output_tokens'),
}
U64_MAX = (1 << 64) - 1


def require(condition, code):
    if not condition:
        raise ValueError(code)


def units(value):
    require(type(value) is int and 0 <= value <= U64_MAX, 'BUDGET_UNITS')
    return value


def identity(value):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), 'BUDGET_IDENTITY')
    return value


def resources(lane, values):
    require(lane in LANES and type(values) is dict and
            set(values) == set(LANES[lane]), 'BUDGET_RESOURCE_KIND')
    return {key: units(value) for key, value in values.items()}


def mining_reward_limit(height, fees):
    """Mirror the existing development subsidy schedule; does not mint it."""
    units(height); units(fees)
    policy = read_config('config/pon/devnet-v1.json')
    halvings = min(height // policy['subsidy_halving_interval'], 64)
    return units((policy['block_subsidy_units'] >> halvings) + fees)


@dataclass
class Funding:
    lane: str
    total: int
    available: int
    maturity: int


@dataclass
class Budget:
    source: str
    lane: str
    cap: int
    maturity: int
    deadline: int
    resource_cap: dict
    paid: int = 0
    refunded: int = 0
    closed: bool = False


@dataclass
class Claim:
    budget: str
    subject: str
    beneficiary: str
    amount: int
    reserved: dict
    contribution_root: str | None
    status: str = 'reserved'
    paid: int = 0


@dataclass
class Branch:
    funding: dict = field(default_factory=dict)
    budgets: dict = field(default_factory=dict)
    claims: dict = field(default_factory=dict)
    subjects: set = field(default_factory=set)


@dataclass(frozen=True)
class ExternalIntent:
    operation: str
    lane: str
    subject: str
    claim: str
    budget: str
    beneficiary: str
    effect: str
    paid: int


class RewardBudgetPlanner:
    """Finite reference accounting conditional on authenticated owner inputs."""

    def __init__(self, *, context, contribution_root_caps, max_records):
        self.context = identity(context)
        self.root_caps = {identity(key): units(value)
                          for key, value in contribution_root_caps.items()}
        source_cap = read_config('config/pon/model-evidence-v3.json')['max_reserved_units_per_source_round']
        require(all(cap <= source_cap for cap in self.root_caps.values()),
                'BUDGET_SOURCE_ROUND_CAP')
        require(type(max_records) is int and 1 <= max_records <= 65536,
                'BUDGET_RECORD_LIMIT')
        self.max_records = max_records
        require(len(self.root_caps) <= max_records, 'BUDGET_RECORD_LIMIT')
        self.branch = Branch()
        self._checkpoints = {}
        self._effects = {}  # Local facts: never included in a branch checkpoint.
        self._operations = {}
        self._funding_pins = {}
        self._budget_pins = {}
        self._resource_jobs = {}
        self._resource_subjects = {}

    def _capacity(self, rows):
        require(len(rows) < self.max_records, 'BUDGET_RECORD_LIMIT')

    def register_funding(self, *, source, lane, amount, height, fees=None):
        """Register one original native funding fact, not a caller-created credit.

        Non-mining input must denote a distinct owner-debited escrow. Mining
        input denotes one unique block reward and must equal its existing amount.
        Native source/owner verification is deliberately not implemented here.
        """
        identity(source); units(amount); units(height)
        require(lane in LANES and amount > 0, 'BUDGET_FUNDING')
        require(source not in self.branch.funding, 'BUDGET_DUPLICATE_SOURCE')
        self._capacity(self.branch.funding)
        units(sum(row.total for row in self.branch.funding.values()) + amount)
        maturity = height
        if lane == 'mining':
            require(fees is not None and amount == mining_reward_limit(height, fees),
                    'BUDGET_MINING_SOURCE')
            maturity = units(height + read_config('config/pon/devnet-v1.json')['reward_maturity_blocks'])
        else:
            require(fees is None, 'BUDGET_NONMINING_ISSUANCE')
        pin = (lane, amount, maturity)
        if source in self._funding_pins:
            require(self._funding_pins[source] == pin, 'BUDGET_SOURCE_REPLAY_MISMATCH')
        else:
            self._capacity(self._funding_pins)
        self._funding_pins[source] = pin
        self.branch.funding[source] = Funding(lane, amount, amount, maturity)

    def open_budget(self, *, budget, source, lane, cap, maturity, deadline,
                    resource_cap):
        identity(budget); identity(source); units(cap); units(maturity); units(deadline)
        capacity = resources(lane, resource_cap)
        require(budget not in self.branch.budgets, 'BUDGET_DUPLICATE')
        self._capacity(self.branch.budgets)
        funding = self.branch.funding[source]
        require(lane == funding.lane, 'BUDGET_LANE_TRANSFER')
        require(0 < cap <= funding.available and funding.maturity <= maturity < deadline,
                'BUDGET_FUNDING_OR_WINDOW')
        pin = (source, lane, cap, maturity, deadline, capacity)
        if budget in self._budget_pins:
            require(self._budget_pins[budget] == pin, 'BUDGET_POLICY_REPLAY_MISMATCH')
        else:
            self._capacity(self._budget_pins)
        self._budget_pins[budget] = pin
        self.branch.budgets[budget] = Budget(source, lane, cap, maturity, deadline,
                                             capacity)
        funding.available -= cap

    def _pending(self, budget):
        return [row for row in self.branch.claims.values()
                if row.budget == budget and row.status == 'reserved']

    def available(self, budget):
        row = self.branch.budgets[budget]
        return row.cap - row.paid - row.refunded - sum(c.amount for c in self._pending(budget))

    def resource_used(self, budget):
        capacity = self._budget_pins[budget][-1]
        jobs = [job for job in self._resource_jobs.values() if job['budget'] == budget]
        return {key: sum(job['consumed'][key] for job in jobs if job['consumed'] is not None)
                for key in capacity}

    def reserve(self, *, claim, budget, subject, beneficiary, amount, resource_reservation,
                height, contribution_root=None):
        for value in (claim, budget, subject, beneficiary):
            identity(value)
        units(amount); units(height)
        row = self.branch.budgets[budget]
        capacity = resources(row.lane, resource_reservation)
        require(not row.closed and height < row.deadline, 'BUDGET_CLOSED')
        require(claim not in self.branch.claims and (row.lane, subject) not in self.branch.subjects,
                'BUDGET_DUPLICATE_CLAIM')
        self._capacity(self.branch.claims)
        require(0 < amount <= self.available(budget), 'BUDGET_FUNDS')
        physical_key = (row.lane, subject)
        binding = (budget, subject, beneficiary, amount, capacity, contribution_root)
        previous = self._resource_jobs.get(claim)
        if previous is not None:
            require(previous['binding'] == binding, 'BUDGET_RESOURCE_REPLAY_MISMATCH')
        else:
            require(physical_key not in self._resource_subjects, 'BUDGET_RESOURCE_SUBJECT_REPLAY')
            self._capacity(self._resource_jobs)
            jobs = [job for job in self._resource_jobs.values() if job['budget'] == budget]
            require(all(capacity[key] + sum((job['reserved'] if job['consumed'] is None
                        else job['consumed'])[key] for job in jobs) <= row.resource_cap[key]
                        for key in capacity), 'BUDGET_RESOURCES')
        if row.lane == 'contribution':
            identity(contribution_root)
            require(contribution_root in self.root_caps, 'BUDGET_UNKNOWN_ROOT')
            committed = sum(c.amount if c.status == 'reserved' else c.paid
                            for c in self.branch.claims.values()
                            if c.contribution_root == contribution_root)
            require(committed + amount <= self.root_caps[contribution_root], 'BUDGET_ROOT_CAP')
        else:
            require(contribution_root is None, 'BUDGET_UNEXPECTED_ROOT')
        self.branch.claims[claim] = Claim(budget, subject, beneficiary, amount,
                                          capacity, contribution_root)
        self.branch.subjects.add((row.lane, subject))
        if previous is None:
            self._resource_jobs[claim] = {'budget': budget, 'binding': binding,
                                          'reserved': capacity, 'consumed': None}
            self._resource_subjects[physical_key] = claim
            return 'new'
        return 'pending' if previous['consumed'] is None else 'done'

    def resolve(self, *, claim, height, paid, consumed, outcome):
        """Account an independently decided outcome, including failed work cost."""
        units(height); units(paid)
        require(outcome in {'positive', 'no-gain', 'invalid', 'unknown', 'cancelled'},
                'BUDGET_OUTCOME')
        reservation = self.branch.claims[claim]
        row = self.branch.budgets[reservation.budget]
        actual = resources(row.lane, consumed)
        require(reservation.status == 'reserved', 'BUDGET_ALREADY_RESOLVED')
        require(paid <= reservation.amount and
                all(actual[k] <= reservation.reserved[k] for k in actual), 'BUDGET_OVERRUN')
        require(paid == 0 or (outcome == 'positive' and row.maturity <= height < row.deadline),
                'BUDGET_UNQUALIFIED_PAYMENT')
        job = self._resource_jobs[claim]
        require(job['consumed'] is None or job['consumed'] == actual,
                'BUDGET_RESOURCE_REPLAY_MISMATCH')
        reservation.status = outcome
        reservation.paid = paid
        row.paid += paid
        job['consumed'] = actual

    def close(self, *, budget, height):
        """Unknown outstanding cost consumes its full resource reservation."""
        units(height)
        row = self.branch.budgets[budget]
        require(not row.closed and height >= row.deadline, 'BUDGET_NOT_DUE')
        for claim, reservation in self.branch.claims.items():
            if reservation.budget == budget and reservation.status == 'reserved':
                consumed = self._resource_jobs[claim]['consumed']
                self.resolve(claim=claim, height=height, paid=0,
                             consumed=consumed if consumed is not None else reservation.reserved,
                             outcome='unknown')
        for job in self._resource_jobs.values():
            if job['budget'] == budget and job['consumed'] is None:
                job['consumed'] = job['reserved'].copy()
        row.refunded = self.available(budget)
        self.branch.funding[row.source].available += row.refunded
        row.closed = True

    def checkpoint(self):
        """Opaque process-local branch snapshot; no deployed persistence claim."""
        require(len(self._checkpoints) < 8, 'BUDGET_CHECKPOINT_LIMIT')
        token = H('reward-budget-reference-checkpoint-v1', bytes.fromhex(self.context),
                  str(len(self._checkpoints)).encode()).hex()
        self._checkpoints[token] = copy.deepcopy(self.branch)
        return token

    def reorg(self, checkpoint):
        self.branch = copy.deepcopy(self._checkpoints[checkpoint])

    def prepare_external(self, *, claim, operation, effect):
        """Record intent before dispatch; pending/unknown must be reconciled."""
        identity(operation); identity(effect)
        reservation = self.branch.claims[claim]
        require(reservation.status == 'positive' and reservation.paid > 0,
                'BUDGET_EFFECT_NOT_SETTLED')
        row = self.branch.budgets[reservation.budget]
        key = (row.lane, reservation.subject)
        binding = ExternalIntent(operation, row.lane, reservation.subject, claim,
                                 reservation.budget, reservation.beneficiary,
                                 effect, reservation.paid)
        indexed = self._operations.get(operation)
        require(indexed is None or indexed == binding, 'BUDGET_OPERATION_REPLAY_MISMATCH')
        if key in self._effects:
            original, status, receipt = self._effects[key]
            require(original == binding, 'BUDGET_EFFECT_REPLAY_MISMATCH')
            require(indexed == original, 'BUDGET_EFFECT_INDEX_MISMATCH')
            return status
        require(indexed is None, 'BUDGET_EFFECT_INDEX_MISMATCH')
        self._capacity(self._effects)
        self._capacity(self._operations)
        self._effects[key] = (binding, 'pending', None)
        self._operations[operation] = binding
        return 'new'

    def finish_external(self, *, lane, subject, operation, receipt):
        identity(subject); identity(operation); identity(receipt)
        require(lane in LANES, 'BUDGET_RESOURCE_KIND')
        key = (lane, subject)
        indexed = self._operations.get(operation)
        require(indexed is not None and indexed.lane == lane and
                indexed.subject == subject and key in self._effects,
                'BUDGET_EFFECT_RECEIPT_MISMATCH')
        binding, status, previous = self._effects[key]
        require(indexed == binding and binding.operation == operation and
                (status == 'pending' or previous == receipt),
                'BUDGET_EFFECT_RECEIPT_MISMATCH')
        self._effects[key] = (binding, 'done', receipt)

    def summary(self):
        """Replay conservation without granting ledger work or public eligibility."""
        require(len(self._effects) == len(self._operations) and
                all((intent.lane, intent.subject) == key and
                    self._operations.get(intent.operation) == intent
                    for key, (intent, _, _) in self._effects.items()),
                'BUDGET_EFFECT_INDEX_MISMATCH')
        for source, funding in self.branch.funding.items():
            committed = sum(b.cap - b.refunded for b in self.branch.budgets.values()
                            if b.source == source)
            require(funding.available + committed == funding.total, 'BUDGET_CONSERVATION')
        totals = {}
        for lane in LANES:
            rows = [(key, b) for key, b in self.branch.budgets.items() if b.lane == lane]
            totals[lane] = {name: sum(getattr(b, name) for _, b in rows)
                            for name in ('cap', 'paid', 'refunded')}
            totals[lane]['available'] = sum(self.available(key) for key, _ in rows)
            totals[lane]['reserved'] = sum(c.amount for key, _ in rows for c in self._pending(key))
            require(totals[lane]['cap'] == sum(totals[lane][key]
                    for key in ('paid', 'refunded', 'available', 'reserved')), 'BUDGET_CONSERVATION')
        liabilities = {}
        for budget, pin in self._budget_pins.items():
            used = self.resource_used(budget)
            jobs = [job for job in self._resource_jobs.values()
                    if job['budget'] == budget and job['consumed'] is None]
            reserved = {key: sum(job['reserved'][key] for job in jobs) for key in used}
            require(all(used[key] + reserved[key] <= pin[-1][key] for key in used),
                    'BUDGET_RESOURCES')
            liabilities[budget] = {'used': used, 'reserved': reserved, 'cap': pin[-1].copy()}
        return {'schema': 'pon-five-lane-budget-reference-v1', 'context': self.context,
                'lanes': totals, 'external_intents': len(self._effects),
                'resource_liabilities': liabilities,
                'physical_resource_jobs': len(self._resource_jobs),
                'orphaned_resource_jobs': sum(claim not in self.branch.claims
                                              for claim in self._resource_jobs),
                'production_activation': False, 'native_funding_verified': False,
                'public_reward_eligible': False, 'additional_chainwork': 0}
