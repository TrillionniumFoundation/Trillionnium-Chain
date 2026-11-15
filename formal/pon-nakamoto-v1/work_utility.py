"""Append-only observational useful-output accounting, never an economic ledger.

The existing verifier and inference owner supply verified outcomes and observed
consumer acknowledgments. This observer cannot authenticate a future window,
an actor's independence, a hardware meter or an external physical effect.
"""
from __future__ import annotations
import copy
from fractions import Fraction
from contract_wire import H, canonical
from evaluation_bundle import digest_text, require

STAGES = ('intake', 'normalization', 'proof', 'quality')
COST_FIELDS = ('cpu_ns', 'wall_ns', 'operations', 'bytes_read', 'bytes_written', 'memory_peak_bytes', 'gpu_ns')


def measured_cost(*, cpu_ns, wall_ns, operations, bytes_read=0, bytes_written=0,
                  memory_peak_bytes=0, gpu_ns=None):
    value = dict(cpu_ns=cpu_ns, wall_ns=wall_ns, operations=operations,
                 bytes_read=bytes_read, bytes_written=bytes_written,
                 memory_peak_bytes=memory_peak_bytes, gpu_ns=gpu_ns)
    for name, amount in value.items():
        if name == 'gpu_ns' and amount is None:
            continue
        require(type(amount) is int and 0 <= amount < 1 << 63, 'UTILITY_COST')
    return value


class UniqueUsefulOutputAccounting:
    """Bounded local observer; the operation/revocation owner retains durability.

    Deduplication uses owner-admitted task content and normalized output content,
    not partition labels, contributor IDs, report wrappers, nonce or branch. The
    caller must canonicalize task/output semantics before supplying those roots.
    Function fingerprints identify the checked adapter but do not prove novelty.
    """
    def __init__(self, *, context, current_branch, required_stages=STAGES,
                 max_attempts=4096, max_events=65536):
        digest_text(context); digest_text(current_branch)
        require(isinstance(required_stages, tuple) and 0 < len(required_stages) <= 16 and
                len(set(required_stages)) == len(required_stages) and
                all(isinstance(stage, str) and 0 < len(stage) <= 128 for stage in required_stages), 'UTILITY_STAGES')
        require(type(max_attempts) is int and 0 < max_attempts <= 65536 and
                type(max_events) is int and 0 < max_events <= 1024*1024, 'UTILITY_LIMIT')
        self.context = context
        self.current_branch = current_branch
        self.required_stages = required_stages
        self.max_attempts = max_attempts
        self.max_events = max_events
        self._attempts = {}
        self._events = []
        self._consumer_operations = set()
        self._adoptions = []
        self._active_branches = {current_branch}
        self._total_costs = {name: 0 for name in COST_FIELDS}

    @property
    def events(self):
        return copy.deepcopy(self._events)

    def _append(self, kind, value):
        require(len(self._events) < self.max_events, 'UTILITY_EVENT_LIMIT')
        self._events.append(dict(sequence=len(self._events)+1, kind=kind, **copy.deepcopy(value)))

    def begin_attempt(self, *, attempt, branch, task_content, output_content,
                      function_fingerprint, source, partition):
        for identity in (attempt, branch, task_content, output_content, function_fingerprint, source):
            digest_text(identity)
        require(isinstance(partition, str) and 0 < len(partition) <= 128, 'UTILITY_PARTITION')
        require(attempt not in self._attempts, 'UTILITY_ATTEMPT_REPLAY')
        require(len(self._attempts) < self.max_attempts, 'UTILITY_ATTEMPT_LIMIT')
        output_key = H('unique-useful-output-v1', canonical({'context': self.context,
                    'task_content': task_content, 'output_content': output_content})).hex()
        value = dict(attempt=attempt, branch=branch, task_content=task_content,
                     output_content=output_content, function_fingerprint=function_fingerprint,
                     source=source, partition=partition, output_key=output_key)
        self._append('attempt', value)
        self._attempts[attempt] = dict(**value, costs=[], verified=None, quality_gain=None)
        return output_key

    def record_cost(self, attempt, stage, *, observer, cost):
        require(attempt in self._attempts, 'UTILITY_ATTEMPT')
        require(isinstance(stage, str) and 0 < len(stage) <= 128 and
                isinstance(observer, str) and 0 < len(observer) <= 256, 'UTILITY_COST_OBSERVER')
        require(isinstance(cost, dict) and set(cost) == set(COST_FIELDS), 'UTILITY_COST_FIELDS')
        exact = measured_cost(**cost)
        for name in COST_FIELDS:
            if name == 'memory_peak_bytes' or exact[name] is None:
                continue
            require(self._total_costs[name]+exact[name] < 1 << 64, 'UTILITY_TOTAL_COST_LIMIT')
        # Multiple invocations of a stage count separately, including retries,
        # rejected proofs, normalization of copied factors and downstream checks.
        self._append('cost', dict(attempt=attempt, stage=stage, observer=observer, cost=exact))
        self._attempts[attempt]['costs'].append(dict(stage=stage, observer=observer, **exact))
        for name, amount in exact.items():
            if amount is not None and name != 'memory_peak_bytes': self._total_costs[name] += amount

    def finish_verification(self, attempt, *, accepted, quality_gain, outcome):
        require(attempt in self._attempts, 'UTILITY_ATTEMPT')
        require(type(accepted) is bool, 'UTILITY_ACCEPTED')
        require(isinstance(quality_gain, Fraction) and -1 <= quality_gain <= 1, 'UTILITY_GAIN')
        require(isinstance(outcome, str) and 0 < len(outcome) <= 256, 'UTILITY_OUTCOME')
        value = self._attempts[attempt]
        require(value['verified'] is None, 'UTILITY_VERIFICATION_REPLAY')
        self._append('verification', dict(attempt=attempt, accepted=accepted,
                     quality_gain=[str(quality_gain.numerator), str(quality_gain.denominator)], outcome=outcome))
        value['verified'] = accepted; value['quality_gain'] = quality_gain

    def adopt_output(self, attempt, *, consumer_operation, consumer, observed_output):
        """Call only after the consumer performed its ordinary bounded use.

        Identity is supplied by its existing durable operation/outbox owner.
        An arbitrary call is not independent signed adoption evidence.
        """
        for identity in (consumer_operation, consumer, observed_output):
            digest_text(identity)
        require(attempt in self._attempts, 'UTILITY_ATTEMPT')
        value = self._attempts[attempt]
        require(consumer_operation not in self._consumer_operations, 'UTILITY_CONSUMER_REPLAY')
        require(value['verified'] is True and value['quality_gain'] > 0, 'UTILITY_NOT_USEFUL')
        require(value['branch'] in self._active_branches, 'UTILITY_STALE_BRANCH')
        require(set(self.required_stages) <= {cost['stage'] for cost in value['costs']}, 'UTILITY_INCOMPLETE_COSTS')
        require(value['output_content'] == observed_output, 'UTILITY_OUTPUT_BINDING')
        adoption = dict(attempt=attempt, consumer_operation=consumer_operation, consumer=consumer,
                        output_key=value['output_key'], branch=value['branch'], observed_output=observed_output)
        self._append('adoption', adoption)
        self._consumer_operations.add(consumer_operation); self._adoptions.append(adoption)
        # This acknowledgement is retained forever in this bounded observation,
        # even if the ledger branch is removed. A reorg does not undo physical use.
        return value['output_key']

    def reorganize(self, *, new_branch, active_branches):
        digest_text(new_branch)
        require(isinstance(active_branches, list) and 0 < len(active_branches) <= 4096 and
                active_branches == sorted(set(active_branches)) and new_branch in active_branches, 'UTILITY_BRANCHES')
        for branch in active_branches:
            digest_text(branch)
        removed = sorted(self._active_branches-set(active_branches))
        self._append('reorganization', dict(new_branch=new_branch, active_branches=active_branches, removed=removed))
        self.current_branch = new_branch; self._active_branches = set(active_branches)

    def snapshot(self):
        attempts = list(self._attempts.values())
        costs = [cost for attempt in attempts for cost in attempt['costs']]
        summed = {name: sum(cost[name] for cost in costs) for name in COST_FIELDS if name not in {'gpu_ns', 'memory_peak_bytes'}}
        summed['memory_peak_bytes'] = max((cost['memory_peak_bytes'] for cost in costs), default=0)
        unknown_gpu = sum(cost['gpu_ns'] is None for cost in costs)
        summed['gpu_ns'] = None if unknown_gpu else sum(cost['gpu_ns'] for cost in costs)
        historic_keys = {adoption['output_key'] for adoption in self._adoptions}
        active_keys = {adoption['output_key'] for adoption in self._adoptions
                       if adoption['branch'] in self._active_branches}
        verified = [attempt for attempt in attempts if attempt['verified'] is True]
        useful_verified = {attempt['output_key'] for attempt in verified if attempt['quality_gain'] > 0}
        return {'schema': 'pon-unique-useful-output-observation-v1', 'context': self.context,
                'current_branch': self.current_branch, 'attempts': len(attempts),
                'rejected_attempts': sum(attempt['verified'] is False for attempt in attempts),
                'unfinished_attempts': sum(attempt['verified'] is None for attempt in attempts),
                'stale_attempts': sum(attempt['branch'] not in self._active_branches for attempt in attempts),
                'repeated_output_attempts': len(attempts)-len({attempt['output_key'] for attempt in attempts}),
                'verified_useful_unique_outputs': len(useful_verified),
                'downstream_adoption_events': len(self._adoptions),
                'unique_useful_outputs_actually_adopted': len(historic_keys),
                'currently_valid_unique_useful_outputs': len(active_keys),
                'accepted_but_unadopted_unique_outputs': len(useful_verified-historic_keys),
                'cost_records': len(costs), 'cost_totals': summed,
                'cost_stages': {stage: sum(cost['stage'] == stage for cost in costs)
                                for stage in sorted({cost['stage'] for cost in costs})},
                'attempts_with_incomplete_required_costs': sum(not set(self.required_stages) <=
                    {cost['stage'] for cost in attempt['costs']} for attempt in attempts),
                'cost_records_with_unknown_gpu': unknown_gpu,
                'cost_scope': 'all-reported-attempts-including-rejections-and-replays; wall-is-cumulative-not-parallel-elapsed',
                'event_root': H('useful-output-observation-events-v1', canonical(self._events)).hex(),
                'public_reward_authority': False, 'ordinary_hepta_entry': False,
                'independent_accepted': False, 'durability_owner': 'existing-kernel-operations-outbox'}
