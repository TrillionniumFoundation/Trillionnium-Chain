"""Bounded public-evaluation lifecycle specification for the existing eval owner.

This fresh off-chain namespace does not change revision4, issue rewards, create
chainwork, authenticate governance or turn signed opinions into objective ML truth.
The caller obtains heights from its admitted confirmation owner, never wall time.
"""
from __future__ import annotations
import copy
import json
from cryptography.exceptions import InvalidSignature
from contract_wire import H, NETWORK, PARAMETER_HASH, canonical, unique
from strict_signature import verify as verify_signature
from evaluation_bundle import digest_text, require

RULE = 'frozen-roster-commit-reveal-abort-v1'
ROUND_FIELDS = {'schema', 'network', 'parameters', 'round_number', 'parent_artifact', 'family',
                'task_root', 'model_contract', 'admission_root', 'roster', 'authors', 'deadlines',
                'max_score', 'rule', 'independent_governance_accepted'}
REVEAL_FIELDS = {'score', 'task_root', 'model_contract', 'evaluation_result', 'salt'}


def admission_root(roster, authors):
    return H('public-evaluation-admitted-lineages-v1', canonical({'roster': roster, 'authors': authors})).hex()


def freeze_round(*, round_number, parent_artifact, family, task_root, model_contract,
                 roster, authors, expected_admission_root, start, candidate_end,
                 commit_end, reveal_end, max_score=1000000):
    for digest in (parent_artifact, family, task_root, model_contract, expected_admission_root):
        digest_text(digest)
    require(type(round_number) is int and 0 <= round_number < 1 << 64, 'PUBLIC_EVAL_ROUND')
    require(isinstance(roster, dict) and 2 <= len(roster) <= 16 and
            isinstance(authors, dict) and 0 < len(authors) <= 16, 'PUBLIC_EVAL_ROSTER')
    for key, lineage in list(roster.items())+list(authors.items()):
        digest_text(key); digest_text(lineage)
    require(len(set(roster.values())) == len(roster) and
            not (set(roster.values()) & set(authors.values())) and not (set(roster) & set(authors)), 'PUBLIC_EVAL_LINEAGE_ALIAS')
    require(admission_root(roster, authors) == expected_admission_root, 'PUBLIC_EVAL_ADMISSION_ROOT')
    require(all(type(v) is int and 0 <= v < 1 << 64 for v in (start, candidate_end, commit_end, reveal_end)) and
            start < candidate_end < commit_end < reveal_end, 'PUBLIC_EVAL_DEADLINES')
    require(type(max_score) is int and 1 <= max_score <= 1000000, 'PUBLIC_EVAL_SCORE_LIMIT')
    value = dict(schema='pon-public-evaluation-round-v1', network=NETWORK.hex(), parameters=PARAMETER_HASH.hex(),
        round_number=round_number, parent_artifact=parent_artifact, family=family, task_root=task_root,
        model_contract=model_contract, admission_root=expected_admission_root, roster=dict(roster), authors=dict(authors),
        deadlines=dict(start=start, candidate_end=candidate_end, commit_end=commit_end, reveal_end=reveal_end),
        max_score=max_score, rule=RULE, independent_governance_accepted=False)
    raw = canonical(value)
    return raw, H('public-evaluation-round-v1', raw).hex()


def signed_record(key, *, phase, round_digest, candidate, payload):
    # Development/owner tooling supplies the signer; no keys are generated here.
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    signer = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    record = dict(schema='pon-public-evaluation-message-v1', phase=phase, round=round_digest,
                  signer=signer, candidate=candidate, payload=copy.deepcopy(payload))
    return {'record': record, 'signature': key.sign(H('public-evaluation-message-sign-v1', canonical(record))).hex()}


def reveal_commitment(payload):
    return H('public-evaluation-reveal-commitment-v1', canonical(payload)).hex()


def candidate_identity(round_digest, artifact, source, components):
    return H('public-evaluation-candidate-v1', bytes.fromhex(round_digest), bytes.fromhex(artifact),
             bytes.fromhex(source), bytes.fromhex(components)).hex()


class PublicEvaluationRound:
    def __init__(self, raw, expected_digest):
        require(type(raw) is bytes and len(raw) <= 32768, 'PUBLIC_EVAL_ROUND_LIMIT')
        digest_text(expected_digest)
        require(H('public-evaluation-round-v1', raw).hex() == expected_digest, 'PUBLIC_EVAL_ROUND_IDENTITY')
        plan = json.loads(raw, object_pairs_hook=unique)
        require(isinstance(plan, dict) and set(plan) == ROUND_FIELDS and canonical(plan) == raw, 'PUBLIC_EVAL_ROUND_FIELDS')
        require(plan['schema'] == 'pon-public-evaluation-round-v1' and plan['network'] == NETWORK.hex() and
                plan['parameters'] == PARAMETER_HASH.hex() and plan['rule'] == RULE and
                plan['independent_governance_accepted'] is False, 'PUBLIC_EVAL_ROUND_SCOPE')
        d = plan['deadlines']
        require(isinstance(d, dict) and set(d) == {'start', 'candidate_end', 'commit_end', 'reveal_end'}, 'PUBLIC_EVAL_DEADLINES')
        replay, _ = freeze_round(round_number=plan['round_number'], parent_artifact=plan['parent_artifact'],
            family=plan['family'], task_root=plan['task_root'], model_contract=plan['model_contract'],
            roster=plan['roster'], authors=plan['authors'], expected_admission_root=plan['admission_root'],
            max_score=plan['max_score'], **d)
        require(raw == replay, 'PUBLIC_EVAL_ROUND_BINDING')
        self._plan = plan; self.digest = expected_digest; self._candidate = None
        self._commits = {}; self._reveals = {}; self._equivocations = {}; self._appeals = []
        self._closed = None; self._last_height = d['start']

    @property
    def plan(self):
        return copy.deepcopy(self._plan)

    def _height(self, height):
        require(type(height) is int and self._last_height <= height < 1 << 64, 'PUBLIC_EVAL_HEIGHT')
        self._last_height = height

    def _verify(self, envelope):
        require(isinstance(envelope, dict) and set(envelope) == {'record', 'signature'} and
                len(canonical(envelope)) <= 16384, 'PUBLIC_EVAL_MESSAGE_LIMIT')
        record = envelope['record']
        require(isinstance(record, dict) and set(record) == {'schema', 'phase', 'round', 'signer', 'candidate', 'payload'}, 'PUBLIC_EVAL_MESSAGE_FIELDS')
        require(record['schema'] == 'pon-public-evaluation-message-v1' and record['round'] == self.digest and
                isinstance(record['phase'], str) and record['phase'] in {'candidate', 'commit', 'reveal', 'appeal'}, 'PUBLIC_EVAL_MESSAGE_CONTEXT')
        digest_text(record['signer']); digest_text(record['candidate']); digest_text(envelope['signature'], 128)
        require(isinstance(record['payload'], dict), 'PUBLIC_EVAL_PAYLOAD')
        try:
            verify_signature(bytes.fromhex(record['signer']), bytes.fromhex(envelope['signature']),
                             H('public-evaluation-message-sign-v1', canonical(record)))
        except (InvalidSignature, ValueError) as error:
            raise ValueError('PUBLIC_EVAL_SIGNATURE') from error
        return record

    def _check_evaluator(self, record):
        require(record['signer'] in self._plan['roster'], 'PUBLIC_EVAL_AUTHORITY')
        require(self._candidate is not None and record['candidate'] == self._candidate['record']['candidate'], 'PUBLIC_EVAL_CANDIDATE_CONTEXT')
        if record['phase'] == 'commit':
            require(set(record['payload']) == {'commitment'}, 'PUBLIC_EVAL_COMMIT_FIELDS')
            digest_text(record['payload']['commitment'])
        else:
            payload = record['payload']
            require(set(payload) == REVEAL_FIELDS, 'PUBLIC_EVAL_REVEAL_FIELDS')
            require(type(payload['score']) is int and 0 <= payload['score'] <= self._plan['max_score'], 'PUBLIC_EVAL_SCORE')
            for field in ('task_root', 'model_contract', 'evaluation_result', 'salt'):
                digest_text(payload[field])
            require(payload['task_root'] == self._plan['task_root'] and
                    payload['model_contract'] == self._plan['model_contract'], 'PUBLIC_EVAL_REVEAL_CONTEXT')

    def intake(self, envelope, *, height):
        record = self._verify(envelope); phase = record['phase']; d = self._plan['deadlines']
        self._height(height)
        if phase == 'appeal':
            require(self._closed is not None and height > d['reveal_end'] and len(self._appeals) < 16, 'PUBLIC_EVAL_APPEAL_PHASE')
            require(record['signer'] in set(self._plan['authors']) | set(self._plan['roster']) and
                    self._candidate is not None and record['candidate'] == self._candidate['record']['candidate'], 'PUBLIC_EVAL_AUTHORITY')
            require(set(record['payload']) == {'result', 'claim', 'evidence'}, 'PUBLIC_EVAL_APPEAL_FIELDS')
            for value in record['payload'].values(): digest_text(value)
            require(record['payload']['result'] == H('public-evaluation-closed-result-v1', canonical(self._closed)).hex(), 'PUBLIC_EVAL_APPEAL_RESULT')
            require(envelope not in self._appeals, 'PUBLIC_EVAL_APPEAL_REPLAY')
            self._appeals.append(copy.deepcopy(envelope))
            return 'appeal-recorded-current-result-unchanged'
        require(self._closed is None, 'PUBLIC_EVAL_CLOSED')
        if phase == 'candidate':
            require(d['start'] <= height <= d['candidate_end'] and self._candidate is None, 'PUBLIC_EVAL_CANDIDATE_PHASE')
            require(record['signer'] in self._plan['authors'] and set(record['payload']) == {'artifact', 'source', 'components'}, 'PUBLIC_EVAL_AUTHOR')
            payload = record['payload']
            for value in payload.values(): digest_text(value)
            require(payload['source'] == self._plan['authors'][record['signer']] and
                    record['candidate'] == candidate_identity(self.digest, **payload), 'PUBLIC_EVAL_CANDIDATE_BINDING')
            self._candidate = copy.deepcopy(envelope)
            return 'candidate-admitted'
        self._check_evaluator(record)
        records = self._commits if phase == 'commit' else self._reveals
        require((d['candidate_end'] < height <= d['commit_end']) if phase == 'commit'
                else (d['commit_end'] < height <= d['reveal_end']), 'PUBLIC_EVAL_PHASE')
        prior = records.get(record['signer'])
        if prior is not None:
            require(canonical(prior) != canonical(envelope), 'PUBLIC_EVAL_MESSAGE_REPLAY')
            self.submit_equivocation(prior, envelope)
            raise ValueError('PUBLIC_EVAL_EQUIVOCATION')
        if phase == 'reveal':
            require(record['signer'] in self._commits and self._commits[record['signer']]['record']['payload']['commitment']
                    == reveal_commitment(record['payload']), 'PUBLIC_EVAL_COMMITMENT_BINDING')
        records[record['signer']] = copy.deepcopy(envelope)
        return phase+'-recorded'

    def submit_equivocation(self, first, second):
        """Objective signature conflict; no silent deletion of current roster."""
        a, b = self._verify(first), self._verify(second)
        require(a['phase'] in {'commit', 'reveal'} and a['phase'] == b['phase'] and
                a['signer'] == b['signer'] and a['candidate'] == b['candidate'], 'PUBLIC_EVAL_EQUIVOCATION_CONTEXT')
        self._check_evaluator(a); self._check_evaluator(b)
        require(canonical(a['payload']) != canonical(b['payload']), 'PUBLIC_EVAL_NOT_EQUIVOCATION')
        key = a['signer']+':'+a['phase']
        require(key not in self._equivocations, 'PUBLIC_EVAL_EVIDENCE_REPLAY')
        ordered = sorted([copy.deepcopy(first), copy.deepcopy(second)], key=canonical)
        self._equivocations[key] = dict(schema='pon-public-evaluation-equivocation-v1',
            round=self.digest, signer=a['signer'], phase=a['phase'], records=ordered,
            disqualification_effect='next-round-only; current-roster-unchanged')
        return copy.deepcopy(self._equivocations[key])

    def close(self, *, height):
        self._height(height)
        require(height > self._plan['deadlines']['reveal_end'], 'PUBLIC_EVAL_CLOSE_PHASE')
        if self._closed is not None:
            return copy.deepcopy(self._closed)
        missing = sorted(set(self._plan['roster'])-set(self._reveals))
        faults = sorted({evidence['signer'] for evidence in self._equivocations.values()})
        aborted = self._candidate is None or bool(missing or faults)
        score = None if aborted else min(e['record']['payload']['score'] for e in self._reveals.values())
        self._closed = dict(schema='pon-public-evaluation-closed-result-v1', round=self.digest,
            status='aborted' if aborted else 'complete-scored', candidate=None if self._candidate is None else self._candidate['record']['candidate'],
            missing_reveals=missing, conflicts_before_close=faults, score=score,
            eligible_for_external_owner_review=not aborted and score > 0,
            adoption_authorized=False, reward_authorized=False, objective_result_replayed=False,
            independent_governance_accepted=False,
            reason='missing-candidate/reveal-or-signed-conflict' if aborted else 'complete-signed-scores-not-objective-ML-truth')
        return copy.deepcopy(self._closed)

    def next_round_disqualified_keys(self):
        return sorted({evidence['signer'] for evidence in self._equivocations.values()})

    def observation(self):
        return {'schema': 'pon-public-evaluation-lifecycle-observation-v1', 'round': self.digest,
                'frozen_roster': copy.deepcopy(self._plan['roster']), 'candidate': copy.deepcopy(self._candidate),
                'commits': copy.deepcopy(self._commits), 'reveals': copy.deepcopy(self._reveals),
                'equivocations': copy.deepcopy(self._equivocations), 'appeals': copy.deepcopy(self._appeals),
                'closed_result': copy.deepcopy(self._closed), 'next_round_disqualified_keys': self.next_round_disqualified_keys(),
                'last_confirmed_height_observed': self._last_height, 'native_revision4_changed': False,
                'new_chainwork': False, 'durability_owner': 'existing-evaluation-artifacts-and-operations-outbox'}


def freeze_successor_round(previous, **parameters):
    """Existing admission owner supplies a new root; known faults cannot disappear.

    Enforces only the immediate successor's evaluator exclusion for verified keys
    and their previously admitted lineage aliases. New hidden control remains an
    unsolved governance/Sybil question, and current closed scores stay immutable.
    """
    require(isinstance(previous, PublicEvaluationRound) and
            previous.observation()['closed_result'] is not None, 'PUBLIC_EVAL_SUCCESSOR_REQUIRES_CLOSED')
    require(type(parameters.get('round_number')) is int and
            parameters['round_number'] > previous.plan['round_number'], 'PUBLIC_EVAL_SUCCESSOR_NUMBER')
    # The prior owner has already observed a confirmed height after reveal_end.
    # A successor may start at that same observed height, after closure/freeze,
    # but never replay phases in the predecessor's already observed past.
    start = parameters.get('start')
    require(type(start) is int and
            start >= previous.observation()['last_confirmed_height_observed'] and
            start > previous.plan['deadlines']['reveal_end'], 'PUBLIC_EVAL_SUCCESSOR_HEIGHT')
    roster = parameters.get('roster')
    require(isinstance(roster, dict), 'PUBLIC_EVAL_ROSTER')
    excluded = set(previous.next_round_disqualified_keys())
    excluded_lineages = {previous.plan['roster'][key] for key in excluded}
    require(not (set(roster) & excluded or set(roster.values()) & excluded_lineages),
            'PUBLIC_EVAL_NEXT_ROUND_DISQUALIFIED')
    return freeze_round(**parameters)
