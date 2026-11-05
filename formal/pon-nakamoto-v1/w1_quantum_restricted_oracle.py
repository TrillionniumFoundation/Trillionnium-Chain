"""A constructive reversible search of an explicit subset of legal W1 winners.

Require the first N*R raw noise words of every label to be canonical. On this
subset the complete native rejection sampler selects exactly these words. The
complete ordered transcript and inclusive ticket comparison remain mandatory.
Any other nonce is unmarked, including otherwise legal native winners.

This is an attacker strategy, not a replacement verifier, a full-predicate
equivalence claim, a cost lower bound, or a uniform-probability theorem. Circuit
resources must be coupled to THIS subset's marked count, never the full count.
"""
from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
import hashlib
import json
import struct

from w1_quantum_oracle import (
    ROOT, SOURCE_FILES, BitPack, Byte, Constant, FixedTemplate, HashPlan, Layout,
    NoiseWord, Operation, OracleProgram, ProductPlan, TranscriptPlan, canonical,
    framed, hash_bytes, ordered,
)
from w1_quantum_primitives import primitive

SCHEMA = "trnm-w1-prefix-restricted-phase-oracle-v1"
RESTRICTION = "all first N*R raw words for each of four labels are canonical"
RESTRICTED_SOURCE_FILES = SOURCE_FILES + (
    "formal/pon-nakamoto-v1/w1_quantum_restricted_oracle.py",
)


class PrefixRestrictedProgram(OracleProgram):
    """Static direct-factor wiring, paid validity guards, and complete reverse.

    The retained clean-XOR arithmetic leaves are total for every raw operand.
    When a prefix word is noncanonical the intermediate trace is irrelevant:
    its validity flag prevents phase marking. No data-dependent address,
    uncharged QRAM lookup, or free conditional shortcut is used.
    """

    STAGES = ("challenge", "noise_hashes", "noise_prefix_guard", "low_rank",
              "offset_matrices", "transcript_arithmetic", "trace_hash",
              "ticket_hash", "predicate")

    def __init__(self, template):
        if type(template) is not FixedTemplate:
            raise ValueError("TEMPLATE_TYPE")
        template = FixedTemplate.from_header(template.header, template.a, template.b,
                                             template.nonce_bits, template.shape)
        self.template, self.shape, self.layout = template, template.shape, Layout()
        n, r, w = self.shape.n, self.shape.r, self.shape.field_bits
        self.required = n * r
        self.prefix_counters = (self.required + 7) // 8
        self.draws = self.required
        self.rank_bits = self.required.bit_length()
        self.nonce = self.layout.allocate("nonce", template.nonce_bits)[0]
        self.zero = self.layout.allocate("constant-zero", 1)[0]
        self.one = self.layout.allocate("constant-one", 1)[0]
        header = list(template.header)
        for i in range(8):
            header[template.nonce_offset + i] = Byte(self.nonce, 8 * i)
        self.challenge = HashPlan(self.layout, "challenge.states",
                                  framed(template.challenge_tag, tuple(header)), 5)
        challenge_bytes = hash_bytes(self.challenge.digest)
        self.noise, self.raw = [], []
        for label in range(4):
            plans = [HashPlan(self.layout, f"noise.{label}.{counter}.states",
                             framed(b"noise", challenge_bytes, (label,),
                                    tuple(struct.pack("<I", counter))))
                     for counter in range(self.prefix_counters)]
            self.noise.append(plans)
            self.raw.append(tuple(NoiseWord(plan.digest, word, w)
                                  for plan in plans for word in range(8))[:self.required])
        self.good = [self.layout.allocate(f"noise.{label}.canonical", 1, self.required)
                     for label in range(4)]
        self.ranks = [self.layout.allocate(f"noise.{label}.valid_prefix_count", self.rank_bits, self.required)
                      for label in range(4)]
        self.complete = self.layout.allocate("noise.prefix_all_canonical", 1, 4)
        self.accept = primitive("accepted", w)
        self.increment = primitive("increment", w, self.rank_bits)
        self.enough = primitive("leq", self.rank_bits)
        # Every factor is a statically addressed word in a SHA output. There is
        # no compaction or destination-selection circuit in this strategy.
        factors = self.raw
        self.low_rank = [ProductPlan(self.layout, name, factors[i], factors[i + 1], n, r, n, w)
                         for name, i in (("E", 0), ("F", 2))]
        self.offset = [self.layout.allocate(name, w, n**2) for name in ("A-prime", "B-prime")]
        self.add = primitive("add", w)
        ap, bp = (tuple(bank[i] for i in range(bank.count)) for bank in self.offset)
        self.transcript = TranscriptPlan(self.layout, ap, bp, self.shape)
        trace_bytes = tuple(b"TRNM-PON-TRACE1\0") + challenge_bytes
        trace_bytes += tuple(Byte(word, shift) for word in self.transcript.prefixes()
                             for shift in (0, 8, 16, 24))
        self.trace = HashPlan(self.layout, "trace.states", trace_bytes)
        self.ticket = HashPlan(self.layout, "ticket.states",
                               framed(b"ticket", challenge_bytes, hash_bytes(self.trace.digest)))
        self.target_hit = self.layout.allocate("ticket.leq_target", 1)[0]
        self.winner = self.layout.allocate("restricted_winner", 1)[0]
        self.compare = primitive("leq", 256)
        self.conjunction = primitive("and", 5)
        self._resources = self._restricted_resources = None

    def stage_operations(self, stage, reverse=False):
        if stage == "noise_hashes":
            for label in ordered(4, reverse):
                for counter in ordered(self.prefix_counters, reverse):
                    yield from self.noise[label][counter].operations(reverse)
        elif stage == "noise_prefix_guard":
            for label in ordered(4, reverse):
                final = Operation(self.enough,
                                  (Constant(self.rank_bits, self.required), self.ranks[label][self.required - 1]),
                                  self.complete[label])
                if reverse:
                    yield final
                for index in ordered(self.required, reverse):
                    before = self.ranks[label][index - 1] if index else Constant(self.rank_bits, 0)
                    accept = Operation(self.accept, (self.raw[label][index],), self.good[label][index])
                    increment = Operation(self.increment, (before, self.good[label][index]), self.ranks[label][index])
                    yield from (increment, accept) if reverse else (accept, increment)
                if not reverse:
                    yield final
        else:
            yield from super().stage_operations(stage, reverse)

    def stage_counts(self):
        n, r = self.shape.n, self.shape.r
        sha, mul, add = self.challenge.leaf, self.transcript.multiply, self.add
        return {
            "challenge": {sha: len(self.challenge.messages)},
            "noise_hashes": {sha: sum(len(plan.messages) for group in self.noise for plan in group)},
            "noise_prefix_guard": {self.accept: 4 * self.required,
                                   self.increment: 4 * self.required, self.enough: 4},
            "low_rank": {mul: 2 * n * n * r, add: 2 * n * n * r},
            "offset_matrices": {add: 2 * n * n},
            "transcript_arithmetic": {mul: n**3, add: n**3},
            "trace_hash": {sha: len(self.trace.messages)},
            "ticket_hash": {sha: len(self.ticket.messages)},
            "predicate": {self.compare: 1, self.conjunction: 1},
        }

    def resources(self):
        if self._restricted_resources is not None:
            return json.loads(json.dumps(self._restricted_resources))
        row = super().resources()
        sources = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                   for name in RESTRICTED_SOURCE_FILES}
        construction = {
            "schema": SCHEMA, "restriction": RESTRICTION, "input": self.template.spec(),
            "source_sha256": sources, "leaf_netlist_sha256": {
                name: leaf["netlist_sha256"] for name, leaf in row["leaves"].items()},
            "layout": self.layout.banks,
            "stage_calls": {name: stage["calls"] for name, stage in row["stages"].items()},
        }
        row.update({
            "schema": SCHEMA,
            "construction_sha256": hashlib.sha256(canonical(construction)).hexdigest(),
            "scope": ("NATIVE_W1_LEGAL_SUBSET_CONSTRUCTION" if self.shape.native
                      else "REDUCED_SHAPE_LEGAL_SUBSET_CONTROL"),
            "source_sha256": sources, "restriction": RESTRICTION,
            "full_legal_winner_predicate_equivalence": False,
            "legal_full_w1_winners_may_be_discarded": True,
            "probability_requires_restricted_marked_count": True,
            "winning_probability_inferred_from_retention": False,
            "data_access": "static prefix-word wires; charged leaf input copies and validity guards; no QRAM or coherent compaction",
        })
        row["hash_framing"].pop("noise_hashes_all_bounded_branches")
        row["hash_framing"].update({
            "noise_hashes_prefix_only": 4 * self.prefix_counters,
            "noise_words_checked_per_label": self.required,
            "original_noise_counter_cap": self.shape.noise_counters,
        })
        self._restricted_resources = row
        return json.loads(json.dumps(row))

    def execute(self, nonce, mode="macro", inverse=True, gate_limit=100_000_000):
        result = super().execute(nonce, mode, inverse, gate_limit)
        result.update({
            "predicate_schema": SCHEMA,
            "prefix_all_accepted": all(result["noise_complete"]),
            "accepted_word_counts_scope": "first N*R raw words only",
            "trace_matches_full_w1_only_when_prefix_all_accepted": True,
            "full_legal_winner_predicate_equivalence": False,
        })
        return result

    def resource_request(self, workload, classical, physical_models=()):
        request = super().resource_request(workload, classical, physical_models)
        request = replace(request,
                          strategy="fixed header nonce search restricted to canonical raw noise prefix",
                          data_access_assumption="static prefix-word wires with paid input copies and validity guards")
        request.validate()
        return request


def conditional_prefix_retention(shape):
    """Exact algebra under an explicit iid-uniform RAW-WORD premise only.

    This is not the success probability of the restricted mining predicate.
    Independence between prefix validity and a ticket hit is not established.
    """
    shape.validate()
    return Fraction(shape.q, 1 << shape.field_bits) ** (4 * shape.n * shape.r)
