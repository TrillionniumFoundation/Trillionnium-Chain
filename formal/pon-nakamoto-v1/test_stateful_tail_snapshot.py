#!/usr/bin/env python3
"""Regression checks for the finite Bellman query's construction-time model.

These checks concern a finite abstract checker, not a native W1 or quantum
security bound. The unchanged report retains all original HOLD claim flags.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
import unittest

from stateful_tail import (
    Action, Model, Transition, _json_default, build_report, make_optimal_tail,
)


def _step(credit: int = 0) -> Transition:
    return Transition(Fraction(1), "s", credit, 0)


def _model(actions) -> Model:
    return Model({"s": actions}, {"s": Fraction(1)}, Fraction(2), Fraction(1))


class SnapshotTests(unittest.TestCase):
    def test_top_level_replacement_keeps_cached_and_uncached_queries_consistent(self):
        model = _model((Action("wait", (_step(),)),))
        query = make_optimal_tail(model)
        self.assertEqual(query("s", 0, 1, 1), 0)

        model.actions["s"] = (Action("release", (_step(1),)),)

        # The original law can never earn credit, at either horizon. Reusing
        # the cached horizon and asking a new horizon must describe that law.
        self.assertEqual(query("s", 0, 1, 1), 0)
        self.assertEqual(query("s", 0, 2, 1), 0)
        fresh = make_optimal_tail(model)
        self.assertEqual(fresh("s", 0, 1, 1), 1)
        self.assertEqual(fresh("s", 0, 2, 1), 1)

    def test_original_state_set_is_captured(self):
        model = _model((Action("wait", (_step(),)),))
        query = make_optimal_tail(model)
        model.actions.clear()
        model.potential.clear()

        self.assertEqual(query("s", 0, 1, 1), 0)
        with self.assertRaisesRegex(ValueError, "unknown initial state"):
            query("added_later", 0, 1, 1)
        with self.assertRaisesRegex(ValueError, "state sets must agree"):
            make_optimal_tail(model)

    def test_accepted_mutable_action_sequence_is_detached(self):
        actions = [Action("wait", (_step(),))]
        model = _model(actions)
        query = make_optimal_tail(model)
        actions.append(Action("release", (_step(1),)))

        self.assertEqual(query("s", 0, 1, 1), 0)
        self.assertEqual(make_optimal_tail(model)("s", 0, 1, 1), 1)

    def test_accepted_mutable_outcome_sequence_is_detached(self):
        outcomes = [_step()]
        model = _model((Action("step", outcomes),))
        query = make_optimal_tail(model)
        outcomes[0] = _step(1)

        self.assertEqual(query("s", 0, 1, 1), 0)
        self.assertEqual(make_optimal_tail(model)("s", 0, 1, 1), 1)

    def test_caller_record_aliases_are_detached(self):
        # Even a caller deliberately bypassing the records' frozen facade
        # cannot mutate the private graph. The public counterexample above
        # only needs ordinary dictionary assignment, not this extra defense.
        for record_kind in ("action", "transition"):
            with self.subTest(record_kind=record_kind):
                transition = _step()
                action = Action("step", (transition,))
                model = _model((action,))
                query = make_optimal_tail(model)
                if record_kind == "action":
                    object.__setattr__(action, "outcomes", (_step(1),))
                else:
                    object.__setattr__(transition, "credit", 1)

                self.assertEqual(query("s", 0, 1, 1), 0)
                self.assertEqual(make_optimal_tail(model)("s", 0, 1, 1), 1)

    def test_invalid_captured_law_is_still_refused(self):
        model = _model((Action("invalid", (
            Transition(Fraction(1, 2), "s", 1, 0),
        )),))
        with self.assertRaisesRegex(ValueError, "sum to one exactly"):
            make_optimal_tail(model)

    def test_historical_static_report_is_unchanged(self):
        # Canonical complete report from Chain 7e044b65454f4c9ea505591727332acffb33e7e5.
        # build_report itself checks 6,156 adaptive cases and 324 independent
        # binomial laws. This digest additionally preserves every HOLD flag.
        report = build_report()
        canonical = json.dumps(report, default=_json_default, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
        self.assertEqual(hashlib.sha256(canonical).hexdigest(),
                         "9fd4114587446ce8a2d39aa11b06b7c37d866d436f15cc5d1deb79e03281453c")
        self.assertEqual(report["status"], "ABSTRACT_CERTIFICATE_ONLY_HOLD_FOR_W1")
        self.assertTrue(all(flag is False for flag in report["claim_flags"].values()))


if __name__ == "__main__":
    unittest.main()
