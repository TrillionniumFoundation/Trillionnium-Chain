#!/usr/bin/env python3
"""Negative controls for the frozen native log rosters."""
import unittest
from check_w1_native_roster import ROSTERS, check

def fixture(profile):
    r = ROSTERS[profile]
    ignored = set(r["ignored"])
    return "\n".join(f"test {name} ... " + ("ignored" if name in ignored else "ok")
                     for name in r["names"]) + f"\n\ntest result: ok. {len(r['names'])-len(ignored)} passed; 0 failed; {len(ignored)} ignored; 0 measured; 17 filtered out; finished in 0.02s\n"

class RosterTests(unittest.TestCase):
    def test_complete_rosters_and_observer_output(self):
        for p in ROSTERS:
            text = fixture(p)
            self.assertEqual(check(text, p)["named"], len(ROSTERS[p]["names"]))
            first = ROSTERS[p]["names"][0]
            self.assertEqual(check(text.replace(f"test {first} ... ok", f'test {first} ... {{"diagnostic":true}}\nok'), p)["named"], len(ROSTERS[p]["names"]))
    def test_missing_duplicate_and_substitution_refuse_even_with_success_summary(self):
        for p in ROSTERS:
            text = fixture(p)
            for name in ROSTERS[p]["names"]:
                outcome = "ignored" if name in ROSTERS[p]["ignored"] else "ok"
                line = f"test {name} ... {outcome}\n"
                for altered in (text.replace(line, "", 1), line + text,
                                text.replace(name, "substituted_test", 1)):
                    with self.subTest(profile=p, name=name), self.assertRaises(ValueError):
                        check(altered, p)
    def test_unknown_name_and_ignore_conversion_refuse(self):
        for p in ROSTERS:
            text = fixture(p)
            for altered in ("test extra ... ok\n"+text,
                            text.replace(" ... ok", " ... ignored", 1)):
                with self.subTest(profile=p), self.assertRaises(ValueError):
                    check(altered, p)
    def test_missing_duplicate_failed_and_wrong_count_summary_refuse(self):
        for p in ROSTERS:
            text=fixture(p); summary=text[text.index("test result:"):]
            for altered in (text[:text.index("test result:")], text+summary,
                            text.replace("test result: ok.", "test result: FAILED."),
                            text.replace("0 failed;", "1 failed;"),
                            text.replace("0 measured;", "1 measured;")):
                with self.subTest(profile=p), self.assertRaises(ValueError):
                    check(altered,p)
    def test_fixed_ignored_child_identity_cannot_move(self):
        text=fixture("history-import")
        ignored=ROSTERS["history-import"]["ignored"][0]
        text=text.replace(f"test {ignored} ... ignored", f"test {ignored} ... ok")
        text=text.replace(" ... ok", " ... ignored", 1)
        with self.assertRaises(ValueError): check(text,"history-import")
    def test_failed_outcome_cannot_use_success_summary(self):
        for p in ROSTERS:
            with self.assertRaises(ValueError):
                check(fixture(p).replace(" ... ok"," ... FAILED",1),p)

if __name__ == "__main__":
    unittest.main()
