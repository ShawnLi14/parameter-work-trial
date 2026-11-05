import json
import os
import unittest
from unittest import mock

from benchmark import judge
from benchmark.catalog import digest
from benchmark.runner import validate_output
from benchmark.scoring import score

KEY = "apik-test-secret"


def label(i):
    return {"id": f"GHSL-2099-{i:03}", "title": f"Bug {i}", "mechanism": f"mechanism {i}", "location_hint": "app.py",
            "evidence_required": ["x"], "source": "https://securitylab.github.com/advisories/x"}


SUITE = {"schema_version": 1, "cases": [
    {"id": "h001", "mode": "pr", "split": "dev", "leakage_group": "g", "construction": "historical_commit_pair",
     "validation": "source_reviewed", "variant": "introduced_historical", "labels": [label(1), label(2)],
     "also_valid": [{"id": "av1", "label_id": None, "description": "Output is logged", "evidence": "app.py:3"}]},
    {"id": "h002", "mode": "pr", "split": "dev", "leakage_group": "g", "construction": "historical_commit_pair",
     "validation": "source_reviewed", "variant": "benign_nearby", "labels": [], "also_valid": []}]}


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.sent = []

    def results(self, **findings_by_case):
        cases = []
        for case_id, count in findings_by_case.items():
            findings = [{"title": f"Finding {i}", "description": f"Explanation {i}", "path": "app.py", "line": 2,
                         "evidence": ["app.py:2"]} for i in range(count)]
            cases.append({"case_id": case_id, "status": "ok", "output": validate_output({"findings": findings})})
        return {"schema_version": 1, "catalog_sha256": digest(SUITE), "cases": cases}

    def grade(self, results, answers, threshold=0.7):
        def send(payload, key):
            self.sent.append((payload, key))
            return {"model": "jev-1.14.0", "answers": {fid: {"choice": c, "confidence": p, "probabilities": {c: p}}
                                                       for fid, (c, p) in answers.pop(0).items()}}
        return judge.grade(SUITE, results, key=KEY, threshold=threshold, send=send)

    def test_one_call_per_case_with_every_finding_and_known_bug(self):
        self.grade(self.results(h001=2), [{"f0001": ("bug_1", 0.9), "f0002": ("none", 0.9)}])
        self.assertEqual(1, len(self.sent))
        payload, key = self.sent[0]
        self.assertEqual(KEY, key)
        self.assertEqual({"f0001", "f0002"}, set(payload["questions"]))
        self.assertEqual({"bug_1", "bug_2", "extra_1", "none"}, set(payload["questions"]["f0001"]["criteria"]))
        for text in ("Explanation 0", "Explanation 1", "mechanism 1", "mechanism 2", "Output is logged"):
            self.assertIn(text, payload["state"])
        self.assertNotIn(KEY, json.dumps(payload))

    def test_choices_map_to_decisions_and_score(self):
        results = self.results(h001=3)
        grades = self.grade(results, [{"f0001": ("bug_2", 0.9), "f0002": ("extra_1", 0.8), "f0003": ("none", 0.95)}])
        self.assertEqual(["match", "also_valid", "false_positive"], [d["decision"] for d in grades["decisions"]])
        self.assertEqual("GHSL-2099-002", grades["decisions"][0]["label_id"])
        self.assertEqual("av1", grades["decisions"][1]["also_valid_id"])
        self.assertIn("jev-1.14.0", grades["adjudicator"])
        metrics = score(SUITE, results, grades)
        self.assertEqual((0.5, 0.5, 1), (metrics["target_recall"], metrics["precision"], metrics["also_valid_findings"]))

    def test_low_confidence_stays_unresolved(self):
        grades = self.grade(self.results(h001=1), [{"f0001": ("bug_1", 0.6)}])
        self.assertEqual("unresolved", grades["decisions"][0]["decision"])
        self.assertIn("human review", grades["decisions"][0]["rationale"])

    def test_second_match_for_a_bug_becomes_a_duplicate(self):
        results = self.results(h001=2)
        grades = self.grade(results, [{"f0001": ("bug_1", 0.8), "f0002": ("bug_1", 0.95)}])
        self.assertEqual(["duplicate", "match"], [d["decision"] for d in grades["decisions"]])
        self.assertEqual((1, 1), (score(SUITE, results, grades)["true_positives"], score(SUITE, results, grades)["duplicates"]))

    def test_findings_on_a_control_can_only_be_false_alarms(self):
        grades = self.grade(self.results(h002=1), [{"f0001": ("none", 0.9)}])
        self.assertEqual({"none"}, set(self.sent[0][0]["questions"]["f0001"]["criteria"]))
        self.assertIn("not known to introduce a vulnerability", self.sent[0][0]["state"])
        self.assertEqual("false_positive", grades["decisions"][0]["decision"])

    def test_failed_and_empty_cases_make_no_calls(self):
        results = self.results(h001=0)
        results["cases"].append({"case_id": "h002", "status": "error", "error": "timeout"})
        self.assertEqual([], self.grade(results, [])["decisions"])
        self.assertEqual([], self.sent)

    def test_key_comes_from_the_environment(self):
        with mock.patch.dict(os.environ, {"JEV_API_KEY": "from-env"}):
            self.assertEqual("from-env", judge.api_key())


if __name__ == "__main__":
    unittest.main()
