import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from secbench import judge, pr_history
from secbench.catalog import digest, load
from secbench.pr_history import build
from secbench.runner import validate_output
from secbench.scoring import score

LABEL = "GHSL-2023-232"
KEY = "apik-test-secret"


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        work = root / "work"
        self.git("init", str(work))
        (work / "app.py").write_text("def run(name):\n    return safe(name)\n", encoding="utf-8")
        base = self.commit(work)
        (work / "app.py").write_text("def run(name):\n    return shell('ls ' + name)\n", encoding="utf-8")
        head = self.commit(work)
        repo = root / "cache" / "t001.git"
        repo.parent.mkdir()
        self.git("clone", "--bare", str(work), str(repo))
        entry = {"candidate_id": "fixture", "snapshot_case": "t001", "kind": "introduced_historical",
                 "label_ids": [LABEL], "base_commit": base, "head_commit": head, "confidence": "high",
                 "mechanism_at_commit": {LABEL: "name reaches a shell"}, "caveats": "",
                 "also_valid": [{"label_id": None, "description": "Command output is logged", "evidence": "app.py:2"}],
                 "evidence": [{"label_id": LABEL, "commit": head, "path": "app.py", "line": 2,
                               "quote": "shell('ls ' + name)", "fact": "sink"}],
                 "review": {"verdict": "confirmed"}}
        manifest = {"name": "fixture", "label_provenance": "fixture", "limitations": ["fixture"], "entries": [entry]}
        self.work = root / "suite"
        with mock.patch.object(pr_history, "fetch"):
            self.suite = build(load(), manifest, repo.parent, self.work)
        self.case = self.suite["cases"][0]
        self.sent = []

    def git(self, *args):
        return subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=", *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, work):
        self.git("-C", str(work), "add", "-A")
        self.git("-C", str(work), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "x")
        return self.git("-C", str(work), "rev-parse", "HEAD")

    def results(self, *findings):
        output = validate_output({"findings": [dict({"title": "t", "description": "d", "path": "app.py", "line": 2,
                                                    "evidence": ["app.py:2"]}, **f) for f in findings]})
        return {"schema_version": 1, "catalog_sha256": digest(self.suite),
                "cases": [{"case_id": self.case["id"], "status": "ok", "output": output}]}

    def jev(self, *answers):
        replies = iter(answers)

        def send(payload, key):
            self.sent.append((payload, key))
            choice, confidence, supported = next(replies)
            return {"model": "jev-1.14.0", "answers": {
                "decision": {"choice": choice, "confidence": confidence, "probabilities": {choice: confidence}},
                "supported": {"noul": supported}}}
        return send

    def grade(self, results, *answers, threshold=0.7):
        return judge.grade(self.suite, results, self.work, key=KEY, threshold=threshold, send=self.jev(*answers))

    def test_confident_supported_target_is_a_match_and_scores(self):
        results = self.results({})
        grades = self.grade(results, ("target_1", 0.92, 0.9))
        self.assertEqual("match", grades["decisions"][0]["decision"])
        self.assertEqual(LABEL, grades["decisions"][0]["label_id"])
        self.assertIn("Jev", grades["adjudicator"])
        self.assertIn("jev-1.14.0", grades["adjudicator"])
        self.assertEqual(1, score(self.suite, results, grades)["target_recall"])

    def test_uncertain_or_unsupported_answers_stay_unresolved(self):
        for answer in (("target_1", 0.55, 0.9), ("target_1", 0.95, 0.2), ("other_issue", 0.99, 0.9), ("false_alarm", 0.5, 0.1)):
            grades = self.grade(self.results({}), answer)
            self.assertEqual("unresolved", grades["decisions"][0]["decision"], answer)
            self.assertIn("human review", grades["decisions"][0]["rationale"])

    def test_false_alarm_and_also_valid(self):
        grades = self.grade(self.results({}, {}), ("false_alarm", 0.9, 0.1), ("extra_1", 0.85, 0.8))
        self.assertEqual(["false_positive", "also_valid"], [d["decision"] for d in grades["decisions"]])
        self.assertEqual("av1", grades["decisions"][1]["also_valid_id"])

    def test_second_match_for_a_target_becomes_a_duplicate(self):
        results = self.results({}, {})
        grades = self.grade(results, ("target_1", 0.8, 0.9), ("target_1", 0.95, 0.9))
        self.assertEqual(["duplicate", "match"], [d["decision"] for d in grades["decisions"]])
        metrics = score(self.suite, results, grades)
        self.assertEqual((1, 1, 0.5), (metrics["true_positives"], metrics["duplicates"], metrics["precision"]))

    def test_finding_in_a_missing_file_is_rejected_without_calling_jev(self):
        grades = self.grade(self.results({"path": "nowhere.py"}))
        self.assertEqual("false_positive", grades["decisions"][0]["decision"])
        self.assertEqual([], self.sent)

    def test_jev_sees_the_finding_and_code_but_no_answers_or_key(self):
        self.grade(self.results({"title": "Shell injection in run"}), ("target_1", 0.9, 0.9))
        payload, key = self.sent[0]
        self.assertEqual(KEY, key)
        state = payload["state"]
        self.assertIn("Shell injection in run", state)
        self.assertIn("2:     return shell('ls ' + name)", state)
        self.assertIn("+    return shell('ls ' + name)", state)
        blob = json.dumps(payload)
        self.assertNotIn(KEY, blob)
        self.assertNotIn(self.case["ref"], blob)
        self.assertEqual({"target_1", "extra_1", "false_alarm", "other_issue"}, set(payload["questions"]["decision"]["criteria"]))

    def test_key_comes_from_environment_and_errors_never_echo_it(self):
        with mock.patch.dict(os.environ, {"JEV_API_KEY": "from-env"}):
            self.assertEqual("from-env", judge.api_key())

    def test_failed_and_empty_cases_are_skipped(self):
        results = self.results()
        results["cases"].append({"case_id": "h999", "status": "error", "error": "timeout"})
        self.assertEqual([], self.grade(results)["decisions"])


if __name__ == "__main__":
    unittest.main()
