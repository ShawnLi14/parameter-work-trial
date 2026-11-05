import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from benchmark import pr_history
from benchmark.catalog import digest, load
from benchmark.pr_history import build, changed_code_lines, check_entry, coverage, load_manifest
from benchmark.runner import case_trees, checked_lock, run, task
from benchmark.scoring import grade_template, score

ROOT = Path(__file__).resolve().parents[1]
LABEL = "GHSL-2023-232"
SECOND_LABEL = "GHSL-2023-245"


class HistoricalFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        # Reproduce a host where Git would rewrite line endings on export.
        config = root / "gitconfig"
        config.write_text("[core]\n\tautocrlf = true\n", encoding="utf-8")
        patcher = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.repo = root / "cache" / "t001.git"
        self.work = root / "work"
        self.git("init", str(self.work))
        self.c0 = self.commit("app.py", "def run(name):\n    return safe(name)\n")
        self.c1 = self.commit("app.py", "def run(name):\n    return shell('ls ' + name)\n")
        self.c2 = self.commit("app.py", "def run(name):\n    return shell('ls -l ' + name)\n")
        self.c3 = self.commit("app.py", "# Explains run.\ndef run(name):\n    return shell('ls -l ' + name)\n")
        (self.work / "docs").mkdir()
        (self.work / "docs" / "CHANGELOG.md").write_text("- Security fix (GHSL-2023-232)\n", encoding="utf-8")
        (self.work / "vendor" / "assets").mkdir(parents=True)
        (self.work / "vendor" / "assets" / "lib.js").write_text("var vendored = 1;\n", encoding="utf-8")
        (self.work / "yarn.lock").write_text("lockfile\n", encoding="utf-8")
        (self.work / "app.min.js").write_text("minified\n", encoding="utf-8")
        self.c4 = self.commit("app.py", "def run(name):\n    return shell('ls -la ' + name)\n")
        self.repo.parent.mkdir(parents=True)
        self.git("clone", "--bare", str(self.work), str(self.repo))

    def git(self, *args):
        return subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=", *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, name, content):
        (self.work / name).write_bytes(content.encode())
        self.git("-C", str(self.work), "add", "-A")
        self.git("-C", str(self.work), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-m", "fixture")
        return self.git("-C", str(self.work), "rev-parse", "HEAD")

    def entry(self, **changes):
        entry = {"candidate_id": "fixture-positive", "snapshot_case": "t001", "kind": "introduced_historical",
                 "label_ids": [LABEL], "base_commit": self.c0, "head_commit": self.c1, "confidence": "high",
                 "mechanism_at_commit": {LABEL: "name reaches a shell command"}, "caveats": "",
                 "evidence": [{"label_id": LABEL, "commit": self.c1, "path": "app.py", "line": 2, "quote": "shell('ls ' + name)", "fact": "sink"}],
                 "review": {"verdict": "confirmed"}}
        entry.update(changes)
        return entry

    def control(self):
        return self.entry(candidate_id="fixture-control", kind="benign_nearby", label_ids=[], base_commit=self.c1,
                          head_commit=self.c2, mechanism_at_commit=None, evidence=[])

    def manifest(self, *entries):
        return {"name": "fixture", "label_provenance": "fixture", "limitations": ["fixture"], "entries": list(entries)}

    def built(self):
        with mock.patch.object(pr_history, "fetch"):
            return build(load(), self.manifest(self.entry(), self.control()), self.repo.parent, Path(self.tmp.name) / "suite")

    def test_rejects_a_pair_that_is_not_parent_and_child(self):
        with self.assertRaisesRegex(ValueError, "first parent"):
            check_entry(self.repo, self.entry(base_commit=self.c0, head_commit=self.c2,
                evidence=[{"label_id": LABEL, "commit": self.c2, "path": "app.py", "line": 2, "quote": "shell", "fact": "x"}]))

    def test_rejects_a_quote_absent_from_the_commit(self):
        evidence = [{"label_id": LABEL, "commit": self.c1, "path": "app.py", "line": 2, "quote": "os.system(name)", "fact": "invented"}]
        with self.assertRaisesRegex(ValueError, "quote not found"):
            check_entry(self.repo, self.entry(evidence=evidence))

    def test_absence_claims_must_be_true(self):
        entry = self.entry(absence_claims=[{"commit": self.c0, "path": "app.py", "string": "shell("},
                                           {"commit": self.c0, "path": "missing.py", "string": None}])
        check_entry(self.repo, entry)
        for claim in ({"commit": self.c0, "path": "app.py", "string": "safe(name)"},
                      {"commit": self.c0, "path": "app.py", "string": None}):
            with self.assertRaisesRegex(ValueError, "claimed absent"):
                check_entry(self.repo, self.entry(absence_claims=[claim]))
        outside = {"commit": self.c2, "path": "app.py", "string": "nothing"}
        with self.assertRaisesRegex(ValueError, "outside this pair"):
            check_entry(self.repo, self.entry(absence_claims=[outside]))

    def test_rejects_evidence_only_at_base_for_a_positive(self):
        evidence = [{"label_id": LABEL, "commit": self.c0, "path": "app.py", "line": 2, "quote": "safe(name)", "fact": "base"}]
        with self.assertRaisesRegex(ValueError, "own evidence at head"):
            check_entry(self.repo, self.entry(evidence=evidence))

    def test_rejects_comment_only_controls(self):
        control = self.control()
        control.update(base_commit=self.c2, head_commit=self.c3)
        with self.assertRaisesRegex(ValueError, "changes no code"):
            check_entry(self.repo, control)

    def test_rejects_unconfirmed_entries(self):
        for verdict in ("rejected", "partial"):
            with self.assertRaisesRegex(ValueError, "only confirmed"):
                check_entry(self.repo, self.entry(review={"verdict": verdict}))

    def test_rejects_a_control_with_a_known_issue(self):
        control = self.control()
        control["also_valid"] = [{"label_id": None, "description": "new flaw", "evidence": "app.py:2"}]
        with self.assertRaisesRegex(ValueError, "not a control"):
            check_entry(self.repo, control)

    def test_also_valid_findings_are_neither_hits_nor_errors(self):
        positive = self.entry(also_valid=[{"label_id": None, "description": "extra flaw", "evidence": "app.py:2"}])
        with mock.patch.object(pr_history, "fetch"):
            suite = build(load(), self.manifest(positive), self.repo.parent, Path(self.tmp.name) / "suite")
        case = suite["cases"][0]
        finding = {"id": "f0001", "title": "t", "description": "d", "path": "app.py", "line": 2, "evidence": ["e"]}
        results = {"catalog_sha256": digest(suite), "cases": [{"case_id": case["id"], "status": "ok",
                   "output": {"findings": [finding, dict(finding, id="f0002")]}}]}
        grades = grade_template(results)
        grades["adjudicator"] = "test reviewer"
        grades["decisions"][0].update(decision="match", label_id=LABEL, rationale="ok")
        grades["decisions"][1].update(decision="also_valid", also_valid_id="av1", rationale="ok")
        metrics = score(suite, results, grades)
        self.assertEqual(1, metrics["also_valid_findings"])
        self.assertEqual(0, metrics["adjudicated_false_positives"])
        self.assertEqual(1, metrics["target_recall"])
        self.assertEqual(1, metrics["precision"])
        grades["decisions"][1]["also_valid_id"] = "av9"
        with self.assertRaisesRegex(ValueError, "also_valid_id"):
            score(suite, results, grades)

    def test_rejects_control_carrying_a_label(self):
        control = self.control()
        control["label_ids"] = [LABEL]
        with self.assertRaisesRegex(ValueError, "controls must not"):
            check_entry(self.repo, control)

    def test_fix_reverted_reverses_the_parent_relationship(self):
        entry = self.entry(kind="fix_reverted", base_commit=self.c1, head_commit=self.c0,
                           evidence=[{"label_id": LABEL, "commit": self.c0, "path": "app.py", "line": 2, "quote": "safe(name)", "fact": "x"}])
        check_entry(self.repo, entry)

    def test_each_target_in_a_shared_pr_needs_its_own_evidence(self):
        entry = self.entry(label_ids=[LABEL, SECOND_LABEL],
                           mechanism_at_commit={LABEL: "a", SECOND_LABEL: "b"})
        with self.assertRaisesRegex(ValueError, SECOND_LABEL + " needs its own evidence"):
            check_entry(self.repo, entry)
        entry["evidence"] = entry["evidence"] + [dict(entry["evidence"][0], label_id=SECOND_LABEL)]
        check_entry(self.repo, entry)
        del entry["mechanism_at_commit"][SECOND_LABEL]
        with self.assertRaisesRegex(ValueError, "needs a mechanism"):
            check_entry(self.repo, entry)

    def test_coverage_accounts_for_every_target(self):
        manifest = self.manifest(self.entry(label_ids=[LABEL, SECOND_LABEL]))
        manifest["unusable_targets"] = [{"label_id": "GHSL-2023-234", "reason": "Introduced in the initial import"}]
        report = coverage(load(), manifest)
        self.assertEqual((49, 2), (report["target_count"], report["covered"]))
        self.assertEqual(46, len(report["unaccounted"]))
        self.assertNotIn("GHSL-2023-234", report["unaccounted"])
        with self.assertRaisesRegex(ValueError, "more than one PR"):
            coverage(load(), self.manifest(self.entry(), self.entry(candidate_id="again")))
        manifest["unusable_targets"] = [{"label_id": LABEL, "reason": "contradiction"}]
        with self.assertRaisesRegex(ValueError, "both covered and unusable"):
            coverage(load(), manifest)

    def test_changelogs_are_left_out_of_the_diff(self):
        control = self.control()
        control.update(base_commit=self.c3, head_commit=self.c4)
        diff, files, _ = check_entry(self.repo, control)
        # The skipped files really are in this commit, so the test is not vacuous.
        changed = self.git("-C", str(self.repo), "diff", "--name-only", self.c3, self.c4).split()
        self.assertTrue({"docs/CHANGELOG.md", "vendor/assets/lib.js", "yarn.lock", "app.min.js"} <= set(changed))
        self.assertNotIn(b"GHSL", diff)
        self.assertNotIn(b"CHANGELOG", diff)
        for skipped in (b"vendored", b"lockfile", b"minified"):
            self.assertNotIn(skipped, diff)
        self.assertIn(b"ls -la", diff)
        self.assertEqual(1, files)

    def test_comment_filter_keeps_code_lines(self):
        diff = "--- a/x\n+++ b/x\n+# note\n+\n-// old\n+run()\n"
        self.assertEqual(["+run()"], changed_code_lines(diff))

    def test_numbering_does_not_depend_on_manifest_order(self):
        first = pr_history.opaque_order([self.entry(), self.control()])
        second = pr_history.opaque_order([self.control(), self.entry()])
        self.assertEqual(first, second)

    def test_rejects_repeated_pairs(self):
        path = Path(self.tmp.name) / "manifest.json"
        path.write_text(json.dumps(self.manifest(self.entry(), self.entry())), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "repeats"):
            load_manifest(path)

    def test_built_suite_end_to_end(self):
        suite = self.built()
        destination = Path(self.tmp.name) / "suite"
        load(destination / "catalog.json")
        by_variant = {c["variant"]: c for c in suite["cases"]}
        positive = by_variant["introduced_historical"]
        self.assertEqual(self.c1, positive["labels"][0]["introducing_commit"])
        self.assertEqual("name reaches a shell command", positive["labels"][0]["mechanism"])
        # Nothing is unpacked until a case is reviewed.
        self.assertFalse((destination / "sources").exists())
        self.assertFalse((destination / "bases").exists())
        # Commits stay referenced, so Git's cleanup cannot delete them from the store.
        self.git("-C", str(self.repo), "rev-parse", "--verify", f"refs/benchmark/{self.c1}")
        # Trees keep upstream bytes despite autocrlf=true on this "host".
        lock = checked_lock(suite, positive, destination)
        with case_trees(lock):
            content = (destination / "sources" / positive["id"] / "app.py").read_bytes()
            self.assertNotIn(b"\r\n", content)
            self.assertEqual(b"def run(name):\n    return shell('ls ' + name)\n", content)
            self.assertIn(b"safe(name)", (destination / "bases" / positive["id"] / "app.py").read_bytes())
        self.assertFalse((destination / "sources" / positive["id"]).exists())
        self.assertFalse((destination / "bases" / positive["id"]).exists())

        for case in suite["cases"]:
            request = task(suite, case, destination)
            blob = json.dumps(request)
            for secret in ("labels", "variant", "commit\"", "upstream_pr", self.c0, self.c1, self.c2, LABEL):
                self.assertNotIn(secret, blob)
            self.assertTrue(request["diff"])
            self.assertNotIn("source_dir", request)
            self.assertIn("lookup", request)

        agent = ROOT / "tests" / "empty_agent.py"
        results = run(suite, suite["cases"], destination, [sys.executable, str(agent)], "smoke", 20)
        self.assertEqual({c["ref"] for c in suite["cases"]}, {r["commit"] for r in results["cases"]})
        self.assertTrue(all(r["status"] == "ok" for r in results["cases"]))
        self.assertEqual([], list((destination / "sources").iterdir()))
        unpacked = run(suite, suite["cases"], destination, [sys.executable, str(agent)], "smoke", 20, unpack=True)
        self.assertTrue(all(r["status"] == "ok" and r["base_tree_sha256"] for r in unpacked["cases"]))
        self.assertEqual([], list((destination / "sources").iterdir()))
        self.assertEqual([], list((destination / "bases").iterdir()))
        metrics = score(suite, results, grade_template(results))
        self.assertEqual(0, metrics["by_variant"]["introduced_historical"]["recall"])
        self.assertEqual(0, metrics["by_variant"]["benign_nearby"]["alarm_rate"])

        # A flagged control counts against its own variant, and only there.
        row = next(r for r in results["cases"] if r["case_id"] == by_variant["benign_nearby"]["id"])
        row["output"]["findings"] = [{"id": "f0001", "title": "Claim", "description": "Claim", "path": "app.py",
                                      "line": 2, "evidence": ["app.py:2"]}]
        grades = grade_template(results)
        grades["adjudicator"] = "test reviewer"
        grades["decisions"][0].update(decision="false_positive", rationale="Diff adds only a flag")
        metrics = score(suite, results, grades)
        self.assertEqual(1, metrics["by_variant"]["benign_nearby"]["alarm_rate"])
        self.assertIsNone(metrics["by_variant"]["introduced_historical"]["alarm_rate"])

        # The reviewer sees the unpacked trees, and cannot silently change them.
        probe = Path(self.tmp.name) / "probe.py"
        probe.write_text("import json, sys\nrequest = json.load(sys.stdin)\n"
                         "open('app.py', 'rb').read()\nopen(request['base_source_dir'] + '/app.py', 'rb').read()\n"
                         "print(json.dumps({'findings': []}))\n", encoding="utf-8")
        self.assertEqual("ok", run(suite, [positive], destination, [sys.executable, str(probe)], "probe", 20, unpack=True)["cases"][0]["status"])
        writer = Path(self.tmp.name) / "writer.py"
        writer.write_text("import json, sys\njson.load(sys.stdin)\nopen('app.py', 'w').write('changed')\n"
                          "print(json.dumps({'findings': []}))\n", encoding="utf-8")
        row = run(suite, [positive], destination, [sys.executable, str(writer)], "writer", 20, unpack=True)["cases"][0]
        self.assertEqual("error", row["status"])
        self.assertIn("modified", row["error"])
        self.assertFalse((destination / "sources" / positive["id"]).exists())

        patch = destination / "diffs" / (positive["id"] + ".patch")
        patch.write_bytes(patch.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValueError, "modified"):
            task(suite, positive, destination)


if __name__ == "__main__":
    unittest.main()
