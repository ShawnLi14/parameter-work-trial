import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secbench import lookup, pr_history
from secbench.catalog import load
from secbench.pr_history import build
from secbench.runner import checked_lock, run

ROOT = Path(__file__).resolve().parents[1]
LABEL = "GHSL-2023-232"


class LookupTests(unittest.TestCase):
    """Reviewers reach code only through lookups that never expose commit data."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        work = root / "work"
        self.git("init", str(work))
        (work / "src").mkdir()
        (work / "CHANGELOG.md").write_text("- Security fix (GHSL-2023-232)\n", encoding="utf-8")
        (work / "src" / "util.py").write_text("def clean(name):\n    return name.strip()\n", encoding="utf-8")
        (work / "app.py").write_text("from src.util import clean\ndef run(name):\n    return safe(clean(name))\n", encoding="utf-8")
        (work / "logo.bin").write_bytes(b"\0\1\2")
        self.base = self.commit(work, "Fix GHSL-2023-232 by removing shell")
        (work / "app.py").write_text("from src.util import clean\ndef run(name):\n    return shell('ls ' + clean(name))\n", encoding="utf-8")
        self.head = self.commit(work, "Reintroduce shell for GHSL-2023-232")
        repo = root / "cache" / "t001.git"
        repo.parent.mkdir()
        self.git("clone", "--bare", str(work), str(repo))
        entry = {"candidate_id": "fixture", "snapshot_case": "t001", "kind": "introduced_historical",
                 "label_ids": [LABEL], "base_commit": self.base, "head_commit": self.head, "confidence": "high",
                 "mechanism_at_commit": {LABEL: "name reaches a shell"}, "caveats": "",
                 "evidence": [{"label_id": LABEL, "commit": self.head, "path": "app.py", "line": 3,
                               "quote": "shell('ls ' + clean(name))", "fact": "sink"}],
                 "review": {"verdict": "confirmed"}}
        manifest = {"name": "fixture", "label_provenance": "fixture", "limitations": ["fixture"], "entries": [entry]}
        self.suite_dir = root / "suite"
        with mock.patch.object(pr_history, "fetch"):
            self.suite = build(load(), manifest, repo.parent, self.suite_dir)
        self.case = self.suite["cases"][0]
        self.lock = checked_lock(self.suite, self.case, self.suite_dir)
        self.catalog = self.suite_dir / "catalog.json"

    def git(self, *args):
        return subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=", *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, work, message):
        self.git("-C", str(work), "add", "-A")
        self.git("-C", str(work), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-m", message)
        return self.git("-C", str(work), "rev-parse", "HEAD")

    def assert_no_commit_data(self, result):
        blob = json.dumps(result)
        for secret in (self.base, self.head, self.base[:7], self.head[:7], "Reintroduce", "Fix GHSL"):
            self.assertNotIn(secret, blob)

    def test_read_each_side(self):
        head = lookup.read(self.lock, "head", "app.py")
        self.assertIn("shell('ls ' + clean(name))", head["lines"][2])
        base = lookup.read(self.lock, "base", "app.py", start=3, end=3)
        self.assertEqual(["    return safe(clean(name))"], base["lines"])
        self.assertEqual(3, base["total_lines"])
        self.assert_no_commit_data(head)

    def test_read_reports_binary_files_without_content(self):
        self.assertTrue(lookup.read(self.lock, "head", "logo.bin")["binary"])

    def test_search_finds_definitions_and_strips_commit_ids(self):
        result = lookup.search(self.lock, "head", r"def clean\(")
        self.assertEqual([{"path": "src/util.py", "line": 1, "text": "def clean(name):"}], result["matches"])
        self.assert_no_commit_data(result)
        self.assertEqual([], lookup.search(self.lock, "base", "shell")["matches"])
        self.assertEqual(1, len(lookup.search(self.lock, "head", "SHELL", ignore_case=True)["matches"]))
        self.assertEqual([], lookup.search(self.lock, "head", "clean", path="src")["matches"][1:])

    def test_list_shows_directories_and_files(self):
        entries = lookup.listing(self.lock, "head")["entries"]
        self.assertIn({"name": "src", "type": "dir"}, entries)
        self.assertIn({"name": "app.py", "type": "file"}, entries)
        self.assertEqual([{"name": "util.py", "type": "file"}], lookup.listing(self.lock, "base", "src")["entries"])

    def test_changelogs_stay_hidden(self):
        self.assertNotIn("CHANGELOG.md", json.dumps(lookup.listing(self.lock, "base")))
        self.assertEqual([], lookup.search(self.lock, "base", "GHSL")["matches"])
        with self.assertRaisesRegex(ValueError, "no such file"):
            lookup.read(self.lock, "base", "CHANGELOG.md")

    def test_rejects_paths_outside_the_repository_and_option_injection(self):
        for path in ("../secret", "/etc/passwd", "C:/x", "a\\b", "--output=x"):
            with self.assertRaises(ValueError):
                lookup.read(self.lock, "head", path)
        self.assertEqual([], lookup.search(self.lock, "head", "--no-index")["matches"])
        with self.assertRaisesRegex(ValueError, "side"):
            lookup.read(self.lock, "parent", "app.py")
        with self.assertRaisesRegex(ValueError, "no such file"):
            lookup.read(self.lock, "head", "missing.py")

    def test_reviewer_uses_lookup_command_from_its_request(self):
        agent = Path(self.tmp.name) / "agent.py"
        agent.write_text(
            "import json, subprocess, sys\n"
            "request = json.load(sys.stdin)\n"
            "assert 'source_dir' not in request and 'commit' not in request\n"
            "out = subprocess.run(request['lookup']['command'] + ['search', '--side', 'head', '--pattern', 'shell'],\n"
            "                     capture_output=True, text=True, check=True).stdout\n"
            "match = json.loads(out)['matches'][0]\n"
            "print(json.dumps({'findings': [{'title': 'Shell injection', 'description': 'name reaches shell',\n"
            "    'path': match['path'], 'line': match['line'], 'evidence': [match['text']]}]}))\n", encoding="utf-8")
        command = [sys.executable, "-m", "secbench", "--catalog", str(self.catalog), "lookup", "--work", str(self.suite_dir)]
        with mock.patch.dict(os.environ, {"PYTHONPATH": str(ROOT)}):
            row = run(self.suite, [self.case], self.suite_dir, [sys.executable, str(agent)], "probe", 60, command)["cases"][0]
        self.assertEqual("ok", row["status"], row.get("error"))
        self.assertEqual(("app.py", 3), (row["output"]["findings"][0]["path"], row["output"]["findings"][0]["line"]))
        self.assertFalse((self.suite_dir / "sources").exists())


if __name__ == "__main__":
    unittest.main()
