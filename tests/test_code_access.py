import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers import DIFF, HEAD_LINE
from reviewer.code_access import CodeAccess, lookup_problem, pin_pr_base, validate_action
from reviewer.evidence import Evidence
from reviewer.tools import check_citations, numbered_diff, rate_limit_wait, shown


def citation(side="head", path="app.py", line=5, quote="shell=True"):
    return {"side": side, "path": path, "line": line, "quote": quote}


class CodeAccessTests(unittest.TestCase):
    def test_local_lookups_are_bounded_cached_and_hide_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text("one\nneedle\nthree\n", encoding="utf-8")
            (root / ".env").write_text("SECRET=needle", encoding="utf-8")
            access = CodeAccess({"source_dir": temp, "base_source_dir": temp})
            args = {"side": "head", "path": "app.py", "start": 2, "end": 2}
            result = access.lookup("read", args)
            self.assertEqual(result["lines"], ["needle"])
            result["lines"].append("corrupt cache")
            (root / "app.py").write_text("mutated tree", encoding="utf-8")
            self.assertEqual(access.lookup("read", args)["lines"], ["needle"])
            self.assertEqual(access.lookup("list", {"side": "head"})["entries"], [{"name": "app.py", "type": "file"}])
            self.assertEqual(access.lookup("search", {"side": "head", "pattern": "needle"})["matches"], [])
            for path in ("../outside", "/absolute", "C:/outside", ".env", ".ENV", ".git/config", "x/.env.key"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    access.lookup("read", {**args, "path": path})
        with self.assertRaises(ValueError):
            validate_action("read", {"side": "head", "path": "app.py", "start": 1, "end": 201})
        with self.assertRaises(ValueError):
            validate_action("shell", {"command": "anything"})

    def test_benchmark_adapter_reconstructs_executable_and_uses_argument_array(self):
        command = ["DO-NOT-EXECUTE", "-m", "benchmark", "--catalog", "cases.json", "lookup", "--work", "suite", "--case", "h001"]
        access = CodeAccess({"lookup": {"command": command}})
        with patch("reviewer.code_access.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout='{"matches": []}')) as run:
            access.lookup("search", {"side": "base", "pattern": "$(hostile)", "path": "src"})
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], sys.executable)
        self.assertIn("$(hostile)", argv)
        self.assertFalse(run.call_args.kwargs["shell"])
        with self.assertRaises(ValueError):
            CodeAccess({"lookup": {"command": ["powershell", "arbitrary command"]}})

    def test_github_base_uses_merge_base_and_reads_fixed_revision(self):
        request = {"pr": {"repository": "a/b", "base_sha": "a"*40, "head_sha": "b"*40}}
        with patch("reviewer.code_access.request_json", return_value={"merge_base_commit": {"sha": "c"*40}}):
            pin_pr_base(request)
        with patch("reviewer.code_access.request_json", return_value={"type": "file", "encoding": "base64", "size": 2, "content": "eAo="}) as get:
            result = CodeAccess(request).lookup("read", {"side": "base", "path": "app.py", "start": 1, "end": 1})
        self.assertEqual(result["lines"], ["x"])
        self.assertIn("?ref=" + "c"*40, get.call_args.args[0])

    def test_evidence_tracks_additions_deletions_and_renames(self):
        added = Evidence("--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+new()\n")
        self.assertEqual(added.versions["new.py"], {"head": "new.py"})
        deleted = Evidence("--- a/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-old()\n")
        self.assertEqual(deleted.versions["old.py"], {"base": "old.py"})
        renamed = Evidence("--- a/old.py\n+++ b/new.py\n@@ -1 +1 @@\n-old()\n+new()\n")
        self.assertEqual(renamed.versions["new.py"], {"base": "old.py", "head": "new.py"})
        self.assertEqual(renamed.citations([citation("base", "old.py", 1, "old()")]), {("base", "old.py", 1)})


class ToolHelperTests(unittest.TestCase):
    def test_citation_errors_name_the_problem(self):
        ledger = Evidence(DIFF)
        _, errors = check_citations(ledger, [{**HEAD_LINE, "line": 99}, {**HEAD_LINE, "quote": "nope"}, HEAD_LINE])
        self.assertIn("never observed", errors[0])
        self.assertIn("which reads", errors[1])
        self.assertEqual(2, len(errors))

    def test_shown_numbers_read_lines_only(self):
        self.assertEqual(["7| x"], shown({"start": 7, "lines": ["x"]})["lines"])
        self.assertEqual({"matches": []}, shown({"matches": []}))

    def test_lookup_problems_are_specific_and_hide_revisions(self):
        self.assertIn("escape regex", lookup_problem("benchmark: search failed: fatal: -e option, 'open(': Unmatched ( or \\("))
        self.assertEqual("no such file: tools/x.py", lookup_problem("benchmark: no such file: tools/x.py"))
        self.assertNotIn("434ad28", lookup_problem("fatal: missing in 434ad280362ff21e10e41d7f6fde55c0f776c313"))

    def test_numbered_diff_labels_each_line_with_its_citable_side(self):
        lines = numbered_diff(DIFF).splitlines()
        self.assertTrue(any(line.startswith("[base 5] -    return subprocess.check_output") for line in lines))
        self.assertTrue(any(line.startswith("[head 5] +") for line in lines))
        self.assertIn("[head 1]  import subprocess", lines)

    def test_only_rate_limits_are_retryable(self):
        self.assertEqual(59, rate_limit_wait("HTTP 429 from api.cerebras.ai; Retry-After: 59"))
        self.assertEqual(10, rate_limit_wait("HTTP 429 from api.example"))
        self.assertIsNone(rate_limit_wait("HTTP 500 from api.example"))


if __name__ == "__main__":
    unittest.main()
