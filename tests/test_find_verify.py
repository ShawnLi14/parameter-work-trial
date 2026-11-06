import contextlib
import io
import json
import unittest
from unittest.mock import patch

from benchmark.runner import validate_output
from reviewer.cli import main
from reviewer.find_verify import (FindVerifyLimits, check_candidate, finder_payload, load_profile, profile_sha256,
                                  review, verifier_prompt)
from reviewer.evidence import Evidence
from helpers import BASE_LINE, CONTEXT, DIFF, HEAD_LINE, INPUT_LINE, ROOT, FakeAccess, sent, tool_reply, tools
from reviewer.inputs import context_from_request

CANDIDATE = {"title": "Command injection", "severity": "high", "path": "app.py", "line": 5, "side": "head",
             "description": "Query input is concatenated into a shell command."}


def report(*items):
    return ("report", {"findings": list(items)})


def verdict(value="confirmed", evidence=(HEAD_LINE, INPUT_LINE, BASE_LINE)):
    return ("verdict", {"verdict": value, "reason": "name flows from the query into shell=True",
                        "evidence": list(evidence)})


def lookup(path="routes.py", start=1):
    return ("lookup", {"question": "Is the route public?", "tool": "read",
                       "args": {"side": "head", "path": path, "start": start, "end": start + 1}})


def run(replies, access=None, **limits):
    with patch("reviewer.find_verify.request_json", side_effect=replies) as client:
        result = review(CONTEXT, "key", access=access or FakeAccess(), limits=FindVerifyLimits(concurrency=1, **limits))
    return result, client


class FindVerifyTests(unittest.TestCase):
    def test_confirmed_candidate_becomes_a_finding(self):
        result, client = run([tools(lookup()), tools(report(CANDIDATE)), tools(verdict())])
        self.assertEqual(1, len(result["findings"]))
        finding = result["findings"][0]
        self.assertIn("Verification:", finding["description"])
        self.assertIn("head app.py:5: shell=True", finding["evidence"])
        self.assertEqual("completed", result["metadata"]["status"])
        validate_output(json.loads(json.dumps(result)))
        finder = sent(client, 0)
        self.assertEqual({"lookup", "report"}, {t["function"]["name"] for t in finder["tools"]})
        self.assertIn("[head 5]", finder["messages"][1]["content"])  # line-numbered diff
        verifier = sent(client, 2)
        self.assertEqual({"lookup", "verdict"}, {t["function"]["name"] for t in verifier["tools"]})
        self.assertEqual(CANDIDATE["title"], json.loads(verifier["messages"][1]["content"])["reported_vulnerability"]["title"])

    def test_rejected_and_uncertain_candidates_are_not_findings(self):
        second = {**CANDIDATE, "title": "Something else", "line": 4}
        result, _ = run([tools(report(CANDIDATE, second)), tools(verdict("rejected", [HEAD_LINE])),
                         tools(verdict("uncertain", ()))])
        self.assertEqual([], result["findings"])
        self.assertEqual(["rejected", "uncertain"], [v["verdict"] for v in result["verifications"]])
        self.assertEqual("partial", result["metadata"]["status"])

    def test_no_candidates_is_a_clean_empty_review(self):
        result, client = run([tools(report())])
        self.assertEqual(([], "completed"), (result["findings"], result["metadata"]["status"]))
        self.assertEqual(1, client.call_count)

    def test_finder_can_run_several_lookups_in_one_turn(self):
        access = FakeAccess()
        result, client = run([tools(lookup("a.py"), lookup("b.py")), tools(report())], access=access)
        self.assertEqual(2, len(access.calls))
        self.assertTrue(sent(client, 0)["parallel_tool_calls"])

    def test_report_off_the_diff_goes_back_to_the_finder(self):
        result, client = run([tools(report({**CANDIDATE, "line": 99})), tools(report(CANDIDATE)), tools(verdict())])
        self.assertIn("not a line in the diff", tool_reply(client, 1)["problems"][0])
        self.assertEqual(1, len(result["findings"]))

    def test_report_with_other_calls_is_not_executed(self):
        result, client = run([tools(lookup(), report(CANDIDATE)), tools(report(CANDIDATE)), tools(verdict())])
        self.assertIn("call report alone", tool_reply(client, 1, "c1")["error"])
        self.assertEqual(1, len(result["candidates"]))

    def test_verifier_must_cite_observed_code_and_can_fix_it(self):
        made_up = {**HEAD_LINE, "quote": "os.system(name)"}
        result, client = run([tools(report(CANDIDATE)), tools(verdict(evidence=[made_up])), tools(verdict())])
        self.assertIn("quote not found", tool_reply(client, 2)["problems"][0])
        self.assertEqual(1, len(result["verifications"][0]["rejections"]))
        self.assertEqual(1, len(result["findings"]))

    def test_confirmed_needs_a_changed_line(self):
        context_line = {"side": "head", "path": "app.py", "line": 1, "quote": "import subprocess"}
        result, _ = run([tools(report(CANDIDATE)), tools(verdict(evidence=[context_line]))], verifier_calls=1)
        self.assertEqual([], result["findings"])
        self.assertEqual("rejected_verdict", result["verifications"][0]["stop_reason"])

    def test_verifier_can_read_code_it_cites(self):
        cite = {"side": "head", "path": "routes.py", "line": 2, "quote": "def route()"}
        result, _ = run([tools(report(CANDIDATE)), tools(lookup()), tools(verdict(evidence=[HEAD_LINE, cite]))])
        self.assertEqual(1, len(result["findings"]))

    def test_text_reply_gets_a_reminder_not_a_failure(self):
        text = {"choices": [{"finish_reason": "length", "message": {"content": '{"verdict":"confirmed","reason":"cut off'}}]}
        result, client = run([tools(report(CANDIDATE)), text, tools(verdict())])
        self.assertIn("calling a tool", sent(client, 2)["messages"][-1]["content"])
        self.assertEqual(1, len(result["findings"]))

    def test_repeated_lookup_is_refused_without_ending_the_review(self):
        access = FakeAccess()
        result, client = run([tools(lookup()), tools(lookup()), tools(report())], access=access)
        self.assertEqual(1, len(access.calls))
        self.assertIn("already ran", tool_reply(client, 2)["error"])

    def test_rate_limit_is_retried_after_the_requested_wait(self):
        limited = ValueError("HTTP 429 from api.example; Retry-After: 2")
        with patch("reviewer.find_verify.time.sleep") as sleep:
            result, _ = run([limited, tools(report(CANDIDATE)), tools(verdict())])
        sleep.assert_called_once_with(2)
        self.assertEqual(1, len(result["findings"]))

    def test_other_http_errors_are_not_retried(self):
        with patch("reviewer.find_verify.time.sleep") as sleep:
            result, _ = run([ValueError("HTTP 500 from api.example")])
        sleep.assert_not_called()
        self.assertEqual("error", result["metadata"]["status"])

    def test_model_input_excludes_harness_fields(self):
        request = {"mode": "pr", "diff": DIFF, "labels": ["SECRET-LABEL"], "task_id": "SECRET-TASK",
                   "source_dir": "SECRET-DIRECTORY", "instructions": "SECRET-INSTRUCTIONS"}
        self.assertNotIn("SECRET", json.dumps(finder_payload(context_from_request(request))))

    def test_finder_failure_is_an_error(self):
        result, _ = run([ValueError("HTTP 500 from api.example")])
        self.assertEqual("error", result["metadata"]["status"])

    def test_candidate_check(self):
        lines = Evidence(DIFF).lines
        self.assertEqual("head", check_candidate(CANDIDATE, lines)["side"])
        for bad in ({**CANDIDATE, "severity": "huge"}, {**CANDIDATE, "title": ""}, {**CANDIDATE, "side": "middle"}):
            with self.assertRaises(ValueError):
                check_candidate(bad, lines)

    def test_specialists_run_by_trigger_and_candidates_merge_by_location(self):
        profile = {**load_profile(), "specialists": [
            {"name": "injection", "focus": "Shell command injection.", "guidance": "Look for shell=True.",
             "triggers": [r"shell\s*=\s*True"]},
            {"name": "crypto", "focus": "Weak cryptography.", "guidance": "Look for ECB.", "triggers": ["Cipher"]}]}
        other = {**CANDIDATE, "title": "Argument injection", "line": 4}
        replies = [tools(report(CANDIDATE)), tools(report(CANDIDATE, other)), tools(verdict()), tools(verdict("rejected", [HEAD_LINE]))]
        with patch("reviewer.find_verify.request_json", side_effect=replies) as client:
            result = review(CONTEXT, "key", access=FakeAccess(), limits=FindVerifyLimits(concurrency=1), profile=profile)
        self.assertEqual({"finder", "injection"}, set(result["hunters"]))  # crypto's trigger did not match
        self.assertIn("specialist reviewer for one class of vulnerability: injection", sent(client, 1)["messages"][0]["content"])
        self.assertEqual([("finder", ["injection"]), ("injection", None)],
                         [(c["source"], c.get("also_proposed_by")) for c in result["candidates"]])
        self.assertEqual(1, len(result["findings"]))
        self.assertEqual(profile_sha256(profile), result["metadata"]["profile"]["sha256"])

    def test_profile_edits_change_the_verifier_prompt(self):
        profile = {**load_profile(), "verifier_criteria": "Confirm only with a quoted sink."}
        with patch("reviewer.find_verify.request_json", side_effect=[tools(report(CANDIDATE)), tools(verdict())]) as client:
            review(CONTEXT, "key", access=FakeAccess(), limits=FindVerifyLimits(concurrency=1), profile=profile)
        self.assertIn("Confirm only with a quoted sink.", sent(client, 1)["messages"][0]["content"])

    def test_default_profile_matches_the_original_prompts(self):
        prompt = verifier_prompt(load_profile())
        self.assertIn("(d) this diff introduced or weakened it (cite a changed line).", prompt)
        self.assertEqual([], load_profile()["specialists"])

    def test_cli_dry_run_shows_finder_payload_without_network(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), patch("reviewer.find_verify.request_json") as network:
            code = main(["--diff", str(ROOT / "reviewer/example.diff"), "--strategy", "find-verify", "--dry-run"])
        self.assertEqual(0, code)
        payload = json.loads(stdout.getvalue())
        self.assertEqual("required", payload["tool_choice"])
        self.assertIn("Find the security vulnerabilities", payload["messages"][0]["content"])
        network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
