import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from reviewer.baseline import DEFAULT_MODEL, build_payload, parse_response, review
from reviewer.cli import main
from reviewer.config import load_environment
from reviewer.http import request_bytes
from reviewer.inputs import context_from_request, fetch_pr
from secbench.runner import validate_output

ROOT = Path(__file__).resolve().parents[1]
DIFF = (ROOT / "examples/review.diff").read_text(encoding="utf-8")
FINDING = {"title": "Command injection", "severity": "high", "description": "The change enables shell evaluation of request input.",
           "path": "app.py", "line": 5, "side": "head", "evidence": ["app.py:5: shell=True"]}


def completion(content=None, finish="stop"):
    return {"id": "fake-id", "model": DEFAULT_MODEL, "provider": "fixture",
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "cost": 0},
            "choices": [{"finish_reason": finish, "message": {"content": content if content is not None
                         else json.dumps({"findings": [FINDING]})}}]}


class InputTests(unittest.TestCase):
    def test_benchmark_fields_do_not_enter_context(self):
        request = {"mode": "pr", "diff": DIFF, "source_dir": "/private", "base_source_dir": "/base",
                   "commit": "secret-commit-hint", "instructions": "LEAK", "labels": ["ANSWER"], "task_id": "case"}
        context = context_from_request(request)
        self.assertEqual(context, {"diff": DIFF})
        self.assertNotIn("LEAK", json.dumps(build_payload(context)))

    def test_rejects_invalid_or_oversized_input(self):
        for request in ({"mode": "snapshot", "diff": DIFF}, {"mode": "pr", "diff": ""},
                        {"mode": "pr", "diff": "review me"}, []):
            with self.subTest(request=request), self.assertRaises(ValueError):
                context_from_request(request)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            context_from_request({"mode": "pr", "diff": DIFF}, max_chars=20)

    def test_pr_metadata_is_allowlisted(self):
        context = context_from_request({"mode": "pr", "diff": DIFF, "pr": {"title": "A change", "labels": ["ANSWER"]}})
        self.assertEqual(context["pr"], {"title": "A change"})

    def test_github_pins_and_checks_input(self):
        metadata = {"base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}, "changed_files": 1,
                    "title": "A change", "body": None}
        with patch("reviewer.inputs.request_json", side_effect=[metadata, metadata]), \
                patch("reviewer.inputs.request_bytes", return_value=DIFF.encode()) as get_diff:
            result = fetch_pr("https://github.com/example/repo/pull/12", "github-test-key")
        self.assertEqual(result["pr"]["head_sha"], "b" * 40)
        self.assertNotIn("github-test-key", json.dumps(result))
        self.assertEqual(get_diff.call_args.kwargs["headers"]["Accept"], "application/vnd.github.diff")

    def test_github_update_or_truncation_fails(self):
        before = {"base": {"sha": "a"}, "head": {"sha": "b"}, "changed_files": 1}
        for after in (before | {"head": {"sha": "c"}}, before | {"changed_files": 2}):
            with self.subTest(after=after), patch("reviewer.inputs.request_json", side_effect=[before, after]), \
                    patch("reviewer.inputs.request_bytes", return_value=DIFF.encode()), self.assertRaises(ValueError):
                fetch_pr("https://github.com/example/repo/pull/12")

    def test_github_url_is_restricted(self):
        for url in ("http://github.com/a/b/pull/1", "https://evil.invalid/a/b/pull/1",
                    "https://github.com/a/b/pull/1?token=x", "https://github.com/../b/pull/1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                fetch_pr(url)


class ResponseTests(unittest.TestCase):
    def test_valid_output_is_compatible_with_benchmark(self):
        findings = parse_response(completion())
        output = validate_output({"findings": findings})
        self.assertEqual(output["findings"][0]["id"], "f0001")

    def test_empty_output_and_markdown_fences(self):
        self.assertEqual(parse_response(completion('{"findings":[]}')), [])
        self.assertEqual(parse_response(completion('```json\n{"findings":[]}\n```')), [])

    def test_malformed_or_incomplete_completion_is_not_clean(self):
        for response in ({"error": {"message": "failed"}}, {}, completion("not JSON"),
                         completion('{"findings":[]}', "length"), completion('{"findings":[]}', "error"),
                         completion('{"findings":{}}'), completion('```json\n{"findings":[]}')):
            with self.subTest(response=response), self.assertRaises(ValueError):
                parse_response(response)

    def test_finding_validation(self):
        for change in ({"line": True}, {"line": 0}, {"path": "../outside.py"}, {"path": "C:/file.py"},
                       {"path": "a\\b.py"}, {"path": "."}, {"evidence": []}, {"title": ""},
                       {"severity": "unknown"}, {"side": "wrong"}, {"severity": []}, {"side": {}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                parse_response(completion(json.dumps({"findings": [FINDING | change]})))

    def test_one_call_with_no_unsupported_json_format(self):
        traces = []
        with patch("reviewer.baseline.request_json", return_value=completion()) as api:
            result = review({"diff": DIFF}, "test-secret", record=lambda trace: traces.append(json.loads(json.dumps(trace))))
        api.assert_called_once()
        payload = api.call_args.kwargs["payload"]
        self.assertNotIn("response_format", payload)
        self.assertNotIn("tools", payload)
        self.assertEqual(result["metadata"]["model_calls"], 1)
        self.assertEqual(result["metadata"]["cost_usd"], 0)
        self.assertEqual(result["metadata"]["cost_source"], "provider")
        self.assertNotIn("test-secret", json.dumps(traces))
        self.assertIn("response", traces[-1])

    def test_failure_is_recorded_without_second_call(self):
        traces = []
        with patch("reviewer.baseline.request_json", return_value=completion("bad")) as api, self.assertRaises(ValueError):
            review({"diff": DIFF}, "key", record=lambda trace: traces.append(dict(trace)))
        api.assert_called_once()
        self.assertIn("error", traces[-1])

    def test_missing_key_makes_no_request(self):
        with patch("reviewer.baseline.request_json") as api, self.assertRaises(ValueError):
            review({"diff": DIFF}, None)
        api.assert_not_called()

    def test_unknown_cost_is_not_claimed_free(self):
        response = completion()
        del response["usage"]["cost"]
        with patch("reviewer.baseline.request_json", return_value=response):
            result = review({"diff": DIFF}, "key", model="example/paid-model")
        self.assertIsNone(result["metadata"]["cost_usd"])
        self.assertEqual(result["metadata"]["cost_source"], "unknown")


class TransportTests(unittest.TestCase):
    def test_http_failure_does_not_echo_provider_body(self):
        error = HTTPError("https://example.invalid", 429, "slow down", {"Retry-After": "5"}, io.BytesIO(b"secret"))
        with patch("reviewer.http.urlopen", side_effect=error), self.assertRaisesRegex(ValueError, "HTTP 429.*Retry-After: 5"):
            request_bytes("https://example.invalid")

    def test_oversized_response_fails(self):
        with patch("reviewer.http.urlopen") as open_url:
            open_url.return_value.__enter__.return_value.read.return_value = b"12345"
            with self.assertRaisesRegex(ValueError, "exceeds"):
                request_bytes("https://example.invalid", max_bytes=4)


class CliTests(unittest.TestCase):
    def test_wrapper_works_from_benchmark_cwd_without_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.run([sys.executable, str(ROOT / "scripts/review_baseline.py"), "--dry-run"],
                                     input=json.dumps({"mode": "pr", "diff": DIFF}), cwd=directory,
                                     capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["model"], DEFAULT_MODEL)

    def test_cli_output_contains_only_protocol_json(self):
        stdout = io.StringIO()
        with patch("reviewer.cli.sys.stdin", io.StringIO(json.dumps({"mode": "pr", "diff": DIFF}))), \
                patch.dict(os.environ, {"OPENROUTER_API_KEY": "test"}), \
                patch("reviewer.baseline.request_json", return_value=completion()), contextlib.redirect_stdout(stdout):
            code = main([])
        self.assertEqual(code, 0)
        validate_output(json.loads(stdout.getvalue()))

    def test_missing_key_emits_no_success_json(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["--diff", str(ROOT / "examples/review.diff")])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("OPENROUTER_API_KEY", stderr.getvalue())


class ConfigTests(unittest.TestCase):
    def test_dotenv_values_quotes_comments_and_process_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text('# comment\nOPENROUTER_API_KEY="file-key"\nREVIEW_MODEL=example/model # comment\n'
                            "export GITHUB_TOKEN='github-key'\nIGNORED=anything\n", encoding="utf-8")
            with patch.dict(os.environ, {"OPENROUTER_API_KEY": "process-key"}, clear=True):
                environment = load_environment(path)
            self.assertEqual(environment, {"OPENROUTER_API_KEY": "process-key",
                                          "REVIEW_MODEL": "example/model", "GITHUB_TOKEN": "github-key"})

    def test_working_directory_dotenv_is_never_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted = root / "trusted.env"
            trusted.write_text("REVIEW_MODEL=trusted/model\n", encoding="utf-8")
            (root / ".env").write_text("REVIEW_MODEL=attacker/model\n", encoding="utf-8")
            with patch("reviewer.config.ENV_PATH", trusted), patch.dict(os.environ, {}, clear=True), \
                    contextlib.chdir(root):
                self.assertEqual(load_environment()["REVIEW_MODEL"], "trusted/model")

    def test_invalid_config_does_not_echo_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text('OPENROUTER_API_KEY="secret\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 1") as raised:
                load_environment(path)
            self.assertNotIn("secret", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
