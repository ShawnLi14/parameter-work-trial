import importlib.util
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from helpers import CONTEXT
from reviewer import claude
from reviewer.baseline import build_payload

HAS_SDK = importlib.util.find_spec("anthropic") is not None


class Block(SimpleNamespace):
    def to_dict(self):
        return dict(vars(self))


def reply(*blocks, stop="tool_use", model="claude-haiku-5-5", usage=(1000, 100)):
    return SimpleNamespace(id="msg_1", model=model, stop_reason=stop, stop_details=None, content=list(blocks),
                           usage=SimpleNamespace(input_tokens=usage[0], output_tokens=usage[1],
                                                 cache_read_input_tokens=0, cache_creation_input_tokens=0))


def use(id_, name, arguments):
    return Block(type="tool_use", id=id_, name=name, input=arguments)


class ConversionTests(unittest.TestCase):
    def test_reply_becomes_chat_completion_with_tool_calls_and_cost(self):
        thinking = Block(type="thinking", thinking="", signature="sig")
        out = claude.to_completion(reply(thinking, use("tu_1", "report", {"findings": []})))
        message = out["choices"][0]["message"]
        self.assertEqual("tool_calls", out["choices"][0]["finish_reason"])
        self.assertEqual([("tu_1", "report", {"findings": []})],
                         [(c["id"], c["function"]["name"], json.loads(c["function"]["arguments"])) for c in message["tool_calls"]])
        self.assertAlmostEqual((1000 * 0.10 + 100 * 0.50) / 1e6, out["usage"]["cost"])

    def test_thinking_blocks_are_replayed_verbatim(self):
        thinking = Block(type="thinking", thinking="", signature="sig-xyz")
        out = claude.to_completion(reply(thinking, use("tu_2", "lookup", {"tool": "list", "args": {"side": "head"}})))
        call = out["choices"][0]["message"]["tool_calls"][0]
        history = [{"role": "system", "content": "rules"}, {"role": "user", "content": "diff"},
                   {"role": "assistant", "content": "", "tool_calls": [call]},
                   {"role": "tool", "tool_call_id": "tu_2", "content": "{}"},
                   {"role": "user", "content": "reminder"}]
        system, messages = claude.to_messages(history)
        self.assertEqual("rules", system)
        self.assertEqual(["user", "assistant", "user"], [m["role"] for m in messages])
        self.assertEqual({"type": "thinking", "thinking": "", "signature": "sig-xyz"}, messages[1]["content"][0])
        self.assertEqual(["tool_result", "text"], [b["type"] for b in messages[2]["content"]])

    def test_unknown_assistant_turns_are_rebuilt_and_refusals_raise(self):
        call = {"id": "never-seen", "type": "function", "function": {"name": "report", "arguments": '{"findings": []}'}}
        _, messages = claude.to_messages([{"role": "user", "content": "x"}, {"role": "assistant", "content": "", "tool_calls": [call]}])
        self.assertEqual({"type": "tool_use", "id": "never-seen", "name": "report", "input": {"findings": []}}, messages[1]["content"][0])
        refused = reply(Block(type="text", text=""), stop="refusal")
        refused.stop_details = SimpleNamespace(category="cyber")
        with self.assertRaisesRegex(ValueError, "declined.*cyber"):
            claude.to_completion(refused)

    def test_payload_has_no_sampling_parameters(self):
        payload = build_payload(CONTEXT, "claude-haiku-5-5", 16384, "medium", "anthropic")
        self.assertNotIn("temperature", payload)
        self.assertEqual("medium", payload["reasoning_effort"])


@unittest.skipUnless(HAS_SDK, "the anthropic SDK is not installed")
class CompleteTests(unittest.TestCase):
    def test_request_uses_auto_tool_choice_effort_and_tools(self):
        seen = {}

        class Messages:
            def create(self, **kwargs):
                seen.update(kwargs)
                return reply(use("tu_9", "report", {"findings": []}))

        payload = {"model": "claude-haiku-5-5", "max_completion_tokens": 1000, "reasoning_effort": "medium",
                   "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
                   "tools": [{"type": "function", "function": {"name": "report", "description": "d",
                                                                 "parameters": {"type": "object", "properties": {}}}}],
                   "tool_choice": "required", "parallel_tool_calls": False}
        with patch.object(claude, "_client", return_value=SimpleNamespace(messages=Messages())):
            out = claude.complete(payload, "key", 30)
        self.assertEqual({"type": "auto", "disable_parallel_tool_use": True}, seen["tool_choice"])
        self.assertEqual({"effort": "medium"}, seen["output_config"])
        self.assertEqual("s", seen["system"])
        self.assertEqual([{"name": "report", "description": "d", "input_schema": {"type": "object", "properties": {}}}], seen["tools"])
        self.assertNotIn("temperature", seen)
        self.assertEqual("tool_calls", out["choices"][0]["finish_reason"])

    def test_rate_limits_become_retryable_errors(self):
        import anthropic
        error = anthropic.RateLimitError.__new__(anthropic.RateLimitError)
        error.response = SimpleNamespace(status_code=429, headers={"retry-after": "7"}, request=None)
        with patch.object(claude, "_client", return_value=SimpleNamespace(messages=SimpleNamespace(
                create=lambda **k: (_ for _ in ()).throw(error)))):
            with self.assertRaisesRegex(ValueError, r"^HTTP 429 from api\.anthropic\.com; Retry-After: 7$"):
                claude.complete({"model": "m", "messages": [{"role": "user", "content": "u"}]}, "key", 30)


if __name__ == "__main__":
    unittest.main()
