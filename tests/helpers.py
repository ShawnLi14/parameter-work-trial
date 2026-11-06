"""Shared fixtures for reviewer tests: the example diff and fake tool-calling model replies."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIFF = (ROOT / "reviewer/example.diff").read_text(encoding="utf-8")
CONTEXT = {"diff": DIFF}

# Lines of reviewer/example.diff, as a model would cite them.
BASE_LINE = {"side": "base", "path": "app.py", "line": 5, "quote": '["getent", "hosts", request.args["name"]]'}
HEAD_LINE = {"side": "head", "path": "app.py", "line": 5, "quote": "shell=True"}
INPUT_LINE = {"side": "head", "path": "app.py", "line": 5, "quote": 'request.args["name"]'}


def tools(*calls):
    """A model reply calling tools natively; each item is (name, arguments[, id])."""
    return {"model": "fixture", "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            "choices": [{"finish_reason": "tool_calls", "message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": item[2] if len(item) > 2 else f"c{i}", "type": "function",
                 "function": {"name": item[0], "arguments": json.dumps(item[1])}} for i, item in enumerate(calls)]}}]}


class FakeAccess:
    """Code access that returns the same two lines for every lookup and records the calls."""
    available = "fixture read/search/list"

    def __init__(self, result=None):
        self.result = result or {"side": "head", "path": "routes.py", "start": 1, "end": 2,
                                 "lines": ["@app.route('/lookup')", "def route(): return lookup()"]}
        self.calls = []

    def lookup(self, tool, args, timeout=30):
        self.calls.append((tool, args))
        return json.loads(json.dumps(self.result))


def sent(client, index):
    """The payload of the index-th model request."""
    return client.call_args_list[index].kwargs["payload"]


def tool_reply(client, index, call_id=None):
    """The last tool reply (optionally for one call id) included in the index-th request."""
    messages = sent(client, index)["messages"]
    replies = [m for m in messages if m["role"] == "tool" and (call_id is None or m["tool_call_id"] == call_id)]
    return json.loads(replies[-1]["content"])
