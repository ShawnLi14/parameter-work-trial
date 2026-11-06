"""Claude provider: the reviewers' chat-completions requests, sent through the Messages API.

The reviewers build OpenAI-style requests (system/user/assistant/tool messages, function
tools) so every provider shares one loop. For Claude this module converts a request to a
Messages API call through the official `anthropic` SDK and converts the reply back.

Claude's thinking blocks must be sent back unchanged with later tool results. Each reply's
raw content is kept, keyed by its tool_use ids, and replayed verbatim when that assistant
turn appears again, so conversations stay append-only. Only this provider needs the SDK
(`pip install anthropic`); the others use the standard library.
"""

import json
import threading

HOST = "api.anthropic.com"
# USD per million tokens (input, output) for prompts up to 100K tokens; others unknown.
PRICES = {"claude-haiku-5-5": (0.10, 0.50)}

_lock = threading.Lock()
_replies = {}   # tool_use id -> the assistant content blocks that contained it
_clients = {}


def _client(api_key):
    import anthropic
    with _lock:
        if api_key not in _clients:
            # The SDK retries 429, 5xx, and connection errors itself.
            _clients[api_key] = anthropic.Anthropic(api_key=api_key, max_retries=3)
        return _clients[api_key]


def to_tools(tools):
    return [{"name": t["function"]["name"], "description": t["function"].get("description", ""),
             "input_schema": t["function"]["parameters"]} for t in tools]


def to_messages(messages):
    """Return (system, messages) in Messages API form; consecutive same-role turns merge."""
    system, out = [], []

    def add(role, blocks):
        if out and out[-1]["role"] == role:
            out[-1]["content"].extend(blocks)
        else:
            out.append({"role": role, "content": list(blocks)})

    for m in messages:
        role = m["role"]
        if role == "system" and not out:
            system.append(m["content"])
        elif role in ("system", "user"):
            add("user", [{"type": "text", "text": m["content"]}])
        elif role == "tool":
            add("user", [{"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}])
        elif role == "assistant":
            calls = m.get("tool_calls") or []
            with _lock:
                raw = _replies.get(calls[0]["id"]) if calls else None
            if raw is not None:
                add("assistant", raw)  # verbatim, thinking blocks included
            else:
                blocks = [{"type": "text", "text": m["content"]}] if m.get("content") else []
                blocks += [{"type": "tool_use", "id": c["id"], "name": c["function"]["name"],
                            "input": json.loads(c["function"].get("arguments") or "{}")} for c in calls]
                add("assistant", blocks)
        else:
            raise ValueError(f"Unsupported message role {role!r}")
    return "\n\n".join(system), out


def to_completion(response):
    """Convert a Messages API reply to the chat-completions shape the reviewers read."""
    if response.stop_reason == "refusal":
        category = getattr(response.stop_details, "category", None) if response.stop_details else None
        raise ValueError(f"Claude declined the request (refusal category: {category})")
    blocks = [block.to_dict() for block in response.content]
    calls = [b for b in blocks if b.get("type") == "tool_use"]
    if calls:
        with _lock:
            for call in calls:
                _replies[call["id"]] = blocks
    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    finish = {"tool_use": "tool_calls", "end_turn": "stop", "max_tokens": "length"}.get(response.stop_reason, response.stop_reason)
    usage = response.usage
    prompt = (usage.input_tokens or 0) + (getattr(usage, "cache_read_input_tokens", 0) or 0) \
        + (getattr(usage, "cache_creation_input_tokens", 0) or 0)
    result_usage = {"prompt_tokens": prompt, "completion_tokens": usage.output_tokens,
                    "total_tokens": prompt + usage.output_tokens}
    price = PRICES.get(response.model)
    if price and prompt <= 100_000:
        result_usage["cost"] = (prompt * price[0] + usage.output_tokens * price[1]) / 1_000_000
    return {"id": response.id, "model": response.model, "usage": result_usage, "choices": [{
        "finish_reason": finish, "message": {"role": "assistant", "content": text or None, "tool_calls": [
            {"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": json.dumps(c["input"])}}
            for c in calls] or None}}]}


def complete(payload, api_key, timeout):
    """Send one chat-completions style payload to Claude; errors become ValueError like the HTTP client's."""
    import anthropic
    system, messages = to_messages(payload["messages"])
    effort = payload.get("reasoning_effort") or "medium"
    kwargs = {"model": payload["model"], "messages": messages, "timeout": timeout,
              "max_tokens": payload.get("max_completion_tokens") or payload.get("max_tokens") or 16000,
              "output_config": {"effort": "low" if effort == "none" else effort}}
    if system:
        kwargs["system"] = system
    if payload.get("tools"):
        kwargs["tools"] = to_tools(payload["tools"])
        # Auto, not forced: a forced tool call would skip thinking. The prompts require a
        # tool call every turn, and the reviewers remind the model if it answers in text.
        choice = {"type": "auto"}
        if payload.get("parallel_tool_calls") is False:
            choice["disable_parallel_tool_use"] = True
        kwargs["tool_choice"] = choice
    try:
        response = _client(api_key).messages.create(**kwargs)
    except anthropic.RateLimitError as error:
        retry = error.response.headers.get("retry-after")
        hint = f"; Retry-After: {int(float(retry))}" if retry else ""
        raise ValueError(f"HTTP 429 from {HOST}{hint}") from None
    except anthropic.APIStatusError as error:
        # Like the HTTP client, never echo the provider's error body.
        raise ValueError(f"HTTP {error.status_code} from {HOST}") from None
    except anthropic.APIConnectionError as error:
        raise ValueError(f"Network request to {HOST} failed ({type(error).__name__})") from None
    return to_completion(response)
