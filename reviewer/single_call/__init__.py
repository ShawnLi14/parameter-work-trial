"""Single-call reviewer: exactly one model request on the diff, with no retrieval or repair pass."""

import json
import time

from .. import __version__
from ..providers import DEFAULT_MODEL, DEFAULT_PROVIDER, PROVIDERS, request_settings, send
from ..tools import sha256, validate_findings
from .prompt import PROMPT_VERSION, SYSTEM_PROMPT

def build_payload(context, model=DEFAULT_MODEL, max_tokens=16384, reasoning_effort="medium", provider=DEFAULT_PROVIDER):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(context, ensure_ascii=False, sort_keys=True)},
    ]
    return {**request_settings(model, max_tokens, reasoning_effort, provider), "messages": messages}


def parse_response(response):
    if not isinstance(response, dict) or response.get("error"):
        raise ValueError("Provider returned an error instead of a completion")
    try:
        choice = response["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise ValueError("Provider response is missing completion content") from None
    if not isinstance(choice, dict):
        raise ValueError("Provider completion choice must be an object")
    if choice.get("finish_reason") != "stop":
        raise ValueError(f"Incomplete model response (finish_reason={choice.get('finish_reason')!r})")
    if not isinstance(content, str):
        raise ValueError("Model response must contain JSON text")
    # Tolerate an enclosing Markdown fence without changing any JSON content.
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0] not in {"```", "```json"} or lines[-1] != "```":
            raise ValueError("Invalid Markdown fence around model JSON")
        text = "\n".join(lines[1:-1])
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        raise ValueError("Model returned invalid JSON; baseline does not retry or repair") from None
    return validate_findings(value)


def review(context, api_key, *, model=DEFAULT_MODEL, max_tokens=16384,
           reasoning_effort="medium", timeout=240, record=None, provider=DEFAULT_PROVIDER):
    settings = PROVIDERS[provider]
    if not api_key or not api_key.strip():
        raise ValueError(f"Set {settings['key']} before running a live review")
    payload = build_payload(context, model, max_tokens, reasoning_effort, provider)
    trace = {"agent_version": __version__, "prompt_version": PROMPT_VERSION, "request": payload}
    if record:
        record(trace)
    start = time.monotonic()
    try:
        response = send(provider, payload, api_key, timeout)
        trace["response"] = response
        if record:
            record(trace)
        findings = parse_response(response)
    except ValueError as error:
        trace["error"] = str(error)
        if record:
            record(trace)
        raise
    usage = response.get("usage") or {}
    cost = usage.get("cost")
    return {"findings": findings, "metadata": {
        "status": "completed", "scope": "diff_only", "agent_version": __version__,
        "prompt_version": PROMPT_VERSION, "prompt_sha256": sha256(SYSTEM_PROMPT),
        "context_sha256": sha256(payload["messages"][1]["content"]),
        "request_sha256": sha256(json.dumps(payload, sort_keys=True)),
        "requested_model": model, "returned_model": response.get("model"),
        "provider": response.get("provider") or provider, "response_id": response.get("id"),
        "usage": usage, "cost_usd": cost, "cost_source": "provider" if cost is not None else "unknown",
        "elapsed_seconds": round(time.monotonic() - start, 3), "model_calls": 1,
        "temperature": 0, "max_tokens": max_tokens, "reasoning_effort": reasoning_effort,
        "limitations": ["Only the supplied diff and its context lines were reviewed.",
                        "Finding locations and exploitability have not been independently verified.",
                        "Binary content and files outside the diff are not inspected."],
    }}
