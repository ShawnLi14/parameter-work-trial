"""Exactly one model request, with no retrieval, repair pass, or semantic scorer."""

import hashlib
import json
from pathlib import PurePosixPath
import time

from . import __version__
from .http import request_json
from .prompt import PROMPT_VERSION, SYSTEM_PROMPT

DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
BASE_URL = "https://openrouter.ai/api/v1"


def sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_payload(context, model=DEFAULT_MODEL, max_tokens=16384, reasoning_effort="medium"):
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False, sort_keys=True)},
        ],
        "temperature": 0,
        "max_tokens": max_tokens,
        "reasoning": {"effort": reasoning_effort},
        "stream": False,
        # Do not silently route to a different model or drop required parameters.
        "provider": {"require_parameters": True},
    }


def validate_findings(value):
    if not isinstance(value, dict) or not isinstance(value.get("findings"), list):
        raise ValueError("Model output must be an object containing a findings list")
    findings = []
    for i, finding in enumerate(value["findings"]):
        prefix = f"Finding {i + 1}"
        if not isinstance(finding, dict):
            raise ValueError(f"{prefix} must be an object")
        for key in ("title", "description", "path"):
            if not isinstance(finding.get(key), str) or not finding[key].strip():
                raise ValueError(f"{prefix} requires a non-empty {key}")
        path = finding["path"]
        if (PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                or "\\" in path or ":" in path or path in {".", ""}):
            raise ValueError(f"{prefix} path must be relative with forward slashes")
        if type(finding.get("line")) is not int or finding["line"] < 1:
            raise ValueError(f"{prefix} requires a positive integer line")
        if finding.get("side", "head") not in ("base", "head"):
            raise ValueError(f"{prefix} side must be base or head")
        if finding.get("severity") not in ("critical", "high", "medium", "low"):
            raise ValueError(f"{prefix} requires a valid severity")
        evidence = finding.get("evidence")
        if not isinstance(evidence, list) or not evidence or not all(isinstance(e, str) and e.strip() for e in evidence):
            raise ValueError(f"{prefix} requires non-empty evidence strings")
        findings.append({key: finding[key] for key in (
            "title", "severity", "description", "path", "line", "evidence")}
            | {"side": finding.get("side", "head")})
    return findings


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
           reasoning_effort="medium", timeout=240, record=None):
    if not api_key or not api_key.strip():
        raise ValueError("Set OPENROUTER_API_KEY before running a live review")
    payload = build_payload(context, model, max_tokens, reasoning_effort)
    trace = {"agent_version": __version__, "prompt_version": PROMPT_VERSION, "request": payload}
    if record:
        record(trace)
    start = time.monotonic()
    try:
        response = request_json(BASE_URL + "/chat/completions", payload=payload, timeout=timeout,
                                headers={"Authorization": f"Bearer {api_key}",
                                         "Content-Type": "application/json",
                                         "X-OpenRouter-Title": "Security PR Review Baseline"})
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
    # This estimate is specific to the explicitly selected free variant.
    estimate = 0.0 if model.endswith(":free") else None
    return {"findings": findings, "metadata": {
        "status": "completed", "scope": "diff_only", "agent_version": __version__,
        "prompt_version": PROMPT_VERSION, "prompt_sha256": sha256(SYSTEM_PROMPT),
        "context_sha256": sha256(payload["messages"][1]["content"]),
        "request_sha256": sha256(json.dumps(payload, sort_keys=True)),
        "requested_model": model, "returned_model": response.get("model"),
        "provider": response.get("provider"), "response_id": response.get("id"),
        "usage": usage, "cost_usd": cost if cost is not None else estimate,
        "cost_source": "provider" if cost is not None else ("free_variant_estimate" if estimate is not None else "unknown"),
        "elapsed_seconds": round(time.monotonic() - start, 3), "model_calls": 1,
        "temperature": 0, "max_tokens": max_tokens, "reasoning_effort": reasoning_effort,
        "limitations": ["Only the supplied diff and its context lines were reviewed.",
                        "Finding locations and exploitability have not been independently verified.",
                        "Binary content and files outside the diff are not inspected."],
    }}
