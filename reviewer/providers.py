"""Model providers: Cerebras (chat completions) and Claude (Messages API via reviewer/claude.py)."""

from .http import request_json

DEFAULT_PROVIDER = "cerebras"
DEFAULT_MODEL = "gpt-oss-120b"
# Requests are built in the OpenAI chat-completions shape, which Cerebras speaks natively.
# Claude requests are converted to the Messages API by reviewer/claude.py.
PROVIDERS = {
    "cerebras": {"url": "https://api.cerebras.ai/v1", "key": "CEREBRAS_API_KEY", "model": DEFAULT_MODEL},
    "anthropic": {"url": "https://api.anthropic.com/v1", "key": "ANTHROPIC_API_KEY", "model": "claude-haiku-5-5"},
}


def request_settings(model=DEFAULT_MODEL, max_tokens=16384, reasoning_effort="medium", provider=DEFAULT_PROVIDER):
    """Every request field except the messages."""
    effort = "low" if reasoning_effort == "none" else reasoning_effort
    if provider == "anthropic":
        # Current Claude models reject sampling parameters; effort controls thinking.
        return {"model": model, "max_completion_tokens": max_tokens, "reasoning_effort": effort, "stream": False}
    # gpt-oss always reasons; "low" is the closest setting to none.
    return {"model": model, "temperature": 0, "max_completion_tokens": max_tokens,
            "reasoning_effort": effort, "stream": False}


def send(provider, payload, api_key, timeout):
    """One model request in chat-completions shape, to whichever provider is selected."""
    if provider == "anthropic":
        from .claude import complete
        return complete(payload, api_key, timeout)
    return request_json(PROVIDERS[provider]["url"] + "/chat/completions", payload=payload, timeout=timeout,
                        headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"})
