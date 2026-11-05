"""Small bounded JSON/HTTP transport; deliberately no implicit model retries."""

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def request_bytes(url, *, headers=None, payload=None, timeout=240, max_bytes=8_000_000):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    # Some providers' firewalls reject Python's default user agent (Cerebras returns 403).
    headers = {"User-Agent": "security-review-baseline", **(headers or {})}
    request = Request(url, data=body, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            content = response.read(max_bytes + 1)
    except HTTPError as error:
        # Avoid echoing provider error bodies: they can contain request content.
        retry = error.headers.get("Retry-After")
        hint = f"; Retry-After: {retry}" if retry else ""
        error.close()
        raise ValueError(f"HTTP {error.code} from {request.host}{hint}") from None
    except (URLError, TimeoutError, OSError) as error:
        raise ValueError(f"Network request to {request.host} failed ({type(error).__name__})") from None
    if len(content) > max_bytes:
        raise ValueError(f"Response exceeds {max_bytes} bytes; nothing was silently truncated")
    return content


def request_json(url, **kwargs):
    try:
        return json.loads(request_bytes(url, **kwargs))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Endpoint returned invalid JSON") from None
