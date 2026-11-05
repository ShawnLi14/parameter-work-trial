"""PR acquisition and label-free model context construction."""

import re

from .http import request_bytes, request_json


def context_from_request(request, max_chars=200_000):
    if not isinstance(request, dict) or request.get("mode") != "pr":
        raise ValueError("Expected a PR request with mode='pr'; snapshot review is not supported")
    diff = request.get("diff")
    if not isinstance(diff, str) or not diff.strip():
        raise ValueError("A non-empty unified diff is required")
    if not re.search(r"^diff --git |^--- ", diff, re.MULTILINE):
        raise ValueError("Input does not look like a unified diff")
    # Do not forward arbitrary harness instructions, source paths, case IDs,
    # evaluator metadata, labels, or local repository contents to the model.
    context = {"diff": diff}
    metadata = request.get("pr")
    if metadata is not None:
        allowed = ("repository", "number", "title", "body", "base_sha", "head_sha")
        if not isinstance(metadata, dict):
            raise ValueError("pr metadata must be an object")
        context["pr"] = {key: metadata[key] for key in allowed if key in metadata}
        for key, value in context["pr"].items():
            if key == "number":
                if type(value) is not int or value < 1:
                    raise ValueError("PR number must be a positive integer")
            elif not isinstance(value, str):
                raise ValueError(f"PR {key} must be a string")
    import json
    if len(json.dumps(context, ensure_ascii=False)) > max_chars:
        raise ValueError(f"PR context exceeds {max_chars} characters; use a larger explicit limit")
    return context


def fetch_pr(url, token=None):
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)/?", url)
    if not match or match[1] in {".", ".."} or match[2] in {".", ".."}:
        raise ValueError("Expected https://github.com/OWNER/REPO/pull/NUMBER")
    owner, repo, number = match.groups()
    endpoint = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "security-review-baseline/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    before = request_json(endpoint, headers=headers, timeout=60)
    raw_diff = request_bytes(endpoint, headers={**headers, "Accept": "application/vnd.github.diff"}, timeout=60)
    after = request_json(endpoint, headers=headers, timeout=60)
    for name in ("base", "head"):
        if before[name]["sha"] != after[name]["sha"]:
            raise ValueError("PR changed while fetching; rerun to obtain a consistent diff")
    diff = raw_diff.decode("utf-8")
    file_count = len(re.findall(r"^diff --git ", diff, re.MULTILINE))
    if file_count != after["changed_files"]:
        raise ValueError("Diff file count differs from GitHub metadata; refusing a potentially incomplete diff")
    return {"mode": "pr", "diff": diff, "pr": {
        "repository": f"{owner}/{repo}", "number": int(number),
        "title": after.get("title") or "", "body": after.get("body") or "",
        "base_sha": after["base"]["sha"], "head_sha": after["head"]["sha"],
    }}
