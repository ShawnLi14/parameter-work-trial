"""Command-line runner shared by the three reviewer agents.

Each agent is its own runnable folder: `python reviewer/single_call`,
`python reviewer/find_verify`, `python reviewer/self_improving` (or `python -m
reviewer.single_call`, ...). With no argument an agent reads one benchmark request on
stdin; otherwise it reviews a unified diff file or a GitHub PR URL. Settings come from
config.toml and API keys from .env, both in the project root.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import time

from .config import ROOT, load_environment, load_settings
from .inputs import context_from_request, fetch_pr
from .providers import PROVIDERS

AGENTS = {"single-call": "single_call", "find-verify": "find_verify", "self-improving": "self_improving"}
# Internal hook for the improvement loop: review with this profile instead of the agent's own.
PROFILE_OVERRIDE = "REVIEWER_PROFILE"


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_request(source, trees, settings, github_token):
    if source is None:
        # Bound the envelope before JSON parsing.
        limit = settings["review"]["max_input_chars"] * 2
        text = sys.stdin.read(limit + 1)
        if len(text) > limit:
            raise ValueError("Input envelope exceeds size limit")
        return json.loads(text)
    if source.startswith("https://"):
        if trees:
            raise ValueError("Source folders apply only to a local diff")
        return fetch_pr(source, github_token)
    request = {"mode": "pr", "diff": Path(source).read_text(encoding="utf-8-sig")}
    if trees:
        if len(trees) != 2 or not all(Path(t).is_dir() for t in trees):
            raise ValueError("Give both the base and the head source folder")
        request.update(base_source_dir=str(Path(trees[0]).resolve()), source_dir=str(Path(trees[1]).resolve()))
    return request


def review(agent, request, settings, environment):
    """Run one agent on one request; returns its output."""
    model = settings["model"]
    provider, name = model["provider"], model["name"]
    github_token = environment.get("GITHUB_TOKEN") or environment.get("GH_TOKEN")
    record = None
    if settings["review"]["record_dir"]:
        trace = ROOT / settings["review"]["record_dir"] / f"{agent}-{time.time_ns()}-{os.getpid()}.json"
        record = lambda value: write_json(trace, value)
    common = dict(model=name, provider=provider, max_tokens=model["max_tokens"],
                  reasoning_effort=model["reasoning_effort"], timeout=model["timeout"], record=record)
    api_key = environment.get(PROVIDERS[provider]["key"])
    if agent == "single-call":
        from .single_call import review as single_call
        return single_call(context_from_request(request, settings["review"]["max_input_chars"]), api_key, **common)
    from .code_access import CodeAccess, pin_pr_base
    from .find_verify import FindVerifyLimits, load_profile
    if request.get("pr"):
        pin_pr_base(request, github_token)
    context = context_from_request(request, settings["review"]["max_input_chars"])
    limits = FindVerifyLimits(**settings["find_verify"])
    override = os.environ.get(PROFILE_OVERRIDE)
    profile = load_profile(override) if override else None
    access = CodeAccess(request, github_token)
    if agent == "find-verify":
        from .find_verify import review as find_verify
        return find_verify(context, api_key, access=access, limits=limits, profile=profile, **common)
    from .self_improving import review as self_improving
    return self_improving(context, api_key, access=access, limits=limits, profile=profile, **common)


def main(agent, argv=None):
    # The benchmark exchanges UTF-8 JSON even on Windows hosts with a legacy
    # console codepage. StringIO streams used in tests have no reconfigure method.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(
        prog=f"python reviewer/{AGENTS[agent]}",
        description=f"The {agent} security reviewer. Settings: config.toml; API keys: .env.")
    parser.add_argument("source", nargs="?", help="unified diff file or GitHub PR URL; omit to read a benchmark request on stdin")
    parser.add_argument("trees", nargs="*", help="for a local diff: its base and head source folders, for lookups")
    args = parser.parse_args(argv)
    try:
        if args.trees and agent == "single-call":
            raise ValueError("The single-call reviewer reads only the diff; source folders are not used")
        settings, environment = load_settings(), load_environment()
        request = read_request(args.source, args.trees, settings,
                               environment.get("GITHUB_TOKEN") or environment.get("GH_TOKEN"))
        result = review(agent, request, settings, environment)
        print(json.dumps(result, ensure_ascii=False))
        # Never score an API/schema failure as a successful empty review.
        return 2 if result.get("metadata", {}).get("status") == "error" else 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"Review failed: {error}", file=sys.stderr)
        return 2


def single_call():
    return main("single-call")


def find_verify():
    return main("find-verify")


def self_improving():
    return main("self-improving")
