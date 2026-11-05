import argparse
import json
from pathlib import Path
import sys

from .baseline import PROVIDERS, build_payload, review
from .config import load_environment
from .inputs import context_from_request, fetch_pr


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv=None):
    # The benchmark exchanges UTF-8 JSON even on Windows hosts with a legacy
    # console codepage. StringIO streams used in tests have no reconfigure method.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="One-call, diff-only security reviewer (default input: benchmark JSON on stdin)")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--pr", help="https://github.com/OWNER/REPO/pull/NUMBER")
    source.add_argument("--diff", type=Path, help="local UTF-8 unified diff")
    parser.add_argument("--provider", choices=sorted(PROVIDERS), help="model provider (default: REVIEW_PROVIDER, else openrouter)")
    parser.add_argument("--model", help="override the model; REVIEW_MODEL applies to OpenRouter only")
    parser.add_argument("--out", type=Path, help="write review JSON here instead of stdout")
    parser.add_argument("--record", type=Path, help="save exact prompt and raw response (contains source code; no API key)")
    parser.add_argument("--dry-run", action="store_true", help="emit exact model payload without calling the provider")
    parser.add_argument("--max-input-chars", type=positive_int, default=200_000)
    parser.add_argument("--max-tokens", type=positive_int, default=16384, help="output allowance, including reasoning")
    parser.add_argument("--reasoning-effort", choices=["none", "medium", "high"], default="medium")
    parser.add_argument("--timeout", type=positive_int, default=240, help="HTTP timeout in seconds")
    args = parser.parse_args(argv)
    try:
        environment = load_environment()
        args.provider = args.provider or environment.get("REVIEW_PROVIDER") or "openrouter"
        if args.provider not in PROVIDERS:
            raise ValueError(f"Unknown provider {args.provider!r}")
        # REVIEW_MODEL names an OpenRouter model, so it never applies to another provider.
        configured = environment.get("REVIEW_MODEL") if args.provider == "openrouter" else None
        args.model = args.model or configured or PROVIDERS[args.provider]["model"]
        if args.pr:
            request = fetch_pr(args.pr, environment.get("GITHUB_TOKEN") or environment.get("GH_TOKEN"))
        elif args.diff:
            request = {"mode": "pr", "diff": args.diff.read_text(encoding="utf-8-sig")}
        else:
            # Bound the envelope too, before JSON parsing. Local source trees are
            # intentionally never read, even when the harness supplies their paths.
            text = sys.stdin.read(args.max_input_chars * 2 + 1)
            if len(text) > args.max_input_chars * 2:
                raise ValueError("Input envelope exceeds size limit")
            request = json.loads(text)
        context = context_from_request(request, args.max_input_chars)
        if args.dry_run:
            result = build_payload(context, args.model, args.max_tokens, args.reasoning_effort, args.provider)
        else:
            result = review(context, environment.get(PROVIDERS[args.provider]["key"]), model=args.model,
                            max_tokens=args.max_tokens, reasoning_effort=args.reasoning_effort,
                            timeout=args.timeout, provider=args.provider,
                            record=(lambda trace: write_json(args.record, trace)) if args.record else None)
        if args.out:
            write_json(args.out, result)
        else:
            print(json.dumps(result, ensure_ascii=False))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"Review failed: {error}", file=sys.stderr)
        return 2
