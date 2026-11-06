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
    parser = argparse.ArgumentParser(description="Security PR reviewer (default input: benchmark JSON on stdin)")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--pr", help="https://github.com/OWNER/REPO/pull/NUMBER")
    source.add_argument("--diff", type=Path, help="local UTF-8 unified diff")
    parser.add_argument("--strategy", choices=["baseline", "find-verify"], default="baseline",
                        help="baseline: one call on the diff; find-verify: a tool-using finder, then a verifier per finding")
    parser.add_argument("--base-dir", type=Path, help="find-verify: base source tree for lookups on a local diff")
    parser.add_argument("--head-dir", type=Path, help="find-verify: head source tree for lookups on a local diff")
    parser.add_argument("--profile", type=Path, help="find-verify: editable prompts and specialists (default: reviewer/profiles/default.json)")
    parser.add_argument("--finder-calls", type=positive_int, default=20, help="find-verify: model-call cap for the finder")
    parser.add_argument("--verifier-calls", type=positive_int, default=12, help="find-verify: model-call cap per verifier")
    parser.add_argument("--concurrency", type=positive_int, default=3, help="find-verify: parallel hunters and verifiers")
    parser.add_argument("--max-calls", type=positive_int, default=150, help="find-verify: total model-call ceiling")
    parser.add_argument("--review-timeout", type=positive_int, default=300, help="find-verify: stop starting work after this many seconds")
    parser.add_argument("--max-context-chars", type=positive_int, default=300_000, help="find-verify: per-call message size limit")
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
        if (args.base_dir or args.head_dir) and (not args.diff or args.strategy == "baseline" or not (args.base_dir and args.head_dir)):
            raise ValueError("--base-dir and --head-dir require each other, --diff, and --strategy find-verify")
        environment = load_environment()
        github_token = environment.get("GITHUB_TOKEN") or environment.get("GH_TOKEN")
        args.provider = args.provider or environment.get("REVIEW_PROVIDER") or "openrouter"
        if args.provider not in PROVIDERS:
            raise ValueError(f"Unknown provider {args.provider!r}")
        # REVIEW_MODEL names an OpenRouter model, so it never applies to another provider.
        configured = environment.get("REVIEW_MODEL") if args.provider == "openrouter" else None
        args.model = args.model or configured or PROVIDERS[args.provider]["model"]
        if args.pr:
            request = fetch_pr(args.pr, github_token)
        elif args.diff:
            request = {"mode": "pr", "diff": args.diff.read_text(encoding="utf-8-sig")}
            if args.base_dir and args.head_dir:
                if not args.base_dir.is_dir() or not args.head_dir.is_dir():
                    raise ValueError("Both source directories must exist")
                request.update(base_source_dir=str(args.base_dir.resolve()), source_dir=str(args.head_dir.resolve()))
        else:
            # Bound the envelope before JSON parsing. Only find-verify uses the source
            # trees and the benchmark's lookup capability.
            text = sys.stdin.read(args.max_input_chars * 2 + 1)
            if len(text) > args.max_input_chars * 2:
                raise ValueError("Input envelope exceeds size limit")
            request = json.loads(text)
        record = (lambda trace: write_json(args.record, trace)) if args.record else None
        if args.strategy == "find-verify":
            from .code_access import CodeAccess, pin_pr_base
            from .find_verify import FindVerifyLimits, finder_payload, load_profile, review as find_verify_review
            profile = load_profile(args.profile)
            limits = FindVerifyLimits(finder_calls=args.finder_calls, verifier_calls=args.verifier_calls,
                                      concurrency=args.concurrency, max_calls=args.max_calls,
                                      review_timeout=args.review_timeout, max_context_chars=args.max_context_chars)
            if args.pr:
                pin_pr_base(request, github_token)
            context = context_from_request(request, args.max_input_chars)
            if args.dry_run:
                result = finder_payload(context, args.model, args.max_tokens, args.reasoning_effort, args.provider, profile)
            else:
                result = find_verify_review(context, environment.get(PROVIDERS[args.provider]["key"]),
                    access=CodeAccess(request, github_token), model=args.model, max_tokens=args.max_tokens,
                    reasoning_effort=args.reasoning_effort, timeout=args.timeout, provider=args.provider,
                    limits=limits, profile=profile, record=record)
        else:
            context = context_from_request(request, args.max_input_chars)
            if args.dry_run:
                result = build_payload(context, args.model, args.max_tokens, args.reasoning_effort, args.provider)
            else:
                result = review(context, environment.get(PROVIDERS[args.provider]["key"]), model=args.model,
                                max_tokens=args.max_tokens, reasoning_effort=args.reasoning_effort,
                                timeout=args.timeout, provider=args.provider, record=record)
        if args.out:
            write_json(args.out, result)
        else:
            print(json.dumps(result, ensure_ascii=False))
        # Preserve diagnostic output, but never score an API/schema failure as a
        # successful empty review. Legitimate budget/context limits remain partial.
        return 2 if result.get("metadata", {}).get("status") == "error" else 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"Review failed: {error}", file=sys.stderr)
        return 2
