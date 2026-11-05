import argparse
import json
from pathlib import Path
import subprocess
import sys

from .catalog import TARGETS, digest, load
from .runner import checked_lock, read_json, remove_case, run, task, unpack_case, write_json
from .scoring import grade_template, score

SUITE = Path("benchmarks/pr-v2/catalog.json")
WORK = Path(".bench/pr-v2")


def lookup_command(args):
    """The command a reviewer appends a lookup action to; it carries no commit IDs."""
    return [sys.executable, "-m", "secbench", "--catalog", str(Path(args.catalog).resolve()),
            "lookup", "--work", str(Path(args.work).resolve())]


def find_case(data, case_id):
    case = next((c for c in data["cases"] if c["id"] == case_id), None)
    if case is None:
        raise ValueError("unknown case ID")
    return case


def main(argv=None):
    p = argparse.ArgumentParser(description="Security review benchmark built from real upstream PRs")
    p.add_argument("--catalog", type=Path, default=SUITE, help="PR suite catalog (default: %(default)s)")
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("validate")
    sub.add_parser("list")
    build = sub.add_parser("build", help="fetch the pinned commits and write the PR suite")
    build.add_argument("--targets", type=Path, default=TARGETS, help="advisory target list the labels come from")
    build.add_argument("--manifest", type=Path, default=Path("benchmarks/pr-v2/manifest.json"))
    build.add_argument("--cache", type=Path, default=Path(".bench/pr-v2-cache"))
    build.add_argument("--out", type=Path, default=WORK)
    build.add_argument("--check-only", action="store_true", help="fetch and verify every entry without writing a suite")
    look = sub.add_parser("lookup", help="read, search, or list a case's code from its Git store")
    look.add_argument("--work", type=Path, default=WORK)
    look.add_argument("--case", required=True)
    look_actions = look.add_subparsers(dest="lookup_action", required=True)
    for name in ("read", "search", "list"):
        action = look_actions.add_parser(name)
        action.add_argument("--side", choices=["base", "head"], required=True)
        action.add_argument("--path", required=(name == "read"))
        if name == "read":
            action.add_argument("--start", type=int, default=1)
            action.add_argument("--end", type=int)
        if name == "search":
            action.add_argument("--pattern", required=True)
            action.add_argument("--ignore-case", action="store_true")
    unpack = sub.add_parser("unpack", help="unpack one case's base and head folders, such as to mount them in a sandbox")
    unpack.add_argument("--case", required=True)
    unpack.add_argument("--work", type=Path, default=WORK)
    unpack.add_argument("--remove", action="store_true", help="delete the case's unpacked folders instead")
    for name in ("export", "run"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--case", action="append", dest="case_ids")
        cmd.add_argument("--split", choices=["dev", "holdout", "all"], default="dev")
        cmd.add_argument("--work", type=Path, default=WORK)
        cmd.add_argument("--out", required=True)
        cmd.add_argument("--unpack", action="store_true", help="give the reviewer unpacked folders instead of lookup commands")
        if name == "run":
            cmd.add_argument("--model", required=True)
            cmd.add_argument("--timeout", type=int, default=300)
            cmd.add_argument("command", nargs=argparse.REMAINDER)
    template = sub.add_parser("grade-template")
    template.add_argument("--results", required=True)
    template.add_argument("--out", required=True)
    judging = sub.add_parser("judge", help="draft adjudications automatically with TypeSafe AI's Jev (needs JEV_API_KEY)")
    judging.add_argument("--results", required=True)
    judging.add_argument("--out", required=True)
    judging.add_argument("--threshold", type=float, default=0.7, help="minimum confidence to resolve a finding")
    judging.add_argument("--model", default="jev-latest")
    scoring = sub.add_parser("score")
    scoring.add_argument("--results", required=True)
    scoring.add_argument("--grades", required=True)
    scoring.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        if args.action == "build":
            from .pr_history import build, coverage, load_manifest
            targets, manifest = load(args.targets), load_manifest(args.manifest)
            covered = coverage(targets, manifest)
            suite = build(targets, manifest, args.cache, args.out, args.check_only)
            print(f"{'Checked' if args.check_only else 'Built'} {len(suite['cases'])} PR cases; validation scope: source review.")
            print(f"Targets: {covered['covered']}/{covered['target_count']} covered, {len(covered['unusable'])} not used, {len(covered['unaccounted'])} unaccounted.")
            if not args.check_only:
                write_json(args.out / "coverage.json", covered)
            return 0
        data = load(args.catalog)
        if args.action == "validate":
            print(json.dumps({"cases": len(data["cases"]), "labels": sum(len(c["labels"]) for c in data["cases"]), "sha256": digest(data)}))
        elif args.action == "list":
            for c in data["cases"]:
                print(f"{c['id']}  {c['split']:7} {c['repository']}  ({len(c['labels'])} labels)")
        elif args.action == "lookup":
            from . import lookup
            lock = checked_lock(data, find_case(data, args.case), args.work)
            if args.lookup_action == "read":
                result = lookup.read(lock, args.side, args.path, args.start, args.end)
            elif args.lookup_action == "search":
                result = lookup.search(lock, args.side, args.pattern, args.path, args.ignore_case)
            else:
                result = lookup.listing(lock, args.side, args.path)
            print(json.dumps(result))
        elif args.action == "unpack":
            lock = checked_lock(data, find_case(data, args.case), args.work)
            if args.remove:
                remove_case(lock)
                print(f"Removed {args.case}'s unpacked folders.")
            else:
                unpack_case(lock)
                print(f"Unpacked {args.case}: {lock['source_dir']} and {lock['base_source_dir']}")
        elif args.action in {"export", "run"}:
            known = {c["id"] for c in data["cases"]}
            if args.case_ids and set(args.case_ids) - known:
                raise ValueError("unknown case ID")
            selected = [c for c in data["cases"] if (c["id"] in args.case_ids if args.case_ids else args.split == "all" or c["split"] == args.split)]
            if not selected:
                raise ValueError("no cases selected")
            if args.action == "export":
                write_json(args.out, [task(data, c, args.work, lookup_command(args), args.unpack) for c in selected])
            else:
                command = args.command[1:] if args.command[:1] == ["--"] else args.command
                result = run(data, selected, args.work, command, args.model, args.timeout, lookup_command(args), args.unpack)
                write_json(args.out, result)
                return int(any(c["status"] == "error" for c in result["cases"]))
        elif args.action == "grade-template":
            write_json(args.out, grade_template(read_json(args.results)))
        elif args.action == "judge":
            from .judge import grade
            grades = grade(data, read_json(args.results), threshold=args.threshold, model=args.model)
            write_json(args.out, grades)
            counts = {}
            for d in grades["decisions"]:
                counts[d["decision"]] = counts.get(d["decision"], 0) + 1
            print(f"Graded {len(grades['decisions'])} findings automatically: {counts}")
        elif args.action == "score":
            result = score(data, read_json(args.results), read_json(args.grades))
            write_json(args.out, result)
            print(json.dumps(result, indent=2))
        return 0
    except (ValueError, AssertionError, KeyError, OSError, subprocess.SubprocessError) as e:
        print(f"secbench: {e}", file=sys.stderr)
        return 2
