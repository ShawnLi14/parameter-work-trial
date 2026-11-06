import argparse
import json
from pathlib import Path
import subprocess
import sys

from .catalog import TARGETS, digest, load
from .runner import checked_lock, read_json, remove_case, run, task, unpack_case, write_json
from .scoring import grade_template, score

ROOT = Path(__file__).resolve().parents[1]
SUITE = Path("benchmark/data/cases.json")
WORK = Path(".bench/suite")
# The reviewer agents in reviewer/, by the name the commands below take.
AGENTS = {"single-call": "single_call", "find-verify": "find_verify", "self-improving": "self_improving"}


def lookup_command(args):
    """The command a reviewer appends a lookup action to; it carries no commit IDs."""
    return [sys.executable, "-m", "benchmark", "--catalog", str(Path(args.catalog).resolve()),
            "lookup", "--work", str(Path(getattr(args, "work", WORK)).resolve())]


def agent_settings():
    from reviewer.config import load_settings
    return load_settings()


def run_dir(agent, settings):
    """Where an agent's run on the configured model lives: .bench/runs/<model>/<agent>/."""
    return ROOT / ".bench" / "runs" / settings["model"]["name"] / agent


def select(data, case_ids, split):
    known = {c["id"] for c in data["cases"]}
    if case_ids and set(case_ids) - known:
        raise ValueError("unknown case ID")
    selected = [c for c in data["cases"] if (c["id"] in case_ids if case_ids else split == "all" or c["split"] == split)]
    if not selected:
        raise ValueError("no cases selected")
    return selected


def run_agent(data, args, settings):
    """Run a reviewer agent on the configured split (or the given cases) and save its results."""
    folder = run_dir(args.agent, settings)
    result = run(data, select(data, args.case_ids, settings["benchmark"]["split"]), WORK,
                 [sys.executable, str(ROOT / "reviewer" / AGENTS[args.agent])], settings["model"]["name"],
                 settings["benchmark"]["timeout"], lookup_command(args))
    write_json(folder / "results.json", result)
    failed = sum(c["status"] == "error" for c in result["cases"])
    print(f"{args.agent} on {settings['model']['name']}: {len(result['cases'])} cases, {failed} failed -> "
          f"{(folder / 'results.json').relative_to(ROOT)}")
    return result


def agent_grades(folder, results):
    """Hand-reviewed grades when they belong to these results, otherwise Jev's."""
    reviewed = folder / "grades-reviewed.json"
    if reviewed.exists() and read_json(reviewed).get("results_sha256") == digest(results):
        return reviewed
    return folder / "grades.json"


def find_case(data, case_id):
    case = next((c for c in data["cases"] if c["id"] == case_id), None)
    if case is None:
        raise ValueError("unknown case ID")
    return case


def judge_results(data, results, threshold=0.7):
    from .judge import grade
    grades = grade(data, results, threshold=threshold)
    counts = {}
    for d in grades["decisions"]:
        counts[d["decision"]] = counts.get(d["decision"], 0) + 1
    print(f"Graded {len(grades['decisions'])} findings automatically: {counts}")
    return grades


def write_score(data, results, grades_path, out):
    result = score(data, results, read_json(grades_path))
    result["grades_file"] = Path(grades_path).name
    write_json(out, result)
    return result


def print_score(result):
    keys = ("true_positives", "target_count", "target_recall", "precision", "f1", "adjudicated_false_positives",
            "unresolved_findings", "failed_cases", "negative_control_alarm_rate")
    print(json.dumps({k: result.get(k) for k in keys} | {"grades_file": result.get("grades_file")}, indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(description="Security review benchmark built from real upstream PRs")
    p.add_argument("--catalog", type=Path, default=SUITE, help="PR suite catalog (default: %(default)s)")
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("validate")
    sub.add_parser("list")
    build = sub.add_parser("build", help="fetch the pinned commits and write the PR suite")
    build.add_argument("--targets", type=Path, default=TARGETS, help="advisory target list the labels come from")
    build.add_argument("--manifest", type=Path, default=Path("benchmark/data/manifest.json"))
    build.add_argument("--cache", type=Path, default=Path(".bench/repos"))
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
    export = sub.add_parser("export", help="write the benchmark requests to a file")
    export.add_argument("--out", required=True)
    export.add_argument("--case", action="append", dest="case_ids")
    export.add_argument("--split", choices=["dev", "holdout", "all"], default="all")
    export.add_argument("--work", type=Path, default=WORK)
    export.add_argument("--unpack", action="store_true", help="give the reviewer unpacked folders instead of lookup commands")
    for name, text in (("run", "run a reviewer agent; results go to .bench/runs/<model>/<agent>/"),
                       ("evaluate", "run a reviewer agent, grade it with Jev, and score it"),
                       ("judge", "grade a reviewer agent's run with Jev (needs JEV_API_KEY)"),
                       ("score", "score a reviewer agent's run (hand-reviewed grades if present)")):
        cmd = sub.add_parser(name, help=text)
        cmd.add_argument("agent", choices=AGENTS, nargs="?" if name in ("judge", "score") else None)
        if name in ("run", "evaluate"):
            cmd.add_argument("--case", action="append", dest="case_ids", help="only this case (repeatable)")
    custom = sub.add_parser("run-command", help="run any reviewer program: ... --out FILE --model LABEL -- COMMAND")
    custom.add_argument("--out", required=True)
    custom.add_argument("--model", required=True, help="label recorded in the results")
    custom.add_argument("--case", action="append", dest="case_ids")
    custom.add_argument("--split", choices=["dev", "holdout", "all"], default="all")
    custom.add_argument("--timeout", type=int, default=420)
    custom.add_argument("--work", type=Path, default=WORK)
    custom.add_argument("--unpack", action="store_true", help="give the reviewer unpacked folders instead of lookup commands")
    custom.add_argument("command", nargs=argparse.REMAINDER)
    sub.add_parser("improve", help="improve the self-improving reviewer's profile for the configured model")
    template = sub.add_parser("grade-template")
    template.add_argument("--results", required=True)
    template.add_argument("--out", required=True)
    judging = sub.choices["judge"]
    judging.add_argument("--results", help="instead of an agent name: a results file")
    judging.add_argument("--out", help="with --results: where to write the grades")
    judging.add_argument("--threshold", type=float, default=0.7, help="minimum confidence to resolve a finding")
    scoring = sub.choices["score"]
    scoring.add_argument("--results", help="instead of an agent name: a results file")
    scoring.add_argument("--grades", help="with --results: its grades file")
    scoring.add_argument("--out", help="with --results: where to write the score")
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
        elif args.action == "export":
            write_json(args.out, [task(data, c, args.work, lookup_command(args), args.unpack)
                                  for c in select(data, args.case_ids, args.split)])
        elif args.action == "run-command":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            result = run(data, select(data, args.case_ids, args.split), args.work, command, args.model,
                         args.timeout, lookup_command(args), args.unpack)
            write_json(args.out, result)
            return int(any(c["status"] == "error" for c in result["cases"]))
        elif args.action == "run":
            result = run_agent(data, args, agent_settings())
            return int(any(c["status"] == "error" for c in result["cases"]))
        elif args.action == "evaluate":
            settings = agent_settings()
            folder = run_dir(args.agent, settings)
            results = run_agent(data, args, settings)
            write_json(folder / "grades.json", judge_results(data, results))
            print_score(write_score(data, results, folder / "grades.json", folder / "score.json"))
        elif args.action == "grade-template":
            write_json(args.out, grade_template(read_json(args.results)))
        elif args.action == "judge":
            if args.agent:
                folder = run_dir(args.agent, agent_settings())
                results_path, out = folder / "results.json", folder / "grades.json"
            elif args.results and args.out:
                results_path, out = Path(args.results), Path(args.out)
            else:
                raise ValueError("give an agent name, or --results and --out")
            write_json(out, judge_results(data, read_json(results_path), args.threshold))
        elif args.action == "score":
            if args.agent:
                folder = run_dir(args.agent, agent_settings())
                results = read_json(folder / "results.json")
                grades, out = agent_grades(folder, results), folder / "score.json"
            elif args.results and args.grades and args.out:
                results, grades, out = read_json(args.results), Path(args.grades), Path(args.out)
            else:
                raise ValueError("give an agent name, or --results, --grades, and --out")
            print_score(write_score(data, results, grades, out))
        elif args.action == "improve":
            from .improve import main as improve
            return improve()
        return 0
    except (ValueError, AssertionError, KeyError, OSError, subprocess.SubprocessError) as e:
        print(f"benchmark: {e}", file=sys.stderr)
        return 2
