import argparse
import json
from pathlib import Path
import subprocess
import sys

from .catalog import CATALOG, digest, load
from .runner import prepare, read_json, run, task, write_json
from .scoring import grade_template, score


def main(argv=None):
    p = argparse.ArgumentParser(description="Security Lab source benchmark")
    p.add_argument("--catalog", type=Path, default=CATALOG)
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("validate")
    sub.add_parser("list")
    check = sub.add_parser("check-sources")
    check.add_argument("--work",type=Path,default=Path(".bench"))
    check.add_argument("--out",required=True)
    build_pr = sub.add_parser("build-pr-cases")
    build_pr.add_argument("--work",type=Path,default=Path(".bench"))
    build_pr.add_argument("--out",type=Path,default=Path(".bench/pr-v1"))
    freeze = sub.add_parser("freeze")
    freeze.add_argument("--out", required=True)
    for name in ("prepare", "export", "run"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--case", action="append", dest="case_ids")
        cmd.add_argument("--split", choices=["dev", "holdout", "all"], default="dev")
        cmd.add_argument("--work", type=Path, default=Path(".bench"))
        if name == "prepare":
            cmd.add_argument("--from-repo", type=Path, help="existing local clone; requires one --case")
        else:
            cmd.add_argument("--out", required=True)
        if name == "run":
            cmd.add_argument("--model", required=True)
            cmd.add_argument("--timeout", type=int, default=300)
            cmd.add_argument("command", nargs=argparse.REMAINDER)
    template = sub.add_parser("grade-template")
    template.add_argument("--results", required=True)
    template.add_argument("--out", required=True)
    scoring = sub.add_parser("score")
    scoring.add_argument("--results", required=True)
    scoring.add_argument("--grades", required=True)
    scoring.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        data = load(args.catalog)
        if args.action == "validate":
            print(json.dumps({"cases": len(data["cases"]), "labels": sum(len(c["labels"]) for c in data["cases"]), "sha256":digest(data)}))
        elif args.action == "list":
            for c in data["cases"]:
                print(f"{c['id']}  {c['split']:7} {c['repository']} @ {c['ref']}  ({len(c['labels'])} labels; {c['validation']})")
        elif args.action == "freeze":
            write_json(args.out, {"catalog_sha256":digest(data), "catalog":data})
        elif args.action == "build-pr-cases":
            from .pr_cases import build
            suite=build(data,args.work,args.out)
            print(f"Built {len(suite['cases'])} PR cases in {args.out}; validation scope: isolated functions.")
        elif args.action == "check-sources":
            from .source_checks import check_sources
            report = check_sources(data,args.work)
            write_json(args.out,report)
            found = sum(l["status"] == "anchor_found" for c in report["cases"] for l in c["labels"])
            total = sum(len(c["labels"]) for c in report["cases"])
            print(f"Located {found}/{total} source anchors; this does not validate exploitability.")
        elif args.action in {"prepare", "export", "run"}:
            known = {c["id"] for c in data["cases"]}
            if args.case_ids and set(args.case_ids) - known:
                raise ValueError("unknown case ID")
            selected = [c for c in data["cases"] if (c["id"] in args.case_ids if args.case_ids else args.split == "all" or c["split"] == args.split)]
            if not selected:
                raise ValueError("no cases selected")
            if args.action == "prepare":
                if args.from_repo and len(selected) != 1:
                    raise ValueError("--from-repo requires exactly one case")
                for c in selected:
                    lock = prepare(data,c,args.work,args.from_repo)
                    print(f"Prepared {c['id']} @ {lock['commit']}")
            elif args.action == "export":
                write_json(args.out, [task(data,c,args.work) for c in selected])
            else:
                command = args.command[1:] if args.command[:1] == ["--"] else args.command
                result = run(data,selected,args.work,command,args.model,args.timeout)
                write_json(args.out,result)
                return int(any(c["status"] == "error" for c in result["cases"]))
        elif args.action == "grade-template":
            write_json(args.out,grade_template(read_json(args.results)))
        elif args.action == "score":
            result = score(data,read_json(args.results),read_json(args.grades))
            write_json(args.out,result)
            print(json.dumps(result,indent=2))
        return 0
    except (ValueError, AssertionError, KeyError, OSError, subprocess.SubprocessError) as e:
        print(f"secbench: {e}",file=sys.stderr)
        return 2
