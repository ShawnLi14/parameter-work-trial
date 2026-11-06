"""Self-improvement loop for the find-verify reviewer, inspired by AgentFlow's harness search.

Each round: evaluate the incumbent profile on the dev split, attribute every failure to a
stage (benchmark/triage.py), ask an optimizer model for ONE edit to the profile, reject
edits that name benchmark repositories, files, or functions, evaluate the edited profile
on dev, and keep it only if dev F1 improves while bugs found stays within --recall-slack
of the starting profile (so recall cannot erode round by round).

  false findings / verifier rejections -> edit the verifier criteria
  bugs never proposed                  -> update a specialist, or add a new one
  bugs found but mislocated or merged  -> edit the finder guidance

The holdout split is never shown to the optimizer and never run inside the loop; use
--evaluate-holdout on a finished profile.

    python -m benchmark.improve --name r1 --rounds 5
    python -m benchmark.improve --name r1 --evaluate-holdout .bench/improve/r1/p003.json
"""

import argparse
import copy
import json
from pathlib import Path
import re
import subprocess
import sys

from .catalog import digest, load
from .judge import grade
from .runner import read_json, write_json
from .scoring import score
from .triage import triage

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "benchmark/data/cases.json"
DEFAULT_PROFILE = ROOT / "reviewer/profiles/default.json"
EDIT_KINDS = ("set_verifier_criteria", "set_finder_guidance", "add_specialist", "update_specialist", "remove_specialist")

OPTIMIZER = """You improve an automated security reviewer for pull requests.

The reviewer has two stages, configured by an editable PROFILE:
1. Hunters propose candidate vulnerabilities from the diff, reading other code as needed:
   a general finder (its prompt ends with profile.finder_guidance) plus optional
   specialists, each hunting one vulnerability class. A specialist has name, focus (one
   sentence: the class it hunts), guidance (how to hunt it: sources, sinks, missing
   defenses to look for), and triggers (case-insensitive regular expressions matched
   against the diff's changed lines; it runs only when one matches; empty = always).
2. A verifier checks each candidate in the code and confirms, rejects, or is uncertain,
   following profile.verifier_criteria. Only confirmed candidates are reported.

You get the results of the CURRENT profile on a development set of real pull requests,
with every failure attributed to a stage:
- not_proposed: a real bug no hunter proposed -> improve a specialist or add one.
- verifier_rejected / verifier_uncertain: a real bug proposed, then wrongly dropped
  -> loosen the verifier criteria precisely for that situation.
- false_findings: a candidate the verifier wrongly confirmed -> tighten the criteria.
Verifier changes pull both ways: never fix false findings by rejecting real bugs.

Diagnose first. For each failure group, state the stage, the bottleneck, what that
component should have done, and what it actually did. Then propose exactly ONE edit that
should fix the largest group without breaking what already works.

Rules for the edit:
- It must be GENERAL: describe vulnerability classes, dangerous operations, and defenses
  that apply to any codebase. Never mention a repository, product, file, function, variable,
  or advisory id from the failures; such edits are rejected automatically.
- At most 8 specialists. Prefer improving an existing specialist over adding a near-duplicate.
- Triggers should be broad enough to fire on any code of the class (common API names,
  framework calls), not on one project's identifiers.
- Keep texts concise: criteria and guidance at most about 1500 characters.

Return one JSON object only:
{"diagnosis": [{"failures": ["case/label or finding ids"], "stage": "...",
  "bottleneck": "...", "intended": "...", "actual": "..."}],
 "edit": {"kind": "set_verifier_criteria", "text": "..."}
       | {"kind": "set_finder_guidance", "text": "..."}
       | {"kind": "add_specialist" | "update_specialist",
          "specialist": {"name": "...", "focus": "...", "guidance": "...", "triggers": ["..."]}}
       | {"kind": "remove_specialist", "name": "..."},
 "expected_effect": "which failures this should fix, and what it might break"}
"""


# --- leakage guard ------------------------------------------------------------------------

def banned_terms(data):
    """Project-specific names from every case (dev and holdout) that edits may not contain."""
    # Ordinary words that happen to appear in repository or route names stay usable.
    common = {"based", "conversion", "credentials", "retrieval", "voice", "project", "server", "files",
              "upload", "download", "export", "assignment", "assignments",
              # Standard API and parameter names that describe a class, not a project.
              "send_file", "redirect_uri", "id_token", "file_name", "model_name", "model_path", "index.ts",
              "upload_file", "upload_files", "write_file", "create_file", "delete_file", "download_file"}
    terms = set()
    for case in data["cases"]:
        owner, repo = case["repository"].lower().split("/")
        terms.update({owner, repo})
        terms.update(p for p in re.split(r"[_-]", owner + "-" + repo) if len(p) >= 6)
        for label in case["labels"] + case.get("also_valid", []):
            terms.add(label["id"].lower())
            hint = label.get("location_hint", "")
            for token in re.findall(r"[A-Za-z0-9_./-]+", hint + " " + label.get("mechanism", "")):
                token = token.strip("./-")
                if "/" in token or re.search(r"\.(py|js|ts|tsx|rb|erb|java|go|php|vue|jsx)$", token):
                    terms.add(token.lower())
                    base = token.rsplit("/", 1)[-1].lower()
                    if re.search(r"[._-]", base):
                        terms.add(base)
                elif "_" in token.strip("_") and len(token) >= 6:
                    terms.add(token.lower())  # project identifiers such as open_denoise
            if ":" in hint:
                for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", hint.split(":", 1)[1]):
                    if "_" in token or re.search(r"[a-z][A-Z]", token):
                        terms.add(token.lower())
    return {t for t in terms if len(t) >= 4 and t not in common}


def leaks(text, banned):
    lowered = text.lower()
    return sorted(t for t in banned if re.search(r"(?<![a-z0-9_])" + re.escape(t) + r"(?![a-z0-9_])", lowered))


# --- profile edits ------------------------------------------------------------------------

def apply_edit(profile, edit):
    """Return a new profile with one edit applied, or raise ValueError."""
    from reviewer.find_verify import load_profile  # validation lives with the reviewer
    if not isinstance(edit, dict) or edit.get("kind") not in EDIT_KINDS:
        raise ValueError(f"edit kind must be one of {EDIT_KINDS}")
    new = copy.deepcopy(profile)
    kind = edit["kind"]
    if kind == "set_verifier_criteria":
        new["verifier_criteria"] = edit.get("text")
    elif kind == "set_finder_guidance":
        new["finder_guidance"] = edit.get("text")
    elif kind == "remove_specialist":
        names = [s["name"] for s in new["specialists"]]
        if edit.get("name") not in names:
            raise ValueError(f"no specialist named {edit.get('name')!r}")
        new["specialists"] = [s for s in new["specialists"] if s["name"] != edit["name"]]
    else:
        spec = edit.get("specialist")
        if not isinstance(spec, dict):
            raise ValueError("specialist object required")
        spec = {k: spec.get(k) for k in ("name", "focus", "guidance", "triggers")}
        spec["triggers"] = spec["triggers"] or []
        names = [s["name"] for s in new["specialists"]]
        if kind == "add_specialist":
            if spec["name"] in names:
                raise ValueError(f"specialist {spec['name']!r} exists; use update_specialist")
            new["specialists"].append(spec)
        else:
            if spec["name"] not in names:
                raise ValueError(f"no specialist named {spec['name']!r}; use add_specialist")
            new["specialists"] = [spec if s["name"] == spec["name"] else s for s in new["specialists"]]
    new["version"] = profile.get("version", 0) + 1
    path = ROOT / ".bench" / "improve" / ".validate.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, new)
    load_profile(path)  # raises ValueError if invalid
    return new


def edit_text(edit):
    return json.dumps(edit, ensure_ascii=False)


# --- evaluation ---------------------------------------------------------------------------

def objective(summary):
    """Dev F1 over labelled bugs: matched bugs against targets and against all findings."""
    tp, fp, targets = summary["true_positives"], summary["adjudicated_false_positives"], summary["target_count"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / targets if targets else 0.0
    return round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0


def keep(candidate, incumbent, start, recall_slack):
    """Keep an edit only if F1 rises and bugs found stays within the slack of the start."""
    return (candidate["objective"] > incumbent["objective"]
            and candidate["true_positives"] >= start["true_positives"] - recall_slack
            and not candidate["failed_cases"])


def summarize(scored):
    keys = ("true_positives", "target_count", "adjudicated_false_positives", "unresolved_findings",
            "failed_cases", "target_recall", "precision", "negative_control_alarm_rate")
    return {k: scored.get(k) for k in keys}


def evaluate(profile_path, out_dir, data, split="dev", label="eval", provider="cerebras", model="gpt-oss-120b"):
    """Run, grade, score, and triage one profile. Returns the summary dict."""
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / f"{label}-results.json"
    if not results_path.exists():
        command = [sys.executable, "-m", "benchmark", "run", "--split", split,
                   "--model", f"{provider}/{model}/find-verify/{Path(profile_path).stem}", "--timeout", "420",
                   "--out", str(results_path), "--", sys.executable, str(ROOT / "reviewer"),
                   "--provider", provider, "--model", model, "--strategy", "find-verify",
                   "--profile", str(Path(profile_path).resolve())]
        print(f"  running {split} for {Path(profile_path).name} ...", flush=True)
        subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return grade_and_triage(read_json(results_path), out_dir, data, label)


def grade_and_triage(results, out_dir, data, label):
    grades_path = out_dir / f"{label}-grades.json"
    if grades_path.exists():
        grades = read_json(grades_path)
    else:
        grades = grade(data, results)
        write_json(grades_path, grades)
    scored = score(data, results, grades)
    write_json(out_dir / f"{label}-score.json", scored)
    triage_path = out_dir / f"{label}-triage.json"
    if triage_path.exists():
        report = read_json(triage_path)
    else:
        report = triage(data, results, grades)
        write_json(triage_path, report)
    summary = summarize(scored)
    summary["objective"] = objective(scored)
    summary["stages"] = report["summary"]
    return summary, report


def subset(results, case_ids):
    return {**results, "cases": [r for r in results["cases"] if r["case_id"] in case_ids]}


# --- optimizer ----------------------------------------------------------------------------

def failures_for_optimizer(report):
    """Dev failures only, grouped by stage; labels carry class and mechanism, not ids."""
    bugs = [b for b in report["bugs"] if b["split"] == "dev" and b["stage"] != "found"]
    return {
        "not_proposed": [{"case": b["case_id"], "class": b["title"], "mechanism": b["mechanism"]}
                         for b in bugs if b["stage"] == "not_proposed"],
        "verifier_dropped": [{"case": b["case_id"], "class": b["title"], "mechanism": b["mechanism"],
                              "stage": b["stage"], "verifier_reasons": b["verifier_reasons"]}
                             for b in bugs if b["stage"] != "not_proposed"],
        "false_findings": [{"case": f["case_id"], "control": not f["variant"] or f["variant"] != "introduced_historical",
                            "title": f["title"], "proposed_by": f["proposed_by"], "description": f["description"][:1500]}
                           for f in report["false_findings"] if f["split"] == "dev"],
        "hunter_stats": report["hunters"],
    }


def parse_object(response):
    """The optimizer's reply as one JSON object (an optional ```json fence is allowed)."""
    try:
        choice = response["choices"][0]
        if choice.get("finish_reason") != "stop":
            raise ValueError("Incomplete optimizer response")
        text = choice["message"]["content"].strip()
        if text.startswith("```"):
            text = "\n".join(text.splitlines()[1:-1])
        value = json.loads(text)
    except (AttributeError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        raise ValueError("Optimizer did not return a JSON object") from None
    if not isinstance(value, dict):
        raise ValueError("Optimizer did not return a JSON object")
    return value


def propose(profile, report, history, banned, attempts=3, provider="cerebras", model="gpt-oss-120b"):
    from reviewer.baseline import PROVIDERS, send
    from reviewer.config import load_environment
    key = load_environment().get(PROVIDERS[provider]["key"])
    if not key:
        raise ValueError(f"Set {PROVIDERS[provider]['key']} for the optimizer")
    payload = {"model": model, "max_completion_tokens": 16384, "reasoning_effort": "high", "stream": False, "messages": [
                   {"role": "system", "content": OPTIMIZER},
                   {"role": "user", "content": json.dumps({
                       "profile": profile, "dev_failures": failures_for_optimizer(report),
                       "history": history}, ensure_ascii=False)}]}
    problems = []
    for _ in range(attempts):
        if problems:
            payload["messages"].append({"role": "user", "content": "Your edit was rejected: " + "; ".join(problems)
                                        + ". Return a corrected JSON object."})
        if provider != "anthropic":
            payload["temperature"] = 0.3  # some variety between attempts; Claude rejects sampling parameters
        response = send(provider, payload, key, 300)
        try:
            value = parse_object(response)
            found = leaks(edit_text(value.get("edit")), banned)
            if found:
                raise ValueError(f"edit names project-specific terms {found}; describe the vulnerability class instead")
            new = apply_edit(profile, value.get("edit"))
            return value, new
        except ValueError as error:
            problems = [str(error)]
            text = (response.get("choices") or [{}])[0].get("message", {}).get("content") or ""
            payload["messages"].append({"role": "assistant", "content": text[:20000]})
    raise ValueError(f"optimizer produced no valid edit: {problems}")


def describe(edit):
    if edit["kind"] in ("add_specialist", "update_specialist"):
        return f"{edit['kind']} {edit['specialist'].get('name')}: {edit['specialist'].get('focus', '')[:120]}"
    if edit["kind"] == "remove_specialist":
        return f"remove_specialist {edit.get('name')}"
    return f"{edit['kind']}: {edit.get('text', '')[:120]}"


# --- loop ---------------------------------------------------------------------------------

def run_loop(args):
    data = load(SUITE)
    banned = banned_terms(data)
    home = ROOT / ".bench" / "improve" / args.name
    home.mkdir(parents=True, exist_ok=True)
    state_path = home / "state.json"
    if state_path.exists():
        state = read_json(state_path)
    else:
        profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
        write_json(home / "p000.json", profile)
        state = {"incumbent": "p000.json", "rounds": [], "catalog_sha256": digest(data)}
        if args.seed_results:
            # Reuse an existing dev run of the starting profile instead of re-running it.
            dev = {c["id"] for c in data["cases"] if c["split"] == "dev"}
            (home / "p000").mkdir(parents=True, exist_ok=True)
            write_json(home / "p000" / "dev-results.json", subset(read_json(args.seed_results), dev))
        summary, _ = evaluate(home / "p000.json", home / "p000", data, label="dev", provider=args.provider, model=args.model)
        state["incumbent_summary"] = state["start_summary"] = summary
        write_json(state_path, state)
    print(f"incumbent {state['incumbent']}: {state['incumbent_summary']}")
    for _ in range(args.rounds):
        number = len(state["rounds"]) + 1
        incumbent = read_json(home / state["incumbent"])
        report = read_json(home / Path(state["incumbent"]).stem / "dev-triage.json")
        history = [{"round": r["round"], "edit": r.get("edit_summary"), "accepted": r["accepted"],
                    "objective": r.get("summary", {}).get("objective")} for r in state["rounds"]]
        print(f"round {number}: proposing an edit ...", flush=True)
        try:
            proposal, profile = propose(incumbent, report, history, banned, provider=args.provider,
                                        model=args.optimizer_model or args.model)
        except ValueError as error:
            state["rounds"].append({"round": number, "accepted": False, "error": str(error)})
            write_json(state_path, state)
            print(f"  no valid edit: {error}")
            continue
        name = f"p{number:03}.json"
        write_json(home / name, profile)
        write_json(home / f"p{number:03}-proposal.json", proposal)
        print(f"  edit: {describe(proposal['edit'])}")
        summary, _ = evaluate(home / name, home / f"p{number:03}", data, label="dev", provider=args.provider, model=args.model)
        accepted = keep(summary, state["incumbent_summary"], state["start_summary"], args.recall_slack)
        state["rounds"].append({"round": number, "profile": name, "edit_summary": describe(proposal["edit"]),
                                "summary": summary, "accepted": accepted,
                                "incumbent_objective": state["incumbent_summary"]["objective"]})
        if accepted:
            state["incumbent"], state["incumbent_summary"] = name, summary
        write_json(state_path, state)
        print(f"  dev F1 {summary['objective']} (bugs {summary['true_positives']}, false {summary['adjudicated_false_positives']}) "
              f"vs incumbent F1 {state['rounds'][-1]['incumbent_objective']}, floor {state['start_summary']['true_positives'] - args.recall_slack} bugs: "
              f"{'ACCEPTED' if accepted else 'rejected'}")
    print(f"final incumbent {state['incumbent']}: {state['incumbent_summary']}")


def main(argv=None):
    # Proposals contain non-ASCII text; Windows consoles default to a legacy codepage.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Improve the find-verify reviewer profile on the dev split")
    parser.add_argument("--name", required=True, help="run name; state lives in .bench/improve/NAME")
    parser.add_argument("--profile", default=str(DEFAULT_PROFILE), help="starting profile")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--recall-slack", type=int, default=3,
                        help="bugs found may fall at most this far below the starting profile")
    parser.add_argument("--seed-results", help="existing results of the starting profile (dev cases are reused)")
    parser.add_argument("--evaluate-holdout", help="evaluate this profile on the holdout split and stop")
    parser.add_argument("--provider", default="cerebras", choices=["cerebras", "anthropic"],
                        help="provider for the reviewer runs and the optimizer")
    parser.add_argument("--model", help="reviewer model (default: the provider's default)")
    parser.add_argument("--optimizer-model", help="optimizer model (default: the reviewer model)")
    args = parser.parse_args(argv)
    from reviewer.baseline import PROVIDERS
    args.model = args.model or PROVIDERS[args.provider]["model"]
    if args.evaluate_holdout:
        data = load(SUITE)
        target = Path(args.evaluate_holdout)
        summary, _ = evaluate(target, ROOT / ".bench" / "improve" / args.name / f"holdout-{target.stem}",
                              data, split="holdout", label="holdout", provider=args.provider, model=args.model)
        print(json.dumps(summary, indent=1))
        return 0
    run_loop(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
