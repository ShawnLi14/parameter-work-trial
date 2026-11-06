"""Self-improvement loop for the self-improving reviewer, inspired by AgentFlow's harness search.

    python -m benchmark improve

The reviewer's model and every loop setting come from config.toml ([model], [improve]).
The loop learns a find-verify profile for that model and, when it finishes, writes the
best one to reviewer/self_improving/profiles/<model>.json, which the self-improving
agent then uses. Its rounds are kept in .bench/runs/<model>/self-improving/loop/; run the
command again to resume, or to keep improving from the learned profile.

Each round: evaluate the incumbent profile, attribute every failure to a stage
(benchmark/triage.py), ask an optimizer model for ONE edit to the profile, reject edits
that name benchmark repositories, files, or functions, evaluate the edited profile, and
keep it only if F1 improves while bugs found stays within improve.recall_slack of the
starting profile (so recall cannot erode round by round).

  false findings / verifier rejections -> edit the verifier criteria
  bugs never proposed                  -> update a specialist, or add a new one
  bugs found but mislocated or merged  -> edit the finder guidance

By default the loop runs on the whole benchmark (improve.split = "all"): the held-out
projects contain mostly different kinds of bug, so tuning on dev cannot transfer to them.
The optimizer then sees every labelled bug, so scores measure how well the profile fits
this benchmark, not how it would do on unseen pull requests. With improve.split = "dev",
the held-out cases are never shown to the optimizer.
"""

import copy
import os
import shutil
import json
from pathlib import Path
import re
import subprocess
import tempfile
import sys

from .catalog import digest, load
from .judge import grade
from .runner import read_json, write_json
from .scoring import score
from .triage import triage

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "benchmark/data/cases.json"
DEFAULT_PROFILE = ROOT / "reviewer/find_verify/profile.json"
RUNS = ROOT / ".bench" / "runs"
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

You get the results of the CURRENT profile on a set of real pull requests,
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
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "profile.json"
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
    """Keep an edit only if F1 rises and bugs found stays within the slack of the start.

    A failed case (for example a timeout) already counts as missed bugs in both
    numbers, so it does not veto an edit on its own.
    """
    return (candidate["objective"] > incumbent["objective"]
            and candidate["true_positives"] >= start["true_positives"] - recall_slack)


def summarize(scored):
    keys = ("true_positives", "target_count", "adjudicated_false_positives", "unresolved_findings",
            "failed_cases", "target_recall", "precision", "negative_control_alarm_rate")
    return {k: scored.get(k) for k in keys}


def evaluate(profile_path, out_dir, data, split, label, model, timeout):
    """Run, grade, score, and triage one profile. Returns the summary dict."""
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / f"{label}-results.json"
    if not results_path.exists():
        command = [sys.executable, "-m", "benchmark", "run-command", "--split", split,
                   "--model", f"{model}/find-verify/{Path(profile_path).stem}", "--timeout", str(timeout),
                   "--out", str(results_path), "--", sys.executable, str(ROOT / "reviewer" / "find_verify")]
        print(f"  running {split} for {Path(profile_path).name} ...", flush=True)
        # The find_verify agent reviews with this profile instead of its own.
        environment = {**os.environ, "REVIEWER_PROFILE": str(Path(profile_path).resolve())}
        # The runner exits 1 when any case fails; failed cases are scored as missed.
        subprocess.run(command, cwd=ROOT, stdout=subprocess.DEVNULL, env=environment)
        if not results_path.exists():
            raise RuntimeError(f"benchmark run wrote no results for {Path(profile_path).name}")
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

def failures_for_optimizer(report, split="dev"):
    """Failures in the loop's split, grouped by stage; labels carry class and mechanism, not ids."""
    def included(item):
        return split == "all" or item["split"] == split

    bugs = [b for b in report["bugs"] if included(b) and b["stage"] != "found"]
    return {
        "not_proposed": [{"case": b["case_id"], "class": b["title"], "mechanism": b["mechanism"]}
                         for b in bugs if b["stage"] == "not_proposed"],
        "verifier_dropped": [{"case": b["case_id"], "class": b["title"], "mechanism": b["mechanism"],
                              "stage": b["stage"], "verifier_reasons": b["verifier_reasons"]}
                             for b in bugs if b["stage"] != "not_proposed"],
        "false_findings": [{"case": f["case_id"], "control": not f["variant"] or f["variant"] != "introduced_historical",
                            "title": f["title"], "proposed_by": f["proposed_by"], "description": f["description"][:1500]}
                           for f in report["false_findings"] if included(f)],
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


def propose(profile, report, history, banned, attempts=3, provider="cerebras", model="gpt-oss-120b", split="dev"):
    from reviewer.config import load_environment
    from reviewer.providers import PROVIDERS, send
    key = load_environment().get(PROVIDERS[provider]["key"])
    if not key:
        raise ValueError(f"Set {PROVIDERS[provider]['key']} for the optimizer")
    payload = {"model": model, "max_completion_tokens": 16384, "reasoning_effort": "high", "stream": False, "messages": [
                   {"role": "system", "content": OPTIMIZER},
                   {"role": "user", "content": json.dumps({
                       "profile": profile, "failures": failures_for_optimizer(report, split),
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

def run_loop(rounds=None):
    from reviewer.config import load_settings
    from reviewer.self_improving import profile_path
    settings = load_settings()
    provider, model = settings["model"]["provider"], settings["model"]["name"]
    loop_settings, timeout = settings["improve"], settings["benchmark"]["timeout"]
    rounds = loop_settings["rounds"] if rounds is None else rounds
    data = load(SUITE)
    banned = banned_terms(data)
    agent_dir = RUNS / model / "self-improving"
    home = agent_dir / "loop"
    home.mkdir(parents=True, exist_ok=True)
    state_path = home / "state.json"
    if state_path.exists():
        state = read_json(state_path)
        split = state.get("split", "dev")  # a resumed run keeps the split it started with
    else:
        split = loop_settings["split"]
        learned = profile_path(model)
        start = learned if learned.exists() else DEFAULT_PROFILE
        write_json(home / "p000.json", read_json(start))
        state = {"incumbent": "p000.json", "rounds": [], "catalog_sha256": digest(data), "split": split,
                 "model": model, "started_from": str(start.relative_to(ROOT))}
        seed = RUNS / model / "find-verify" / "results.json"
        if start == DEFAULT_PROFILE and seed.exists():
            # find-verify's own run used this same default profile: reuse it as round 0.
            ids = {c["id"] for c in data["cases"] if split == "all" or c["split"] == split}
            (home / "p000").mkdir(parents=True, exist_ok=True)
            write_json(home / "p000" / f"{split}-results.json", subset(read_json(seed), ids))
        summary, _ = evaluate(home / "p000.json", home / "p000", data, split, split, model, timeout)
        state["incumbent_summary"] = state["start_summary"] = summary
        write_json(state_path, state)
    print(f"{model}: incumbent {state['incumbent']}: {state['incumbent_summary']}")
    for _ in range(rounds):
        number = len(state["rounds"]) + 1
        incumbent = read_json(home / state["incumbent"])
        report = read_json(home / Path(state["incumbent"]).stem / f"{split}-triage.json")
        history = [{"round": r["round"], "edit": r.get("edit_summary"), "accepted": r["accepted"],
                    "objective": r.get("summary", {}).get("objective")} for r in state["rounds"]]
        name = f"p{number:03}.json"
        saved = home / f"p{number:03}-proposal.json"
        if saved.exists() and (home / name).exists():
            # An interrupted round resumes with its saved edit and any results already run.
            proposal, profile = read_json(saved), read_json(home / name)
            print(f"round {number}: resuming its saved edit", flush=True)
        else:
            print(f"round {number}: proposing an edit ...", flush=True)
            try:
                proposal, profile = propose(incumbent, report, history, banned, provider=provider,
                                            model=loop_settings["optimizer_model"] or model, split=split)
            except ValueError as error:
                state["rounds"].append({"round": number, "accepted": False, "error": str(error)})
                write_json(state_path, state)
                print(f"  no valid edit: {error}")
                continue
            write_json(home / name, profile)
            write_json(saved, proposal)
        print(f"  edit: {describe(proposal['edit'])}")
        summary, _ = evaluate(home / name, home / f"p{number:03}", data, split, split, model, timeout)
        accepted = keep(summary, state["incumbent_summary"], state["start_summary"], loop_settings["recall_slack"])
        state["rounds"].append({"round": number, "profile": name, "edit_summary": describe(proposal["edit"]),
                                "summary": summary, "accepted": accepted,
                                "incumbent_objective": state["incumbent_summary"]["objective"]})
        if accepted:
            state["incumbent"], state["incumbent_summary"] = name, summary
        write_json(state_path, state)
        print(f"  {split} F1 {summary['objective']} (bugs {summary['true_positives']}, false {summary['adjudicated_false_positives']}) "
              f"vs incumbent F1 {state['rounds'][-1]['incumbent_objective']}, floor {state['start_summary']['true_positives'] - loop_settings['recall_slack']} bugs: "
              f"{'ACCEPTED' if accepted else 'rejected'}")
    publish(home, state, agent_dir, profile_path(model), split)
    print(f"final incumbent {state['incumbent']}: {state['incumbent_summary']}")
    print(f"learned profile: {profile_path(model).relative_to(ROOT)}")


def publish(home, state, agent_dir, destination, split):
    """Give the self-improving agent the best profile, and keep its run beside the others."""
    write_json(destination, read_json(home / state["incumbent"]))
    rounds = home / Path(state["incumbent"]).stem
    for name in ("results", "grades", "score"):
        source = rounds / f"{split}-{name}.json"
        if source.exists():
            shutil.copyfile(source, agent_dir / f"{name}.json")


def main(argv=None):
    # Proposals contain non-ASCII text; Windows consoles default to a legacy codepage.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    run_loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
