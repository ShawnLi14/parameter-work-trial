"""Find-then-verify reviewer: one tool-using finder, then one tool-using verifier per finding.

Stage 1, the finder, reads the line-numbered diff, may look up any other code at base or
head, and calls `report` with candidate vulnerabilities. Stage 2 starts one verifier per
candidate; each looks up the code involved and calls `verdict`. Only confirmed candidates
become findings. Code checks every verifier citation against text that verifier observed.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import threading
import time

from .baseline import DEFAULT_MODEL, PROVIDERS, build_payload, send, sha256, validate_findings
from .code_access import validate_action
from .evidence import Evidence
from .tools import (BASE, CITATION, CITATION_RULES, LOOKUP_TOOL, RATE_LIMIT_ATTEMPTS, NoToolCall,
                    check_citations, echo, model_context, rate_limit_wait, shown, tool_calls)

VERSION = "find-verify-v2"
DEFAULT_PROFILE = Path(__file__).resolve().parent / "profiles" / "default.json"

LOOKUP_HELP = """
lookup reads, searches, or lists repository code on side base (before the PR) or head
(after it). read takes path, start, end (at most 200 lines); search takes a pattern (a
regular expression; escape ( [ . for literal text) and an optional path; list takes an
optional path. Paths are repository-relative. You may call several lookups in one turn.
"""

FINDER = BASE + """
Find the security vulnerabilities this PR introduces or materially worsens.
The diff is labelled with line numbers. Use lookup whenever the diff alone does not
show enough: callers, routes, where input comes from, guards, sanitizers, configuration.
When done, call report ALONE with every vulnerability you found, or an empty list.
For each vulnerability give the diff line where it is introduced (an added line on head,
or a removed protection on base), the mechanism, who controls the input, and the impact.
""" + LOOKUP_HELP

SPECIALIST = BASE + """
You are a specialist reviewer for one class of vulnerability: {name}.
{focus}
Find only vulnerabilities of this class that this PR introduces or materially worsens;
other reviewers cover other classes. The diff is labelled with line numbers. Use lookup
whenever the diff alone does not show enough.
When done, call report ALONE with every vulnerability of this class you found, or an
empty list. For each, give the diff line where it is introduced (an added line on head,
or a removed protection on base), the mechanism, who controls the input, and the impact.
""" + LOOKUP_HELP

VERIFIER = BASE + """
Another reviewer reported the vulnerability below in this PR. Verify, in the code,
whether it is a real problem introduced by this PR. Use lookup to read the code involved.

{criteria}
Stop as soon as you can decide, and call verdict ALONE.
""" + LOOKUP_HELP + CITATION_RULES

_NAME = re.compile(r"[a-z0-9][a-z0-9-]{1,40}")


def load_profile(path=None):
    """Read and validate an editable profile: finder guidance, verifier criteria, specialists."""
    profile = json.loads(Path(path or DEFAULT_PROFILE).read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise ValueError("profile must be a JSON object")
    for key in ("finder_guidance", "verifier_criteria"):
        if not isinstance(profile.get(key), str) or len(profile[key]) > 4000:
            raise ValueError(f"profile {key} must be a string of at most 4000 characters")
    if not profile["verifier_criteria"].strip():
        raise ValueError("profile verifier_criteria must not be empty")
    specialists = profile.get("specialists", [])
    if not isinstance(specialists, list) or len(specialists) > 8:
        raise ValueError("profile specialists must be a list of at most 8")
    names = set()
    for s in specialists:
        if not isinstance(s, dict) or not isinstance(s.get("name"), str) or not _NAME.fullmatch(s["name"]):
            raise ValueError("each specialist needs a lowercase name (letters, digits, hyphens)")
        if s["name"] in names or s["name"] == "finder":
            raise ValueError(f"duplicate or reserved specialist name {s['name']!r}")
        names.add(s["name"])
        for key in ("focus", "guidance"):
            if not isinstance(s.get(key), str) or not s[key].strip() or len(s[key]) > 2000:
                raise ValueError(f"specialist {s['name']}: {key} must be non-empty, at most 2000 characters")
        triggers = s.get("triggers", [])
        if not isinstance(triggers, list) or len(triggers) > 20 or not all(isinstance(t, str) and t for t in triggers):
            raise ValueError(f"specialist {s['name']}: triggers must be a list of regular expressions")
        for t in triggers:
            try:
                re.compile(t)
            except re.error as error:
                raise ValueError(f"specialist {s['name']}: invalid trigger {t!r}: {error}") from None
    return profile


def profile_sha256(profile):
    return sha256(json.dumps(profile, sort_keys=True))


def changed_text(diff):
    return "\n".join(line[1:] for line in diff.splitlines()
                     if line[:1] in "+-" and not line.startswith(("+++", "---")))


def hunters(profile, diff):
    """(name, system prompt) for the general finder and every specialist whose triggers match."""
    text = changed_text(diff)
    result = [("finder", FINDER + "\n" + profile["finder_guidance"])]
    for s in profile.get("specialists", []):
        # A specialist without triggers always runs; otherwise only when the change matches.
        if not s.get("triggers") or any(re.search(t, text, re.IGNORECASE | re.MULTILINE) for t in s["triggers"]):
            prompt = SPECIALIST.replace("{name}", s["name"]).replace("{focus}", s["focus"])
            result.append((s["name"], prompt + "\n" + s["guidance"]))
    return result


def verifier_prompt(profile):
    return VERIFIER.replace("{criteria}", profile["verifier_criteria"])

_SIDE = {"type": "string", "enum": ["base", "head"]}
REPORT_TOOL = {"type": "function", "function": {
    "name": "report", "description": "Submit every vulnerability found (possibly none). Call alone.",
    "parameters": {"type": "object", "properties": {"findings": {"type": "array", "items": {
        "type": "object", "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
            "description": {"type": "string", "description": "mechanism, who controls the input, impact, change relative to base"},
            "path": {"type": "string"}, "line": {"type": "integer"}, "side": _SIDE},
        "required": ["title", "severity", "description", "path", "line", "side"]}}},
        "required": ["findings"]}}}
VERDICT_TOOL = {"type": "function", "function": {
    "name": "verdict", "description": "Give the verification result. Call alone.",
    "parameters": {"type": "object", "properties": {
        "verdict": {"type": "string", "enum": ["confirmed", "rejected", "uncertain"]},
        "reason": {"type": "string", "description": "concise: source, path, sink, change, and any guard seen"},
        "evidence": {"type": "array", "items": CITATION}},
        "required": ["verdict", "reason"]}}}
FINDER_TOOLS = [LOOKUP_TOOL, REPORT_TOOL]
VERIFIER_TOOLS = [LOOKUP_TOOL, VERDICT_TOOL]


@dataclass(frozen=True)
class FindVerifyLimits:
    finder_calls: int = 20
    specialist_calls: int = 14
    verifier_calls: int = 12
    max_candidates: int = 10
    concurrency: int = 3
    max_calls: int = 150
    review_timeout: int = 300
    max_context_chars: int = 300_000

    def __post_init__(self):
        for key, value in asdict(self).items():
            if type(value) is not int or value < 1:
                raise ValueError(f"Invalid limit: {key}")


def finder_messages(context, system):
    return [{"role": "system", "content": system},
            {"role": "user", "content": json.dumps(model_context(context), ensure_ascii=False)}]


def finder_payload(context, model=DEFAULT_MODEL, max_tokens=16384, reasoning_effort="medium", provider="openrouter",
                   profile=None):
    profile = profile or load_profile()
    payload = build_payload(context, model, max_tokens, reasoning_effort, provider)
    return {**payload, "messages": finder_messages(context, hunters(profile, context["diff"])[0][1]),
            "tools": FINDER_TOOLS, "tool_choice": "required", "parallel_tool_calls": True}


def check_candidate(item, diff_lines):
    """Return a cleaned candidate or raise ValueError with a reason the finder can act on."""
    if not isinstance(item, dict):
        raise ValueError("finding must be an object")
    for key in ("title", "description", "path"):
        if not isinstance(item.get(key), str) or not item[key].strip():
            raise ValueError(f"{key} is required")
    if item.get("severity") not in ("critical", "high", "medium", "low"):
        raise ValueError("severity must be critical, high, medium, or low")
    if item.get("side") not in ("base", "head") or type(item.get("line")) is not int:
        raise ValueError("side (base or head) and an integer line are required")
    if (item["side"], item["path"], item["line"]) not in diff_lines:
        raise ValueError(f"{item['side']} {item['path']}:{item['line']} is not a line in the diff; use a [side N] label")
    return {k: item[k] for k in ("title", "severity", "description", "path", "line", "side")}


def review(context, api_key, *, access, model=DEFAULT_MODEL, max_tokens=16384,
           reasoning_effort="medium", timeout=240, record=None, provider="openrouter", limits=None, profile=None):
    limits = limits or FindVerifyLimits()
    profile = profile or load_profile()
    if not api_key or not api_key.strip():
        raise ValueError(f"Set {PROVIDERS[provider]['key']} before running a live review")
    started = time.monotonic()
    deadline = started + limits.review_timeout
    lock = threading.Lock()
    trace = {"prompt_version": VERSION, "limits": asdict(limits), "calls": []}
    usages = []
    prototype = build_payload(context, model, max_tokens, reasoning_effort, provider)
    diff_ledger = Evidence(context["diff"])
    if not diff_ledger.changed:
        raise ValueError("No reviewable changed text lines; binary or unsupported diff paths")

    def save():
        if record:
            record(json.loads(json.dumps(trace)))

    def call(messages, stage, tools):
        if time.monotonic() >= deadline:
            raise TimeoutError("Review deadline exhausted")
        if len(json.dumps(messages, ensure_ascii=False)) > limits.max_context_chars:
            raise ValueError("Context exceeds configured limit")
        payload = {**prototype, "messages": json.loads(json.dumps(messages)), "tools": tools,
                   "tool_choice": "required", "parallel_tool_calls": True}
        entry = {"stage": stage, "request": payload}
        with lock:
            if len(trace["calls"]) >= limits.max_calls:
                raise TimeoutError("Global model-call budget exhausted")
            trace["calls"].append(entry)
            save()
        try:
            for attempt in range(RATE_LIMIT_ATTEMPTS):
                try:
                    response = send(provider, payload, api_key, max(0.01, min(timeout, deadline-time.monotonic())))
                    break
                except ValueError as error:
                    # Only HTTP 429 (refused unprocessed) is resent, and never past the deadline.
                    wait = rate_limit_wait(str(error))
                    if wait is None or attempt == RATE_LIMIT_ATTEMPTS - 1 or time.monotonic() + wait >= deadline:
                        raise
                    with lock:
                        entry.setdefault("rate_limited", []).append(wait)
                    time.sleep(wait)
            with lock:
                entry["response"] = response
                usages.append(response.get("usage") or {})
                save()
            return tool_calls(response)
        except (ValueError, OSError) as error:
            with lock:
                entry["error"] = str(error)
                save()
            raise

    def loop(stage, messages, tools, final_name, accept, max_calls, observed):
        """Run one tool-using agent until `accept` takes its final call. Never raises.

        accept(arguments) returns (value, problems); problems go back to the agent to fix.
        """
        lookups, done, rejections = [], set(), []
        for turn in range(max_calls):
            remaining = max_calls - turn - 1
            try:
                batch = call(messages, f"{stage}/{turn+1}", tools)
            except NoToolCall:
                messages.append({"role": "user", "content": f"You replied with text. Act only by calling a tool: "
                                 f"lookup, or {final_name} alone."})
                continue
            except TimeoutError as error:
                return {"value": None, "stop_reason": "deadline", "error": str(error), "lookups": lookups,
                        "rejections": rejections, "model_calls": turn + 1}
            except (ValueError, OSError) as error:
                return {"value": None, "stop_reason": "error", "error": str(error), "lookups": lookups,
                        "rejections": rejections, "model_calls": turn + 1}
            replies = {}
            for cid, name, args, _ in batch:
                if args is None:
                    replies[cid] = {"error": "Tool arguments were not a valid JSON object"}
                elif name == final_name:
                    if len(batch) > 1:
                        replies[cid] = {"error": f"Not executed: call {final_name} alone, after reading lookup results."}
                elif name == "lookup":
                    try:
                        clean = validate_action(args.get("tool"), args.get("args"))
                        key = json.dumps([args["tool"], clean], sort_keys=True)
                    except (ValueError, TypeError, KeyError) as error:
                        replies[cid] = {"error": f"Invalid lookup: {error}"}
                        continue
                    if key in done:
                        replies[cid] = {"error": "You already ran this exact lookup; use its earlier result."}
                        continue
                    done.add(key)
                    result = access.lookup(args["tool"], clean, timeout=max(0.01, min(30, deadline-time.monotonic())))
                    observed.observe(clean, result)
                    lookups.append({"question": args.get("question"), "tool": args["tool"], "args": clean, "result": result})
                    replies[cid] = {"observation": shown(result)}
                else:
                    replies[cid] = {"error": f"Unknown tool {name!r}; use lookup or {final_name}."}
            if len(batch) == 1 and batch[0][1] == final_name and batch[0][2] is not None:
                value, problems = accept(batch[0][2])
                if not problems:
                    return {"value": value, "stop_reason": final_name, "lookups": lookups,
                            "rejections": rejections, "model_calls": turn + 1}
                rejections.append(problems)
                if remaining == 0:
                    return {"value": value, "stop_reason": f"rejected_{final_name}", "error": "; ".join(problems),
                            "lookups": lookups, "rejections": rejections, "model_calls": turn + 1}
                replies[batch[0][0]] = {"error": f"Rejected; fix these and call {final_name} again.", "problems": problems}
            messages.append(echo(batch))
            for cid, _, _, _ in batch:
                reply = replies.get(cid, {"error": "Not executed."})
                if remaining <= 2 and "error" not in reply:
                    reply = {**reply, "instruction": f"Model calls are nearly exhausted. Call {final_name} next."}
                messages.append({"role": "tool", "tool_call_id": cid, "content": json.dumps(reply, ensure_ascii=False)})
        return {"value": None, "stop_reason": "call_budget", "lookups": lookups, "rejections": rejections,
                "model_calls": max_calls}

    # Stage 1: find.
    def accept_report(args):
        items = args.get("findings")
        if not isinstance(items, list):
            return None, ["findings must be a list"]
        accepted, problems = [], []
        for i, item in enumerate(items, 1):
            try:
                accepted.append(check_candidate(item, diff_ledger.lines))
            except ValueError as error:
                problems.append(f"finding {i}: {error}")
        return accepted, problems

    def hunt(hunter):
        name, system = hunter
        calls = limits.finder_calls if name == "finder" else limits.specialist_calls
        return name, loop(f"find-{name}", finder_messages(context, system), FINDER_TOOLS, "report", accept_report,
                          calls, Evidence(context["diff"]))

    with ThreadPoolExecutor(max_workers=limits.concurrency) as pool:
        hunts = dict(pool.map(hunt, hunters(profile, context["diff"])))
    finder = hunts["finder"]
    # A report still invalid at the last call keeps its valid candidates. Candidates at the
    # same location are merged; the first hunter in order (finder first) keeps the text.
    candidates, at = [], {}
    for name, run in hunts.items():
        for item in run["value"] or []:
            key = (item["side"], item["path"], item["line"])
            if key in at:
                at[key].setdefault("also_proposed_by", []).append(name)
                continue
            item["source"] = name
            at[key] = item
            candidates.append(item)
    for i, item in enumerate(candidates, 1):
        item["id"] = f"c{i:02}"
    to_verify, unverified = candidates[:limits.max_candidates], candidates[limits.max_candidates:]

    # Stage 2: verify each candidate independently.
    def verify(candidate):
        observed = Evidence(context["diff"])

        def accept_verdict(args):
            verdict, reason = args.get("verdict"), args.get("reason")
            problems = []
            if verdict not in ("confirmed", "rejected", "uncertain"):
                problems.append("verdict must be confirmed, rejected, or uncertain")
            if not isinstance(reason, str) or not reason.strip():
                problems.append("reason is required")
            keys, cite_problems = check_citations(observed, args.get("evidence"), required=verdict in ("confirmed", "rejected"))
            if verdict == "uncertain":
                cite_problems = []  # bad citations on an uncertain verdict only lose those citations
            problems.extend(cite_problems)
            if verdict == "confirmed" and not cite_problems and not keys & observed.changed:
                problems.append("confirmed needs at least one citation of a line this diff changed")
            evidence = args.get("evidence") if not cite_problems and isinstance(args.get("evidence"), list) else []
            return {"verdict": verdict, "reason": reason, "evidence": evidence}, problems

        task = {k: candidate[k] for k in ("title", "severity", "description", "path", "line", "side")}
        messages = [{"role": "system", "content": verifier_prompt(profile)},
                    {"role": "user", "content": json.dumps({**model_context(context), "reported_vulnerability": task},
                                                           ensure_ascii=False)}]
        run = loop(f"verify-{candidate['id']}", messages, VERIFIER_TOOLS, "verdict", accept_verdict,
                   limits.verifier_calls, observed)
        value = run["value"] if run["stop_reason"] == "verdict" else None
        return {"candidate": candidate, "verdict": value["verdict"] if value else "uncertain",
                "reason": value["reason"] if value else run.get("error") or run["stop_reason"],
                "evidence": value["evidence"] if value else [], **{k: run[k] for k in (
                    "stop_reason", "lookups", "rejections", "model_calls")}}

    with ThreadPoolExecutor(max_workers=limits.concurrency) as pool:
        verifications = list(pool.map(verify, to_verify))

    findings = []
    for item in verifications:
        if item["verdict"] != "confirmed":
            continue
        c = item["candidate"]
        evidence = [f"{e['side']} {e['path']}:{e['line']}: {e['quote'].strip()}" for e in item["evidence"]]
        findings.extend(validate_findings({"findings": [{
            "title": c["title"], "severity": c["severity"], "path": c["path"], "line": c["line"], "side": c["side"],
            "description": f"{c['description']}\n\nVerification: {item['reason']}", "evidence": evidence}]}))

    usage = {key: sum(u.get(key, 0) or 0 for u in usages) for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
    costs = [u.get("cost") for u in usages]
    reported_cost = bool(costs) and all(isinstance(c, (int, float)) for c in costs) and len(usages) == len(trace["calls"])
    if finder["stop_reason"] == "error" or any(v["stop_reason"] == "error" for v in verifications):
        status = "error"
    elif (any(h["stop_reason"] != "report" for h in hunts.values()) or unverified
          or any(v["verdict"] == "uncertain" for v in verifications)):
        status = "partial"
    else:
        status = "completed"
    result = {"findings": findings, "candidates": candidates, "verifications": verifications,
              "finder": {k: finder.get(k) for k in ("stop_reason", "error", "rejections", "model_calls")}
                        | {"lookups": finder["lookups"]},
              "hunters": {name: {k: run.get(k) for k in ("stop_reason", "error", "model_calls")}
                          | {"lookups": len(run["lookups"]), "candidates": len(run["value"] or [])}
                          for name, run in hunts.items()},
              "unverified": unverified, "metadata": {
        "status": status, "scope": "find_then_verify", "prompt_version": VERSION,
        "profile": {"name": profile.get("name"), "version": profile.get("version"), "sha256": profile_sha256(profile)},
        "prompt_sha256": sha256(FINDER + SPECIALIST + VERIFIER + json.dumps([FINDER_TOOLS, VERIFIER_TOOLS], sort_keys=True)),
        "context_sha256": sha256(json.dumps(context, sort_keys=True)),
        "requested_model": model, "provider": provider, "model_calls": len(trace["calls"]), "usage": usage,
        "cost_usd": sum(costs) if reported_cost else 0.0 if model.endswith(":free") else None,
        "cost_source": "provider" if reported_cost else "free_variant_estimate" if model.endswith(":free") else "unknown",
        "elapsed_seconds": round(time.monotonic()-started, 3), "limits": asdict(limits),
        "max_tokens_per_call": max_tokens, "reasoning_effort": reasoning_effort,
        "limitations": ["Only candidates the finder reported were verified; no guarantee of complete coverage.",
                        "Citations are checked against observed text; exploit semantics are judged by the model.",
                        "No exploits are executed. Rejected or uncertain candidates are not safety assurances."]}}
    with lock:
        trace["result"] = result
        save()
    return result
