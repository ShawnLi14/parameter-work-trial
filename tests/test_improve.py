import json
import unittest

from benchmark.catalog import digest
from benchmark.improve import apply_edit, banned_terms, failures_for_optimizer, keep, leaks, objective
from benchmark.triage import triage

LABEL = {"id": "GHSL-0000-001", "title": "Command injection", "location_hint": "webui.py: open_denoise",
         "mechanism": "UI field denoise_input_dir -> clean_path -> Popen(cmd, shell=True)."}
DATA = {"cases": [
    {"id": "h001", "repository": "Acme/GPT-Widget", "split": "dev", "variant": "introduced_historical",
     "labels": [LABEL], "also_valid": []},
    {"id": "h002", "repository": "Acme/GPT-Widget", "split": "dev", "variant": "benign_nearby",
     "labels": [], "also_valid": []}]}
PROFILE = {"name": "default", "version": 1, "finder_guidance": "Report concrete vulnerabilities.",
           "verifier_criteria": "Confirm only with cited code.", "specialists": []}


def candidate(cid, title, line, source="finder"):
    return {"id": cid, "title": title, "severity": "high", "description": f"{title} details", "path": "webui.py",
            "line": line, "side": "head", "source": source}


def results(rows):
    return {"catalog_sha256": digest(DATA), "cases": rows}


def row(case_id, candidates, verdicts, findings):
    return {"case_id": case_id, "status": "ok", "output": {
        "findings": findings, "candidates": candidates, "unverified": [],
        "verifications": [{"candidate": c, "verdict": v, "reason": f"{v} because"} for c, v in zip(candidates, verdicts)]}}


def jev(choices):
    """A fake Jev that answers each finding id with a fixed choice."""
    def send(payload, key):
        return {"model": "fake", "answers": {fid: {"choice": choices.get(fid, "none"), "confidence": 1.0}
                                             for fid in payload["questions"]}}
    return send


class TriageTests(unittest.TestCase):
    def test_bug_dropped_by_verifier_is_attributed_to_the_verifier(self):
        c = candidate("c01", "Command injection", 229)
        res = results([row("h001", [c], ["rejected"], [])])
        report = triage(DATA, res, {"decisions": []}, key="k", send=jev({"c01": "bug_1"}))
        self.assertEqual("verifier_rejected", report["bugs"][0]["stage"])
        self.assertEqual(["rejected because"], report["bugs"][0]["verifier_reasons"])

    def test_bug_never_proposed_and_false_finding(self):
        noise = candidate("c01", "Weak logging", 10)
        finding = {**{k: noise[k] for k in ("title", "severity", "description", "path", "line", "side")},
                   "id": "f0001", "evidence": ["x"]}
        res = results([row("h001", [], [], []), row("h002", [noise], ["confirmed"], [finding])])
        grades = {"decisions": [{"case_id": "h002", "finding_id": "f0001", "decision": "false_positive", "label_id": None}]}
        report = triage(DATA, res, grades, key="k", send=jev({}))
        self.assertEqual("not_proposed", report["bugs"][0]["stage"])
        self.assertEqual(1, len(report["false_findings"]))
        self.assertEqual({"not_proposed": 1, "verifier_confirmed_false": 1}, report["summary"]["dev"])

    def test_found_bug_and_hunter_stats(self):
        c = candidate("c01", "Command injection", 229, source="injection")
        finding = {**{k: c[k] for k in ("title", "severity", "description", "path", "line", "side")},
                   "id": "f0001", "evidence": ["x"]}
        res = results([row("h001", [c], ["confirmed"], [finding])])
        grades = {"decisions": [{"case_id": "h001", "finding_id": "f0001", "decision": "match", "label_id": LABEL["id"]}]}
        report = triage(DATA, res, grades, key="k", send=jev({"c01": "bug_1"}))
        self.assertEqual("found", report["bugs"][0]["stage"])
        self.assertEqual({"candidates": 1, "matched_labels": 1, "confirmed": 1}, report["hunters"]["injection"])


class LeakGuardTests(unittest.TestCase):
    def test_project_names_are_banned_but_generic_terms_are_not(self):
        banned = banned_terms(DATA)
        self.assertEqual(["open_denoise", "webui.py"], leaks("check open_denoise in webui.py", banned))
        self.assertIn("gpt-widget", leaks("as in gpt-widget", banned))
        self.assertEqual([], leaks("Popen(cmd, shell=True) with UI input and missing quoting; credentials", banned))
        self.assertIn("ghsl-0000-001", banned)


class EditTests(unittest.TestCase):
    def test_edits_apply_and_validate(self):
        spec = {"name": "injection", "focus": "Command injection.", "guidance": "Find shell=True.", "triggers": ["Popen"]}
        added = apply_edit(PROFILE, {"kind": "add_specialist", "specialist": spec})
        self.assertEqual(["injection"], [s["name"] for s in added["specialists"]])
        self.assertEqual(2, added["version"])
        updated = apply_edit(added, {"kind": "update_specialist", "specialist": {**spec, "guidance": "More."}})
        self.assertEqual("More.", updated["specialists"][0]["guidance"])
        removed = apply_edit(updated, {"kind": "remove_specialist", "name": "injection"})
        self.assertEqual([], removed["specialists"])
        self.assertEqual("New.", apply_edit(PROFILE, {"kind": "set_verifier_criteria", "text": "New."})["verifier_criteria"])
        self.assertEqual([], PROFILE["specialists"])  # the original is never mutated

    def test_invalid_edits_are_rejected(self):
        bad = [{"kind": "rewrite_everything"},
               {"kind": "update_specialist", "specialist": {"name": "ghost", "focus": "x", "guidance": "y"}},
               {"kind": "add_specialist", "specialist": {"name": "Bad Name", "focus": "x", "guidance": "y"}},
               {"kind": "add_specialist", "specialist": {"name": "re", "focus": "x", "guidance": "y", "triggers": ["("]}},
               {"kind": "set_verifier_criteria", "text": ""}]
        for edit in bad:
            with self.assertRaises(ValueError, msg=json.dumps(edit)):
                apply_edit(PROFILE, edit)

    def test_objective_and_optimizer_view(self):
        start = {"true_positives": 15, "adjudicated_false_positives": 17, "target_count": 21, "failed_cases": 0}
        round1 = {"true_positives": 10, "adjudicated_false_positives": 3, "target_count": 21, "failed_cases": 0}
        for s in (start, round1):
            s["objective"] = objective(s)
        self.assertEqual((0.566, 0.5882), (round(start["objective"], 3), round1["objective"]))
        self.assertFalse(keep(round1, start, start, 3))  # F1 rose, but 5 bugs were lost
        better = {**round1, "true_positives": 13, "adjudicated_false_positives": 5}
        better["objective"] = objective(better)
        self.assertTrue(keep(better, start, start, 3))
        self.assertFalse(keep(start, start, start, 3))  # no F1 gain
        self.assertTrue(keep({**better, "failed_cases": 1}, start, start, 3))  # a timeout alone is no veto
        report = {"bugs": [{"case_id": "h001", "split": "dev", "stage": "not_proposed", "title": "Command injection",
                            "mechanism": "m", "verifier_reasons": []},
                           {"case_id": "h009", "split": "holdout", "stage": "not_proposed", "title": "SSRF",
                            "mechanism": "m", "verifier_reasons": []}],
                  "false_findings": [], "hunters": {}}
        view = failures_for_optimizer(report)
        self.assertEqual(["Command injection"], [b["class"] for b in view["not_proposed"]])  # holdout never shown


if __name__ == "__main__":
    unittest.main()
