import copy
from pathlib import Path
import sys
import tempfile
import unittest

from secbench.catalog import digest, load
from secbench.pr_cases import build, replace_once
from secbench.runner import run, task
from secbench.scoring import grade_template, score

ROOT=Path(__file__).resolve().parents[1]


class ConstructionTests(unittest.TestCase):
    def test_edit_requires_one_exact_anchor(self):
        for text in ("missing", "eval(x) eval(x)"):
            with self.assertRaises(ValueError): replace_once(text,"eval(x)","literal_eval(x)")

    @unittest.skipUnless((ROOT/".bench/locks/t005.json").exists(),"requires prepared upstream snapshots")
    def test_upstream_function_checks_and_all_variants(self):
        with tempfile.TemporaryDirectory() as td:
            destination=Path(td)/"pr"
            suite=build(load(),ROOT/".bench",destination)
            self.assertEqual(6,len(suite["cases"]))
            load(destination/"catalog.json")
            published=ROOT/"benchmarks/pr-v1/catalog.json"
            if published.exists():
                self.assertEqual(digest(load(published)),digest(suite))
            for c in suite["cases"]:
                request=task(suite,c,destination)
                self.assertEqual("pr",request["mode"])
                self.assertTrue(request["diff"])
                self.assertTrue(Path(request["base_source_dir"]).is_dir())
                self.assertNotIn("labels",request)
                self.assertNotIn("variant",request)
            agent=ROOT/"examples/empty_agent.py"
            result=run(suite,suite["cases"],destination,[sys.executable,str(agent)],"protocol-smoke",20)
            self.assertTrue(all(r["status"] == "ok" for r in result["cases"]))
            metrics=score(suite,result,grade_template(result))
            self.assertEqual(2,metrics["false_negatives"])
            self.assertEqual(4,metrics["negative_control_cases"])
            self.assertEqual(0,metrics["negative_control_alarm_rate"])
            # A reviewed false alarm on a control must affect the control metric.
            result["cases"][1]["output"]["findings"]=[{
                "id":"f0001","title":"Incorrect claim","description":"Claims comment introduces eval",
                "path":"infer-web.py","line":1,"evidence":["fixture false alarm"]}]
            grades=grade_template(result)
            grades["adjudicator"]="test reviewer"
            grades["decisions"][0].update(decision="false_positive",rationale="Only a comment changed")
            self.assertEqual(.25,score(suite,result,grades)["negative_control_alarm_rate"])
            failed=copy.deepcopy(result)
            failed["cases"][1].update(status="error",error="timeout")
            self.assertIsNone(score(suite,failed,grade_template(failed))["negative_control_alarm_rate"])
            # Old-vulnerability controls alone have no positive targets: no divide by zero.
            subset=copy.deepcopy(result)
            subset["cases"]=[subset["cases"][2]]
            metrics=score(suite,subset,grade_template(subset))
            self.assertIsNone(metrics["target_recall"])
            self.assertIsNone(metrics["f1"])
            with self.assertRaisesRegex(ValueError,"already exists"):
                build(load(),ROOT/".bench",destination)
            patch=destination/"diffs"/"p001.patch"
            patch.write_text(patch.read_text()+"tampered\n")
            with self.assertRaisesRegex(ValueError,"modified"):
                task(suite,suite["cases"][0],destination)


if __name__ == "__main__": unittest.main()
