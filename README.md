# Security review benchmark

This repository has two parts, plus their tests:

- **`benchmark/`**: 67 real upstream pull requests from six open-source projects. A
  reviewer sees each PR's diff and reports any vulnerability the PR introduces;
  findings are graded against known advisory targets and scored. The cases are in
  `benchmark/data/cases.json`, built from `manifest.json` and `targets.json` there.
- **`reviewer/`**: two reviewers. `baseline` (the default) sends the diff to a model in
  one call. `find-verify` lets a finder look up any code it needs, then has a
  separate verifier check each candidate in the code before it is reported.
  See [reviewer/README.md](reviewer/README.md).
- **`tests/`**: unit tests for both, and `empty_agent.py`, a protocol smoke test.

Python 3.11+ and Git are required. Neither part has third-party runtime dependencies.

## Results

Both reviewers ran on all 67 cases with Cerebras `gpt-oss-120b`.

| | Single-call `baseline` | `find-verify` |
|---|---|---|
| Known bugs found (recall) | 26 of 37 (70%) | 25 of 37 (68%) |
| Precision | 29% | **48%** |
| F1 | 0.41 | **0.56** |
| False findings | 62 | **24** |
| Clean PRs with a false alarm | 29 of 40 (73%) | **11 of 40 (28%)** |
| Failed cases | 1 (invalid JSON) | 0 |
| Model calls per PR (median) | 1 | 13 |
| Time for all 67 cases | 91 s | about 13 min (median 8 s per PR) |

By split:

| | Baseline dev (40) | find-verify dev | Baseline held-out (27) | find-verify held-out |
|---|---|---|---|---|
| Recall | 14 of 21 (67%) | 15 of 21 (71%) | 12 of 16 (75%) | 10 of 16 (62%) |
| Precision | 26% | 45% | 33% | 53% |
| Clean PRs with a false alarm | 20 of 26 | 8 of 26 | 9 of 14 | 3 of 14 |

The verifier works as a filter. It removes over 60% of the baseline's false
findings and of its false alarms on clean PRs, for about the same recall (two
held-out bugs fewer, one dev bug more). It also confirmed 21 real issues outside the
labelled targets (`also_valid`), against the baseline's 16. Both reviewers find 77%
of bugs in PRs that added them; on reversed fixes the baseline finds 60% and
find-verify 53%.

Grading: Jev drafted every decision (106 for the baseline, 73 for find-verify). The
ones it left unresolved (13 and 5) were decided by Claude under the strict rule
below; the user approved the baseline's. No independent human checked the grades.
Each column is one run at temperature 0, and repeated runs vary by a few bugs.

## The PR suite

The projects are Flowise, DataHub, MarkUs, Camaleon CMS, RVC WebUI, and GPT-SoVITS.
Their 49 vulnerabilities, from seven GitHub Security Lab reports, are listed in
`benchmark/data/targets.json`. The suite uses 37 of them; the other 12 had no clean
commit pair and are listed with reasons in `benchmark/data/manifest.json`.

| Case type | Count | What the PR is |
|---|---|---|
| `introduced_historical` | 17 | The upstream commit that added the vulnerability |
| `fix_reverted` | 10 | An upstream security fix, reversed |
| `security_fix` | 9 | A real security fix (control) |
| `benign_nearby` | 13 | A real logic change near dangerous code (control) |
| `preexisting_touch` | 18 | An edit beside an existing flaw that leaves it unchanged (control) |

A vulnerable PR can carry several targets. Controls have no labels: any finding on
one is a false alarm unless it is listed in that case's `also_valid` entries.

Splits follow the repository, because cases from one project are correlated:
Flowise, Camaleon, RVC, and GPT-SoVITS are development (40 cases); DataHub and
MarkUs are held out (27 cases). Do not tune a reviewer on held-out cases.

## Run the benchmark

```powershell
# 1. Fetch the pinned commits (about 540 MB) and write the suite to .bench/suite.
python -m benchmark build

# 2. Run a reviewer: any command that reads one request on stdin and prints findings JSON.
#    This runs the bundled reviewer; pass its folder's absolute path.
python -m benchmark run --split dev --model cerebras/gpt-oss-120b --out .bench/run.json -- python C:\absolute\path\reviewer --provider cerebras
#    The find-verify reviewer uses the lookup command; give it a longer timeout.
python -m benchmark run --split dev --model cerebras/gpt-oss-120b/find-verify --timeout 420 --out .bench/fv.json -- python C:\absolute\path\reviewer --provider cerebras --strategy find-verify

# 3. Grade every finding (automatically with Jev, or by hand from a template), then score.
python -m benchmark judge --results .bench/run.json --out .bench/grades.json
python -m benchmark score --results .bench/run.json --grades .bench/grades.json --out .bench/score.json
```

`tests/empty_agent.py` is a protocol smoke test that always returns no findings.
A full pass over all 67 cases with it takes about 12 seconds.

## Reviewer protocol

Each request contains `task_id`, `mode: "pr"`, `instructions`, the unified `diff`,
and a `lookup` command. It never contains labels, case types, commit IDs, or commit
messages. Changelog files are left out of diffs, because they name the advisory, as
are vendored libraries, lockfiles, and minified files, which are not reviewable code.

To read surrounding code, append an action to `lookup.command`; results are JSON:

```powershell
<lookup.command> read --side head --path app/models/user.rb --start 40 --end 80
<lookup.command> search --side base --pattern "def checked_join" --path app
<lookup.command> list --side head --path app/controllers
```

`base` is the pre-change code and `head` the proposed code. Lookups read the Git
stores directly, take well under a second, and hide changelogs. Searches are
extended regular expressions capped at 200 matches; reads are capped at 2000 lines.
A diff-only reviewer can ignore the lookup command.

The reviewer must print only this JSON on stdout; logs go to stderr:

```json
{"findings": [{"title": "Specific vulnerability",
  "description": "Attacker control, data flow, failed defense, preconditions, impact",
  "path": "relative/file.py", "line": 42,
  "evidence": ["relative/file.py:42: the relevant fact"]}]}
```

Report each vulnerability as its own finding; one finding can match one target.
Timeouts, invalid JSON, and nonzero exits are recorded as failed cases and stay in
the recall denominator.

**Isolation.** The runner is not a sandbox. A reviewer process can read the catalog,
which holds the answers, and the lookup command runs the benchmark CLI. For a
credible evaluation, run the reviewer in a sandbox that can reach only its request,
and run lookups outside it, relaying their output.

To give a reviewer plain base and head folders instead, add `--unpack` to `run` or
`export`. Each case is then unpacked just before review, deleted afterwards, and
reported as an error if the reviewer changed it. This is slow: several minutes per
DataHub case. To unpack one case by hand, such as to mount it in a sandbox:

```powershell
python -m benchmark unpack --case h001
python -m benchmark unpack --case h001 --remove
```

## Grading

`grade-template` lists every finding as `unresolved`. Set `adjudicator`, then give
each decision a `rationale` and one of:

- `match`: the finding names the target's mechanism with code evidence. Set `label_id`.
- `duplicate`: repeats a matched target. Set that target's `label_id`.
- `also_valid`: a real issue this diff introduces beyond its labels, listed in the
  case's `also_valid` entries. Set `also_valid_id`. It counts as neither a hit nor
  a false positive.
- `false_positive`: an unsupported security claim.
- `unresolved`: needs investigation, including possibly real issues not yet listed.

Credit needs the concrete mechanism and supported preconditions, not just the same
file or weakness class. Never grade by string or CWE overlap.

The scorer reports target recall, per-repository (macro) recall, precision and F1
once nothing is unresolved, the control alarm rate, and all of these by case type
in `by_variant`. While grading is incomplete, recall is a lower bound and precision
is null. Scores describe these 37 targets, not every vulnerability in the projects.

### Automatic grading with Jev

`judge` drafts the grades file with TypeSafe AI's Jev, a decision model that picks
from named options and reports probabilities but writes no text. Set `JEV_API_KEY`
in `.env`, then grade and score as usual:

```powershell
python -m benchmark judge --results .bench/run.json --out .bench/grades.json
python -m benchmark score --results .bench/run.json --grades .bench/grades.json --out .bench/score.json
```

Jev makes one call per case. It sees the reviewer's whole output for that case,
explanations included, next to the case's known bugs, and answers for each finding
which known bug it describes, or none. It judges alignment with the known bugs
only: it does not check the code, and it never sees commit IDs or the API key. A
confident bug choice is a `match` (extra matches of one bug become `duplicate`), a
confident `also_valid` choice is accepted, and a confident "none" is a
`false_positive`. Anything below the threshold stays `unresolved` for a person.

Because "none" counts as a false positive, a real bug the labels missed is also
scored as one, so precision can be understated. Review a sample of false
positives, and add any real new bug to the case's `also_valid` list.

Each decision's rationale records Jev's choice and confidence, its full answer is
kept under `judge`, and `adjudicator` names the exact Jev version and threshold, so
automatic grades are never mistaken for human ones. Grading costs a small fraction
of a cent per run. **The default threshold (0.7) is not calibrated.** Hand-grade a
sample of findings, compare, and report that agreement alongside any Jev-graded
score. Jev's own docs say its confidence is calibrated across groups of answers, not
for any single one. The account exposes only `jev-latest`, which changes with
releases, so compare runs only when they were graded by the same Jev version.

Results record the catalog's SHA-256 and grades record the results' SHA-256, so a
label change after a run cannot be scored silently. Changing labels means a new
catalog version and regrading.

## Improving the reviewer

`python -m benchmark.improve` tunes find-verify's profile (its finder guidance,
verifier criteria, and specialists; see [reviewer/README.md](reviewer/README.md))
from its own dev failures, in the spirit of AgentFlow's harness search.

**Triage.** `benchmark/triage.py` attributes every failure to the stage that caused
it. Each labelled bug is `found`, `not_proposed` (no hunter proposed it),
`verifier_rejected`, `verifier_uncertain`, or `unverified` (over the candidate cap).
Each false finding is a `verifier_confirmed_false` and records the hunter that
proposed it. The scorer never grades rejected candidates, so triage asks Jev to match
all candidates, not only findings, against the labels.

**Each round:**

1. An optimizer model (Cerebras `gpt-oss-120b`, high reasoning) sees the current
   profile, the dev failures grouped by stage, and earlier rounds' edits. It writes
   a diagnosis (stage, bottleneck, intended and actual behaviour) and exactly one
   edit: set the verifier criteria, set the finder guidance, or add, update, or
   remove a specialist. Bugs never proposed call for specialists; false findings and
   wrongly dropped bugs call for verifier changes.
2. The edit is rejected, and the optimizer asked again (up to three attempts), if it
   is invalid or names any benchmark repository, file, function, or advisory id.
   The banned terms come from every case, held-out included.
3. The edited profile runs on the dev split and is graded by Jev.
4. The edit is kept only if dev F1 improves **and** bugs found stays within
   `--recall-slack` (default 3) of the starting profile. The floor is measured from
   the start, not the last round, so recall cannot erode a little each round.

```powershell
python -m benchmark.improve --name run1 --rounds 3
# Reuse an existing full run's dev cases as round 0 instead of re-running them:
python -m benchmark.improve --name run1 --rounds 3 --seed-results .bench/fv-full-run.json
# Evaluate a finished profile on the held-out split (never done inside the loop):
python -m benchmark.improve --name run1 --evaluate-holdout .bench/improve/run1/p002.json
```

Everything is saved under `.bench/improve/NAME/`: each profile, the optimizer's
proposal, and the dev results, grades, score, and triage per round, plus
`state.json` with the incumbent. A stopped run resumes from its state.

The optimizer never sees held-out cases, and holdout runs only on request. A dev run
takes 10 to 20 minutes, and repeated runs of one profile vary by a few bugs, so a
small gain in one round can be noise. No loop result is reported yet: the first runs
rejected verifier edits that cut false findings but lost too many real bugs (one
kept 9 of 15 dev bugs).

## How the suite was built, and how far to trust it

Separate AI agents mined the commit pairs from each project's history, then other
agents tried to refute each one by reading source. 14 candidates were dropped:
fixes that did not work, and "clean" commits that added a weakness. Nothing was
executed and no human reviewed the labels, so a label means "reviewed from
source", not "exploit reproduced".

`python -m benchmark build` re-checks every entry: the pair must be parent and child,
the diff must change code within size limits, every quoted line must exist at its
commit, every claimed absence must hold, and a control must have no known issue.
Case numbers come from a hash, so their order reveals nothing.

Limits to keep in mind:

- Reversed fixes read as removals, which is a different task from reviewing new code.
- Controls were chosen near dangerous code, so they do not represent ordinary PRs.
- Vulnerable PRs skew larger than controls; compare `by_variant` rather than one aggregate.
- The advisories are public and may be in a model's training data.

Rebuild with `--check-only` to verify every entry without writing a suite.
