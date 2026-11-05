# Security review benchmark

This repository has two parts:

- **`secbench`**: a benchmark of 67 real upstream pull requests from six open-source
  projects. A reviewer sees each PR's diff and reports any vulnerability the PR
  introduces; adjudicated findings are scored against known advisory targets.
- **`reviewer`**: a baseline single-call reviewer that sends the diff to a model.
  See [reviewer/README.md](reviewer/README.md).

Python 3.11+ and Git are required. Neither part has third-party runtime dependencies.
No model performance has been measured yet.

## The PR suite

The projects are Flowise, DataHub, MarkUs, Camaleon CMS, RVC WebUI, and GPT-SoVITS.
Their 49 vulnerabilities, from seven GitHub Security Lab reports, are listed in
`secbench/data/targets.json`. The suite uses 37 of them; the other 12 had no clean
commit pair and are listed with reasons in `benchmarks/pr-v2/manifest.json`.

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
# 1. Fetch the pinned commits (about 540 MB) and write the suite to .bench/pr-v2.
python -m secbench build

# 2. Run a reviewer. It reads one request per case on stdin and writes findings JSON.
python -m secbench run --split dev --model YOUR_MODEL --out .bench/run.json -- python C:\absolute\path\agent.py

# 3. Adjudicate every finding, then score.
python -m secbench grade-template --results .bench/run.json --out .bench/grades.json
python -m secbench score --results .bench/run.json --grades .bench/grades.json --out .bench/score.json
```

`examples/empty_agent.py` is a protocol smoke test that always returns no findings.
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
python -m secbench unpack --case h001
python -m secbench unpack --case h001 --remove
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
python -m secbench judge --results .bench/run.json --out .bench/grades.json
python -m secbench score --results .bench/run.json --grades .bench/grades.json --out .bench/score.json
```

For each finding, Jev sees the finding, the diff for the cited file, and numbered
code around the cited line. It chooses between the case's targets, its `also_valid`
issues, a false alarm, or another plausible issue, and separately judges whether the
code supports the claim. It never sees commit IDs or the API key. A finding whose
file exists on neither side is a false positive without a call. A confident,
supported target choice is a `match` (extra matches of one target become
`duplicate`), a confident `also_valid` choice is accepted, and a confident false
alarm is a `false_positive`. Everything else, including other plausible issues,
stays `unresolved` for a person, so precision and F1 stay unset until it is settled.

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

## How the suite was built, and how far to trust it

Separate AI agents mined the commit pairs from each project's history, then other
agents tried to refute each one by reading source. 14 candidates were dropped:
fixes that did not work, and "clean" commits that added a weakness. Nothing was
executed and no human reviewed the labels, so a label means "reviewed from
source", not "exploit reproduced".

`python -m secbench build` re-checks every entry: the pair must be parent and child,
the diff must change code within size limits, every quoted line must exist at its
commit, every claimed absence must hold, and a control must have no known issue.
Case numbers come from a hash, so their order reveals nothing.

Limits to keep in mind:

- Reversed fixes read as removals, which is a different task from reviewing new code.
- Controls were chosen near dangerous code, so they do not represent ordinary PRs.
- Vulnerable PRs skew larger than controls; compare `by_variant` rather than one aggregate.
- The advisories are public and may be in a model's training data.

Rebuild with `--check-only` to verify every entry without writing a suite.
