# Security review benchmark

A standalone Python benchmark CLI for an external security review agent. The seed
collection covers all six repositories we selected: Flowise, DataHub, MarkUs,
Camaleon CMS, Retrieval-based Voice Conversion WebUI, and GPT-SoVITS.
There are **6 repository-snapshot tasks and 49 advisory-backed target findings**.
Python 3.11+ and Git are required; the CLI has no third-party runtime dependencies.

## Current status

This implements the benchmark infrastructure and source-backed case collection.
The 49 targets are manually paraphrased from seven GitHub Security Lab reports,
with source links, location hints, mechanisms, and evidence requirements in
`secbench/data/catalog.json`. They have **not been independently reproduced**.
All six advisory-tested refs have now been fetched and resolved to immutable
commits locally. Source snapshots live in ignored `.bench/sources/`; they are not
redistributed. `source-checks.json` records their commits, tree hashes, and source
locations for the advisory-related symbols. Symbol presence is not proof of the
exploit path, attacker control, or the absence of effective defenses.

The original catalog measures vulnerability detection in historical snapshots.
A separate first PR suite now contains **two reconstructed regression scenarios,
each with three variants**: a security regression, a safe edit, and an edit next to
a pre-existing vulnerability. These are authored transformations of the pinned
upstream source, not claims about historical vulnerability-introducing commits.
Function-level validation and target-specific controls are provided; no fixed tree
is claimed to be globally vulnerability-free. The remaining four repositories are
still snapshot-only. There is no production reviewer, model performance result,
or measured agent improvement yet. The original work trial's core requirements
are not yet complete, and no stretch goals have been attempted.

## Reconstructed PR cases

After preparing the snapshot catalog, build the PR suite in a fresh directory:

```powershell
python -m secbench build-pr-cases --out .bench/pr-v1
python -m secbench --catalog .bench/pr-v1/catalog.json list
python -m secbench --catalog .bench/pr-v1/catalog.json export --work .bench/pr-v1 --split all --out .bench/pr-tasks.json
```

The local `.bench/pr-v1` suite is already built in this workspace. Building into
an existing directory fails rather than replacing artifacts. For a repeat build,
choose a new directory and update `--catalog` / `--work` accordingly.

- RVC `GHSL-2025-015`: a log reader evaluates file contents as Python. The authored
  baseline uses `ast.literal_eval`. An isolated replay executes the upstream reader
  with a controlled log expression that writes a harmless temporary marker; the
  repaired reader rejects it. Normal dictionary-log parsing is checked on both.
- GPT-SoVITS `GHSL-2025-048`: `change_label` builds a shell command containing a
  user-supplied path. The authored baseline passes an argument list with
  `shell=False`. The isolated function's `Popen` call is captured and checked for
  argument preservation. Upstream `clean_path` is used; file-existence checking is
  stubbed. This checks the process boundary, **not an actual shell exploit**.

For each scenario, base/head are:

1. Repaired → upstream vulnerable code: the target is introduced.
2. Repaired → repaired plus a neutral comment: no target introduced.
3. Vulnerable → vulnerable plus the same comment: the target pre-exists.

The control edits are intentionally simple initial sanity checks. Their Python
ASTs are identical to their bases. They are not a representative sample of safe
feature PRs. Other existing vulnerabilities remain in the full repository trees.
Cases are opaque `p001`–`p006` to the reviewer; evaluator metadata contains variant
and target information. Generated artifacts include full base/head trees, unified
diffs, source hashes, a frozen catalog, and a validation record. Portable copies of
the catalog/freeze/validation are under `benchmarks/pr-v1/`.

All six variants are **development only**: the two projects share a code family.
Do not present six variants as six independent vulnerabilities or claim a held-out
score. Application reachability, UI prerequisites, and a deployed exploit have not
been validated. The behavioral test executes only extracted function definitions,
avoiding the upstream modules' heavyweight initialization.

Run your reviewer with the same JSON protocol:

```powershell
python -m secbench --catalog .bench/pr-v1/catalog.json run --work .bench/pr-v1 --split all --model YOUR_MODEL --out .bench/pr-run.json -- python C:\absolute\path\agent.py
python -m secbench --catalog .bench/pr-v1/catalog.json grade-template --results .bench/pr-run.json --out .bench/pr-grades.json
# Adjudicate findings, including whether each issue was introduced relative to base.
python -m secbench --catalog .bench/pr-v1/catalog.json score --results .bench/pr-run.json --grades .bench/pr-grades.json --out .bench/pr-score.json
```

PR requests add `base_source_dir` and the unified `diff`; `source_dir` is the head.
The `commit` field identifies the source upstream snapshot, while tree hashes
identify the authored base/head variants. These authored trees are not historical
commits. PR locks verify base, head, and diff integrity before and after agent runs.
Mount both trees and the request into your reviewer sandbox, with no evaluator data.

`negative_control_alarm_rate` measures the fraction of successfully reviewed
controls with at least one adjudicated false alarm about the proposed change. It
is null if grading is incomplete or a control failed. The general
`false_positive_rate` remains null: these are target-specific controls, not a claim
of exhaustively clean codebases. Positive-case recall excludes zero-target controls.
An unchanged old vulnerability in a pre-existing control is not a valid PR finding.

## Run without installation

From the project root:

```powershell
python -m secbench validate
python -m secbench list
python -m unittest discover -s tests -v
```

Optional installation: `python -m pip install -e .` provides the `secbench` command.

## Freeze the benchmark before tuning

```powershell
python -m secbench freeze --out benchmark.freeze.json
```

Commit the catalog, scorer, and freeze file before running or modifying your agent.
Runs record the canonical catalog SHA-256; grades record the entire run's SHA-256.
The committed freeze file records the initial collection. Changing the labels
requires a versioned catalog revision, a new freeze, and regrading/rerunning affected
comparisons. Do not silently edit labels after seeing a favorable score.

Development: Flowise, Camaleon CMS, RVC WebUI, GPT-SoVITS.
Held out: DataHub and MarkUs. RVC and GPT-SoVITS share code, so they stay together.
This is a small, deliberately selected suite, not a statistically representative
sample of software. Public reports may appear in model training data; this is not
a contamination-free evaluation. Avoid tuning on held-out results.

## Prepare the source snapshots

With terminal network access, fetch the advisory-tested refs:

```powershell
python -m secbench prepare --split all
```

Or prepare a single case from an existing local clone, without network access:

```powershell
python -m secbench prepare --case t001 --from-repo C:\repos\Flowise
```

The local clone must contain the exact advisory ref. `prepare` resolves it to an
immutable commit, exports the tracked files without Git history, and writes a lock
with commit, archive SHA-256 and source tree SHA-256 under `.bench/locks/`.
Subsequent exports/runs verify source integrity. Existing untracked/modified snapshots
are rejected; choose a new `--work` directory to prepare again. Git LFS objects and
submodule contents are not materialized; archived symlinks are skipped and recorded.
No dependency installation, application build, or vulnerable service startup occurs.
An unavailable ref is an error, never a reason to silently use the default branch.

The user successfully ran network preparation for all six cases. Local Git
preparation is also covered by tests.

Verify prepared sources and regenerate the location inventory:

```powershell
python -m secbench check-sources --out source-checks.json
```

This checks all snapshot hashes and searches for a case-specific source anchor
for each of the 49 targets. A missing anchor is marked `needs_investigation`, not
silently discarded or counted as a detection miss. Found anchors do not promote
labels from `advisory_only` to exploit-validated. The location inventory is an
evaluator artifact: do not mount it into the agent's sandbox.

## Agent protocol

Export reviewer-visible requests:

```powershell
python -m secbench export --case t001 --out .bench/tasks.json
```

Or launch your agent once per selected repository:

```powershell
python -m secbench run --case t001 --model YOUR_MODEL --out .bench/baseline.json -- python C:\absolute\path\agent.py
```

The command receives one JSON object on stdin with `schema_version`, opaque
`task_id`, `mode`, `source_dir`, `commit`, and `instructions`. Its working directory
is the source snapshot. Use absolute paths for your agent script and interpreter
if necessary. It must emit only this JSON on stdout; logs belong on stderr:

```json
{
  "findings": [
    {
      "title": "Specific vulnerability",
      "description": "Attacker control, data flow, failed defense, preconditions, impact",
      "path": "relative/source/file.py",
      "line": 42,
      "evidence": ["relative/source/file.py:42: the relevant repository fact"]
    }
  ]
}
```

Use an empty `findings` list for no findings. The harness assigns stable finding IDs.
Timeouts, invalid JSON, malformed findings and nonzero process exits are recorded
as failed cases and stay in the recall denominator. CLI exit codes: 0 success,
1 a run with failed cases, 2 invalid input or preparation failure.

`examples/empty_agent.py` exercises the protocol and intentionally has zero recall:

```powershell
python -m secbench run --case t001 --model protocol-smoke --out .bench/smoke.json -- python C:\absolute\project\examples\empty_agent.py
```

Requests exclude target labels, hints, advisory URLs, and expected finding counts.
This subprocess runner is **not an isolation boundary**: a process on the same
machine can read outside its working directory. For a credible evaluation, run
your agent in a separate sandbox/container that mounts only the prepared source
and request, disables web/history access, and excludes the catalog, grades and
freeze file. Treat repository instructions as untrusted. This is necessary to
prevent answer-key leakage; omission from the request alone is insufficient.

## Adjudicate and score

```powershell
python -m secbench grade-template --results .bench/baseline.json --out .bench/grades.json
# Review each finding against the source code and catalog rubric, then edit grades.json.
python -m secbench score --results .bench/baseline.json --grades .bench/grades.json --out .bench/score.json
```

Set `adjudicator` to a reviewer/judge identifier. Each decision requires `case_id`,
`finding_id`, `decision`, `label_id`, and `rationale`.

- `match`: correct target mechanism and repository-backed evidence. Set the label ID.
- `duplicate`: repeats an already matched target. Set that target's label ID.
- `false_positive`: demonstrably unsupported security claim. Explain why.
- `unresolved`: needs investigation, including plausible new vulnerabilities.

Credit requires the concrete security mechanism and supported preconditions, not
just the same file, CWE, or a generic warning. Treat incorrect account privileges,
unproven model-artifact control, and unsupported deployment assumptions as evidence
gaps. Match each finding to at most one target and each target once. Consolidated
multi-location findings should be split into separate findings before freezing a
run if independent per-location credit is desired; do not edit saved results during
grading. Report that output convention to the agent in any future protocol version.

The scorer reports:

- Target recall = unique matched targets / selected advisory targets.
- Macro case recall = average per-repository recall, so large reports don't dominate.
- Precision = matches / (matches + adjudicated false positives + duplicates).
- F1 from that precision and target recall, only once all findings are resolved.
- Failed cases, duplicates, unresolved findings, and case IDs for comparison.

While grading is incomplete, recall is a lower bound and precision/F1 are null.
False-positive **rate** is null in the original positive-only snapshot collection:
there are no reviewed negative cases there. The separate PR suite reports its
control alarm rate as described above. A valid finding absent from the advisory is not a false
positive: investigate it and revise the catalog with provenance before recomputing
comparisons. Even final scores describe this incomplete advisory target set, not
all vulnerabilities in the projects. Never use string/CWE overlap as an automatic
semantic correctness oracle.

Run baseline and improved agents on the same cases and locked commits. Keep raw
results and blinded adjudications. Record exact model identifiers and your provider's
token usage/prices separately; the generic runner records the supplied model label
and latency but cannot infer token cost from an arbitrary external command. No paid
model calls were used to build or test this CLI.

## Provenance and next steps

Every target points to its Security Lab report. `scripts/build_catalog.py` reconstructs
the curated JSON deterministically. MarkUs excludes withdrawn GHSL-2024-061;
DataHub includes ten issues listed in its body; Flowise separates four XSS endpoints.
These related findings are not independent experiments. Upstream licenses apply to
prepared source files; source is fetched locally rather than redistributed here.

To promote this seed into a PR benchmark, identify and pin a base/head pair for
each selected target, establish that the failure is absent at base and present at
head, validate a repaired counterpart, and add independently reviewed benign PRs.
Record exploit/regression-test evidence and adjudicate incomplete fixes separately.
Keep snapshot results separate from PR introduction results. Finish those steps
before claiming the original assignment's core benchmark is complete.
