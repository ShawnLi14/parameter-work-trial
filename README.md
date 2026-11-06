# Security PR review: a benchmark and three reviewer agents

Can an LLM reviewer spot a security vulnerability in a pull request? This repository
has a benchmark of real pull requests to measure that, and three reviewer agents.

## The benchmark

**67 real pull requests from six open-source projects.** 27 of them introduce a
known vulnerability and 40 are clean, so a reviewer is scored both on bugs found and
on false alarms.

| Project | Language | PRs | With a vulnerability |
|---|---|---|---|
| [Flowise](https://github.com/FlowiseAI/Flowise) | TypeScript | 11 | 4 |
| [DataHub](https://github.com/datahub-project/datahub) | Java | 16 | 8 |
| [MarkUs](https://github.com/MarkUsProject/Markus) | Ruby | 11 | 5 |
| [Camaleon CMS](https://github.com/owen2345/camaleon-cms) | Ruby | 12 | 5 |
| [RVC WebUI](https://github.com/RVC-Project/Retrieval-based-Voice-Conversion-WebUI) | Python | 8 | 2 |
| [GPT-SoVITS](https://github.com/RVC-Boss/GPT-SoVITS) | Python | 9 | 3 |

**Where they come from.** The vulnerabilities are from seven public
[GitHub Security Lab](https://securitylab.github.com/advisories/) reports on these
projects: command and code injection, path traversal, file write and deletion, XSS,
unsafe deserialization, SSRF, broken authentication, and others. 37 of the reports'
49 vulnerabilities could be tied to clean commits in each project's history:

- **Vulnerable PRs (27):** the upstream commit that introduced the bug (17), or an
  upstream security fix applied in reverse (10). One PR can contain several bugs.
- **Clean PRs (40):** real security fixes, real logic changes near dangerous code, and
  edits next to an existing flaw that leave it unchanged.

A reviewer gets each PR's diff, can look up any other code at the base or head
commit, and reports the vulnerabilities the PR introduces. Each finding is graded
against the known bugs, automatically by [Jev](https://typesafe.ai), with uncertain
ones decided by hand. Details, grading rules, and limits:
[benchmark/README.md](benchmark/README.md).

## The reviewer agents

Three agents in [`reviewer/`](reviewer/README.md), each its own program:

- **`single_call`**: sends the diff to the model once and asks for the vulnerabilities.
- **`find_verify`**: a finder reads the diff and looks up whatever code it needs, then
  a separate verifier checks each candidate in the code. Only candidates the verifier
  confirms with quoted code are reported.
- **`self_improving`**: find-verify with a profile it tunes itself. A loop looks at
  which bugs it missed and which false alarms it raised, proposes one change at a time
  (for example a specialist that hunts one kind of bug), and keeps a change only if the
  benchmark score improves.

They run on Claude (`claude-haiku-5-5`, the default) or Cerebras (`gpt-oss-120b`).

## Results

All 67 PRs, one run each.

| Agent | Model | Bugs found (of 37) | Precision | F1 | Clean PRs with a false alarm (of 40) |
|---|---|---|---|---|---|
| single_call | gpt-oss-120b | 26 | 29% | 0.41 | 29 |
| find_verify | gpt-oss-120b | 25 | 48% | 0.56 | 11 |
| single_call | claude-haiku-5-5 | **27** | 61% | 0.67 | 3 |
| find_verify | claude-haiku-5-5 | 23 | 68% | 0.65 | **0** |
| self_improving\* | claude-haiku-5-5 | 24 | **83%** | **0.73** | **0** |

\* Tuned on these same 67 PRs, so this shows how well it fits the benchmark, not how it
would do on new PRs. Its gain is about the size of the run-to-run variation (a few bugs).

The verifier mainly removes false alarms: it cut gpt-oss's from 29 clean PRs to 11.
Haiku is already precise in a single call, so there the verifier helps less. A full
Haiku run costs about $0.11 (single_call) to $0.63 (the others).

## Quick start

```powershell
# Python 3.11+ and Git. For Claude, install the SDK; then add your API key to .env.
pip install -e ".[claude]"
Copy-Item .env.example .env

python reviewer/find_verify reviewer/example.diff     # review one diff
python -m benchmark build                             # fetch the 67 PRs (about 540 MB)
python -m benchmark evaluate find-verify              # run, grade, and score an agent
python -m benchmark improve                           # tune the self_improving agent
```

Settings (model, limits, which PRs to run) are in [`config.toml`](config.toml).
Tests: `python -m unittest discover -s tests`.
