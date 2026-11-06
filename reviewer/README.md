# Security PR reviewers

Two strategies share the same model providers (Cerebras and Claude; see
[Model providers](#model-providers)), input protocol, and output format:

- `--strategy baseline` (default): one model call on the diff. Documented below under
  [Single-call baseline](#single-call-baseline).
- `--strategy find-verify`: a finder that can look up any code, then one verifier per
  candidate. Only candidates the verifier confirms in the code are reported.

Results on the benchmark are in the [root README](../README.md#results).

## find-verify

1. **Find.** The finder reads the diff, with every line labelled `[base N]` or
   `[head N]`, and calls `lookup` whenever the diff is not enough: callers, routes,
   where input comes from, guards, sanitizers. It may run several lookups per turn.
   It ends by calling `report` with its candidates. A candidate must point at a line
   in the diff; if one does not, the finder is told which and can fix its report.
2. **Verify.** Each candidate gets its own verifier, with the same lookup tool and a
   fresh conversation; up to three run in parallel. It confirms only if code it cites
   shows that an attacker controls the input, the input reaches the operation with no
   effective guard, the operation has the claimed impact, and this diff introduced or
   weakened it. Otherwise it rejects (quoting the guard or line) or says uncertain.
3. **Report.** Confirmed candidates become findings, with the verifier's reasoning
   appended to the description and its citations as evidence.

```powershell
# A local diff with its base and head source trees (keep them unchanged during the review).
python -m reviewer --strategy find-verify --provider cerebras --diff change.diff --base-dir C:\sources\base --head-dir C:\sources\head

# A public GitHub PR: reads files at the pinned head and merge-base revisions (no search).
python -m reviewer --strategy find-verify --provider cerebras --pr https://github.com/OWNER/REPO/pull/123 --out .reviews/pr-123.json

# The finder's exact first request, without a model call.
python -m reviewer --strategy find-verify --diff reviewer/example.diff --dry-run
```

**Checks done in code, not by a model.** A citation must quote one line exactly as
the verifier saw it, in the diff or its own lookup results; otherwise the verifier is
told what is wrong (never observed, quote not found, several lines joined) and can
fix it. A confirmation must cite at least one line the diff changed. Lookups go
through `code_access.py`: the benchmark's lookup command (reconstructed, never run as
given), local trees, or pinned GitHub revisions. They hide `.git`, `.env*`, and
changelogs, and return specific errors such as "no such file" or "invalid search
pattern" with commit ids removed. No model-supplied command is executed.

**Robustness.** Models act only through native tool calls. A reply in plain text gets
a reminder instead of failing the review; an identical repeated lookup is refused
with a pointer to the earlier result. HTTP 429 responses are retried after the
provider's `Retry-After`, at most three attempts and never past the review deadline;
other errors are not retried. There is no lookup quota: each finder and verifier
has a call cap (`--finder-calls 20`, `--verifier-calls 12`), the review has a global
cap (`--max-calls 150`) and deadline (`--review-timeout 300`), and the last turns
are told to finish. At most 10 candidates are verified; any beyond that are listed
as `unverified`.

**Profiles and specialists.** The parts of the prompts meant to be tuned live in a
JSON profile, `reviewer/profiles/default.json` unless `--profile` names another:

- `finder_guidance`: appended to the finder's prompt.
- `verifier_criteria`: the checklist the verifier confirms against.
- `specialists`: up to 8 extra finders, each hunting one class of vulnerability, with
  a `name`, a one-sentence `focus`, `guidance` on sources, sinks, and missing
  defenses, and `triggers`: regular expressions matched against the diff's changed
  lines. A specialist runs only when a trigger matches (always, if it has none).

The general finder and the matching specialists run in parallel. Candidates at the
same location are merged; each records which hunter proposed it (`source`, and
`also_proposed_by`). The default profile has no specialists and reproduces the
fixed prompts above. Fixed rules (untrusted input, tool use, citations, report
format) stay in code. `metadata.profile` records the profile's name, version, and
SHA-256. The benchmark's improvement loop edits profiles; see the
[root README](../README.md#improving-the-reviewer).

**Output.** `findings` is benchmark-compatible. The output also keeps every
`candidates` entry, each `verifications` verdict with its reason, citations,
lookups, and stop reason, and the finder's lookups. `metadata.status` is `partial`
when a verifier was uncertain or something hit a cap, and `error` (exit code 2) when
a model call failed outright, so the benchmark counts it as a failed case.
`--record` saves every request and response.

## Model providers

Both strategies run on either provider:

| `--provider` | Default model | Key in `.env` | Needs |
|---|---|---|---|
| `cerebras` (default) | `gpt-oss-120b` | `CEREBRAS_API_KEY` | the standard library only |
| `anthropic` | `claude-haiku-5-5` | `ANTHROPIC_API_KEY` | the `anthropic` SDK: `pip install -e ".[claude]"` |

`--model` overrides the default model, and `REVIEW_PROVIDER` in `.env` sets the
default provider. Requests are built in the OpenAI chat-completions shape, which
Cerebras speaks natively. For Claude, `reviewer/claude.py` converts each request to
the Messages API through the official SDK and the reply back, so the reviewers'
loops are the same on both. On Claude it sends no sampling parameters (current models
reject them), sets thinking depth through `effort`, passes thinking blocks back
unchanged with tool results, and lets the model choose its tool calls (forcing one
would skip thinking); the reviewers remind it if it answers in text instead.

The reported results used Cerebras. For private code, first check that the provider's
data terms permit sending it.

## Single-call baseline

This baseline sends one unified diff to the model, asks for security
vulnerabilities introduced by the PR, and validates the returned JSON structure.
It uses Python 3.11+ and the standard library, with no agent framework.

The baseline is intentionally limited to the diff and its included context lines.
It does not read repository files, follow imports, search history, run code, invoke
tools, repair JSON with another model call, or verify exploitability. An empty
finding list means no issue was established from this context. Model/API failures
exit nonzero and never become successful empty reviews.

## Run a review

From the project root in PowerShell:

```powershell
# Add your key to the project-root .env file first (see the provider table above).
# If setting up a fresh checkout: Copy-Item .env.example .env

# One GitHub PR. Public PRs can be fetched without a GitHub token.
python -m reviewer --pr https://github.com/OWNER/REPO/pull/123 --out .reviews/pr-123.json --record .reviews/pr-123-trace.json

# One local unified diff. This example is synthetic; it is not a benchmark case.
python -m reviewer --diff reviewer/example.diff --out .reviews/example.json --record .reviews/example-trace.json

# The same review with Claude.
python -m reviewer --provider anthropic --diff reviewer/example.diff

# Inspect the exact model payload without a key, network call, or model inference.
python -m reviewer --diff reviewer/example.diff --dry-run
```

Optionally set `GITHUB_TOKEN` (or `GH_TOKEN`) for authenticated GitHub fetching.
The reviewer only fetches metadata and the diff; it never posts GitHub comments.

The reviewer automatically loads `.env` from its own project root, including when
the benchmark launches it from another working directory. Copy `.env.example` to
`.env` in a fresh checkout and fill in the key for your provider. Existing process
environment variables take precedence; `--provider` and `--model` take precedence
over both. The loader supports simple `KEY=value` assignments, optional
single/double quotes, and comments. It performs no variable interpolation or command
execution. It reads only the documented configuration keys and never loads a
reviewed repository's `.env`. The personal `.env` is ignored by Git; `.env.example`
has empty key fields. Keys are never placed in prompts or trace files. Traces
contain PR source code and raw model output; `.reviews/` is ignored by Git.

To use an installed console command:

```powershell
python -m pip install -e .            # add ".[claude]" for the Claude provider
security-review --diff reviewer/example.diff
```

## Benchmark integration

Without `--pr` or `--diff`, the command reads one request JSON object from stdin.
It supports the benchmark's `mode: "pr"` protocol. The baseline only sends the
`diff` and, when provided, explicitly allowed `pr` metadata; it ignores the lookup
command, task IDs, instructions, and any other fields. find-verify also uses the
lookup command. Other modes are rejected.

The benchmark runs each reviewer in an empty temporary folder, so pass the
reviewer folder's absolute path; it puts itself on the import path:

```powershell
$reviewer = (Resolve-Path reviewer).Path
$python = (Get-Command python).Source   # for Claude, a Python that has the anthropic SDK
python -m benchmark run --split dev --model cerebras/gpt-oss-120b --out .bench/run.json -- $python $reviewer --provider cerebras
```

Build the suite first with `python -m benchmark build`, as described in the root README.
The output is compatible with the benchmark (`findings` plus an additional `metadata`
object). The harness retains usage metadata in each case's output. Keep its model
label consistent with `--provider` and `--model`. Use a distinct output file for each
run. Model output must be adjudicated using the benchmark's scorer; these tests do
not establish detection quality.

One finding looks like:

```json
{
  "title": "User-controlled name reaches a shell command",
  "severity": "high",
  "description": "Attacker control, mechanism, prerequisites, impact, and what changed.",
  "path": "app.py",
  "line": 5,
  "side": "head",
  "evidence": ["app.py:5: request input is concatenated into a command with shell=True"]
}
```

`side` is `head` or `base`; a removed guard can be anchored in the base.
`severity` is `critical`, `high`, `medium`, or `low`. Locations are structurally
validated but not checked against complete source trees. The model supplies the
severity and explanation; neither is independently verified by this baseline.

## Reproducibility and limits

- Prompt: `reviewer/prompt.py`, version `diff-only-v1`. Preserve this version when
  comparing against the reported baseline scores. Version future prompt changes explicitly.
- Defaults: medium reasoning effort, 16,384 output-token allowance including
  reasoning, 240-second HTTP timeout, and 200,000 characters of serialized PR
  context. On Cerebras the temperature is 0, which does not guarantee deterministic
  results; Claude accepts no sampling parameters.
- `--max-input-chars`, `--max-tokens`, `--reasoning-effort`, `--timeout`, and `--model`
  are configurable. No model fallback is configured; changing a model is a separate
  experiment.
- Oversized input fails before inference; no diff is silently clipped. GitHub
  fetching checks file counts against PR metadata and checks base/head SHAs before
  and after downloading. This detects some incomplete responses and update races;
  it is not a proof that all remote diff content is complete. Binary contents are
  not reviewed. Title and body are included for URL inputs, while benchmark inputs
  normally contain only the diff. These input differences are part of the scope.
- The baseline asks for JSON text, accepts a single enclosing Markdown JSON fence,
  and fails on malformed findings, incomplete output, or invalid JSON. It makes no
  second model call. On Claude the SDK retries rate limits and server errors itself;
  on Cerebras a rate limit fails the review, so re-run explicitly rather than
  silently mixing attempts.
- Metadata includes prompt/context/request hashes, requested and returned model,
  provider and response ID when available, usage, cost, elapsed time, and settings.
  Use `--record` to preserve the exact model request and raw response, including an
  invalid response for debugging. Record files are written before the call, then
  updated after the response and on validation failure. Each `--record` path is
  for one review; do not reuse it across benchmark cases.
- Cost: Cerebras does not report one, so `cost_usd` is null there. For
  `claude-haiku-5-5` it is computed from list prices ($0.10 / $0.50 per million input /
  output tokens, for prompts up to 100K tokens); otherwise it is null.

Measured results for both strategies are in the root README.

## Verification

```powershell
python -m unittest discover -s tests -v
```

Tests use synthetic diffs and mocked provider responses. They check request
construction, benchmark compatibility, error handling, PR-fetch consistency, and
that evaluator-only input never enters the model context. They do not execute
vulnerable application code or call a live model. The Claude request tests are
skipped when the `anthropic` SDK is not installed.

References: [Cerebras inference docs](https://inference-docs.cerebras.ai),
[Claude API docs](https://platform.claude.com/docs).
