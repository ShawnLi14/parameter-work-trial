# Single-call security reviewer baseline

This baseline sends one unified diff to
`nvidia/nemotron-3-ultra-550b-a55b:free` through OpenRouter, asks for security
vulnerabilities introduced by the PR, and validates the returned JSON structure.
It uses Python 3.11+ and the standard library, with no agent framework or runtime
dependencies. The HTTP integration uses OpenRouter's documented Chat Completions
endpoint directly.

The baseline is intentionally limited to the diff and its included context lines.
It does not read repository files, follow imports, search history, run code, invoke
tools, repair JSON with another model call, or verify exploitability. An empty
finding list means no issue was established from this context. Model/API failures
exit nonzero and never become successful empty reviews.

## Run a review

From the project root in PowerShell:

```powershell
# Add your key to OPENROUTER_API_KEY in the project-root .env file first.
# If setting up a fresh checkout: Copy-Item .env.example .env

# One GitHub PR. Public PRs can be fetched without a GitHub token.
python -m reviewer --pr https://github.com/OWNER/REPO/pull/123 --out .reviews/pr-123.json --record .reviews/pr-123-trace.json

# One local unified diff. This example is synthetic; it is not a benchmark case.
python -m reviewer --diff reviewer/example.diff --out .reviews/example.json --record .reviews/example-trace.json

# Inspect the exact model payload without a key, network call, or model inference.
python -m reviewer --diff reviewer/example.diff --dry-run
```

To use Cerebras instead of OpenRouter, set `CEREBRAS_API_KEY` and pass
`--provider cerebras` (or set `REVIEW_PROVIDER=cerebras`). Its default model is
`gpt-oss-120b`; `REVIEW_MODEL` applies to OpenRouter only. On six dev cases it took
1 to 2 seconds per review.

Optionally set `GITHUB_TOKEN` (or `GH_TOKEN`) for authenticated GitHub fetching.
The reviewer only fetches metadata and the diff; it never posts GitHub comments.
For private PRs, first ensure that your chosen model endpoint permits the data.
This free NVIDIA endpoint specifically asks users not to send confidential or
personal information and says usage is logged and may be used for product
improvement. Use public or synthetic source with this endpoint.

The reviewer automatically loads `.env` from its own project root, including when
the benchmark launches it from another working directory. Copy `.env.example` to
`.env` in a fresh checkout and fill in `OPENROUTER_API_KEY`. Existing process
environment variables take precedence; `--model` takes precedence over both.
The loader supports simple `KEY=value` assignments, optional single/double quotes,
and comments. It performs no variable interpolation or command execution. It reads
only the four documented configuration keys and never loads a reviewed repository's
`.env`. The personal `.env` is ignored by Git; `.env.example` has empty key fields.
Keys are never placed in prompts or trace files.
Traces contain PR source code and raw model output; `.reviews/` is ignored by Git.

To use an installed console command:

```powershell
python -m pip install -e .
security-review --diff reviewer/example.diff
```

## Benchmark integration

Without `--pr` or `--diff`, the command reads one request JSON object from stdin.
It supports the benchmark's `mode: "pr"` protocol. It only sends the `diff` and,
when provided, explicitly allowed `pr` metadata. It ignores the lookup command,
task IDs, instructions, and any other fields. Other modes are rejected.

The benchmark runs each reviewer in an empty temporary folder, so pass the
reviewer folder's absolute path; it puts itself on the import path:

```powershell
$reviewer = (Resolve-Path reviewer).Path
$python = (Get-Command python).Source
python -m benchmark run --split dev --model cerebras/gpt-oss-120b --out .bench/run.json -- $python $reviewer --provider cerebras
```

Build the suite first with `python -m benchmark build`, as described in the root README.
The output is compatible with the benchmark (`findings` plus an additional `metadata`
object). The harness retains usage metadata in each case's output. Keep its model
label consistent with `--model`/`REVIEW_MODEL`. Use a distinct output file for each
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
  establishing baseline scores. Version future prompt changes explicitly.
- Defaults: temperature 0, medium reasoning effort, 16,384 output-token allowance
  including reasoning, 240-second HTTP timeout, and 200,000 characters of serialized
  PR context. Temperature 0 does not guarantee deterministic model results.
- `--max-input-chars`, `--max-tokens`, `--reasoning-effort`, `--timeout`, and `--model`
  are configurable. `REVIEW_MODEL` supplies an optional default model override.
  Models must support the requested reasoning and sampling parameters. No model
  fallback is configured; changing a model is a separate experiment.
- Oversized input fails before inference; no diff is silently clipped. GitHub
  fetching checks file counts against PR metadata and checks base/head SHAs before
  and after downloading. This detects some incomplete responses and update races;
  it is not a proof that all remote diff content is complete. Binary contents are
  not reviewed. Title and body are included for URL inputs, while benchmark inputs
  normally contain only the diff. These input differences are part of the scope.
- The free endpoint does not currently advertise strict JSON/schema output.
  This baseline asks for JSON text, accepts a single enclosing Markdown JSON fence,
  and fails on malformed findings, incomplete output, or invalid JSON. It makes no
  second model call and performs no transport retries. A rate limit is a failed
  review; re-run explicitly rather than silently mixing attempts.
- Metadata includes prompt/context/request hashes, requested and returned model,
  provider and response ID when available, usage, cost, elapsed time, and settings.
  Use `--record` to preserve the exact model request and raw response, including an
  invalid response for debugging. Record files are written before the call, then
  updated after the response and on validation failure. Each `--record` path is
  for one review; do not reuse it across benchmark cases.
- The listed free variant has zero input/output token prices. Reported provider
  cost takes precedence; otherwise `cost_usd: 0` is explicitly marked as a free
  variant estimate. Other models have unknown cost unless the provider reports it.
  Free-tier request limits and provider availability can constrain benchmark runs.

No live model calls or measured quality results are claimed by this implementation.
Establish baseline scores on the frozen benchmark before adding retrieval or a
verification pass. The work trial's core benchmark/improvement requirements remain
unfinished until those comparisons are run and adjudicated.

## Verification

```powershell
python -m unittest discover -s tests -p test_reviewer.py -v
```

Tests use synthetic diffs and mocked provider responses. They check request
construction, benchmark compatibility, error handling, PR-fetch consistency, and
that evaluator-only input never enters the model context. They do not execute
vulnerable application code or call a live model.

References: [OpenRouter API](https://openrouter.ai/docs/api/reference/overview),
[model endpoint capabilities](https://openrouter.ai/api/v1/models/nvidia/nemotron-3-ultra-550b-a55b:free/endpoints),
[endpoint data notice](https://openrouter.ai/nvidia/nemotron-3-ultra-550b-a55b:free),
[request limits](https://openrouter.ai/docs/api_reference/limits).
