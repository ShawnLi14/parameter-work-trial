# Security PR reviewers

Three reviewer agents, each its own program, sharing the code in this folder:

| Agent | What it does |
|---|---|
| [`single_call/`](#single_call) | One model call on the diff. |
| [`find_verify/`](#find_verify) | A finder that can look up any code, then one verifier per candidate; only candidates the verifier confirms in the code are reported. |
| [`self_improving/`](#self_improving) | find-verify running on a profile learned from its own benchmark failures. |

Results on the benchmark are in the [root README](../README.md#results).

## Run an agent

```powershell
# Fresh checkout: Copy-Item .env.example .env, then add your API key.
python reviewer/single_call reviewer/example.diff                     # a local unified diff
python reviewer/find_verify https://github.com/OWNER/REPO/pull/123     # a public GitHub PR
python reviewer/find_verify change.diff C:\sources\base C:\sources\head   # a diff and its source trees
Get-Content request.json | python reviewer/self_improving             # one benchmark request on stdin
```

Each agent prints its review as JSON on stdout. `python -m reviewer.single_call` and
the other module forms work too, and `pip install -e ".[claude]"` adds the commands
`review-single-call`, `review-find-verify`, and `review-self-improving`. With no
argument an agent reads one benchmark request on stdin, which is how the benchmark
runs them (`python -m benchmark evaluate find-verify`). An agent folder runs from any
working directory and needs no installation.

There are no other options: every setting is in `config.toml` in the project root.

## Settings

`config.toml` (all keys optional; the file in the repository lists the defaults):

| Section | Settings |
|---|---|
| `[model]` | `provider` (`anthropic` or `cerebras`), `name` (empty: the provider's default), `reasoning_effort`, `max_tokens`, `timeout` per request |
| `[review]` | `max_input_chars`, `record_dir` (e.g. `".reviews"` to save every review's model calls) |
| `[find_verify]` | call caps for the finder, specialists, and verifiers, `max_candidates`, `concurrency`, `max_calls`, `review_timeout`, `max_context_chars`; also used by `self_improving` |
| `[benchmark]`, `[improve]` | used by `python -m benchmark`; see the root README |

An unknown section or key, or a value of the wrong type, is an error rather than being
ignored. `.env` holds only API keys: `ANTHROPIC_API_KEY`, `CEREBRAS_API_KEY`, and
optionally `GITHUB_TOKEN` (or `GH_TOKEN`) for authenticated GitHub fetching. Both
files are read from the project root only, never from the working directory, so a
reviewed repository's own `.env` or `config.toml` is never loaded. Process
environment variables take precedence over `.env`. The `.env` loader supports simple
`KEY=value` assignments, optional quotes, and comments, with no interpolation or
command execution. Keys are never placed in prompts or trace files. The personal
`.env` and `.reviews/` (traces contain PR source code) are ignored by Git.

## Model providers

| `provider` | Default model | Key in `.env` | Needs |
|---|---|---|---|
| `anthropic` (default) | `claude-haiku-5-5` | `ANTHROPIC_API_KEY` | the `anthropic` SDK: `pip install -e ".[claude]"` |
| `cerebras` | `gpt-oss-120b` | `CEREBRAS_API_KEY` | the standard library only |

Requests are built in the OpenAI chat-completions shape, which Cerebras speaks
natively (`providers.py`). For Claude, `claude.py` converts each request to the
Messages API through the official SDK and the reply back, so the agents are the same
on both. On Claude it sends no sampling parameters (current models reject them), sets
thinking depth through `effort`, passes thinking blocks back unchanged with tool
results, and lets the model choose its tool calls (forcing one would skip thinking);
the agents remind it if it answers in text instead. For private code, first check
that the provider's data terms permit sending it.

## single_call

Sends one unified diff to the model, asks for security vulnerabilities introduced by
the PR, and validates the returned JSON. It is intentionally limited to the diff and
its context lines: it does not read repository files, follow imports, run code,
invoke tools, repair JSON with another model call, or verify exploitability. An empty
finding list means no issue was established from this context. It asks for JSON text,
accepts one enclosing Markdown JSON fence, and fails on malformed findings, incomplete
output, or invalid JSON, with no second model call. Its prompt is
`single_call/prompt.py`, version `diff-only-v1`; version any change explicitly.

## find_verify

1. **Find.** The finder reads the diff, with every line labelled `[base N]` or
   `[head N]`, and calls `lookup` whenever the diff is not enough: callers, routes,
   where input comes from, guards, sanitizers. It may run several lookups per turn.
   It ends by calling `report` with its candidates. A candidate must point at a line
   in the diff; if one does not, the finder is told which and can fix its report.
2. **Verify.** Each candidate gets its own verifier, with the same lookup tool and a
   fresh conversation; several run in parallel. It confirms only if code it cites
   shows that an attacker controls the input, the input reaches the operation with no
   effective guard, the operation has the claimed impact, and this diff introduced or
   weakened it. Otherwise it rejects (quoting the guard or line) or says uncertain.
3. **Report.** Confirmed candidates become findings, with the verifier's reasoning
   appended to the description and its citations as evidence.

**Checks done in code, not by a model.** A citation must quote one line exactly as
the verifier saw it, in the diff or its own lookup results; otherwise the verifier is
told what is wrong (never observed, quote not found, several lines joined) and can
fix it. A confirmation must cite at least one line the diff changed. Lookups go
through `code_access.py`: the benchmark's lookup command (reconstructed, never run as
given), local source trees, or pinned GitHub revisions (read and list; no search).
They hide `.git`, `.env*`, and changelogs, and return specific errors such as "no
such file" or "invalid search pattern" with commit ids removed. No model-supplied
command is executed.

**Robustness.** Models act only through native tool calls. A reply in plain text gets
a reminder instead of failing the review; an identical repeated lookup is refused
with a pointer to the earlier result. HTTP 429 responses are retried after the
provider's `Retry-After`, at most three attempts and never past the review deadline;
other errors are not retried. There is no lookup quota: the finder, each specialist,
and each verifier have call caps, the review has a global cap and a deadline (all in
`[find_verify]`), and the last turns are told to finish. Candidates beyond
`max_candidates` are listed as `unverified`.

**Profiles and specialists.** The parts of the prompts meant to be tuned live in a
JSON profile; find_verify uses `find_verify/profile.json`:

- `finder_guidance`: appended to the finder's prompt.
- `verifier_criteria`: the checklist the verifier confirms against.
- `specialists`: up to 8 extra finders, each hunting one class of vulnerability, with
  a `name`, a one-sentence `focus`, `guidance` on sources, sinks, and missing
  defenses, and `triggers`: regular expressions matched against the diff's changed
  lines. A specialist runs only when a trigger matches (always, if it has none).

The general finder and the matching specialists run in parallel. Candidates at the
same location are merged; each records which hunter proposed it (`source`, and
`also_proposed_by`). The default profile has no specialists. Fixed rules (untrusted
input, tool use, citations, report format) stay in code. `metadata.profile` records
the profile's name, version, and SHA-256.

## self_improving

find-verify with a learned profile: `self_improving/profiles/<model>.json` for the
model in `config.toml`. `python -m benchmark improve` learns it from the agent's own
benchmark failures and writes it there when its loop finishes (see the
[benchmark README](../benchmark/README.md#the-improvement-loop)). A model with no learned profile
yet runs on find-verify's default profile; `metadata.learned_profile` says which.
Because the loop learns from the benchmark's cases, this agent's benchmark score is a
fit to those cases, not a held-out estimate.

## Output

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

Each agent prints `{"findings": [...], "metadata": {...}}`, which the benchmark
accepts. `side` is `head` or `base` (a removed guard can be anchored in the base);
`severity` is `critical`, `high`, `medium`, or `low`. find_verify and self_improving
also output every candidate, each verifier's verdict with its reason, citations,
lookups, and stop reason, and the finder's lookups.

`metadata` records prompt and context hashes, requested and returned model,
provider, usage, cost, elapsed time, and settings. `metadata.status` is `partial` when
a verifier was uncertain or something hit a cap, and `error` (exit code 2) when a
model call failed outright, so the benchmark counts a failed case rather than a clean
review. Cost is computed for `claude-haiku-5-5` from list prices ($0.10 / $0.50 per
million input / output tokens, for prompts up to 100K tokens); Cerebras does not
report one, so it is null there.

The agents support the benchmark's `mode: "pr"` protocol only. They send the model the
`diff` and, for a GitHub PR, its allowed metadata (title and body included), never the
benchmark's labels, task IDs, instructions, or file paths. Oversized input fails
instead of being clipped. GitHub fetching checks file counts and base/head SHAs before
and after downloading; this catches some incomplete responses and races, not all.
Binary contents are not reviewed. The agents never post GitHub comments.

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
