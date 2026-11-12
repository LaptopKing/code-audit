---
name: code-audit
description: Audit a whole codebase or one folder of it and show the result as a one-screen terminal dashboard with pages. Covers test coverage (module ↔ test counts), code structure (measured bottlenecks: file length, function length, nesting depth — christmas tree vs non-nester —, naming, copy-paste and dead code, plus how each kind of code is written with real good and bad examples), code links (entry point such as an HTTP route, CLI command, UI button or another project's API call → functions → final command/DB write/file), and security holes (pattern scan + semgrep, gitleaks, osv-scanner, verified by reading the code). Use this whenever the user asks to audit, review the health of, assess, or get an overview of a repo or folder, asks "how well tested is X", "how is this code written", "what calls what", "where does this endpoint end up", "is this secure", or wants a dashboard/report of code quality, even when they don't say "audit". Not for reviewing a single diff or PR (use code-review for that).
---

# Code audit dashboard

The user reads the result in a terminal window that is often only ~28 rows tall. They asked for a
dashboard that fits the window so they never scroll and lose what they read. So the audit is a set of
**pages**, each exactly one window tall, drawn by `scripts/render.py`, which measures the real window.
Your reply for each page is the rendered block and nothing that pushes it off screen.

Two kinds of work, kept apart on purpose:
- **Counts** come from `scripts/scan.py`, so two runs on the same code give the same numbers.
- **Judgement** (which code is good or bad, how a request flows, whether a pattern hit is real) is your
  job. You write it to `notes.json`; the renderer merges it in.

## 1. Pick the scope and the callers (~1 min)

- Scope = the path(s) the user named; no path → the repo root.
- Callers = other projects that call this one (a plugin, a frontend in another repo). Look for sibling
  folders named like the repo (`ls ..` → e.g. `promo-tool-premiere-plugin` next to `promo-tool`) and
  any project the user names. A frontend inside the scope is found automatically.
- A huge scope (>1500 code files): tell the user the size and offer to start with the biggest folder.

## 2. Run the scan

```bash
python3 ~/.claude/skills/code-audit/scripts/scan.py <scope> [--callers <dir> ...] [--history]
```

- Prints the path of `facts.json` (cached under `~/.cache/code-audit/<scope>-<hash>/`).
- Runs semgrep, gitleaks and osv-scanner when installed (npm audit when osv-scanner is missing).
  semgrep is the slow part (measured: ~3.5 min for a 1100-file repo, ~3 s without tools), so run
  it in the background and tell the user the expected time. `--no-tools` skips them for a quick look.
- `--history` makes gitleaks scan the whole git history; offer it for whole-repo audits, because a
  secret deleted from the code is still in history.
- If a tool is missing, the security page says so. Tell the user the install line
  (`brew install gitleaks osv-scanner`, `uv tool install semgrep`), don't install it unasked.

Read facts.json with `jq` on the parts you need, not whole: it can be large.

## 3. Judgement pass → notes.json

Write `notes.json` next to `facts.json`. Small scope (<150 code files): do it yourself. Bigger: spawn
three subagents in one message (structure, links, security), each returning its part of the JSON, then
merge. Give each the facts.json path and the schema below; tell them to use CodeMapper
(`outline`/`expand`/`path`), `rg` and `sg` before reading, and to read only the lines they cite.

```json
{
  "top": [{"sev": "high|med|low", "text": "≤60 chars, plain words", "where": "file:line"}],
  "structure": {
    "grade": "A|B|C|D|F",
    "verdict": "one line: how this codebase is written overall",
    "shape_notes": {"channel-handling/channel-handling.js": "≤40 chars: what to split it into",
                    "dsp/biquad.js:40": "≤40 chars: verdict on that long/deep function",
                    "naming:dsp/biquad.js": "≤40 chars, e.g. a0/q = standard filter notation"},
    "examples": [{"kind": "routes/api", "style": "≤40 chars: how this kind is written",
                  "good": {"where": "path:12-40", "why": "≤50 chars"},
                  "bad":  {"where": "path:80-190", "why": "≤50 chars"}}]
  },
  "chains": [{"entry": "POST /api/mix ← plugin src/api.ts:88",
              "steps": ["routes/mix.js:41 startMix()", "services/mixer.js:120 runMixer()",
                        "dsp/ffmpeg.js:33 spawn('ffmpeg')"],
              "result": "writes mix.wav to storage/<job>, returns job id"}],
  "security": {"verdicts": {"S1": "confirmed|false-positive|unsure",
                            "path-join-resolve-traversal": "false-positive"},
               "notes": {"S1": "≤50 chars: what you saw in the code",
                         "path-join-resolve-traversal": "≤50 chars, shown on the rule's row"}}
}
```

Keep every string inside its limit: the page has fixed columns and long text gets cut. Limits not
shown above: `top.where` ≤36, `chains.entry` and each step ≤70, `result` ≤70. Paths in `where` are
relative to the scope; paths in chain steps (often outside the scope) are relative to the repo root
with any shared prefix like `backend/src/` dropped. A kind with no bad (or good) example: set that
key to `null`.

**Structure, part 1: the measured shape (`facts.shape`, page `structure`).** This is what the user
cares about most: files of hundreds or thousands of lines, christmas-tree nesting, functions that do
five jobs, names that don't say what a thing is. scan.py measures six dimensions and grades each A-F
(`shape.grades`, rules in `scripts/shape.py`):
- **size**: share of all lines (comments too) in files over 600 lines; also files >300/>600/>1000.
- **functions**: share of named functions over 50 lines; >100 is a hard bottleneck.
- **nesting**: control-flow depth inside a function: if/for/while/switch/try and callbacks nested in
  each other. 0-2 = non-nester (good: guard clauses, early returns, extracted helpers); 4+ = christmas
  tree. Object literals and the function body itself don't count.
- **naming**: names too short to say anything (`q`, `vb`), vague (`data`, `tmp`, `obj`, `item2`),
  too long (>40), off the language convention (snake_case in JS, camelCase in Python, lower-case
  classes), and folders that mix kebab/snake/camel file names.
- **duplication**: share of lines in 6+ line blocks that appear twice (Karpathy: copy-paste instead of
  one helper).
- **dead**: exports no other file names, and files nothing imports or names in a path string
  (Karpathy: dead code left behind).
Judge it, don't just repeat it:
1. Open the 3 largest files (outline only) and say in `shape_notes` what each mixes and how it would
   split (e.g. "analysis + 9 stages + report: split stages out"). A long file of one cohesive job
   (a reference DSP port, a constants table) gets a note saying so.
2. Read the deepest-nested and longest functions you cite; confirm or dismiss each in `shape_notes`.
3. Naming: decide per file whether flagged names are real problems or domain notation (DSP
   coefficients `a0`, `q`, `x1` are standard and fine; `vb`, `tmp`, `data` usually are not). Note it.
4. Copy blocks and dead exports/files: open one or two; a dead file is a top issue when it is big.
5. Also look for the other Karpathy smells while reading: abstractions with one user, options and
   config nobody passes, error handling for cases that can't happen, 200 lines where 50 would do.
**Grade rule:** your `structure.grade` may be at most one letter better than `shape.grade_hint`, and
a scope with any file over 1000 lines or any function 6+ deep is C or worse. Put the worst size or
nesting bottleneck in `top` (sev high when a file is over 1000 lines or a function over 100 lines).

**Structure, part 2: how each kind is written (page `kinds`).** The user wants to oversee every kind
of code in the scope, so cover every kind in
`structure.kinds` that has ≥3 files — the 12 biggest in the first pass, the rest when the user pages
to `kinds 2` (judge those kinds then, before rendering). To pick candidates fast, list the
functions with their line spans once (`sg`, or CodeMapper `outline` per file) instead of reading
files (kinds are role folders like routes/services/components, else the
folder name). For each, open the `calm_candidates` and `knotty_candidates` (outline first, then the one
function you will cite) and pick one real good and one real bad example with an exact line range.
"Good" = small, clear names, one job, errors handled; "bad" = long function, deep nesting, mixed
concerns, copy-paste, swallowed errors. If a kind has no bad example, say so rather than inventing one.
`style` describes what you actually saw (e.g. "async fns, early return, no types"). Grade the whole
scope: A = consistent and easy to change; C = works but hotspots slow you down; F = most files hard to
follow. Paths in `where` are relative to the scope.

**Chains.** Trace 5–10 flows from an entry point to its final effect. Order: routes called by another
project first (`callers` containing `[project]`), then routes called by the UI, then CLI commands and
workers. Each step is `file:line function()`; stop at the last thing that does work: a spawned
command (ffmpeg, a script), a DB write, a file write, an outgoing HTTP call, or the response sent.
`result` says what the user gets back or what changes on disk. Use `expand` for callees and `path`
between two known symbols; when a call goes through a queue or event, name it as a step
(`queue 'mix' → worker.js:20`).
If the scope has no entry points of its own (a service or library folder), start from outside:
find who imports the scope's exported functions (`rg`/`expand`), follow them up to the route, CLI or
worker that starts them, then trace down into the scope. Caller projects (`--callers`) are matched
only against routes inside the scope, so for a sub-folder scope check the caller code by hand when
labelling an entry. The `sinks` list only sees direct calls (`execa(`, `spawn(`, `fs.writeFile(`);
calls through a wrapper such as an `ffmpeg-executor` helper are yours to find. `unmatched_calls` are calls with no route in the scope: mention
important ones in `top` (a caller hitting a route that no longer exists is a bug).

**Security.** semgrep alone can report hundreds of hits, so work per rule: the page shows one row per
rule. For each high and med rule, read 2–3 of its hits. If they're all harmless for the same reason,
set a verdict on the rule name (it covers every hit); if they differ, set verdicts per id (`S12`).
false-positive = the input isn't user-controlled, or it's a test fixture. For `route-no-auth-hint`,
check the app setup for global auth first. Low rules: check only if few. `vulnerable-dependency`:
say whether the package is a direct dependency and if a fixed version exists. Never print a secret's
value anywhere, not in notes, not in your reply: scan.py stores secret lines redacted, keep it so.

**Top.** 3–5 items across all sections, most harmful first: confirmed high security, broken links,
big untested modules on hot paths, worst structure hotspot.

## 4. Show a page

```bash
python3 ~/.claude/skills/code-audit/scripts/render.py <facts.json> --page overview
```

Pages: `overview`, `tests`, `structure`, `kinds`, `links`, `security`. `--n 2` shows the next page of
a long list; `--filter <text>` narrows to matching folders, kinds, chains or findings. On `structure`,
`--filter files|functions|nesting|naming|copy|dead` lists every item of that dimension.

Copy the printed block **verbatim** as your whole reply: the Bash output is not shown to the user, and
any line you add above it pushes the top of the dashboard off screen. At most one short line under the
block (e.g. what you skipped). The block's last line already lists what the user can type next.

## 5. Follow-ups

- "tests", "security 2", "links upload", "kinds dsp", "structure files" → render that page with `--page`, `--n`,
  `--filter`. Don't rescan. `security <rule>` (exact rule name as `--filter`) lists every hit.
- "trace X" / "how does X work" → trace that chain, add it to `notes.json`, render `links --filter X`.
- "rescan" or the code changed → run step 2 again; keep notes whose `where` still exists.
- "it doesn't fit" / lines cut off → re-render with `CODE_AUDIT_RESERVE=<n>` (lines kept free below
  the block, default 10) or `--rows/--cols`; tell the user which value worked.

## What the numbers mean (tell the user when asked)

- **Tested module** = a source file in the scope that some test file in the repo imports, or whose
  name matches a test file name. A file only mentioned in a comment does not count. No tests are run;
  a real coverage report (`coverage/coverage-summary.json`, `lcov.info`) is shown when one exists,
  with its age.
- **Cases** = `it(`/`test(`/`def test_` blocks in the tests that touch the scope.
- **Complexity** = scc's branch count per file; hotspots are the highest.
- **File length** = every line of the file, comments and blanks included (a reader wades through all
  of them); `code` next to it is scc's count without comments and blanks.
- **Nesting depth** = how many if/for/while/switch/try blocks and callbacks sit inside each other
  within one function, read by a small brace/indentation reader (strings and comments ignored). It is
  a heuristic, not a parser: every finding names file:line so it can be checked.
- **Shape grades** = A-F per dimension from a share or rate (thresholds at the top of shape.py), so a
  small and a big scope compare; `grade_hint` is their average, capped at C when any file is over
  1000 lines or any function nests 6+ deep.
- **Routes with known callers** = a call string in the scope or a caller project matches the route path
  (params like `:id` and `${x}` match anything). Calls built from variables are not seen.

## Automatic runs (Stop hook)

When installed with `install.py --hook`, a global Stop hook runs `scripts/audit_gate.py` after each final reply (~0.05 s, no tokens). It
looks at the files Claude edited this session, maps each to a module (a role folder plus the folder
under it, e.g. `backend/src/services/audio-mixing`), and asks Claude to audit a module when:
- it was never audited (initial audit: always run it), or
- it changed ≥150 lines since its last audit (`CODE_AUDIT_THRESHOLD`) — then Claude decides if the
  change is big (new feature, new route/export/file, behaviour across files) or not (renames, fixes).

The audit runs in a background subagent, which ends with `audit_gate.py --mark <module>` so the
module's current code becomes the new baseline (a copy under `~/.cache/code-audit/gate/`). A "not
big" answer isn't repeated until the change grows by another half threshold.
`audit_gate.py --status` lists the modules and how much each changed since its audit.
Turn it off: remove the hook from `~/.claude/settings.json` (or `/hooks`).
