# code-audit

A [Claude Code](https://claude.com/claude-code) skill that audits a repo or folder and shows the result
as a one-screen terminal dashboard: **tests**, **code structure**, **code links** (entry point → final
effect) and **security**.

## Install

Needs `git` and Python 3.8+. The installer copies the skill into your agent's skills folder, so it
works right away (restart the agent session). Linux, macOS and Windows.

**One command**

```bash
git clone https://github.com/LaptopKing/code-audit && python3 code-audit/install.py
```

Windows (PowerShell): `git clone https://github.com/LaptopKing/code-audit; python code-audit\install.py`

**One prompt** (paste into Claude Code or any other agent)

```text
Install the code-audit skill: clone https://github.com/LaptopKing/code-audit and run its install.py
with Python. Ask me first whether to add --hook for automatic audits.
```

**Options** (combine freely)

| Add | Installs into |
|-----|---------------|
| nothing | Claude Code: `~/.claude/skills/code-audit` |
| `--target agents` | Codex, Gemini CLI, OpenCode: `~/.agents/skills/code-audit` |
| `--target claude agents` | both |
| `--dir PATH` | any other harness: `PATH/code-audit` |
| `--hook` | also auto-audits modules you changed a lot (Claude Code only, see below) |

Update: `git -C code-audit pull` then run `install.py` again with the same options.
Optional scanners for the security page: `uv tool install semgrep` · `brew install gitleaks osv-scanner`
(Windows: `scoop install gitleaks osv-scanner`).

**Automatic audits (`--hook`, optional)**

Adds a Stop hook to `~/.claude/settings.json` (a `.bak` copy is kept). After each Claude Code reply
it checks the modules Claude edited (~0.05 s, no tokens) and asks Claude to audit one in a background
agent when it was never audited, or changed ≥150 lines since its last audit and Claude judges the
change big. Status: `python3 ~/.claude/skills/code-audit/scripts/audit_gate.py --status`.
Turn it off: remove the `audit_gate.py` entry under `hooks.Stop` (or use `/hooks`).

## Usage

```text
/code-audit                      audit the whole repo
/code-audit backend/src/routes   audit one folder
how well tested is src/api?      plain questions trigger it too
```

Then type a page name to switch pages, no rescan:

| Type | Shows |
|------|-------|
| `tests` | module ↔ test counts, untested hot files |
| `structure` · `structure nesting` | file/function size, nesting, naming, copy-paste, dead code |
| `kinds` | how each kind of code is written, with a good and a bad example |
| `links` · `trace upload` | entry point → functions → command / DB write / file |
| `security` · `security 2` | findings per rule, each checked by reading the code |
| `rescan` | run the scan again after code changes |

## Example

This repo auditing itself (`/code-audit`, scanners off):

```text
AUDIT · . · 6 code files · 2026-11-12 10:55
────────────────────────────────────────────────────────────────────────────────────────────
TESTS     █████░░░░░  50%  2/4 modules · 15 cases
STRUCTURE C    size D fn B nest C name F copy A dead F · files >1000: 0, >600: 1
LINKS     0 routes (0 with known callers) · 7 CLI · 0 workers · 0 traced chains
SECURITY  🔴 0 high · 🟠 0 med · 🟡 0 low · 5 false alarms hidden · patterns only, scanners…
────────────────────────────────────────────────────────────────────────────────────────────
TOP ISSUES
1. 🟠 scan.py: 664 lines, no tests                     scripts/scan.py
2. 🟠 render.py has no tests                           scripts/render.py
3. 🟡 security hits are rule regexes                   scripts/scan.py:92-98
────────────────────────────────────────────────────────────────────────────────────────────
next: tests · structure · kinds · links · security   (add a number for the next page)
```

Counts come from `scripts/scan.py` (same code → same numbers); Claude adds the judgement (grades,
examples, false-positive checks). Full agent instructions: [`SKILL.md`](SKILL.md).

## Tests

```bash
cd scripts && python3 -m pytest -q
```
