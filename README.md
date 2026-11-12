# code-audit

A [Claude Code](https://claude.com/claude-code) skill that audits a repo or folder and shows the result
as a one-screen terminal dashboard: **tests**, **code structure**, **code links** (entry point → final
effect) and **security**.

## Install

**One command**

```bash
git clone https://github.com/LaptopKing/code-audit ~/projects/code-audit && ln -s ~/projects/code-audit ~/.claude/skills/code-audit
```

**One prompt** (paste into Claude Code)

```text
Install the code-audit skill: clone https://github.com/LaptopKing/code-audit to ~/projects/code-audit and symlink it to ~/.claude/skills/code-audit.
```

Update: `git -C ~/projects/code-audit pull`. Optional scanners for the security page:
`uv tool install semgrep` · `brew install gitleaks osv-scanner`.

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
