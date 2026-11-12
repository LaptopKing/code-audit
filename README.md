# code-audit

A [Claude Code](https://claude.com/claude-code) skill that audits a whole codebase or one folder and
shows the result as a one-screen terminal dashboard with pages:

- **Test coverage**: module ↔ test counts
- **Code structure**: file/function length, nesting depth, naming, copy-paste, dead code, with real good and bad examples
- **Code links**: entry point (HTTP route, CLI command, UI button, external API call) → functions → final command / DB write / file
- **Security**: pattern scan plus semgrep, gitleaks and osv-scanner, verified by reading the code

Full instructions for the agent are in [`SKILL.md`](SKILL.md).

## Install

```bash
git clone <this-repo-url> ~/projects/code-audit
ln -s ~/projects/code-audit ~/.claude/skills/code-audit
```

Then run `/code-audit` in Claude Code, or ask it to "audit this repo".

Optional tools for the security page: `semgrep`, `gitleaks`, `osv-scanner` (skipped when missing).

## Layout

| Path | What it does |
|------|--------------|
| `SKILL.md` | The skill: steps the agent follows |
| `scripts/scan.py` | Deterministic counts → `facts.json` |
| `scripts/render.py` | Draws one window-tall dashboard page |
| `scripts/shape.py` | Code-shape measurements (nesting, length) |
| `scripts/audit_gate.py` | Optional hook that suggests audits for changed modules |
| `scripts/test_*.py` | Tests |

## Tests

```bash
cd scripts && python3 -m pytest -q
```
