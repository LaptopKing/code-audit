#!/usr/bin/env python3
"""Install the code-audit skill by copying it into a harness' skills folder.

  python install.py                    Claude Code  (~/.claude/skills/code-audit)
  python install.py --target agents    Codex, Gemini CLI, OpenCode  (~/.agents/skills/code-audit)
  python install.py --target claude agents
  python install.py --dir PATH         any other harness: PATH/code-audit
  python install.py --hook             also add the Claude Code Stop hook that audits
                                       modules you changed a lot (see README)

Run it again to update. Works on Linux, macOS and Windows; needs only Python 3.8+.
"""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path

NAME = "code-audit"
REPO = Path(__file__).resolve().parent
HOME = Path.home()
TARGETS = {
    "claude": HOME / ".claude" / "skills",
    "agents": HOME / ".agents" / "skills",
}
FILES = ["SKILL.md", "LICENSE", "scripts"]
SKILL_PATH_IN_DOCS = "~/.claude/skills/code-audit"
PYTHON = "python" if os.name == "nt" else "python3"
CLAUDE_SETTINGS = HOME / ".claude" / "settings.json"


def install(skills_dir):
    dest = Path(skills_dir).expanduser() / NAME
    if dest.resolve() == REPO:
        print(f"{dest} is this checkout already, nothing to copy")
        return
    if dest.is_symlink():
        dest.unlink()  # an older symlink install: replace it with a real copy
    dest.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        src, out = REPO / name, dest / name
        if src.is_dir():
            shutil.rmtree(out, ignore_errors=True)
            shutil.copytree(src, out, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
        else:
            shutil.copy2(src, out)
    # SKILL.md names its scripts by path: point it at this install and this OS's python.
    skill = dest / "SKILL.md"
    text = skill.read_text(encoding="utf-8").replace(SKILL_PATH_IN_DOCS, dest.as_posix())
    if PYTHON != "python3":
        text = text.replace("python3 ", PYTHON + " ")
    skill.write_text(text, encoding="utf-8")
    print(f"installed {dest}")


def add_hook(skill_dir):
    """Add (or repoint) the Stop hook in ~/.claude/settings.json. Keeps a .bak copy."""
    settings = {}
    if CLAUDE_SETTINGS.exists():
        try:
            settings = json.loads(CLAUDE_SETTINGS.read_text(encoding="utf-8"))
        except ValueError as e:
            sys.exit(f"{CLAUDE_SETTINGS} is not valid JSON ({e}); hook not added")
        shutil.copy2(CLAUDE_SETTINGS, CLAUDE_SETTINGS.with_suffix(".json.bak"))
    command = f'{PYTHON} "{(skill_dir / "scripts" / "audit_gate.py").as_posix()}"'
    groups = settings.setdefault("hooks", {}).setdefault("Stop", [])
    ours = [h for g in groups for h in g.get("hooks", []) if "audit_gate.py" in h.get("command", "")]
    if ours:
        for h in ours:
            h["command"] = command
        print("Stop hook already present, pointed it at this install")
    else:
        groups.append({"hooks": [{"type": "command", "command": command, "timeout": 30}]})
        print(f"Stop hook added to {CLAUDE_SETTINGS}")
    CLAUDE_SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    CLAUDE_SETTINGS.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", nargs="+", choices=sorted(TARGETS), default=[],
                    help="harness skill folder(s) to install into (default: claude)")
    ap.add_argument("--dir", action="append", default=[], help="install into DIR/code-audit instead")
    ap.add_argument("--hook", action="store_true",
                    help="add the Claude Code Stop hook that auto-audits modules you changed")
    args = ap.parse_args()
    targets = args.target or ([] if args.dir else ["claude"])
    if args.hook and "claude" not in targets:
        targets.append("claude")  # the hook is Claude Code only and runs the Claude copy
    for d in [TARGETS[t] for t in targets] + args.dir:
        install(d)
    if args.hook:
        add_hook(TARGETS["claude"] / NAME)
    print("done. Restart your agent session, then run /code-audit")


if __name__ == "__main__":
    main()
