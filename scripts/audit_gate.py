#!/usr/bin/env python3
"""Stop-hook gate for the code-audit skill.

After Claude's final reply, look at the modules Claude edited this session and
ask Claude to audit one when it was never audited or has changed a lot since
its last audit. Claude decides whether the change is big; the audit itself runs
in a background subagent. Costs no tokens when nothing qualifies.

  audit_gate.py              Stop hook: reads hook JSON on stdin
  audit_gate.py --mark DIR   after an audit: snapshot DIR as the new baseline
  audit_gate.py --status     list known modules and their change since audit

State lives in ~/.cache/code-audit/gate/ (state.json + one snapshot per module).
"""
import difflib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scan import CODE_EXT, KIND_WORDS, SKIP_DIRS, is_test  # noqa: E402

GATE_DIR = Path(os.environ.get("CODE_AUDIT_GATE_DIR", Path.home() / ".cache" / "code-audit" / "gate"))
# Lines added+removed since the last audit before Claude is asked "is this big?".
THRESHOLD = int(os.environ.get("CODE_AUDIT_THRESHOLD", "150"))
# A never-audited module that Claude was asked about is asked again after this long.
INITIAL_RETRY_S = 24 * 3600
SKILL_DIR = Path(__file__).resolve().parent.parent.as_posix()
PYTHON = "python" if os.name == "nt" else "python3"
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
CONTAINERS = {w for _, words in KIND_WORDS for w in words} | {"modules", "packages", "apps", "features"}


def git_root(path):
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return Path(out) if out else None


def module_of(path, root):
    """The module a file belongs to: a role folder plus the folder under it
    (backend/src/services/audio-mixing), else the first three folders."""
    try:
        rel = Path(path).resolve().relative_to(root)
    except ValueError:
        return None
    dirs = rel.parts[:-1]
    if not dirs or rel.suffix not in CODE_EXT or is_test(rel) or set(dirs) & SKIP_DIRS or dirs[0].startswith("."):
        return None
    for i, d in enumerate(dirs):
        if d.lower() in CONTAINERS:
            return root.joinpath(*dirs[:i + 2])
    return root.joinpath(*dirs[:3])


def edited_files(transcript):
    """file_path of every Edit/Write tool call in this session's transcript."""
    files = set()
    try:
        with open(transcript, errors="replace") as fh:
            for line in fh:
                if '"tool_use"' not in line or "file_path" not in line:
                    continue
                try:
                    content = json.loads(line).get("message", {}).get("content", [])
                except ValueError:
                    continue
                for item in content if isinstance(content, list) else []:
                    if item.get("type") == "tool_use" and item.get("name") in EDIT_TOOLS:
                        fp = item.get("input", {}).get("file_path") or item.get("input", {}).get("notebook_path")
                        if fp:
                            files.add(fp)
    except OSError:
        pass
    return files


def code_files(module):
    out = subprocess.run(["rg", "--files", *sum((["-g", f"!**/{d}/**"] for d in SKIP_DIRS), []), str(module)],
                         capture_output=True, text=True).stdout
    return {str(Path(p).relative_to(module)) for p in out.splitlines() if Path(p).suffix in CODE_EXT}


def snap_dir(module):
    return GATE_DIR / "snapshots" / hashlib.sha1(str(module).encode()).hexdigest()[:12]


def read_lines(p):
    try:
        return p.read_text(errors="replace").splitlines()
    except OSError:
        return []


def change_since_snapshot(module):
    """(changed lines, new files) between the snapshot and the module now."""
    snap = snap_dir(module)
    now, then = code_files(module), {str(p.relative_to(snap)) for p in snap.rglob("*") if p.is_file()}
    changed, new = 0, 0
    for rel in now | then:
        a, b = snap / rel, module / rel
        if rel in now and rel in then and a.stat().st_size == b.stat().st_size and a.read_bytes() == b.read_bytes():
            continue
        new += rel in now and rel not in then
        for line in difflib.unified_diff(read_lines(a), read_lines(b), lineterm="", n=0):
            if line[:1] in "+-" and not line.startswith(("+++", "---")):
                changed += 1
    return changed, new


def load_state():
    try:
        return json.loads((GATE_DIR / "state.json").read_text())
    except (OSError, ValueError):
        return {}


def save_state(state):
    GATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = GATE_DIR / "state.json.tmp"
    tmp.write_text(json.dumps(state, indent=1))
    tmp.replace(GATE_DIR / "state.json")


def decide(entry, changed, now):
    """Why this module should be offered for an audit now, or None."""
    if not entry.get("audited_at"):
        asked = entry.get("asked_at", 0)
        return "never audited" if now - asked > INITIAL_RETRY_S else None
    # Ask once per THRESHOLD of growth, so a "not big" answer isn't repeated every turn.
    if changed >= THRESHOLD and changed >= entry.get("asked_size", 0) + THRESHOLD // 2:
        return f"{changed} lines changed since the audit on {time.strftime('%m-%d %H:%M', time.localtime(entry['audited_at']))}"
    return None


REASON = """code-audit gate (automatic, from the Stop hook): {lines}

Decide per module whether to audit it now. Initial audits ("never audited") always run. For the others,
audit only if the change is big: a new feature, a new route/export/file, or behaviour changed across
several files. Renames, comments, formatting and small fixes are not big.

For each module to audit, spawn ONE background Agent (subagent_type general-purpose, run_in_background
true) with this prompt, filled in:
"USE ONLY TOKEN-SAVING TOOLS per root CLAUDE.md - structural search before reading, scoped shell output.
Follow {skill}/SKILL.md for scope <module> with the security tools on, and callers
= sibling projects of the repo if any. Do the full judgement pass and write notes.json. Then run
{py} {skill}/scripts/audit_gate.py --mark <module> and return ONLY the rendered
overview block, verbatim."
Then reply with one line: "Auditing <module> in the background - the overview follows when it's done."
When the agent reports back, reply with its overview block verbatim and nothing above it.
If no module needs it, reply with one line: "No audit: <module> change is small." Do not repeat your
earlier answer."""


def hook():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return
    if data.get("stop_hook_active"):
        return  # we are already inside a continuation this hook caused
    root = git_root(data.get("cwd") or os.getcwd()) or Path(data.get("cwd") or os.getcwd())
    modules = {m for f in edited_files(data.get("transcript_path", "")) if (m := module_of(f, root)) and m.is_dir()}
    if not modules:
        return
    state, now, lines = load_state(), time.time(), []
    for m in sorted(modules):
        entry = state.setdefault(str(m), {})
        changed = change_since_snapshot(m)[0] if entry.get("audited_at") else 0
        why = decide(entry, changed, now)
        if why:
            entry.update(asked_at=now, asked_size=changed)
            lines.append(f"{m.relative_to(root) if m != root else m} ({why})")
    if lines:
        save_state(state)
        print(json.dumps({"decision": "block", "reason": REASON.format(lines="; ".join(lines), skill=SKILL_DIR, py=PYTHON)}))


def mark(module):
    module = Path(module).resolve()
    snap = snap_dir(module)
    shutil.rmtree(snap, ignore_errors=True)
    for rel in code_files(module):
        dest = snap / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(module / rel, dest)
    state = load_state()
    state[str(module)] = {"audited_at": time.time(), "asked_size": 0}
    save_state(state)
    print(f"baseline saved for {module}")


def status():
    for m, entry in sorted(load_state().items()):
        if entry.get("audited_at") and Path(m).is_dir():
            changed, new = change_since_snapshot(Path(m))
            print(f"{m}: audited {time.strftime('%Y-%m-%d %H:%M', time.localtime(entry['audited_at']))}, "
                  f"{changed} lines / {new} new files since")
        else:
            print(f"{m}: not audited yet")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--mark"] and len(sys.argv) == 3:
        mark(sys.argv[2])
    elif sys.argv[1:2] == ["--status"]:
        status()
    else:
        try:
            hook()
        except Exception:  # a hook must never break the session; the gate just skips this turn
            pass
