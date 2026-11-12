"""Tests for audit_gate.py. Run: python3 -m unittest test_audit_gate (from scripts/)."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TMP = tempfile.mkdtemp(prefix="gate-test-")
os.environ["CODE_AUDIT_GATE_DIR"] = str(Path(TMP) / "gate")
os.environ["CODE_AUDIT_THRESHOLD"] = "20"
sys.path.insert(0, str(Path(__file__).parent))
import audit_gate as g  # noqa: E402


def run_hook(payload):
    out = io.StringIO()
    with mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), mock.patch("sys.stdout", out):
        g.hook()
    return json.loads(out.getvalue()) if out.getvalue().strip() else None


class GateTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=TMP))
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.mod = self.root / "backend/src/services/mixer"
        (self.mod / "dsp").mkdir(parents=True)
        (self.mod / "mix.js").write_text("export function mix() {}\n" * 5)
        (self.root / "backend/test").mkdir(parents=True)
        self.transcript = self.root / "t.jsonl"
        g.save_state({})

    def edit(self, *paths):
        with open(self.transcript, "a") as fh:
            for p in paths:
                fh.write(json.dumps({"message": {"content": [
                    {"type": "tool_use", "name": "Edit", "input": {"file_path": str(p)}}]}}) + "\n")

    def payload(self, **kw):
        return {"cwd": str(self.root), "transcript_path": str(self.transcript), **kw}

    def test_module_of(self):
        r = self.root
        self.assertEqual(g.module_of(r / "backend/src/services/mixer/dsp/x.js", r), self.mod)
        self.assertEqual(g.module_of(r / "backend/src/routes/a.js", r), r / "backend/src/routes")
        self.assertEqual(g.module_of(r / "src/js/main/x.ts", r), r / "src/js/main")
        self.assertIsNone(g.module_of(r / "backend/test/a.test.js", r))   # tests define no module
        self.assertIsNone(g.module_of(r / "README.md", r))                 # not code
        self.assertIsNone(g.module_of(r / ".claude/x.js", r))              # dot folders
        self.assertIsNone(g.module_of("/elsewhere/x.js", r))               # outside repo

    def test_no_edits_no_output(self):
        self.assertIsNone(run_hook(self.payload()))

    def test_never_audited_asks_once(self):
        self.edit(self.mod / "mix.js")
        first = run_hook(self.payload())
        self.assertEqual(first["decision"], "block")
        self.assertIn("backend/src/services/mixer (never audited)", first["reason"])
        self.assertIsNone(run_hook(self.payload()))  # not asked again within 24 h

    def test_continuation_never_blocks(self):
        self.edit(self.mod / "mix.js")
        self.assertIsNone(run_hook(self.payload(stop_hook_active=True)))

    def test_small_change_after_mark_is_quiet(self):
        self.edit(self.mod / "mix.js")
        g.mark(self.mod)
        (self.mod / "mix.js").write_text("export function mix() {}\n" * 6)  # 1 line added
        self.assertIsNone(run_hook(self.payload()))

    def test_big_change_asks_then_waits_for_growth(self):
        self.edit(self.mod / "mix.js")
        g.mark(self.mod)
        (self.mod / "dsp/new.js").write_text("const a = 1;\n" * 25)  # 25 new lines >= 20
        out = run_hook(self.payload())
        self.assertIn("25 lines changed", out["reason"])
        self.assertIsNone(run_hook(self.payload()))  # same size: no repeat
        (self.mod / "dsp/new.js").write_text("const a = 1;\n" * 36)  # +11 >= threshold/2
        self.assertIn("36 lines changed", run_hook(self.payload())["reason"])

    def test_change_counts_edits_and_deletes(self):
        g.mark(self.mod)
        (self.mod / "mix.js").write_text("export function mix() {}\n" * 3 + "changed\n")
        (self.mod / "dsp/b.js").write_text("x\ny\n")
        self.assertEqual(g.change_since_snapshot(self.mod), (2 + 1 + 2, 1))
        (self.mod / "dsp/b.js").unlink()
        self.assertEqual(g.change_since_snapshot(self.mod), (3, 0))


if __name__ == "__main__":
    unittest.main()
