"""Tests for shape.py. Run: python3 -m pytest -q test_shape.py (or python3 test_shape.py)."""
import tempfile
from pathlib import Path

import shape

FLAT = """
export function flat(items) {
    if (!items) return [];
    const out = items.map((item) => item * 2);
    return out;
}
"""

TREE = """
function tree(rows) {
    for (const row of rows) {
        if (row.ok) {
            try {
                rows.forEach((cell) => {
                    if (cell) {
                        console.log(`${cell} {not a brace}`);
                    }
                });
            } catch (e) {
                // a { in a comment
            }
        }
    }
}
"""

CLASSY = """
class Mixer {
    constructor() {
        this.config = { a: { b: 1 } };
    }

    async run(job) {
        if (job) {
            return 1;
        } else {
            return 2;
        }
    }
}
"""

PY = """
def outer(a):
    for x in a:
        if x:
            while x:
                with open(x) as fh:
                    pass
    return a

class Thing:
    def fetchData(self):
        return 1
"""


def fns_of(src):
    return {f["name"]: f for f in shape.brace_functions(shape.strip_brace_code(src))}


def test_flat_function_with_a_one_line_callback_has_no_nesting():
    fn = fns_of(FLAT)["flat"]
    assert fn["depth"] == 0  # a one-line arrow without braces is no block
    assert fn["end"] - fn["line"] == 4


def test_christmas_tree_counts_loops_ifs_try_and_callbacks_but_not_strings_or_comments():
    assert fns_of(TREE)["tree"]["depth"] == 5


def test_class_methods_are_functions_and_objects_do_not_nest():
    fns = fns_of(CLASSY)
    assert fns["constructor"]["depth"] == 0
    assert fns["run"]["depth"] == 1  # if and else sit side by side
    assert "Mixer" not in fns


def test_destructured_parameters_and_multi_line_heads_stay_one_function():
    src = "export async function plan(\n    { a, b },\n    log\n) {\n    if (a) {\n        return b;\n    }\n}\n"
    fns = fns_of(src)
    assert list(fns) == ["plan"]
    assert fns["plan"]["line"] == 1 and fns["plan"]["end"] == 8 and fns["plan"]["depth"] == 1


def test_python_depth_and_naming():
    fns = {f["name"]: f for f in shape.python_functions(PY)}
    assert fns["outer"]["depth"] == 4
    assert fns["outer"]["end"] == 8
    issues = shape.naming_issues("x.py", PY, ".py")
    assert [i["name"] for i in issues] == ["fetchData"]


def test_naming_flags_vague_short_and_snake_in_js():
    src = "const data = 1;\nconst q = 2;\nconst user_name = 3;\nconst i = 0;\nconst MAX_DB = 9;\nclass mixer {}\n"
    issues = shape.naming_issues("a.js", src, ".js")
    assert [(i["name"], i["why"]) for i in issues] == [
        ("data", "vague"), ("q", "too short"), ("user_name", "snake_case in JS"), ("mixer", "class not PascalCase")]


def test_duplication_finds_a_copied_block():
    block = [f"    total += values[{k}] * weights[{k}];" for k in range(8)]
    rows_a = [(n, shape.meaningful(l)) for n, l in enumerate(block, 1)]
    rows_b = [(n + 100, shape.meaningful(l)) for n, l in enumerate(block, 1)]
    dup, total, blocks = shape.duplication({"a.js": rows_a, "b.js": rows_b})
    assert dup == 16 and total == 16
    assert blocks[0] == {"a": "a.js:1-8", "b": "b.js:101", "lines": 8}


def test_dead_code_finds_unused_export_and_unimported_file():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "used.js").write_text("export function used() {}\nexport const lonely = 1;\n")
        (root / "main.js").write_text("import { used } from './used.js';\nused();\n")
        (root / "orphan.js").write_text("export function orphan() {}\n")
        files = sorted(root.iterdir())
        read = lambda p: p.read_text()
        unused, unimported = shape.dead_code(root, files, files, read)
        assert {u["name"] for u in unused} == {"lonely", "orphan"}
        assert unimported == ["orphan.js"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
