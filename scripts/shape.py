"""Code shape facts for the code-audit skill: the measurable half of "how is this written".

Six dimensions, each graded A-F from a share or a rate so a big and a small scope compare:
- size:        share of all lines (comments too) that sit in files over 600 lines.
- functions:   share of named functions over 50 lines.
- nesting:     share of functions whose control flow nests 4+ deep (the "christmas tree").
               Depth counts if/for/while/switch/try blocks and callbacks inside a function;
               object literals, classes and the function's own body do not count.
- naming:      vague, too-short or off-convention names per 1000 code lines.
- duplication: share of meaningful lines inside 6-line blocks that appear twice or more.
- dead code:   exports no other file names, and files nothing imports, per 100 files.

Brace languages (JS/TS/Vue script/Go/Java/Rust/PHP) are read with a small tokenizer that
blanks strings and comments; Python is read by indentation. It is a heuristic reader, not
a parser: good enough to rank files and functions, and every finding names file:line so the
agent can open it.
"""
import re
from collections import defaultdict
from pathlib import Path

BRACE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".go", ".java", ".rs", ".php"}
JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue"}

FILE_BIG = 600
FILE_WARN = 300
FILE_HUGE = 1000
FN_LONG = 50
FN_HUGE = 100
DEPTH_DEEP = 4
DUP_WINDOW = 6

CLASS_HEAD = re.compile(r"(^|[^\w$.])(class|interface|enum|struct|impl|namespace)\b")
FN_HEAD = re.compile(r"=>\s*$|(^|[^\w$.])function\b|(^|[^\w$.])func\b|(^|[^\w$.])fn\s+\w+|\)\s*(:\s*[\w<>\[\]|., ]+)?\s*$")
NAME_PATTERNS = [
    re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)"),
    re.compile(r"([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)"),
    re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"),
    re.compile(r"\bfn\s+([A-Za-z_]\w*)"),
    re.compile(r"^\s*(?:(?:public|private|protected|static|async|get|set|override|readonly)\s+)*\*?\s*([#A-Za-z_$][\w$]*)\s*\("),
]
NOT_A_NAME = {"if", "for", "while", "switch", "catch", "return", "function", "new", "typeof", "await"}

DECL_JS = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)")
CLASS_JS = re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")
SHORT_OK = {"i", "j", "k", "n", "x", "y", "z", "e", "_", "$", "id", "db", "fs", "io", "os", "ok",
            "el", "cb", "fn", "ms", "ip", "ui", "dt", "re", "db", "t0", "t1", "dx", "dy", "hz", "db"}
VAGUE = {"data", "info", "obj", "tmp", "temp", "foo", "bar", "baz", "val", "arr", "str", "ret",
         "retval", "stuff", "thing", "things", "misc", "dummy", "res2", "data2", "item2", "result2",
         "helper", "helpers", "handle", "doit", "doStuff", "process2", "x1", "x2", "flag", "flag2"}
NUMBERED = re.compile(r"^(data|item|value|result|list|arr|obj|file|path|tmp|temp|res|x|str|val|out|buf)\d+$")
SNAKE = re.compile(r"^_*[a-z][a-z0-9]*(_[a-z0-9]+)+$")
CAMEL = re.compile(r"^_*[a-z][a-z0-9]*([A-Z][a-z0-9]*)+$")
PASCAL = re.compile(r"^[A-Z][A-Za-z0-9]*$")
UPPER = re.compile(r"^[A-Z][A-Z0-9_]*$")


def grade(value, cuts):
    """Letter for a value where lower is better; cuts are the A/B/C/D upper bounds."""
    for letter, cut in zip("ABCD", cuts):
        if value < cut:
            return letter
    return "F"


# ---------------------------------------------------------------- reading

def strip_brace_code(text):
    """Blank strings and comments, keep newlines and every other character in place.
    Template literals keep their ${...} code, which may hold braces and strings itself."""
    out = []
    modes = ["code"]  # code | tmpl ; a 'code' pushed from a template counts its braces
    depth = [0]
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        mode = modes[-1]
        if mode == "tmpl":
            if c == "\\":
                out.append("  " if i + 1 < n and text[i + 1] != "\n" else " ")
                i += 2
                continue
            if c == "`":
                modes.pop()
                out.append("`")
            elif c == "$" and i + 1 < n and text[i + 1] == "{":
                modes.append("code")
                depth.append(0)
                out.append("${")
                i += 2
                continue
            else:
                out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif c in "'\"":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(c + " " * (min(j, n) - i - 1) + (c if j < n and text[j] == c else ""))
            i = j + 1 if j < n and text[j] == c else j
        elif c == "`":
            modes.append("tmpl")
            out.append("`")
            i += 1
        else:
            if len(modes) > 1:
                if c == "{":
                    depth[-1] += 1
                elif c == "}":
                    if depth[-1] == 0:
                        modes.pop()
                        depth.pop()
                        out.append("}")
                        i += 1
                        continue
                    depth[-1] -= 1
            out.append(c)
            i += 1
    return "".join(out)


def vue_script(text):
    """Only the <script> part of a .vue file, other lines blanked so line numbers hold."""
    lines = text.split("\n")
    keep, inside = [], False
    for line in lines:
        if re.search(r"<script\b", line):
            inside = True
            keep.append("")
            continue
        if re.search(r"</script>", line):
            inside = False
            keep.append("")
            continue
        keep.append(line if inside else "")
    return "\n".join(keep)


def fn_name(head):
    for pattern in NAME_PATTERNS:
        m = pattern.search(head)
        if m and m.group(1) not in NOT_A_NAME:
            return m.group(1)
    return None


CONTROL_START = re.compile(r"(^|[\s)])(else\s+)?(if|for|while|switch|catch|select)\b")
CONTROL_END = re.compile(r"(^|[^\w$.])(else|try|finally|do)$")


# Inside an open argument list only a finished callback head opens a function body.
CALLBACK_HEAD = re.compile(r"=>$|(^|[^\w$.])function\b\s*\*?\s*[\w$]*\s*\([^()]*\)$")


def block_kind(h):
    """What a "{" opens, from the code since the last { } or ;: fn, ctrl, class or other."""
    if h.endswith("=>") or re.search(r"(^|[^\w$.])function\b", h):
        return "fn"
    if CONTROL_START.search(h) or CONTROL_END.search(h):
        return "ctrl"
    if CLASS_HEAD.search(h):
        return "class"
    if FN_HEAD.search(h):
        return "fn"
    return "other"


def brace_functions(clean):
    """Walk braces and return the functions as {name, line, end, depth}; depth = the deepest
    control/callback nesting inside the function. A brace opened inside parentheses that is
    not a callback body (a destructured parameter, an object argument) is part of the
    statement head, so `function f({ a }) {` still reads as one function named f."""
    stack = []  # frames: [kind, fn_index, parens outside, inline]
    fns = []
    head, head_line, parens = "", 1, 0
    line_no = 1
    for ch in clean:
        if ch == "\n":
            line_no += 1
            head += " "
            continue
        if ch == "(":
            parens += 1
        elif ch == ")":
            parens = max(0, parens - 1)
        if ch == "{":
            h = head.strip()
            inline = parens > 0 and not CALLBACK_HEAD.search(h)
            kind = "other" if inline else block_kind(h)
            idx = None
            if kind == "fn":
                outer_fn = any(frame[0] in ("fn", "cb") for frame in stack)
                name = fn_name(h)
                if outer_fn and not name:
                    kind = "cb"
                else:
                    fns.append({"name": name or "(anonymous)", "line": head_line, "end": line_no, "depth": 0})
                    idx = len(fns) - 1
            stack.append([kind, idx, parens, inline])
            parens = 0
            owner = next((i for k, i, _, _ in reversed(stack) if k == "fn" and i is not None), None)
            if owner is not None and kind in ("ctrl", "cb"):
                level = 0
                for k, i, _, _ in reversed(stack):
                    if k == "fn" and i == owner:
                        break
                    if k in ("ctrl", "cb", "fn"):
                        level += 1
                fns[owner]["depth"] = max(fns[owner]["depth"], level)
            if not inline:
                head = ""
        elif ch == "}":
            inline = False
            if stack:
                kind, idx, parens, inline = stack.pop()
                if idx is not None:
                    fns[idx]["end"] = line_no
            if not inline:
                head = ""
        elif ch == ";" and parens == 0:
            head = ""
        else:
            if not head.strip() and not ch.isspace():
                head_line = line_no
            head += ch
    return fns


def python_functions(text):
    """Indentation walk for Python: functions with their span and control depth."""
    stack = []  # (indent, kind, fn_index)
    fns = []
    last_code_line = 0
    for no, raw in enumerate(text.split("\n"), 1):
        line = re.sub(r"#.*$", "", re.sub(r"(\"\"\"|''').*?\1|\"[^\"]*\"|'[^']*'", "\"\"", raw))
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        while stack and indent <= stack[-1][0]:
            _, kind, idx = stack.pop()
            if idx is not None:
                fns[idx]["end"] = last_code_line
        stripped = line.strip()
        m = re.match(r"(async\s+)?def\s+(\w+)", stripped)
        if m:
            fns.append({"name": m.group(2), "line": no, "end": no, "depth": 0})
            stack.append((indent, "fn", len(fns) - 1))
        elif re.match(r"class\s+\w+", stripped):
            stack.append((indent, "class", None))
        elif re.match(r"(if|elif|else|for|while|with|try|except|finally|match|case)\b.*:$", stripped):
            stack.append((indent, "ctrl", None))
            owner = next((pos for pos, (_, k, _i) in reversed(list(enumerate(stack))) if k == "fn"), None)
            if owner is not None:
                level = sum(1 for _, k, _i in stack[owner + 1:] if k == "ctrl")
                fn_idx = stack[owner][2]
                fns[fn_idx]["depth"] = max(fns[fn_idx]["depth"], level)
        last_code_line = no
    for _, _, idx in stack:
        if idx is not None:
            fns[idx]["end"] = last_code_line
    return fns


# ---------------------------------------------------------------- naming

def naming_issues(rel, clean, ext):
    out = []
    lines = clean.split("\n")
    for no, line in enumerate(lines, 1):
        names = []
        if ext in JS_EXT:
            names += [(m.group(1), "var") for m in DECL_JS.finditer(line)]
            names += [(m.group(1), "class") for m in CLASS_JS.finditer(line)]
        elif ext == ".py":
            names += [(m.group(1), "fn") for m in re.finditer(r"^\s*(?:async\s+)?def\s+(\w+)", line)]
            names += [(m.group(1), "class") for m in re.finditer(r"^\s*class\s+(\w+)", line)]
            names += [(m.group(1), "var") for m in re.finditer(r"^\s*([a-zA-Z_]\w*)\s*=[^=]", line)]
        for name, role in names:
            why = name_problem(name, role, ext)
            if why:
                out.append({"path": rel, "line": no, "name": name, "why": why})
    return out


def name_problem(name, role, ext):
    bare = name.lstrip("_#$")
    if not bare:
        return None
    if role == "class":
        return None if PASCAL.match(bare) else "class not PascalCase"
    if len(bare) <= 2 and bare not in SHORT_OK and name not in SHORT_OK:
        return "too short"
    if bare in VAGUE or NUMBERED.match(bare):
        return "vague"
    if len(bare) > 40:
        return "too long"
    if ext in JS_EXT and SNAKE.match(bare):
        return "snake_case in JS"
    if ext == ".py" and role in ("fn", "var") and CAMEL.match(bare):
        return "camelCase in Python"
    return None


def file_name_style(stem):
    if "-" in stem:
        return "kebab"
    if "_" in stem:
        return "snake"
    if PASCAL.match(stem):
        return "Pascal"
    if CAMEL.match(stem):
        return "camel"
    return "plain"


# ---------------------------------------------------------------- duplication

def meaningful(line):
    s = re.sub(r"\s+", " ", line.strip())
    if len(s) < 8 or re.fullmatch(r"[\s{}()\[\];,]*", s):
        return None
    if re.match(r"(import |export \{|} from |from \S+ import|#include|\*)", s):
        return None
    return s


def duplication(per_file):
    """per_file: {rel: [(line_no, normalized)]}. Returns (dup line count, total, blocks)."""
    seen = defaultdict(list)
    for rel, rows in per_file.items():
        for i in range(len(rows) - DUP_WINDOW + 1):
            key = hash("\n".join(r[1] for r in rows[i:i + DUP_WINDOW]))
            seen[key].append((rel, i))
    dup = defaultdict(set)
    diag = defaultdict(list)
    for occ in seen.values():
        if len(occ) < 2:
            continue
        for rel, i in occ:
            dup[rel].update(range(i, i + DUP_WINDOW))
        (ra, ia), (rb, ib) = occ[0], occ[1]
        if ra == rb and abs(ia - ib) < DUP_WINDOW:
            continue
        diag[(ra, rb, ib - ia)].append(ia)
    blocks = []
    for (ra, rb, off), starts in diag.items():
        starts.sort()
        run_start = prev = starts[0]
        for s in starts[1:] + [None]:
            if s is not None and s == prev + 1:
                prev = s
                continue
            rows_a, rows_b = per_file[ra], per_file[rb]
            end = prev + DUP_WINDOW - 1
            blocks.append({
                "a": f"{ra}:{rows_a[run_start][0]}-{rows_a[end][0]}",
                "b": f"{rb}:{rows_b[run_start + off][0]}",
                "lines": end - run_start + 1,
            })
            if s is not None:
                run_start = prev = s
    total = sum(len(r) for r in per_file.values())
    return sum(len(v) for v in dup.values()), total, sorted(blocks, key=lambda b: -b["lines"])


# ---------------------------------------------------------------- dead code

EXPORT_NAMED = re.compile(r"^\s*export\s+(?:async\s+)?(?:function\*?|const|let|var|class)\s+([A-Za-z_$][\w$]*)")
EXPORT_LIST = re.compile(r"^\s*export\s*\{([^}]*)\}\s*;?\s*$")
IMPORT_SPEC = re.compile(r"""(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|^\s*import\s+|new\s+URL\s*\(\s*)['"]([^'"]+)['"]""", re.M)
PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.M)


def dead_code(root, scope_files, repo_files, read):
    """Exports no other repo file names, and scope files no import or path string reaches."""
    exports = []
    for f in scope_files:
        if f.suffix not in JS_EXT:
            continue
        for no, line in enumerate(read(f).split("\n"), 1):
            m = EXPORT_NAMED.match(line)
            if m:
                exports.append((f, no, m.group(1)))
            m = EXPORT_LIST.match(line)
            if m:
                for part in m.group(1).split(","):
                    name = part.split(" as ")[-1].strip()
                    if re.fullmatch(r"[A-Za-z_$][\w$]*", name or "") and name != "default":
                        exports.append((f, no, name))
    wanted = {name for _, _, name in exports}
    users = defaultdict(set)
    referenced = set()
    word = re.compile(r"[A-Za-z_$][\w$]*")
    for f in repo_files:
        text = read(f)
        if not text:
            continue
        for w in set(word.findall(text)) & wanted:
            users[w].add(f)
        for spec in IMPORT_SPEC.findall(text):
            base = (f.parent / spec).resolve() if spec.startswith(".") else None
            referenced.add(Path(spec).name)
            referenced.add(Path(spec).stem)
            if base is not None:
                referenced.add(str(base))
                referenced.add(str(base.with_suffix("")))
        for a, b in PY_IMPORT.findall(text):
            for mod in (a or b).split("."):
                referenced.add(mod)
        if f.name == "package.json":
            for m in re.findall(r"[\w./-]+\.(?:[cm]?js|ts)", text):
                referenced.add(Path(m).name)
    unused_exports = [{"path": str(f.relative_to(root)), "line": no, "name": name}
                      for f, no, name in exports if not (users[name] - {f})]
    entry_names = {"index", "main", "server", "app", "cli", "__init__", "__main__", "setup", "conftest"}
    unimported = []
    for f in scope_files:
        if f.suffix not in BRACE_EXT | {".py"} or f.stem in entry_names:
            continue
        keys = {f.name, f.stem, str(f), str(f.with_suffix(""))}
        if not keys & referenced:
            unimported.append(str(f.relative_to(root)))
    return unused_exports, unimported


# ---------------------------------------------------------------- facts

def shape_facts(root, scope, files, repo_files, sizes, read, is_test):
    code_files = [f for f in files if (f.suffix in BRACE_EXT or f.suffix == ".py")
                  and not is_test(f.relative_to(scope))]
    fns, naming, dup_rows, sizes_out = [], [], {}, []
    style_by_dir = defaultdict(lambda: defaultdict(list))
    for f in code_files:
        rel = str(f.relative_to(root))
        text = read(f)
        # Size counts every line: a reader wades through comments too. "code" is scc's count.
        code = sizes.get(str(f), (len(text.splitlines()), 0, ""))[0]
        sizes_out.append({"path": rel, "lines": len(text.splitlines()), "code": code})
        if f.suffix == ".py":
            file_fns = python_functions(text)
            clean = re.sub(r"#.*", "", text)
        else:
            src = vue_script(text) if f.suffix == ".vue" else text
            clean = strip_brace_code(src)
            file_fns = brace_functions(clean)
        for fn in file_fns:
            fns.append({"path": rel, "line": fn["line"], "name": fn["name"],
                        "lines": fn["end"] - fn["line"] + 1, "depth": fn["depth"]})
        naming += naming_issues(rel, clean, f.suffix)
        dup_rows[rel] = [(no, s) for no, line in enumerate(clean.split("\n"), 1) if (s := meaningful(line))]
        style_by_dir[str(f.parent.relative_to(root))][file_name_style(f.stem)].append(f.name)

    total_code = sum(s["code"] for s in sizes_out) or 1
    total_lines = sum(s["lines"] for s in sizes_out) or 1
    big_lines = sum(s["lines"] for s in sizes_out if s["lines"] > FILE_BIG)
    named = [fn for fn in fns if fn["name"] != "(anonymous)"] or fns
    n_fns = len(named) or 1
    long_fns = [fn for fn in named if fn["lines"] > FN_LONG]
    deep_fns = [fn for fn in fns if fn["depth"] >= DEPTH_DEEP]
    dup_lines, dup_total, blocks = duplication(dup_rows)
    dup_pct = 100 * dup_lines / max(dup_total, 1)
    unused_exports, unimported = dead_code(root, code_files, repo_files, read)
    # Pascal sits fine next to another style (components, classes); two others do not.
    mixed_dirs = [{"dir": d, "styles": {k: len(v) for k, v in styles.items()}}
                  for d, styles in style_by_dir.items()
                  if len(set(styles) - {"plain", "Pascal"}) > 1]
    naming_rate = 1000 * len(naming) / total_code
    dead_rate = 100 * (len(unused_exports) + len(unimported)) / max(len(code_files), 1)

    grades = {
        "size": grade(100 * big_lines / total_lines, (5, 15, 30, 50)),
        "functions": grade(100 * len(long_fns) / n_fns, (3, 8, 15, 25)),
        "nesting": grade(100 * len(deep_fns) / max(len(fns), 1), (3, 8, 15, 25)),
        "naming": grade(naming_rate, (2, 5, 10, 20)),
        "duplication": grade(dup_pct, (2, 5, 10, 20)),
        "dead": grade(dead_rate, (2, 5, 10, 20)),
    }
    points = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
    mean = sum(points[g] for g in grades.values()) / len(grades)
    overall = "ABCDF"[min(4, round(4 - mean))]
    # One huge file or a 6-deep function is a bottleneck whatever the averages say.
    if any(s["lines"] > FILE_HUGE for s in sizes_out) or any(fn["depth"] >= 6 for fn in fns):
        overall = max(overall, "C")
    by_why = defaultdict(int)
    for x in naming:
        by_why[x["why"]] += 1
    return {
        "thresholds": {"file_warn": FILE_WARN, "file_big": FILE_BIG, "file_huge": FILE_HUGE,
                       "fn_long": FN_LONG, "fn_huge": FN_HUGE, "depth_deep": DEPTH_DEEP,
                       "dup_window": DUP_WINDOW},
        "grades": grades,
        "grade_hint": overall,
        "files": {
            "count": len(sizes_out),
            "over_warn": sum(1 for s in sizes_out if s["lines"] > FILE_WARN),
            "over_big": sum(1 for s in sizes_out if s["lines"] > FILE_BIG),
            "over_huge": sum(1 for s in sizes_out if s["lines"] > FILE_HUGE),
            "big_share_pct": round(100 * big_lines / total_lines, 1),
            "largest": sorted(sizes_out, key=lambda s: -s["lines"])[:20],
        },
        "functions": {
            "count": len(named),
            "over_long": len(long_fns),
            "over_huge": sum(1 for fn in named if fn["lines"] > FN_HUGE),
            "longest": sorted(named, key=lambda fn: -fn["lines"])[:25],
        },
        "nesting": {
            "deep": len(deep_fns),
            "histogram": {str(d): sum(1 for fn in fns if fn["depth"] == d) for d in range(0, 9)},
            "deepest": sorted(fns, key=lambda fn: (-fn["depth"], -fn["lines"]))[:25],
        },
        "naming": {
            "count": len(naming),
            "per_1000_lines": round(naming_rate, 1),
            "by_why": dict(sorted(by_why.items(), key=lambda kv: -kv[1])),
            "issues": naming[:300],
            "mixed_file_name_dirs": mixed_dirs[:20],
        },
        "duplication": {"dup_lines": dup_lines, "lines": dup_total, "pct": round(dup_pct, 1),
                        "blocks": blocks[:25]},
        "dead": {"unused_exports": unused_exports[:100], "unused_export_count": len(unused_exports),
                 "unimported_files": unimported[:50]},
    }
