#!/usr/bin/env python3
"""Deterministic facts for the code-audit skill.

Collects the countable parts of an audit (module/test matching, file sizes,
entry points, sinks, security pattern hits, external scanner results) into one
facts.json so every run counts the same way. Judgement (good/bad examples,
call-chain tracing, verifying findings) is left to the agent.

Usage: scan.py <scope> [--callers DIR ...] [--history] [--no-tools]
Prints the path of the written facts.json.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from shape import shape_facts

CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".py", ".go",
            ".rs", ".java", ".rb", ".php", ".sh", ".jsx"}
# Languages where "is there a test for this module" is a meaningful question.
TESTABLE_EXT = CODE_EXT - {".sh"}
SKIP_DIRS = {"node_modules", "dist", "build", ".git", "coverage", "vendor",
             "__pycache__", ".venv", "venv", ".next", ".nuxt", "out"}
CONFIG_NAME = re.compile(r"(^|\.)(config|conf|setup)\.[a-z]+$|^(vite|jest|webpack|babel|"
                         r"eslint|prettier|tailwind|postcss|vitest|playwright)\b", re.I)
TEST_NAME = re.compile(r"\.(test|spec)\.[cm]?[jt]sx?$|^test_.*\.py$|_test\.(py|go)$|Test\.java$")
TEST_DIRS = {"test", "tests", "__tests__", "spec", "e2e"}

KIND_WORDS = [
    ("routes/api", {"routes", "route", "controllers", "controller", "api", "endpoints", "handlers"}),
    ("middleware", {"middleware", "middlewares"}),
    ("services", {"services", "service"}),
    ("models/db", {"models", "model", "schemas", "schema", "db", "migrations", "repositories"}),
    ("workers/queues", {"workers", "worker", "jobs", "queue", "queues"}),
    ("components", {"components", "component"}),
    ("views/pages", {"views", "pages", "screens", "panels"}),
    ("state", {"store", "stores", "composables", "hooks", "state"}),
    ("utils", {"utils", "util", "helpers", "lib", "common", "shared"}),
    ("scripts/cli", {"scripts", "bin", "cli", "tools"}),
    ("types", {"types", "typings", "interfaces"}),
]

ROUTE_RE = re.compile(r"\b(?:app|router|server|api|\w*[Rr]outer|\w*[Rr]outes)\.(get|post|put|patch|delete|all)"
                      r"\(\s*['\"`]([^'\"`]+)")
PY_ROUTE_RE = re.compile(r"@\w+\.(route|get|post|put|patch|delete)\(\s*['\"]([^'\"]+)")
MOUNT_RE = re.compile(r"\.use\(\s*['\"`](/[^'\"`]*)['\"`]\s*,\s*(.+)\)")
IMPORT_BIND_RE = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]|"
                            r"import\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]")
CALL_RE = re.compile(r"\b(?:axios|api|http|client|\$http|request|instance|backend)\s*\.\s*"
                     r"(get|post|put|patch|delete)\s*(?:<[^>]*>)?\(\s*['\"`]([^'\"`]+)|"
                     r"\b\w*[Ff]etch\w*\(\s*['\"`]([^'\"`]+)|"
                     # URL built from a base, e.g. `${BACKEND_URL}/media/x` (method unknown)
                     r"`\$\{\s*[\w.]*(?:url|base|api|host|origin|endpoint)[\w.]*\s*\}(/[^`'\"\s]*)", re.I)
SPEC_RE = re.compile(r"(?:require\(|from\s+|import\(|import\s+)['\"]([^'\"]+)['\"]")
PY_IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.M)
CASE_RE = re.compile(r"^\s*(?:it|test)(?:\.only|\.each\b[^(]*\([^)]*\))?\s*\(|^\s*def test_\w+|"
                     r"^\s*func Test\w+", re.M)
SKIP_RE = re.compile(r"\b(?:it|test|describe)\.(?:skip|todo)\b|\bx(?:it|describe|test)\(|"
                     r"@pytest\.mark\.skip|\bt\.Skip\(")
AUTH_WORD = re.compile(r"auth|protect|verifyToken|jwt|requireLogin|ensureLogged|apiKey|"
                       r"isAdmin|requireRole|passport", re.I)

SINK_PATTERNS = {
    # (?:^|[^.\w]) keeps regex.exec( and obj.spawn( methods out; execa is the common wrapper.
    "process": r"(?:^|[^.\w])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\(|"
               r"\bexeca(?:Sync|Command)?\(|\bchild_process\.\w+\(|subprocess\.\w+\(|os\.system\(",
    "fs-write": r"\bfs(?:\.promises|Promises)?\.(?:writeFile\w*|createWriteStream|unlink\w*|rm\w*|rename\w*|appendFile\w*|copyFile\w*)\(",
    # find/findOne only on a Model (capitalised) or a collection, so Array.find is not a DB call.
    "db": r"\b(?:[A-Z]\w*|\w*[Cc]ollection\w*|db\.\w+)\.(?:find|findOne|findById\w*)\(|"
          r"\.(?:insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|"
          r"aggregate|bulkWrite|findOneAndUpdate|countDocuments)\(",
    "http-out": r"\b(?:axios|got|fetch|request)\s*(?:\.\w+)?\(\s*['\"`]https?://|\bfetch\(\s*`https?://",
}

# (id, severity, regex, what it means). Hits are candidates: the agent verifies them.
SEC_PATTERNS = [
    ("cmd-injection", "high", r"\b(?:exec|execSync)\(\s*(?:`[^`]*\$\{|[^'\"`\s,)]+\s*\+|['\"][^'\"]*['\"]\s*\+)",
     "shell command built from a string; injection if any part comes from input"),
    ("cmd-injection", "high", r"\bspawn\w*\([^)]*shell\s*:\s*true", "spawn with shell:true"),
    ("cmd-injection", "high", r"subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(", "python shell call"),
    ("code-eval", "high", r"\beval\(|\bnew Function\(", "dynamic code execution"),
    ("path-traversal", "med", r"(?:path\.(?:join|resolve)|sendFile|createReadStream|readFile\w*|res\.download|"
     r"unlink\w*)\([^)]*req\.(?:params|query|body)", "file path from request input"),
    ("open-redirect", "low", r"res\.redirect\([^)]*req\.(?:query|body|params)", "redirect target from request"),
    ("nosql-injection", "med", r"\$where|\.find(?:One)?\(\s*req\.(?:body|query)", "query object from request"),
    ("regex-dos", "low", r"new RegExp\([^)]*req\.", "regex built from request input"),
    ("xss", "med", r"v-html=|dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=", "raw HTML injection"),
    ("tls-off", "high", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|verify\s*=\s*False",
     "TLS certificate check disabled"),
    ("cors-any", "med", r"origin\s*:\s*['\"]\*['\"]|Allow-Origin['\"]\s*,\s*['\"]\*|\bcors\(\s*\)", "CORS open to any origin"),
    ("hardcoded-secret", "high", r"(?i)(?:api[_-]?key|secret|passw(?:or)?d|token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-/+]{16,}['\"]",
     "literal credential in code"),
    ("hardcoded-secret", "high", r"AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|\bsk-[A-Za-z0-9]{20,}|"
     r"\bxox[bap]-[A-Za-z0-9-]{10,}|\bghp_[A-Za-z0-9]{30,}", "known secret format"),
    ("unsafe-deserialize", "med", r"pickle\.loads?\(|yaml\.load\((?![^)]*Loader)", "unsafe deserialization"),
    ("weak-hash", "low", r"createHash\(\s*['\"](?:md5|sha1)['\"]|hashlib\.(?:md5|sha1)\(", "md5/sha1 (fine for cache keys, not for secrets)"),
]
SECRET_FILE_RE = re.compile(r"\.(pem|key|p12|pfx|jks)$|(^|/)\.env(\.[\w-]+)?$|service[-_]?account.*\.json$|"
                            r"credentials.*\.json$|google_auth\.json$|id_(rsa|ed25519)$", re.I)


SECRET_RULE = re.compile(r"secret|key|token|passw|credential|auth", re.I)
SECRET_VALUE = re.compile(r"(['\"`])[^'\"`\s]{8,}\1|\b(?:AKIA|sk-|xox[bap]-|ghp_)[A-Za-z0-9_-]{8,}")


def redact(rule, text):
    """Never store a secret's value: facts.json is printed on screen and cached."""
    if SECRET_RULE.search(rule) or "PRIVATE KEY" in text:
        return SECRET_VALUE.sub(lambda m: (m[1] or "") + "<redacted>" + (m[1] or ""), text)
    return text


def run(cmd, cwd=None, timeout=600):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not installed"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def git_root(path):
    code, out, _ = run(["git", "-C", str(path), "rev-parse", "--show-toplevel"])
    return Path(out.strip()) if code == 0 else None


def list_files(scope):
    """Files rg would search: respects .gitignore, skips build/vendor dirs."""
    globs = sum((["-g", f"!**/{d}/**"] for d in SKIP_DIRS), [])
    code, out, _ = run(["rg", "--files", *globs, "-g", "!*.min.js", str(scope)])
    if code not in (0, 1):
        sys.exit("rg --files failed")
    return sorted(Path(line).resolve() for line in out.splitlines() if line)


def is_test(rel):
    parts = set(Path(rel).parts[:-1])
    return bool(TEST_NAME.search(Path(rel).name)) or bool(parts & TEST_DIRS)


def kind_of(rel):
    """Role folder (routes, services, ...) plus the folder under it, so a big
    services/ tree shows as services/audio-mixing, services/research, ..."""
    parts = [p.lower() for p in Path(rel).parts[:-1]]
    for kind, words in KIND_WORDS:
        for i, p in enumerate(parts):
            if p in words:
                return f"{kind}/{parts[i + 1]}" if i + 1 < len(parts) else kind
    return (parts[-1] if parts else "(root)")


def read(path):
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def scc_sizes(scope):
    """{abs path: (code lines, complexity)} from scc; falls back to line counts."""
    code, out, _ = run(["scc", "--by-file", "-f", "json", "--no-cocomo", str(scope)])
    sizes = {}
    if code == 0:
        for lang in json.loads(out or "[]"):
            for f in lang.get("Files", []):
                sizes[str(Path(f["Location"]).resolve())] = (f.get("Code", 0), f.get("Complexity", 0), lang["Name"])
    return sizes


def resolve_spec(spec, test_path, src_by_suffix, src_set):
    """Map an import specifier in a test file to a source file, or None."""
    exts = ["", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx", ".vue", "/index.js", "/index.ts"]
    if spec.startswith("."):
        base = (test_path.parent / spec).resolve()
        for e in exts:
            cand = Path(str(base) + e)
            if str(cand) in src_set:
                return str(cand)
        return None
    if "/" not in spec:
        return None  # bare package import
    tail = re.sub(r"^(@|~|#)/", "", spec)
    for e in exts:
        hit = src_by_suffix.get(tail + e)
        if hit:
            return hit
    return None


def test_facts(root, scope, files, repo_files, sizes):
    """Modules come from the scope; tests come from the whole repo, because a
    scoped folder is usually tested from a test/ dir elsewhere."""
    src = [f for f in files if f.suffix in TESTABLE_EXT and not is_test(f.relative_to(scope))
           and not CONFIG_NAME.search(f.name) and not f.name.endswith(".d.ts")]
    tests = [f for f in repo_files if f.suffix in TESTABLE_EXT and is_test(f.relative_to(root))]
    src_set = {str(f) for f in src}
    src_by_suffix = {}
    for f in src:
        parts = f.parts
        for i in range(1, min(len(parts), 6)):
            src_by_suffix.setdefault("/".join(parts[-i:]).rsplit(".", 1)[0], str(f))
            src_by_suffix.setdefault("/".join(parts[-i:]), str(f))
    stem_index = defaultdict(list)
    for f in src:
        stem_index[f.name.split(".")[0].lower()].append(str(f))

    tested = defaultdict(set)  # src path -> test files
    for t in tests:
        text = read(t)
        for spec in SPEC_RE.findall(text):
            hit = resolve_spec(spec, t, src_by_suffix, src_set)
            if hit:
                tested[hit].add(str(t))
        if t.suffix == ".py":
            for a, b in PY_IMPORT_RE.findall(text):
                mod = (a or b).replace(".", "/")
                hit = src_by_suffix.get(mod) or src_by_suffix.get(mod + "/__init__")
                if hit:
                    tested[hit].add(str(t))
        # foo.test.js / foo.spec.ts / test_foo.py / foo_test.go / FooTest.java -> foo
        stem = re.sub(r"^test_|_test$|Test$", "", t.name.split(".")[0]).lower()
        for hit in stem_index.get(stem, []):
            tested[hit].add(str(t))

    def group(p):
        rel = Path(p).relative_to(scope).parts[:-1]
        return rel

    depth = 1
    while depth < 4:
        groups = {"/".join(group(f)[:depth]) or "." for f in src}
        if len(groups) >= 4 or all(len(group(f)) <= depth for f in src):
            break
        depth += 1
    by_dir = defaultdict(lambda: {"modules": 0, "tested": 0, "code": 0})
    for f in src:
        key = "/".join(group(f)[:depth]) or "."
        d = by_dir[key]
        d["modules"] += 1
        d["tested"] += 1 if str(f) in tested else 0
        d["code"] += sizes.get(str(f), (0,))[0]
    # Only tests that touch the scope count toward cases/skipped.
    relevant = {t for ts in tested.values() for t in ts} if scope != root else {str(t) for t in tests}
    cases = sum(len(CASE_RE.findall(read(Path(t)))) for t in relevant)
    skipped = sum(len(SKIP_RE.findall(read(Path(t)))) for t in relevant)
    untested = sorted(((sizes.get(str(f), (0,))[0], str(f.relative_to(root))) for f in src if str(f) not in tested),
                      reverse=True)
    return {
        "modules_total": len(src),
        "modules_tested": sum(1 for f in src if str(f) in tested),
        "test_files": len(relevant),
        "cases": cases,
        "skipped": skipped,
        "group_depth": depth,
        "by_dir": sorted(({"dir": k, **v} for k, v in by_dir.items()), key=lambda d: -d["code"]),
        "untested_largest": [{"path": p, "code": c} for c, p in untested[:40]],
        "coverage_report": coverage_report(scope, root),
    }


def coverage_report(scope, root):
    """Read an existing coverage report if one is lying around; never runs tests."""
    for base in {scope, root, scope.parent}:
        for name in ("coverage/coverage-summary.json", "coverage/lcov.info", "coverage.json"):
            p = base / name
            if not p.exists():
                continue
            age = (dt.datetime.now() - dt.datetime.fromtimestamp(p.stat().st_mtime)).days
            try:
                if name.endswith("summary.json"):
                    pct = json.loads(read(p))["total"]["lines"]["pct"]
                elif name.endswith("lcov.info"):
                    text = read(p)
                    lf = sum(int(x) for x in re.findall(r"^LF:(\d+)", text, re.M))
                    lh = sum(int(x) for x in re.findall(r"^LH:(\d+)", text, re.M))
                    pct = round(100 * lh / lf, 1) if lf else 0
                else:
                    pct = round(json.loads(read(p))["totals"]["percent_covered"], 1)
                return {"lines_pct": pct, "source": str(p.relative_to(root)), "age_days": age}
            except (KeyError, ValueError, ZeroDivisionError):
                continue
    return None


def structure_facts(root, scope, files, sizes):
    kinds = defaultdict(list)
    for f in files:
        if f.suffix not in CODE_EXT:
            continue
        rel = f.relative_to(scope)
        kind = "tests" if is_test(rel) else kind_of(rel)
        code, cx, _ = sizes.get(str(f), (len(read(f).splitlines()), 0, ""))
        kinds[kind].append({"path": str(f.relative_to(root)), "code": code, "complexity": cx})
    out = []
    for kind, items in kinds.items():
        sized = [i for i in items if i["code"] >= 40]
        by_density = sorted(sized, key=lambda i: i["complexity"] / max(i["code"], 1))
        out.append({
            "kind": kind, "files": len(items), "code": sum(i["code"] for i in items),
            # Disjoint lists: calm = lowest branch density, knotty = most branches of the rest.
            "calm_candidates": [i["path"] for i in by_density[:min(3, len(sized) // 2 or 1)]],
            "knotty_candidates": [i["path"] for i in sorted(by_density[min(3, len(sized) // 2 or 1):],
                                                             key=lambda i: -i["complexity"])[:3]],
        })
    out.sort(key=lambda k: -k["code"])
    allf = [i for items in kinds.values() for i in items]
    langs = defaultdict(lambda: {"files": 0, "code": 0})
    for path, (code, _, lang) in sizes.items():
        langs[lang]["files"] += 1
        langs[lang]["code"] += code
    marks = rg_count(scope, r"\b(TODO|FIXME|HACK|XXX)\b")
    return {
        "kinds": out,
        "languages": sorted(({"name": k, **v} for k, v in langs.items()), key=lambda l: -l["code"])[:8],
        "hotspots": sorted(allf, key=lambda i: -i["complexity"])[:15],
        "files_over_400": sum(1 for i in allf if i["code"] > 400),
        "todo_marks": marks,
    }


def rg_lines(scope, pattern, extra=()):
    globs = sum((["-g", f"!**/{d}/**"] for d in SKIP_DIRS), [])
    code, out, _ = run(["rg", "-n", "--no-heading", "--max-columns", "240", "--max-columns-preview",
                        *globs, "-g", "!*.min.js", *extra, "-e", pattern, str(scope)])
    hits = []
    for line in out.splitlines():
        m = re.match(r"(.+?):(\d+):(.*)", line)
        if m:
            hits.append((Path(m[1]).resolve(), int(m[2]), m[3].strip()))
    return hits


def rg_count(scope, pattern):
    return len(rg_lines(scope, pattern))


def norm_path(p):
    p = re.sub(r"^https?://[^/]+", "", p)
    p = re.sub(r"^\$\{[^}]*\}", "", p)
    p = p.split("?")[0].rstrip("/") or "/"
    p = re.sub(r"\$\{[^}]*\}|:\w+\??|\{[^}]*\}|<[^>]*>", "*", p)
    return p if p.startswith("/") else "/" + p


def path_match(call, route):
    """Segment-wise match, * matches one segment. A call path made only of
    wildcards (e.g. `${url}`) would match everything, so it never matches."""
    sa, sb = call.strip("/").split("/"), route.strip("/").split("/")
    if not any(x and "*" not in x for x in sa):
        return False
    return len(sa) == len(sb) and all(x == y or "*" in x or "*" in y for x, y in zip(sa, sb))


def link_facts(root, scope, callers, files):
    # Route mounts: parent file --prefix--> child file, so full paths are known.
    binds = {}
    mounts = []
    # Mounts are read repo-wide: the app file that mounts a scoped router
    # (e.g. backend/index.js) often sits outside the scope.
    for f, line, text in rg_lines(root, r"\.use\(\s*['\"`]/"):
        if is_test(f.relative_to(root)):
            continue
        m = MOUNT_RE.search(text)
        if m:
            mounts.append((f, m[1], m[2]))
    for f in {m[0] for m in mounts}:
        for a, b, c, d in IMPORT_BIND_RE.findall(read(f)):
            binds[(f, a or c)] = b or d
    child_prefix = {}
    for f, prefix, arg in mounts:
        for ident in re.findall(r"[A-Za-z_]\w*", arg):
            spec = binds.get((f, ident))
            if spec and spec.startswith("."):
                for e in ("", ".js", ".ts", "/index.js", "/index.ts"):
                    cand = Path(str((f.parent / spec).resolve()) + e)
                    if cand.exists():
                        child_prefix[cand] = (f, prefix, bool(AUTH_WORD.search(arg)))
                        break

    def prefix_of(f):
        parts, auth, seen = [], False, set()
        while f in child_prefix and f not in seen:
            seen.add(f)
            parent, prefix, a = child_prefix[f]
            parts.insert(0, prefix.rstrip("/"))
            auth = auth or a
            f = parent
        return "".join(parts), auth

    file_level_auth = {}
    routes = []
    for f, line, text in rg_lines(scope, ROUTE_RE.pattern) + rg_lines(scope, PY_ROUTE_RE.pattern):
        if is_test(f.relative_to(scope)):
            continue
        m = ROUTE_RE.search(text) or PY_ROUTE_RE.search(text)
        prefix, mount_auth = prefix_of(f)
        if f not in file_level_auth:
            file_level_auth[f] = bool(re.search(r"\.use\(\s*[^'\"`)]*(" + AUTH_WORD.pattern + ")", read(f), re.I))
        method = m[1].upper() if m[1] != "route" else "ANY"
        routes.append({"method": method, "path": (prefix + m[2]) or "/", "file": str(f.relative_to(root)),
                       "line": line, "auth_hint": bool(AUTH_WORD.search(text)) or mount_auth or file_level_auth[f],
                       "callers": []})

    calls = []
    for base in [scope, *callers]:
        for f, line, text in rg_lines(base, CALL_RE.pattern):
            if is_test(f.relative_to(base)):
                continue
            for m in CALL_RE.finditer(text):
                raw = m[2] or m[3] or m[4]
                if not raw or raw.startswith(("http://", "https://")) and base == scope and "localhost" not in raw:
                    continue
                method = m[1].upper() if m[1] else "GET" if m[3] else "ANY"
                calls.append({"method": method, "path": norm_path(raw),
                              "from": f"{Path(f).relative_to(base.parent if base != scope else root)}:{line}",
                              "project": base.name if base != scope else "(scope)"})
    calls = list({(c["from"], c["path"]): c for c in calls}.values())
    for c in calls:
        for r in routes:
            if path_match(c["path"], norm_path(r["path"])) and (c["method"] == r["method"] or "ANY" in (c["method"], r["method"]) or r["method"] == "ALL"):
                r["callers"].append(c["from"] + ("" if c["project"] == "(scope)" else f" [{c['project']}]"))
                c["matched"] = True
    unmatched_calls = [c for c in calls if not c.get("matched")]

    cli = []
    for pj in [p for p in files if p.name == "package.json"]:
        try:
            scripts = json.loads(read(pj)).get("scripts", {})
        except ValueError:
            continue
        for name, cmd in scripts.items():
            cli.append({"name": f"npm run {name}", "cmd": cmd, "file": str(pj.relative_to(root))})
    for f, line, _ in rg_lines(scope, r"process\.argv|require\(['\"](commander|yargs)['\"]|from ['\"](commander|yargs)|"
                                      r"argparse\.ArgumentParser|if __name__ == ['\"]__main__['\"]"):
        cli.append({"name": str(f.relative_to(root)), "cmd": "direct", "file": f"{f.relative_to(root)}:{line}"})
    workers = [{"file": f"{f.relative_to(root)}:{line}", "text": text[:120]}
               for f, line, text in rg_lines(scope, r"new Worker\(|\b\w*(?:[Qq]ueue|bull|[Ww]orker)\w*\.process\(|\.on\(\s*['\"]message['\"]")
               if not is_test(f.relative_to(scope))]

    sinks = defaultdict(lambda: defaultdict(int))
    for kind, pat in SINK_PATTERNS.items():
        for f, _, _ in rg_lines(scope, pat):
            if not is_test(f.relative_to(scope)):
                sinks[kind][str(f.relative_to(root))] += 1
    return {
        "routes": routes,
        "unmatched_calls": unmatched_calls[:60],
        "unmatched_calls_total": len(unmatched_calls),
        "callers_scanned": [str(c) for c in callers],
        "cli": cli[:80],
        "workers": workers[:40],
        "sinks": {k: sorted(({"file": f, "hits": n} for f, n in v.items()), key=lambda x: -x["hits"])[:15]
                  for k, v in sinks.items()},
        "sink_totals": {k: sum(v.values()) for k, v in sinks.items()},
    }


def sev_from_score(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "med"
    return "high" if s >= 7 else "med" if s >= 4 else "low"


def security_facts(root, scope, routes, use_tools, history):
    findings = []
    for rule, sev, pat, why in SEC_PATTERNS:
        for f, line, text in rg_lines(scope, pat, ["-P"] if "(?!" in pat or "(?i)" in pat else []):
            rel = f.relative_to(scope)
            if is_test(rel) and rule != "hardcoded-secret":
                continue
            findings.append({"rule": rule, "sev": "low" if is_test(rel) else sev, "file": str(f.relative_to(root)),
                             "line": line, "text": text[:160], "why": why, "source": "pattern"})
    code, out, _ = run(["git", "-C", str(scope), "ls-files", "--full-name", "."])
    tracked_secrets = [p for p in out.splitlines() if SECRET_FILE_RE.search(p) and not p.endswith(".example")]
    for p in tracked_secrets:
        findings.append({"rule": "secret-file-in-git", "sev": "high", "file": p, "line": 0,
                         "text": "credential-like file is tracked by git", "why": "anyone with repo access has it",
                         "source": "git"})
    no_auth = [r for r in routes if not r["auth_hint"]]
    if no_auth:
        findings.append({"rule": "route-no-auth-hint", "sev": "med", "file": no_auth[0]["file"], "line": no_auth[0]["line"],
                         "text": f"{len(no_auth)} of {len(routes)} routes show no auth middleware (heuristic)",
                         "why": "verify the app has auth upstream (gateway, app.use) or routes are public on purpose",
                         "source": "routes", "examples": [f"{r['method']} {r['path']}" for r in no_auth[:12]]})

    tools = {}
    tmp = Path(tempfile.mkdtemp(prefix="code-audit-"))
    if use_tools:
        # The scanners are independent processes, so run them side by side. Each fills its own list;
        # merging in the old order (gitleaks, semgrep, osv) keeps the dedup below picking the same hit.
        found = {"gitleaks": [], "semgrep": [], "osv-scanner": []}
        with ThreadPoolExecutor(max_workers=3) as pool:
            jobs = {"gitleaks": pool.submit(run_gitleaks, scope, root, tmp, found["gitleaks"], history),
                    "semgrep": pool.submit(run_semgrep, scope, root, found["semgrep"]),
                    "osv-scanner": pool.submit(run_osv, scope, root, found["osv-scanner"])}
        for name, job in jobs.items():
            tools[name] = job.result()
            findings.extend(found[name])
        if tools["osv-scanner"] != "ran":
            tools["npm-audit"] = run_npm_audit(scope, root, findings)
    shutil.rmtree(tmp, ignore_errors=True)

    seen, unique = set(), []
    for f in findings:
        f["text"] = redact(f["rule"], f["text"])
        key = (f["file"], f["line"], f["rule"].split("-")[0])
        if key in seen and f["line"]:
            continue
        seen.add(key)
        unique.append(f)
    order = {"high": 0, "med": 1, "low": 2}
    unique.sort(key=lambda f: (order[f["sev"]], f["rule"], f["file"], f["line"]))
    for i, f in enumerate(unique, 1):
        f["id"] = f"S{i}"
    return {"findings": unique, "tools": tools, "tracked_secret_files": tracked_secrets}


def run_gitleaks(scope, root, tmp, findings, history):
    if not shutil.which("gitleaks"):
        return "missing"
    report = tmp / "gitleaks.json"
    if history:
        cmd = ["gitleaks", "git", str(root), "--no-banner", "--redact", "-f", "json", "-r", str(report)]
    else:
        # `gitleaks dir` ignores .gitignore and would walk node_modules and data
        # folders for minutes, so skip git-ignored paths through an allowlist.
        _, out, _ = run(["git", "-C", str(root), "ls-files", "--others", "--ignored", "--exclude-standard", "--directory"])
        skip = [re.escape(str(root / e.rstrip("/"))) + ("/" if e.endswith("/") else "$") for e in out.splitlines() if e]
        skip += [f"/{re.escape(d)}/" for d in SKIP_DIRS]
        cfg = tmp / "gitleaks.toml"
        paths = "".join(f"  {json.dumps(p)},\n" for p in skip)  # TOML basic strings use JSON escaping
        cfg.write_text(f"[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = [\n{paths}]\n")
        cmd = ["gitleaks", "dir", str(scope), "--config", str(cfg), "--no-banner", "--redact",
               "-f", "json", "-r", str(report)]
    code, _, err = run(cmd)
    if not report.exists():
        return f"error: {err.strip()[:80]}"
    for leak in json.loads(read(report) or "[]"):
        path = Path(leak.get("File", ""))
        path = path if path.is_absolute() else (root if history else scope) / path
        try:
            rel = str(path.resolve().relative_to(root))
        except ValueError:
            rel = str(path)
        if "/node_modules/" in rel:
            continue
        commit = f" (commit {leak['Commit'][:8]})" if leak.get("Commit") else ""
        findings.append({"rule": "hardcoded-secret", "sev": "high", "file": rel, "line": leak.get("StartLine", 0),
                         "text": f"{leak.get('RuleID')}: {leak.get('Description', '')}{commit}"[:160],
                         "why": "gitleaks secret match", "source": "gitleaks"})
    return "ran" + (" (history)" if history else "")


def run_semgrep(scope, root, findings):
    if not shutil.which("semgrep"):
        return "missing"
    excludes = sum((["--exclude", d] for d in SKIP_DIRS), [])
    code, out, err = run(["semgrep", "scan", "--config", "p/default", "--json", "--metrics=off", "--quiet",
                          "--timeout", "20", *excludes, str(scope)], timeout=900)
    if not out.strip().startswith("{"):
        return f"error: {(err or 'no output').strip()[:80]}"
    sev = {"ERROR": "high", "WARNING": "med", "INFO": "low"}
    for r in json.loads(out).get("results", []):
        p = Path(r["path"]).resolve()
        try:
            rel = p.relative_to(scope)
        except ValueError:
            continue
        findings.append({"rule": r["check_id"].split(".")[-1][:40], "sev": "low" if is_test(rel) else sev.get(r["extra"].get("severity"), "med"),
                         "file": str(p.relative_to(root)), "line": r["start"]["line"],
                         "text": r["extra"].get("lines", "").strip()[:160],
                         "why": r["extra"].get("message", "").strip().split("\n")[0][:160], "source": "semgrep"})
    return "ran"


def run_osv(scope, root, findings):
    if not shutil.which("osv-scanner"):
        return "missing"
    code, out, err = run(["osv-scanner", "scan", "source", "-r", "--format", "json", str(scope)], timeout=600)
    if not out.strip().startswith("{"):
        code, out, err = run(["osv-scanner", "--format", "json", "-r", str(scope)], timeout=600)
    if not out.strip().startswith("{"):
        return f"error: {(err or 'no output').strip()[:80]}"
    for res in json.loads(out).get("results", []):
        lock = res.get("source", {}).get("path", "")
        for pkg in res.get("packages", []):
            name = pkg["package"]["name"]
            ver = pkg["package"].get("version", "")
            groups = pkg.get("groups", [])
            worst = max((g.get("max_severity") or "0" for g in groups), key=lambda s: float(s or 0), default="0")
            ids = [g["ids"][0] for g in groups if g.get("ids")]
            findings.append({"rule": "vulnerable-dependency", "sev": sev_from_score(worst), "file": os.path.relpath(lock, root),
                             "line": 0, "text": f"{name}@{ver}: {len(groups)} advisories ({', '.join(ids[:2])})",
                             "why": f"max CVSS {worst}", "source": "osv"})
    return "ran"


def run_npm_audit(scope, root, findings):
    if not shutil.which("npm"):
        return "missing"
    locks = [p for p in list_files(scope) if p.name == "package-lock.json"]
    if not locks:
        return "no lockfile"
    for lock in locks:
        code, out, err = run(["npm", "audit", "--json"], cwd=lock.parent, timeout=180)
        try:
            vulns = json.loads(out).get("vulnerabilities", {})
        except ValueError:
            return f"error: {err.strip()[:80]}"
        m = {"critical": "high", "high": "high", "moderate": "med", "low": "low", "info": "low"}
        for name, v in vulns.items():
            if v.get("isDirect"):
                findings.append({"rule": "vulnerable-dependency", "sev": m.get(v.get("severity"), "med"),
                                 "file": str(lock.relative_to(root)), "line": 0,
                                 "text": f"{name} {v.get('range', '')} ({v.get('severity')})"[:160],
                                 "why": "npm audit, direct dependency", "source": "npm-audit"})
    return "ran"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scope")
    ap.add_argument("--callers", nargs="*", default=[], help="other projects that call this one (e.g. a plugin)")
    ap.add_argument("--history", action="store_true", help="gitleaks scans the whole git history")
    ap.add_argument("--no-tools", action="store_true", help="skip semgrep/gitleaks/osv/npm audit")
    a = ap.parse_args()
    for tool in ("rg", "scc"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is required")
    scope = Path(a.scope).resolve()
    root = git_root(scope) or scope
    callers = [Path(c).resolve() for c in a.callers]
    files = [f for f in list_files(scope) if f.is_file()]
    sizes = scc_sizes(scope)

    links = link_facts(root, scope, callers, files)
    facts = {
        "scope": str(scope.relative_to(root)) if scope != root else ".",
        "root": str(root),
        "generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "files_total": len(files),
        "code_files": sum(1 for f in files if f.suffix in CODE_EXT),
        "tests": test_facts(root, scope, files, files if scope == root else list_files(root), sizes),
        "structure": structure_facts(root, scope, files, sizes),
        "shape": shape_facts(root, scope, files, files if scope == root else list_files(root), sizes,
                             read, is_test),
        "links": links,
        "security": security_facts(root, scope, links["routes"], not a.no_tools, a.history),
    }
    slug = hashlib.sha1(str(scope).encode()).hexdigest()[:10]
    out_dir = Path.home() / ".cache" / "code-audit" / f"{scope.name}-{slug}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "facts.json"
    out.write_text(json.dumps(facts, indent=1))
    print(out)


if __name__ == "__main__":
    main()
