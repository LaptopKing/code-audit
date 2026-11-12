#!/usr/bin/env python3
"""Render one code-audit dashboard page sized to the real terminal window.

Usage: render.py <facts.json> [--page overview|tests|structure|kinds|links|security]
                 [--n 2] [--filter TEXT] [--rows R --cols C]
Reads notes.json (the agent's judgements) from the same folder when present.
Prints a fenced ```text block that is exactly as tall as the window allows.
"""
import argparse
import json
import re
import os
import subprocess
import unicodedata
from pathlib import Path

# Lines Claude Code itself uses below/around a reply: input box, status line,
# the reply marker and the fence lines. Override with CODE_AUDIT_RESERVE.
RESERVE = int(os.environ.get("CODE_AUDIT_RESERVE", "10"))
SEV_ICON = {"high": "🔴", "med": "🟠", "low": "🟡"}


def term_size():
    """The Bash tool has no tty, so find the tty of the parent claude process."""
    if os.environ.get("CODE_AUDIT_ROWS"):
        return int(os.environ["CODE_AUDIT_ROWS"]), int(os.environ.get("CODE_AUDIT_COLS", "100"))
    pid = os.getpid()
    for _ in range(8):
        try:
            out = subprocess.run(["ps", "-o", "tty=,ppid=", "-p", str(pid)], capture_output=True, text=True).stdout.split()
        except OSError:
            break
        if len(out) < 2:
            break
        tty, ppid = out[0], out[1]
        if tty not in ("?", ""):
            size = subprocess.run(["stty", "-F", f"/dev/{tty}", "size"], capture_output=True, text=True).stdout.split()
            if len(size) == 2:
                return int(size[0]), int(size[1])
        pid = int(ppid)
    return 24, 80


def width(s):
    w = 0
    for ch in s:
        if unicodedata.combining(ch) or ch == "️":
            continue
        w += 2 if unicodedata.east_asian_width(ch) in "WF" or ord(ch) >= 0x1F300 else 1
    return w


def fit(s, w):
    """Cut s to display width w, marking the cut with …"""
    if width(s) <= w:
        return s
    out = ""
    for ch in s:
        if width(out + ch) > w - 1:
            break
        out += ch
    return out + "…"


def lfit(path, w):
    """Cut a path from the left so the file name survives."""
    if width(path) <= w:
        return path
    return "…" + path[-(w - 1):]


def short(path, f):
    """Paths are stored repo-relative; show them scope-relative."""
    pre = f["scope"].rstrip("/") + "/"
    return path[len(pre):] if f["scope"] != "." and path.startswith(pre) else path


def pad(s, w):
    s = fit(s, w)
    return s + " " * (w - width(s))


def bar(frac, n=10):
    full = round(max(0, min(1, frac)) * n)
    return "█" * full + "░" * (n - full)


class Page:
    def __init__(self, rows, cols):
        self.h = max(8, rows - RESERVE)
        self.w = max(50, cols - 4)
        self.lines = []

    def add(self, s=""):
        self.lines.append(fit(s, self.w))

    def rule(self):
        self.add("─" * self.w)

    def left(self, footer_lines=1):
        return self.h - len(self.lines) - footer_lines

    def listing(self, items, fmt, n, footer_lines=1, page_cmd=""):
        """Add as many items as fit; say how many are left and how to see them."""
        room = self.left(footer_lines + 1)
        start = (n - 1) * max(room, 1)
        chunk = items[start:start + room]
        for i, it in enumerate(chunk, start + 1):
            self.add(fmt(i, it))
        rest = len(items) - start - len(chunk)
        if rest > 0:
            self.add(f"  +{rest} more → '{page_cmd} {n + 1}'")
        return chunk

    def render(self):
        body = self.lines[:self.h]
        return "```text\n" + "\n".join(body) + "\n```"


def head(p, f, title):
    p.add(f"{title} · {f['scope']} · {f['code_files']} code files · {f['generated']}")
    p.rule()


def safe_text(x):
    """Second guard: never show the code line of a secret finding."""
    if re.search(r"secret|key|token|passw|credential", x["rule"], re.I):
        return x["why"]
    return x["text"]


def verdict(v, x):
    """A verdict can be set per finding id (S12) or for a whole rule."""
    return v.get(x["id"]) or v.get(x["rule"])


def sev_counts(f, notes):
    v = notes.get("security", {}).get("verdicts", {})
    live = [x for x in f["security"]["findings"] if verdict(v, x) != "false-positive"]
    c = {s: sum(1 for x in live if x["sev"] == s) for s in ("high", "med", "low")}
    return c, live, len(f["security"]["findings"]) - len(live)


def page_overview(p, f, notes, n, flt):
    head(p, f, "AUDIT")
    t, s, l = f["tests"], f["structure"], f["links"]
    pct = t["modules_tested"] / max(t["modules_total"], 1)
    cov = f" · report {t['coverage_report']['lines_pct']}% lines" if t["coverage_report"] else ""
    p.add(f"TESTS     {bar(pct)} {pct:4.0%}  {t['modules_tested']}/{t['modules_total']} modules · "
          f"{t['cases']} cases{cov}")
    grade = notes.get("structure", {}).get("grade", "?")
    sh = f.get("shape")
    if sh:
        short_labels = {"size": "size", "functions": "fn", "nesting": "nest", "naming": "name",
                        "duplication": "copy", "dead": "dead"}
        letters = " ".join(f"{short_labels[k]} {v}" for k, v in sh["grades"].items())
        t = sh["thresholds"]
        p.add(f"STRUCTURE {grade:<4} {letters} · files >{t['file_huge']}: {sh['files']['over_huge']}, "
              f">{t['file_big']}: {sh['files']['over_big']}")
    else:
        p.add(f"STRUCTURE {grade:<4} {len(s['kinds'])} code kinds · {s['files_over_400']} files >400 lines · "
              f"{s['todo_marks']} TODO/FIXME")
    called = sum(1 for r in l["routes"] if r["callers"])
    p.add(f"LINKS     {len(l['routes'])} routes ({called} with known callers) · {len(l['cli'])} CLI · "
          f"{len(l['workers'])} workers · {len(notes.get('chains', []))} traced chains")
    c, _, fp = sev_counts(f, notes)
    ran = [k for k, v in f["security"]["tools"].items() if v.startswith("ran")]
    p.add(f"SECURITY  🔴 {c['high']} high · 🟠 {c['med']} med · 🟡 {c['low']} low"
          + (f" · {fp} false alarms hidden" if fp else "")
          + (f" · tools: {', '.join(ran)}" if ran else " · patterns only, scanners skipped"))
    p.rule()
    p.add("TOP ISSUES")
    # Without the agent's picks, show the worst hit of each rule rather than five of one rule.
    firsts = list({x["rule"]: x for x in reversed(sev_counts(f, notes)[1])}.values())[::-1]
    tops = notes.get("top") or [{"sev": x["sev"], "text": x["why"], "where": short(f"{x['file']}:{x['line']}", f)}
                                for x in firsts[:5]]
    def top_line(i, x):
        # The place goes in a fixed right column, cut from the left so file:line survives.
        where = lfit(x.get("where", ""), 36)
        return f"{i}. {SEV_ICON.get(x.get('sev'), '•')} {pad(x['text'], p.w - 44)} {where}"
    p.listing(tops, top_line,
              n, footer_lines=2, page_cmd="overview")
    p.rule()
    p.add("next: tests · structure · kinds · links · security   (add a number for the next page)")


def page_tests(p, f, notes, n, flt):
    t = f["tests"]
    head(p, f, "TESTS")
    pct = t["modules_tested"] / max(t["modules_total"], 1)
    p.add(f"{t['modules_tested']}/{t['modules_total']} modules imported by a test ({pct:.0%}) · {t['test_files']} test files · "
          f"{t['cases']} cases · {t['skipped']} skipped")
    cr = t["coverage_report"]
    p.add(f"coverage report: {cr['lines_pct']}% lines, {cr['source']}, {cr['age_days']} days old" if cr
          else "coverage report: none found (counts above are import-based, no tests were run)")
    p.rule()
    dirs = [d for d in t["by_dir"] if flt.lower() in d["dir"].lower()]
    unt = [u for u in t["untested_largest"] if flt.lower() in u["path"].lower()]
    split = max(3, (p.left(3) * 3) // 5)  # ~60% of the room for folders
    dw = p.w - 34
    p.add(f"{pad('FOLDER', dw)} MODULES TESTED    %")
    room = min(split, len(dirs))
    start = (n - 1) * room
    for d in dirs[start:start + room]:
        frac = d["tested"] / max(d["modules"], 1)
        p.add(f"{pad(d['dir'], dw)} {d['modules']:>7} {d['tested']:>6} {frac:4.0%} {bar(frac, 8)}")
    if len(dirs) > start + room:
        p.add(f"  +{len(dirs) - start - room} more folders → 'tests {n + 1}'")
    p.rule()
    p.add("LARGEST UNTESTED")
    p.listing(unt, lambda i, u: f"{u['code']:>5} lines  {lfit(short(u['path'], f), p.w - 14)}",
              n, page_cmd="tests")


SHAPE_LABELS = {"size": "size", "functions": "functions", "nesting": "nesting", "naming": "naming",
                "duplication": "copy", "dead": "dead"}


def shape_sections(f, notes):
    """(name, header line, item lines) per measured dimension, worst items first."""
    sh, sc = f["shape"], f
    remark = notes.get("structure", {}).get("shape_notes", {})

    def note(key):
        return f"  ← {remark[key]}" if key in remark else ""

    fl, fn, ne, na, du, de = (sh["files"], sh["functions"], sh["nesting"], sh["naming"],
                              sh["duplication"], sh["dead"])
    t = sh["thresholds"]
    files = [f"{x['lines']:>6}  {short(x['path'], sc)} ({x['code']} code){note(short(x['path'], sc))}"
             for x in fl["largest"] if x["lines"] > t["file_warn"]]
    fns = [f"{x['lines']:>6}  {short(x['path'], sc)}:{x['line']} {x['name']}()"
           f"{note(short(x['path'], sc) + ':' + str(x['line']))}"
           for x in fn["longest"] if x["lines"] > t["fn_long"]]
    nest = [f"   d{x['depth']}  {short(x['path'], sc)}:{x['line']} {x['name']}() {x['lines']} lines"
            f"{note(short(x['path'], sc) + ':' + str(x['line']))}"
            for x in ne["deepest"] if x["depth"] >= max(3, t["depth_deep"] - 1)]
    per_file = {}
    for x in na["issues"]:
        per_file.setdefault(short(x["path"], sc), []).append(x)
    names = [f"{len(v):>6}  {k}" + (note("naming:" + k) if "naming:" + k in remark else ": " + ", ".join(
                 f"{x['name']} ({x['why']})" for x in v[:4]))
             for k, v in sorted(per_file.items(), key=lambda kv: -len(kv[1]))]
    names += [f"   mixed file-name styles in {d['dir']}: {d['styles']}" for d in na["mixed_file_name_dirs"]]
    copy = [f"{x['lines']:>6}  {short(x['a'], sc)} = {short(x['b'], sc)}" for x in du["blocks"]]
    dead = [f"  file  {short(x, sc)} (nothing imports it)" for x in de["unimported_files"]]
    dead += [f"  export {short(x['path'], sc)}:{x['line']} {x['name']}" for x in de["unused_exports"]]
    why = ", ".join(f"{v} {k}" for k, v in list(na["by_why"].items())[:3])
    return [
        ("files", f"FILES     {fl['over_huge']} >{t['file_huge']} · {fl['over_big']} >{t['file_big']} · "
                  f"{fl['over_warn']} >{t['file_warn']} lines · {fl['big_share_pct']}% of lines in files >{t['file_big']}", files),
        ("functions", f"FUNCTIONS {fn['over_huge']} >{t['fn_huge']} · {fn['over_long']} >{t['fn_long']} lines "
                      f"of {fn['count']} named", fns),
        ("nesting", f"NESTING   {ne['deep']} functions {t['depth_deep']}+ deep (if/for/try/callback inside "
                    f"each other) · max {max((x['depth'] for x in ne['deepest']), default=0)}", nest),
        ("naming", f"NAMING    {na['count']} names ({na['per_1000_lines']}/1000 lines): {why}", names),
        ("copy", f"COPY      {du['pct']}% of lines in repeated {t['dup_window']}+ line blocks", copy),
        ("dead", f"DEAD      {de['unused_export_count']} exports no other file names · "
                 f"{len(de['unimported_files'])} files nothing imports", dead),
    ]


def page_structure(p, f, notes, n, flt):
    st = notes.get("structure", {})
    head(p, f, "STRUCTURE")
    if "shape" not in f:
        p.add("no shape facts: rescan with the current scan.py")
        return
    sh = f["shape"]
    letters = " · ".join(f"{SHAPE_LABELS[k]} {v}" for k, v in sh["grades"].items())
    p.add(f"grade {st.get('grade', '?')} (measured {sh['grade_hint']}) · {letters}")
    if st.get("verdict"):
        p.add(st["verdict"])
    p.rule()
    sections = shape_sections(f, notes)
    if flt:  # one dimension, all of its items, paged
        for name, header, items in sections:
            if name == flt.lower():
                p.add(header)
                p.listing(items, lambda i, x: x, n, page_cmd=f"structure {name}")
                return
        p.add(f"no section '{flt}': files · functions · nesting · naming · copy · dead")
        return
    # Overview: every header, then the worst items shared out round-robin over the room left.
    room = p.left(2) - len(sections)
    shown = {name: 0 for name, _, _ in sections}
    while room > 0:
        grew = False
        for name, _, items in sections:
            if room > 0 and shown[name] < len(items):
                shown[name] += 1
                room -= 1
                grew = True
        if not grew:
            break
    for name, header, items in sections:
        more = len(items) - shown[name]
        p.add(header + (f"   → 'structure {name}' (+{more})" if more > 0 else ""))
        for item in items[:shown[name]]:
            p.add(item)
    p.rule()
    p.add("next: structure <files|functions|nesting|naming|copy|dead> · kinds (good/bad examples)")


def page_kinds(p, f, notes, n, flt):
    s = f["structure"]
    st = notes.get("structure", {})
    head(p, f, "KINDS")
    langs = " · ".join(f"{l['name']} {l['files']}f/{l['code']}" for l in s["languages"][:4])
    p.add(f"grade {st.get('grade', '?')} · {langs}")
    if st.get("verdict"):
        p.add(st["verdict"])
    p.rule()
    ex = {e["kind"]: e for e in st.get("examples", [])}
    kinds = [k for k in s["kinds"] if flt.lower() in k["kind"].lower()]
    per = 3 if ex else 1
    room = max(1, p.left(3) // per)  # keep rows for "+more", the rule and hotspots
    start = (n - 1) * room
    kw = 30
    for k in kinds[start:start + room]:
        p.add(f"{pad(k['kind'], kw)} {k['files']:>4} files {k['code']:>6} lines  {fit(ex.get(k['kind'], {}).get('style', ''), p.w - kw - 28)}")
        e = ex.get(k["kind"])
        if e:
            for mark, key in (("✓", "good"), ("✗", "bad")):
                if e.get(key):
                    if e[key].get("where", "-") != "-":
                        p.add(f"   {mark} {lfit(e[key]['where'], 48)}  {e[key]['why']}")
            if per == 3 and not (e.get("good") and e.get("bad")):
                p.add("")
    if len(kinds) > start + room:
        p.add(f"  +{len(kinds) - start - room} more kinds → 'kinds {n + 1}'")
    p.rule()
    hs = s["hotspots"]
    p.add("hotspots: " + " · ".join(f"{short(h['path'], f)} cx{h['complexity']}" for h in hs[:4]))


def page_links(p, f, notes, n, flt):
    l = f["links"]
    head(p, f, "LINKS")
    called = [r for r in l["routes"] if r["callers"]]
    p.add(f"{len(l['routes'])} routes · {len(called)} with a known caller · {l['unmatched_calls_total']} calls hit no route · "
          f"{len(l['cli'])} CLI · {len(l['workers'])} workers")
    per_project = {Path(c).name: sum(1 for r in l["routes"] if any(f"[{Path(c).name}]" in x for x in r["callers"]))
                   for c in l["callers_scanned"]}
    callers = " · ".join(f"{k} {v}" for k, v in per_project.items())
    p.add(f"routes used by: {callers or 'no caller projects scanned'} · ends in: "
          + " · ".join(f"{k} {v}" for k, v in l["sink_totals"].items()))
    p.rule()
    chains = [c for c in notes.get("chains", []) if flt.lower() in json.dumps(c).lower()]
    if not chains:
        p.add("no traced chains yet — routes with callers:")
        p.listing(called or l["routes"], lambda i, r: f"{r['method']:<6} {r['path']}  ← {', '.join(r['callers'][:2]) or 'no caller found'}",
                  n, page_cmd="links")
        return
    items = []
    for c in chains:
        block = [f"▶ {c['entry']}"]
        steps = c.get("steps", [])
        for j, s in enumerate(steps):
            block.append(f"  {'└' if j == len(steps) - 1 and not c.get('result') else '├'}→ {s}")
        if c.get("result"):
            block.append(f"  └= {c['result']}")
        items.append(block)
    room = p.left(2)
    pages, cur, used = [[]], 0, 0
    for b in items:  # pack whole chains into pages, never split one
        if used + len(b) > room and pages[cur]:
            pages.append([])
            cur, used = cur + 1, 0
        pages[cur].append(b)
        used += len(b)
    for b in pages[min(n, len(pages)) - 1]:
        for line in b:
            p.add(line)
    if n < len(pages):
        p.add(f"  +{sum(len(pg) for pg in pages[n:])} more chains → 'links {n + 1}'")


def page_security(p, f, notes, n, flt):
    c, live, fp = sev_counts(f, notes)
    head(p, f, "SECURITY")
    tools = " · ".join(f"{k}: {v}" for k, v in f["security"]["tools"].items()) or "external tools skipped"
    p.add(f"🔴 {c['high']} high · 🟠 {c['med']} med · 🟡 {c['low']} low hits · {fp} false alarms hidden")
    p.add(tools)
    p.rule()
    v = notes.get("security", {}).get("verdicts", {})
    why = notes.get("security", {}).get("notes", {})
    mark = {"confirmed": "✔", "unsure": "?"}
    rules = {}
    for x in live:
        rules.setdefault(x["rule"], []).append(x)
    if flt in rules:  # one rule: list every hit
        def fmt(i, x):
            where = lfit(short(f"{x['file']}:{x['line']}" if x["line"] else x["file"], f), 44)
            return f"{SEV_ICON[x['sev']]} {x['id']:<5}{mark.get(verdict(v, x), ' ')} {pad(where, 44)} {why.get(x['id'], safe_text(x))}"
        p.listing(rules[flt], fmt, n, page_cmd=f"security {flt}")
    else:  # one row per rule, worst first
        groups = sorted((g for r, g in rules.items() if flt.lower() in json.dumps(g).lower()),
                        key=lambda g: ({"high": 0, "med": 1, "low": 2}[g[0]["sev"]], -len(g)))

        def fmt(i, g):
            x = g[0]
            where = lfit(short(f"{x['file']}:{x['line']}" if x["line"] else x["file"], f), 34)
            note = why.get(x["rule"]) or why.get(x["id"]) or x["why"]
            return (f"{SEV_ICON[x['sev']]}{mark.get(verdict(v, x), ' ')}{pad(x['rule'], 24)} ×{len(g):<4} "
                    f"{pad(where, 34)} {note}")
        p.listing(groups, fmt, n, page_cmd="security")
    p.add("'security <rule>' lists each hit · ✔ checked in code · ? unsure · blank = not checked yet")


PAGES = {"overview": page_overview, "tests": page_tests, "structure": page_structure, "kinds": page_kinds,
         "links": page_links, "security": page_security}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("facts")
    ap.add_argument("--page", default="overview", choices=PAGES)
    ap.add_argument("--n", type=int, default=1)
    ap.add_argument("--filter", default="")
    ap.add_argument("--rows", type=int)
    ap.add_argument("--cols", type=int)
    a = ap.parse_args()
    facts = json.loads(Path(a.facts).read_text())
    notes_path = Path(a.facts).with_name("notes.json")
    notes = json.loads(notes_path.read_text()) if notes_path.exists() else {}
    rows, cols = term_size()
    p = Page(a.rows or rows, a.cols or cols)
    PAGES[a.page](p, facts, notes, max(1, a.n), a.filter)
    print(p.render())


if __name__ == "__main__":
    main()
