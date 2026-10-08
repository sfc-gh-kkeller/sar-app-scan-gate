#!/usr/bin/env python3
"""Apply the gate's SAFE rewrites to a copy of the app, then the caller rescans.

  python3 rewrite.py <app_dir> <scan_result.json> <out_dir> [--diff out.diff]

Only findings with class REWRITE and a known `rewrite` kind are touched:
  delete-statement     remove the statement's lines (sendBeacon, header logging)
  delete-tag           remove the matched markup (external <script src>, pixel <img>)
  strip-cookie-domain  drop the Domain= attribute / domain: option
  st-unsafe-html-false unsafe_allow_html=True -> False
  remove-eai           drop the unapproved name from external_access_integrations

Anything else is left alone. The result is NOT trusted: run gate.py on <out_dir>.
One rewrite pass per submission (enforced in sql/02_procs.sql).
"""
import argparse
import difflib
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gate import SKIP_DIRS  # noqa: E402

MARK_JS = "/* removed by sar-app-scan-gate: {rule} */"
MARK_HTML = "<!-- removed by sar-app-scan-gate: {rule} -->"
MARK_PY = "# removed by sar-app-scan-gate: {rule}"


def marker(path, rule):
    if path.endswith((".html", ".htm", ".vue", ".svelte")):
        return MARK_HTML.format(rule=rule)
    if path.endswith(".py"):
        return MARK_PY.format(rule=rule)
    return MARK_JS.format(rule=rule)


def line_span(text, start_line, end_line):
    """Byte offsets covering whole lines start_line..end_line (1-based, inclusive)."""
    lines = text.splitlines(keepends=True)
    s = sum(len(l) for l in lines[:start_line - 1])
    e = sum(len(l) for l in lines[:end_line])
    return s, e


def edit_text(path, text, fs):
    """Apply span edits back-to-front so earlier offsets stay valid."""
    edits = []
    for f in fs:
        kind = f["rewrite"]
        if kind == "delete-statement":
            s, e = line_span(text, f["line"], f.get("end_line", f["line"]))
            indent = re.match(r"\s*", text[s:e]).group(0)
            edits.append((s, e, f"{indent}{marker(path, f['rule'])}\n"))
        elif kind == "delete-tag":
            edits.append((f["start_offset"], f["end_offset"], marker(path, f["rule"])))
        elif kind == "strip-cookie-domain":
            s, e = line_span(text, f["line"], f.get("end_line", f["line"]))
            seg = text[s:e]
            seg = re.sub(r"(?i);\s*domain=[^;\"'`]*", "", seg)
            seg = re.sub(r"(?i)\bdomain\s*:\s*[\"'][^\"']*[\"']\s*,?\s*", "", seg)
            edits.append((s, e, seg))
        elif kind == "st-unsafe-html-false":
            s, e = f["start_offset"], f["end_offset"]
            edits.append((s, e, text[s:e].replace("unsafe_allow_html=True", "unsafe_allow_html=False")))
    applied = []
    last = len(text) + 1
    for s, e, rep in sorted(edits, key=lambda x: x[0], reverse=True):
        if e > last:  # overlapping edit: skip, the rescan will still report it
            continue
        text = text[:s] + rep + text[e:]
        last = s
        applied.append((s, e))
    return text, len(applied)


def remove_eais(path, names):
    import yaml
    doc = yaml.safe_load(open(path)) or {}
    drop = {n.upper() for n in names}

    def clean(node):
        for key in ("external_access_integrations", "service_eai"):
            if key in node:
                vals = node[key] if isinstance(node[key], list) else [node[key]]
                keep = [v for v in vals if str(v).upper() not in drop]
                if keep:
                    node[key] = keep
                else:
                    node.pop(key)
    clean(doc)
    for group in ("targets", "entities"):
        for v in (doc.get(group) or {}).values():
            if isinstance(v, dict):
                clean(v)
    with open(path, "w") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("app")
    ap.add_argument("scan")
    ap.add_argument("out")
    ap.add_argument("--diff")
    a = ap.parse_args()

    res = json.load(open(a.scan))
    todo = [f for f in res["findings"] if f["class"] == "REWRITE" and f.get("rewrite")]
    if any(f["class"] == "REFUSE" for f in res["findings"]):
        print("refusing to rewrite: scan has REFUSE findings", file=sys.stderr)
        sys.exit(1)

    if os.path.exists(a.out):
        shutil.rmtree(a.out)
    shutil.copytree(a.app, a.out, ignore=shutil.ignore_patterns(*SKIP_DIRS))

    by_file = {}
    for f in todo:
        by_file.setdefault(f["file"], []).append(f)

    diff, report = [], []
    for rel, fs in sorted(by_file.items()):
        path = os.path.join(a.out, rel)
        before = open(path).read()
        eai = [f["eai"] for f in fs if f["rewrite"] == "remove-eai"]
        if eai:
            remove_eais(path, eai)
            after = open(path).read()
            n = len(eai)
        else:
            after, n = edit_text(rel, before, fs)
            with open(path, "w") as fh:
                fh.write(after)
        report.append({"file": rel, "rules": sorted({f["rule"] for f in fs}), "edits": n})
        diff += difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                     f"a/{rel}", f"b/{rel}")
    if a.diff:
        with open(a.diff, "w") as fh:
            fh.writelines(diff)
    print(json.dumps({"rewritten": report}, indent=1))


if __name__ == "__main__":
    main()
