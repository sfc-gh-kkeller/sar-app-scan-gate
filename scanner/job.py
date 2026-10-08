#!/usr/bin/env python3
"""SPCS job entrypoint for the gate.

Volumes (stage mounts):
  /inbox    @GATE.INBOX    builder-writable upload area
  /frozen   @GATE.FROZEN   gate-only; one folder per scanned digest
  /results  @GATE.RESULTS  gate-only; <scan_id>.json (+ .diff for rewrites)

Env:
  MODE=scan     APP_PATH=<folder under /inbox>   SCAN_ID=<id>
  MODE=rewrite  PARENT_DIGEST=<digest under /frozen>  PARENT_SCAN_ID=<id>  SCAN_ID=<id>
  BLESSED_REGISTRY, ALLOWED_EAI (comma), ALLOWED_BUILD_EAI (comma)

The inbox is copied to local disk FIRST and that copy is what gets hashed, scanned
and frozen, so a concurrent re-upload cannot change what was scanned.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate  # noqa: E402

INBOX, FROZEN, RESULTS = "/inbox", "/frozen", "/results"
AI_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".vue", ".svelte", ".py")
AI_MAX_BYTES = 60_000


def ai_bundle(app):
    """Source text for the AI advisory: code files only, capped, flagged files first."""
    files = [(rel, full) for rel, full in gate.walk(app) if rel.endswith(AI_EXT)]
    out, used = [], 0
    for rel, full in files:
        text = open(full, errors="replace").read()[:20_000]
        if used + len(text) > AI_MAX_BYTES:
            out.append({"file": rel, "truncated": True})
            continue
        out.append({"file": rel, "text": text})
        used += len(text)
    return out


def env_list(name):
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def freeze(src, d):
    dst = os.path.join(FROZEN, d)
    if not os.path.exists(os.path.join(dst, ".gate_frozen")):
        shutil.copytree(src, dst, dirs_exist_ok=True, ignore=shutil.ignore_patterns(*gate.SKIP_DIRS))
        open(os.path.join(dst, ".gate_frozen"), "w").write(d)
    return dst


def safe_join(base, rel):
    p = os.path.realpath(os.path.join(base, rel))
    if not p.startswith(os.path.realpath(base) + os.sep):
        raise ValueError(f"path escapes {base}: {rel}")
    return p


def main():
    mode, scan_id = os.environ["MODE"], os.environ["SCAN_ID"]
    opts = dict(blessed=os.environ.get("BLESSED_REGISTRY") or None,
                allowed_eai=env_list("ALLOWED_EAI"), allowed_build_eai=env_list("ALLOWED_BUILD_EAI"))
    work = tempfile.mkdtemp()
    local = os.path.join(work, "app")
    extra = {"scan_id": scan_id, "mode": mode}
    try:
        if mode == "scan":
            src = safe_join(INBOX, os.environ["APP_PATH"])
            shutil.copytree(src, local, ignore=shutil.ignore_patterns(*gate.SKIP_DIRS))
            extra["app_path"] = os.environ["APP_PATH"]
        elif mode == "rewrite":
            parent = os.environ["PARENT_SCAN_ID"]
            pres = json.load(open(os.path.join(RESULTS, f"{parent}.json")))
            psrc = safe_join(FROZEN, pres["digest"])
            pjson = os.path.join(work, "parent.json")
            json.dump(pres, open(pjson, "w"))
            diff = os.path.join(RESULTS, f"{scan_id}.diff")
            p = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "rewrite.py"),
                                psrc, pjson, local, "--diff", diff], capture_output=True, text=True)
            if p.returncode:
                raise RuntimeError("rewrite failed: " + p.stderr[-500:])
            extra.update(parent_scan_id=parent, parent_digest=pres["digest"],
                         rewrites=json.loads(p.stdout)["rewritten"],
                         diff=open(diff).read()[:20_000] if os.path.exists(diff) else "")
        else:
            raise ValueError(f"unknown MODE {mode}")
        res = gate.scan(local, **opts)
        res.update(extra)
        res["ai_input"] = ai_bundle(local)
        res["frozen_path"] = os.path.relpath(freeze(local, res["digest"]), FROZEN)
    except Exception as e:  # fail closed, but still leave a result row behind
        res = {"verdict": "ERROR", "error": str(e)[:2000], **extra}
    with open(os.path.join(RESULTS, f"{scan_id}.json"), "w") as fh:
        json.dump(res, fh)
    print(json.dumps({k: res.get(k) for k in ("scan_id", "verdict", "digest", "counts", "error")}))


if __name__ == "__main__":
    main()
