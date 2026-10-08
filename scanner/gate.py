#!/usr/bin/env python3
"""sar-app-scan-gate: deterministic pre-publish scan of a SAR / Streamlit app tree.

  python3 gate.py <app_dir> [--out result.json] [--blessed-registry URL]
                  [--allowed-eai NAME ...] [--allowed-build-eai NAME ...]

Verdict (worst finding wins):
  REFUSE   at least one REFUSE finding           -> never published
  REWRITE  only REWRITE (+WARN/INFO) findings     -> rewrite.py, then rescan
  HOLD     only WARN findings                     -> human must approve
  PASS     nothing blocking                       -> eligible for auto-publish

The result includes a content digest of the scanned tree. Publish must deploy a
tree with exactly that digest (see sql/02_procs.sql).
Exit code: 0 PASS, 1 REFUSE, 2 REWRITE, 3 HOLD, 4 scanner error (fail closed).
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.environ.get("GATE_RULES", os.path.join(HERE, "..", "rules"))
SEMGREP = os.environ.get("SEMGREP_BIN", "semgrep")

SKIP_DIRS = {"node_modules", ".git", ".next", "output", "dist", "build", ".venv",
             "__pycache__", ".snowflake", "coverage"}
PRIVILEGED_ROLES = {"ACCOUNTADMIN", "SYSADMIN", "SECURITYADMIN", "USERADMIN", "ORGADMIN"}
ORDER = {"REFUSE": 3, "REWRITE": 2, "WARN": 1, "INFO": 0}
VERDICT = {3: "REFUSE", 2: "REWRITE", 1: "HOLD", 0: "PASS"}
EXIT = {"PASS": 0, "REFUSE": 1, "REWRITE": 2, "HOLD": 3}

SECRET_PATTERNS = [
    ("secret-private-key", re.compile(r"-----BEGIN (RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----")),
    ("secret-snowflake-credential", re.compile(
        r"(?i)\b(SNOWFLAKE_(PASSWORD|TOKEN|PRIVATE_KEY(_PASSPHRASE)?|PAT)|programmatic_access_token)\b\s*[=:]\s*[\"']?(?!\$|<|\{|process\.env|os\.environ)[^\s\"'<]{8,}")),
    ("secret-authorization-token", re.compile(r"Snowflake Token=\\?\"[A-Za-z0-9._-]{20,}")),
    ("secret-npm-token", re.compile(r"_authToken\s*=\s*(?!\$\{)[A-Za-z0-9._-]{16,}")),
]
SECRET_FILES = re.compile(r"(^|/)(\.env(\.[\w-]+)?|connections\.toml|config\.toml|[^/]+\.(p8|pem|key|pat))$")
TEXT_EXT = re.compile(r"\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|html?|py|json|ya?ml|toml|md|txt|sh|env|npmrc|css)$|(^|/)\.[a-z]+rc$")


def walk(app):
    for root, dirs, files in os.walk(app):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            full = os.path.join(root, f)
            if os.path.islink(full) or f == ".gate_frozen":  # gate's own freeze marker
                continue
            yield os.path.relpath(full, app).replace(os.sep, "/"), full


def digest(app):
    """Order-independent hash of (path, content-hash) for every scanned file."""
    h = hashlib.sha256()
    n = 0
    for rel, full in walk(app):
        with open(full, "rb") as fh:
            fh_hash = hashlib.sha256(fh.read()).hexdigest()
        h.update(f"{rel}\0{fh_hash}\n".encode())
        n += 1
    return h.hexdigest(), n


def finding(rule, cls, path, line, message, rewrite=None, **extra):
    f = {"rule": rule, "class": cls, "file": path, "line": line, "message": message}
    if rewrite:
        f["rewrite"] = rewrite
    f.update(extra)
    return f


def run_semgrep(app):
    exclude = []
    for d in SKIP_DIRS:
        exclude += ["--exclude", d]
    cmd = [SEMGREP, "scan", "--config", RULES, "--json", "--metrics=off", "--disable-version-check",
           "--no-git-ignore", "--quiet", "--timeout", "30"] + exclude + [app]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed ({p.returncode}): {p.stderr[-2000:]}")
    data = json.loads(p.stdout)
    out = []
    for r in data.get("results", []):
        meta = r["extra"].get("metadata", {})
        rel = os.path.relpath(r["path"], app).replace(os.sep, "/")
        out.append(finding(
            r["check_id"].split(".")[-1], meta.get("gate_class", "REFUSE"), rel,
            r["start"]["line"], r["extra"]["message"], meta.get("rewrite"),
            end_line=r["end"]["line"], start_offset=r["start"]["offset"],
            end_offset=r["end"]["offset"], snippet=r["extra"].get("lines", "")[:300]))
    # a rule that failed to parse a file must not pass silently
    for e in data.get("errors", []):
        if e.get("level") == "error":
            out.append(finding("scanner-parse-error", "WARN", e.get("path", "?"), 0,
                               "Semgrep could not fully parse this file: " + str(e.get("message", ""))[:200]))
    return out


def load_yaml(path):
    import yaml
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def manifest_checks(app, allowed_eai, allowed_build_eai):
    out = []
    app_yml = os.path.join(app, "app.yml")
    sf_yml = os.path.join(app, "snowflake.yml")
    if not os.path.exists(app_yml) and not os.path.exists(sf_yml):
        return [finding("manifest-missing", "REFUSE", "app.yml", 0,
                        "No app.yml or snowflake.yml: the deploy target and runtime settings are unknown.")]
    for name in ("app.yml", "snowflake.yml"):
        path = os.path.join(app, name)
        if not os.path.exists(path):
            continue
        try:
            doc = load_yaml(path)
        except Exception as e:  # fail closed
            out.append(finding("manifest-parse-error", "REFUSE", name, 0, f"Manifest does not parse: {e}"))
            continue
        # app.yml v2: top level + targets.*; snowflake.yml: entities.*
        scopes = [("", doc)]
        scopes += [(f"targets.{k}", v) for k, v in (doc.get("targets") or {}).items() if isinstance(v, dict)]
        scopes += [(f"entities.{k}", v) for k, v in (doc.get("entities") or {}).items() if isinstance(v, dict)]
        for where, node in scopes:
            for key in ("external_access_integrations", "service_eai"):
                vals = node.get(key) or []
                vals = [vals] if isinstance(vals, str) else vals
                for eai in vals:
                    if str(eai).upper() not in allowed_eai:
                        out.append(finding(
                            "manifest-runtime-eai", "REWRITE", name, 0,
                            f"Runtime EAI {eai} ({where or 'top'}.{key}) is not approved. A runtime EAI also copies its "
                            "hosts into the browser CSP (0.0.0.0 => any https: host); removed automatically.",
                            "remove-eai", eai=str(eai)))
            beai = node.get("build_eai")
            if beai and str(beai).upper() not in allowed_build_eai:
                out.append(finding("manifest-build-eai", "REFUSE", name, 0,
                                   f"build_eai {beai} is not an approved (blessed-registry) integration."))
            role = node.get("execute_as_role")
            if role and str(role).upper() in PRIVILEGED_ROLES:
                out.append(finding("manifest-privileged-role", "REFUSE", name, 0,
                                   f"execute_as_role {role}: the execution role is the data blast radius; "
                                   "use a purpose-built role."))
    return out


def secret_checks(app):
    out = []
    for rel, full in walk(app):
        if SECRET_FILES.search(rel) and os.path.getsize(full) > 0:
            out.append(finding("secret-file", "REFUSE", rel, 0, "Credential-type file in the upload tree."))
            continue
        if not TEXT_EXT.search(rel) or os.path.getsize(full) > 2_000_000:
            continue
        with open(full, errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                for rule, rx in SECRET_PATTERNS:
                    if rx.search(line):
                        out.append(finding(rule, "REFUSE", rel, i, "Hard-coded credential in source."))
    return out


def npm_checks(app, blessed):
    pj = os.path.join(app, "package.json")
    if not os.path.exists(pj):
        return []
    try:
        pkg = json.load(open(pj))
    except Exception as e:
        return [finding("npm-package-json-invalid", "REFUSE", "package.json", 0, f"package.json does not parse: {e}")]
    if not any(pkg.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies",
                                    "peerDependencies", "bundleDependencies")):
        return []  # nothing is fetched, so there is no provenance to check
    if not blessed:
        return [finding("npm-no-blessed-registry", "WARN", "package.json", 0,
                        "No blessed registry configured for this gate; package provenance not enforced.")]
    p = subprocess.run([sys.executable, os.path.join(HERE, "check_app.py"), app, blessed],
                       capture_output=True, text=True)
    if p.returncode == 0:
        return []
    lines = [l.strip()[2:] for l in p.stdout.splitlines() if l.strip().startswith("- ")]
    return [finding("npm-provenance", "REFUSE", "package-lock.json", 0,
                    "Packages must resolve only from the blessed registry: " + l) for l in lines[:50]] or \
        [finding("npm-provenance", "REFUSE", "package.json", 0, p.stdout[-300:] or p.stderr[-300:])]


def csp_note(app):
    """Advisory: an app-level CSP with form-action/script-src tightens the SPCS baseline."""
    for rel, full in walk(app):
        if TEXT_EXT.search(rel) and os.path.getsize(full) < 2_000_000:
            with open(full, errors="replace") as fh:
                if "form-action" in fh.read():
                    return []
    return [finding("csp-not-tightened", "INFO", "-", 0,
                    "No app CSP with form-action/script-src found. The app may add one to tighten the "
                    "SPCS baseline (it cannot loosen it).")]


def scan(app, blessed=None, allowed_eai=(), allowed_build_eai=()):
    app = os.path.abspath(app)
    d, nfiles = digest(app)
    findings = (manifest_checks(app, {e.upper() for e in allowed_eai}, {e.upper() for e in allowed_build_eai})
                + secret_checks(app) + npm_checks(app, blessed) + run_semgrep(app) + csp_note(app))
    worst = max([ORDER[f["class"]] for f in findings] + [0])
    verdict = VERDICT[worst]
    counts = {}
    for f in findings:
        counts[f["class"]] = counts.get(f["class"], 0) + 1
    return {"digest": d, "files": nfiles, "verdict": verdict, "counts": counts,
            "rewrites_available": sorted({f["rewrite"] for f in findings if f["class"] == "REWRITE"}),
            "findings": sorted(findings, key=lambda f: (-ORDER[f["class"]], f["file"], f["line"]))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("app")
    ap.add_argument("--out")
    ap.add_argument("--blessed-registry", default=os.environ.get("BLESSED_REGISTRY"))
    ap.add_argument("--allowed-eai", nargs="*", default=[])
    ap.add_argument("--allowed-build-eai", nargs="*", default=[])
    a = ap.parse_args()
    try:
        res = scan(a.app, a.blessed_registry, a.allowed_eai, a.allowed_build_eai)
    except Exception as e:  # fail closed
        res = {"verdict": "ERROR", "error": str(e)}
        print(json.dumps(res), file=sys.stderr)
        if a.out:
            json.dump(res, open(a.out, "w"), indent=1)
        sys.exit(4)
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(res, fh, indent=1)
    for f in res["findings"]:
        if f["class"] != "INFO":
            print(f"{f['class']:8} {f['rule']:30} {f['file']}:{f['line']}  {f['message'][:90]}")
    print(f"VERDICT {res['verdict']}  digest={res['digest'][:16]}  files={res['files']}  {json.dumps(res['counts'])}")
    sys.exit(EXIT[res["verdict"]])


if __name__ == "__main__":
    main()
