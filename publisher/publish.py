#!/usr/bin/env python3
"""Publisher job: deploy exactly the frozen, scanned tree to the shared schema.

Runs as an SPCS job owned by the PUBLISH role (its service token carries that role).
Volumes: /frozen (@GATE.FROZEN, read), /results (@GATE.RESULTS, write)
Env: SCAN_ID DIGEST APP_NAME TARGET_DB TARGET_SCHEMA QUERY_WAREHOUSE CONSUMER_ROLE
     BUILD_JOB_LOCATION (DB.SCHEMA)

Steps (fail closed at each one):
  1. copy /frozen/<digest> to local disk, recompute the digest, abort on mismatch
  2. write a publisher-owned app.yml: keep only install/build/run + display fields from
     the scanned manifest; force database/schema/warehouse/build location; no EAIs,
     no secrets, no execute_as_role, no targets
  3. snow app deploy (service token -> PUBLISH role)
  4. GRANT USAGE on the application service to CONSUMER_ROLE
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, "/gate/scanner")
import gate  # noqa: E402  (digest + SKIP_DIRS: same code as the scanner)

KEEP_KEYS = ("install", "build", "run", "ignore", "label", "description", "icon")
TOKEN = "/snowflake/session/token"


def account_from_token():
    """SPCS tokens authenticate only against the issuing account's regional host."""
    tok = open(TOKEN).read().strip()
    p = tok.split(".")[1]
    p += "=" * (-len(p) % 4)
    iss = json.loads(base64.urlsafe_b64decode(p))["iss"].replace("https://", "").strip("/")
    return iss, iss.split(".")[0]


def snow(args, cwd=None, timeout=1800):
    host, account = account_from_token()
    cmd = ["snow"] + args + ["-x", "--host", host, "--account", account, "--authenticator", "OAUTH",
                             "--token-file-path", TOKEN, "--warehouse", os.environ["QUERY_WAREHOUSE"]]
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)[-6000:]


def main():
    e = os.environ
    res = {"scan_id": e["SCAN_ID"], "digest": e["DIGEST"], "status": "FAILED"}
    out = os.path.join("/results", f"{e['SCAN_ID']}.publish.json")
    try:
        src = os.path.join("/frozen", e["DIGEST"])
        work = os.path.join(tempfile.mkdtemp(), "app")
        shutil.copytree(src, work, ignore=shutil.ignore_patterns(*gate.SKIP_DIRS, ".gate_frozen"))
        d, _ = gate.digest(work)
        if d != e["DIGEST"]:
            raise RuntimeError(f"digest mismatch: frozen tree hashes to {d}")

        import yaml
        scanned = {}
        if os.path.exists(os.path.join(work, "app.yml")):
            scanned = yaml.safe_load(open(os.path.join(work, "app.yml"))) or {}
        manifest = {"version": 2, "name": e["APP_NAME"],
                    "database": e["TARGET_DB"], "schema": e["TARGET_SCHEMA"],
                    "query_warehouse": e["QUERY_WAREHOUSE"],
                    "build_job_location": e["BUILD_JOB_LOCATION"]}
        manifest.update({k: scanned[k] for k in KEEP_KEYS if k in scanned})
        with open(os.path.join(work, "app.yml"), "w") as fh:
            yaml.safe_dump(manifest, fh, sort_keys=False)
        res["manifest"] = manifest

        rc, log = snow(["app", "deploy", "--verbose"], cwd=work)
        res["deploy_log_tail"] = log[-3000:]
        if rc:
            raise RuntimeError(f"snow app deploy exit {rc}")
        fqn = f"{e['TARGET_DB']}.{e['TARGET_SCHEMA']}.{e['APP_NAME']}"
        rc, log = snow(["sql", "-q", f"GRANT USAGE ON APPLICATION SERVICE {fqn} TO ROLE {e['CONSUMER_ROLE']}"])
        if rc:
            raise RuntimeError("grant failed: " + log[-500:])
        rc, log = snow(["sql", "--format", "json", "-q", f"DESCRIBE APPLICATION SERVICE {fqn}"])
        try:
            row = json.loads(log[log.index("["):log.rindex("]") + 1])[0]
            res["url"] = "https://" + row["url"] if row.get("url") else None
            res["source"] = row.get("source")
        except Exception:
            res["url"] = None
        res.update(status="PUBLISHED", service=fqn)
    except Exception as ex:
        res["error"] = str(ex)[:3000]
    with open(out, "w") as fh:
        json.dump(res, fh)
    print(json.dumps({k: res.get(k) for k in ("scan_id", "status", "service", "url", "error")}))
    sys.exit(0 if res["status"] == "PUBLISHED" else 1)


if __name__ == "__main__":
    main()
