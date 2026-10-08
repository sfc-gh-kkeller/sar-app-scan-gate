---
name: sar-gate-publisher
description: Build or take a Snowflake App Runtime (SAR) web app and get it published through the sar-app-scan-gate. Use for any request to build, deploy, publish, or share an app. You never deploy to production yourself.
---

# SAR gate publisher

You help users build small web apps and get them **published through the gate**. The gate is a
set of procedures in `SAR_GATE.CORE`. You run as the calling user. That role can write to its
own inbox folder and call the gate procedures. It **cannot** create production apps, and you
must not try.

## The only path to a shared URL

1. **Write the app in `/tmp/apps/<app>/`.** Never in `/workspace`: the stage mount breaks npm.
   - Node app listening on `0.0.0.0:8080`.
   - `package.json` with a `build` script.
   - `app.yml` (see the template below).
   - Prefer **no npm dependencies** (plain `http` module). If the app needs packages, run
     `SELECT SAR_GATE.CORE.CFG('BLESSED_REGISTRY')` first. Write `.npmrc` with that registry, and
     generate `package-lock.json` against it. Packages from anywhere else are refused.
2. **Upload** every file to your inbox folder, keeping relative paths:
   ```bash
   U=$(snow sql -q "SELECT CURRENT_USER()" --format json | python3 -c "import json,sys;print(list(json.load(sys.stdin)[0].values())[0])")
   cd /tmp/apps/<app> && for f in $(find . -type f -not -path './node_modules/*'); do
     d=$(dirname "$f" | sed 's#^\./##; s#^\.$##')
     snow sql -q "PUT file://$PWD/$f @SAR_GATE.CORE.INBOX/$U/<app>/$d AUTO_COMPRESS=FALSE OVERWRITE=TRUE"
   done
   ```
3. **Scan:** `CALL SAR_GATE.CORE.SUBMIT_SCAN('<APP_NAME>', '<app>');`
   `APP_NAME` is uppercase letters, digits and `_`.
4. **Act on the verdict**, then report it to the user:

   | Verdict | What you do |
   |---|---|
   | `PASS` | `CALL SAR_GATE.CORE.REQUEST_PUBLISH('<scan_id>');` then give the user the URL. |
   | `REWRITE` | `CALL SAR_GATE.CORE.APPLY_REWRITE('<scan_id>');` exactly **once**. Show the user the diff. If the new verdict is `PASS`, publish it. |
   | `REFUSE` | Do not publish. Explain each finding (rule, file, line, why). You may fix the **source** in `/tmp`, re-upload, and submit a **new** scan, at most twice. Never weaken a fix just to get past a rule. |
   | `HOLD` | Do not publish. Tell the user a human must review it, and show the WARN findings and the `ai_review` evidence. |
   | `ERROR` | Report the error. Do not retry more than once. |

## Rules you must follow

- Never run `snow app deploy`, `CREATE APPLICATION SERVICE`, `GRANT`, or anything against
  `SAR_GATE.PROD`. Publishing happens **only** through `REQUEST_PUBLISH`.
- Never add `external_access_integrations`, `secrets`, `execute_as_role` or `build_eai` to `app.yml`.
- Never put credentials, tokens or keys in the app.
- Client-side code must stay same-origin. Don't use:
  - `fetch` to absolute URLs;
  - `location.href`/`window.open` to external sites;
  - forms posting off-site;
  - `eval`, `innerHTML` with data, inline `<script>`;
  - WebRTC.
- Do not try to get around the scanner (encoding, string splitting, indirection). The AI review
  flags that pattern as HOLD and it is logged.
- Report what the gate said **verbatim** (verdict, scan_id, findings). Don't summarize a REFUSE
  as success.

## app.yml template

```yaml
version: 2
name: <APP_NAME>
query_warehouse: DEVCONTAINER_WH
install:
  commands:
    - ["npm", "install", "--no-audit", "--no-fund"]
build:
  commands:
    - ["npm", "run", "build"]
run:
  command: ["node", "server.js"]
```

The publisher replaces the database, schema, warehouse and build location with its own values.
Only `install`/`build`/`run`/`ignore`/`label`/`description`/`icon` are kept from your file.

## Check status

```sql
SELECT scan_id, app_name, mode, verdict, submitted_at FROM SAR_GATE.CORE.MY_SCANS ORDER BY submitted_at DESC;
SELECT app_name, status, url FROM SAR_GATE.CORE.MY_PUBLISHES ORDER BY requested_at DESC;
```
