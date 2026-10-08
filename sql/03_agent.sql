-- 03_agent.sql — Cortex Agent that drives the gate.
--
-- RUN_GATE_AGENT(prompt) is CALLER'S RIGHTS: the Cortex coding sandbox runs as the calling
-- user/role (SAR_GATE_BUILDER), so the agent has exactly the builder's power:
-- write its own @INBOX folder and call SUBMIT_SCAN / APPLY_REWRITE / REQUEST_PUBLISH.
-- It cannot create prod apps even if the model tries.
--
-- Tool config is inline in AGENT_RUN: code_toolset_all only activates there, not via an
-- agent object (observed in snowflake-vibe-code/agent-2-agent).
USE ROLE SAR_GATE_ADMIN;
USE SCHEMA SAR_GATE.CORE;

CREATE STAGE IF NOT EXISTS SKILLS ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE') DIRECTORY = (ENABLE = TRUE);
GRANT READ ON STAGE SKILLS TO ROLE SAR_GATE_BUILDER;
-- upload:  PUT file://agent/SKILL.md @SAR_GATE.CORE.SKILLS/sar-gate-publisher/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE;

CREATE OR REPLACE PROCEDURE RUN_GATE_AGENT(PROMPT STRING)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
COMMENT = 'Build/scan/publish an app through sar-app-scan-gate, as the caller.'
EXECUTE AS CALLER
AS
$$
import json

SYSTEM = (
    "You build small web apps and publish them ONLY through the sar-app-scan-gate procedures "
    "(SUBMIT_SCAN, APPLY_REWRITE, REQUEST_PUBLISH in SAR_GATE.CORE). Follow the sar-gate-publisher "
    "skill exactly. Work in /tmp/apps. Never run snow app deploy, CREATE APPLICATION SERVICE or GRANT. "
    "At the end, report: app name, every scan_id with its verdict, findings for any REFUSE/HOLD, "
    "and the published URL if REQUEST_PUBLISH returned PUBLISHED."
)


def run(session, prompt):
    if not prompt or not prompt.strip():
        return {"error": "describe the app"}
    body = {
        "models": {"orchestration": "auto"},
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
        "tools": [{"tool_spec": {"type": "code_toolset_all", "name": "code_toolset_all"}}],
        "tool_resources": {"code_toolset_all": {"permission_policy": {"type": "always_allow"}}},
        "instructions": {"system": SYSTEM},
        "skills": [{"name": "sar-gate-publisher",
                    "source": {"type": "STAGE", "path": "@SAR_GATE.CORE.SKILLS/sar-gate-publisher"}}],
    }
    dd = "$" + "$"
    row = session.sql(f"SELECT SNOWFLAKE.CORTEX.AGENT_RUN({dd}{json.dumps(body)}{dd}, TRUE) AS R").collect()[0]
    resp = json.loads(str(row["R"]))
    texts = [c.get("text", "") for c in resp.get("content", []) if c.get("type") == "text"]
    md = resp.get("metadata", {})
    return {"response": "\n".join(texts), "thread_id": md.get("thread_id"), "status": md.get("status")}
$$;

GRANT USAGE ON PROCEDURE RUN_GATE_AGENT(STRING) TO ROLE SAR_GATE_BUILDER;
