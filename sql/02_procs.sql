-- 02_procs.sql — the gate's control plane.
--
-- Builder-callable (owner's rights):
--   SUBMIT_SCAN(app_name, app_path)   scan @INBOX/<CURRENT_USER()>/<app_path>
--   APPLY_REWRITE(scan_id)            one safe rewrite pass + rescan
--   REQUEST_PUBLISH(scan_id)          deploy the frozen digest to SAR_GATE.PROD (PUBLISH role)
-- Internal (no grant to builders): _RUN_SCAN_JOB, _AI_REVIEW, _READ_RESULT
--
-- Every value interpolated into a job spec is validated (regex) or comes from GATE_CONFIG.
USE ROLE SAR_GATE_ADMIN;
USE SCHEMA SAR_GATE.CORE;

CREATE FILE FORMAT IF NOT EXISTS JSON_FF TYPE = JSON STRIP_OUTER_ARRAY = FALSE;
GRANT USAGE ON FILE FORMAT JSON_FF TO ROLE SAR_GATE_PUBLISH;

CREATE TABLE IF NOT EXISTS GATE_CONFIG (key STRING, value STRING);
MERGE INTO GATE_CONFIG t USING (
  SELECT column1 k, column2 v FROM VALUES
    ('COMPUTE_POOL', 'SAR_GATE_POOL'),
    ('WAREHOUSE', 'DEVCONTAINER_WH'),
    ('BLESSED_REGISTRY', ''),        -- e.g. http://registry.<hash>.svc.spcs.internal:4873/
    ('ALLOWED_EAI', ''),             -- comma list of runtime EAIs apps may keep
    ('ALLOWED_BUILD_EAI', ''),
    ('CONSUMER_ROLE', 'SAR_GATE_CONSUMER'),
    ('AI_REVIEW', 'ON'),
    ('AI_MODEL', 'claude-sonnet-4-5'),
    ('AI_HOLD_CONFIDENCE', '0.6')) s ON t.key = s.k
WHEN NOT MATCHED THEN INSERT VALUES (s.k, s.v);
GRANT SELECT ON TABLE GATE_CONFIG TO ROLE SAR_GATE_PUBLISH;

CREATE OR REPLACE FUNCTION CFG(K STRING) RETURNS STRING AS
$$ (SELECT MAX(value) FROM SAR_GATE.CORE.GATE_CONFIG WHERE key = K) $$;
GRANT USAGE ON FUNCTION CFG(STRING) TO ROLE SAR_GATE_PUBLISH;

-- Read one JSON result file from @RESULTS
CREATE OR REPLACE PROCEDURE _READ_RESULT(FNAME STRING)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS OWNER AS
$$
DECLARE
  rs RESULTSET;
  v VARIANT DEFAULT NULL;
BEGIN
  IF (NOT REGEXP_LIKE(FNAME, '^[A-Za-z0-9_.-]+\\.json$')) THEN
    RETURN OBJECT_CONSTRUCT('verdict', 'ERROR', 'error', 'bad result file name');
  END IF;
  rs := (EXECUTE IMMEDIATE 'SELECT $1 AS V FROM @SAR_GATE.CORE.RESULTS/' || FNAME ||
                           ' (FILE_FORMAT => ''SAR_GATE.CORE.JSON_FF'')');
  FOR r IN rs DO v := r.V; END FOR;
  RETURN v;
END;
$$;

-- AI advisory. Tighten-only: may turn PASS into HOLD, never anything into PASS.
CREATE OR REPLACE PROCEDURE _AI_REVIEW(RES VARIANT)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS OWNER AS
$$
DECLARE
  out VARIANT;
  model STRING DEFAULT (SELECT SAR_GATE.CORE.CFG('AI_MODEL'));
BEGIN
  out := (SELECT AI_COMPLETE(
    model => :model,
    prompt => 'You are a security reviewer for web apps that will be published inside Snowflake '
      || '(Snowpark Container Services). The platform CSP allows inline script and eval, does not set '
      || 'form-action, and does not govern navigation. A deterministic scanner already passed this app; '
      || 'your job is to catch what pattern rules miss: obfuscated or encoded payloads, data sent off-site '
      || 'via navigation/forms/redirects/WebRTC, credential or token harvesting, hidden backdoors, '
      || 'cross-user data leakage. Ignore style issues. Judge ONLY the code below. '
      || 'Answer MALICIOUS or SUSPICIOUS only with concrete evidence (file + what it does).\n\n'
      || 'Scanner findings: ' || LEFT(TO_JSON(:RES:findings), 4000) || '\n\nSource files:\n'
      || LEFT(TO_JSON(:RES:ai_input), 60000),
    response_format => {
      'type': 'json',
      'schema': {'type': 'object',
                 'properties': {'verdict': {'type': 'string', 'enum': ['BENIGN', 'SUSPICIOUS', 'MALICIOUS']},
                                'confidence': {'type': 'number'},
                                'evidence': {'type': 'string'}},
                 'required': ['verdict', 'confidence', 'evidence']}}));
  RETURN TRY_PARSE_JSON(out::STRING);
EXCEPTION
  WHEN OTHER THEN
    -- AI unavailable: record it; do not block on infra, do not upgrade anything either
    RETURN OBJECT_CONSTRUCT('verdict', 'UNAVAILABLE', 'error', SQLERRM);
END;
$$;

-- Run the scanner job (scan or rewrite), apply AI advisory, record SCAN_RUNS.
CREATE OR REPLACE PROCEDURE _RUN_SCAN_JOB(MODE STRING, SCAN_ID STRING, APP_NAME STRING,
                                          APP_PATH STRING, PARENT_SCAN_ID STRING)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS OWNER AS
$$
DECLARE
  spec STRING;
  res VARIANT;
  ai VARIANT DEFAULT NULL;
  verdict STRING;
  job STRING DEFAULT 'SAR_GATE.CORE.GATE_' || UPPER(REPLACE(:SCAN_ID, '-', '_'));
BEGIN
  spec := 'spec:\n  containers:\n  - name: scanner\n    image: /sar_gate/core/images/sar-gate-scanner:latest\n'
       || '    env:\n'
       || '      MODE: "' || :MODE || '"\n'
       || '      SCAN_ID: "' || :SCAN_ID || '"\n'
       || '      APP_PATH: "' || COALESCE(:APP_PATH, '') || '"\n'
       || '      PARENT_SCAN_ID: "' || COALESCE(:PARENT_SCAN_ID, '') || '"\n'
       || '      BLESSED_REGISTRY: "' || COALESCE(SAR_GATE.CORE.CFG('BLESSED_REGISTRY'), '') || '"\n'
       || '      ALLOWED_EAI: "' || COALESCE(SAR_GATE.CORE.CFG('ALLOWED_EAI'), '') || '"\n'
       || '      ALLOWED_BUILD_EAI: "' || COALESCE(SAR_GATE.CORE.CFG('ALLOWED_BUILD_EAI'), '') || '"\n'
       || '    volumeMounts:\n'
       || '    - {name: inbox, mountPath: /inbox}\n'
       || '    - {name: frozen, mountPath: /frozen}\n'
       || '    - {name: results, mountPath: /results}\n'
       || '  volumes:\n'
       || '  - {name: inbox, source: "@SAR_GATE.CORE.INBOX", uid: 1001, gid: 1001}\n'
       || '  - {name: frozen, source: "@SAR_GATE.CORE.FROZEN", uid: 1001, gid: 1001}\n'
       || '  - {name: results, source: "@SAR_GATE.CORE.RESULTS", uid: 1001, gid: 1001}\n';
  -- no EXTERNAL_ACCESS_INTEGRATIONS: the scanner runs with no egress
  BEGIN
    EXECUTE IMMEDIATE 'EXECUTE JOB SERVICE IN COMPUTE POOL ' || SAR_GATE.CORE.CFG('COMPUTE_POOL')
      || ' NAME = ' || :job || ' FROM SPECIFICATION $' || '$' || :spec || '$' || '$';
  EXCEPTION
    WHEN OTHER THEN NULL;  -- a crashed job leaves no result file -> recorded as ERROR below
  END;
  CALL SAR_GATE.CORE._READ_RESULT(:SCAN_ID || '.json') INTO :res;
  IF (res IS NULL) THEN
    res := OBJECT_CONSTRUCT('verdict', 'ERROR', 'error', 'scanner wrote no result');
  END IF;
  verdict := res:verdict::STRING;

  IF (verdict = 'PASS' AND SAR_GATE.CORE.CFG('AI_REVIEW') = 'ON') THEN
    CALL SAR_GATE.CORE._AI_REVIEW(:res) INTO :ai;
    IF (ai:verdict::STRING IN ('MALICIOUS', 'SUSPICIOUS')
        AND ai:confidence::FLOAT >= SAR_GATE.CORE.CFG('AI_HOLD_CONFIDENCE')::FLOAT) THEN
      verdict := 'HOLD';  -- tighten only
    END IF;
  END IF;

  INSERT INTO SAR_GATE.CORE.SCAN_RUNS (scan_id, parent_scan_id, submitted_by, app_name, app_path, mode,
                                       verdict, digest, counts, findings, rewrites, diff, ai_review, error,
                                       finished_at)
    SELECT :SCAN_ID, NULLIF(:PARENT_SCAN_ID, ''), CURRENT_USER(), :APP_NAME, :APP_PATH, :MODE,
           :verdict, :res:digest::STRING, :res:counts, :res:findings, :res:rewrites, :res:diff::STRING, :ai,
           :res:error::STRING, CURRENT_TIMESTAMP();
  RETURN OBJECT_CONSTRUCT('scan_id', :SCAN_ID, 'verdict', :verdict, 'digest', :res:digest,
                          'counts', :res:counts, 'ai_review', :ai, 'error', :res:error,
                          'rewrites', :res:rewrites, 'diff', LEFT(:res:diff::STRING, 4000),
                          'findings', ARRAY_SLICE(:res:findings, 0, 25),
                          'next', CASE :verdict
                                    WHEN 'PASS' THEN 'CALL SAR_GATE.CORE.REQUEST_PUBLISH(''' || :SCAN_ID || ''')'
                                    WHEN 'REWRITE' THEN 'CALL SAR_GATE.CORE.APPLY_REWRITE(''' || :SCAN_ID || ''')'
                                    WHEN 'HOLD' THEN 'needs human review (WARN findings or AI advisory)'
                                    ELSE 'fix the REFUSE findings and submit again' END);
END;
$$;

CREATE OR REPLACE PROCEDURE SUBMIT_SCAN(APP_NAME STRING, APP_PATH STRING)
RETURNS VARIANT LANGUAGE SQL
COMMENT = 'Scan @SAR_GATE.CORE.INBOX/<your user>/<APP_PATH>. Returns verdict and next step.'
EXECUTE AS OWNER
AS
$$
DECLARE
  sid STRING DEFAULT UUID_STRING();
  full_path STRING;
  r VARIANT;
BEGIN
  IF (NOT REGEXP_LIKE(APP_NAME, '^[A-Z][A-Z0-9_]{0,59}$')) THEN
    RETURN OBJECT_CONSTRUCT('verdict', 'ERROR', 'error', 'APP_NAME must match ^[A-Z][A-Z0-9_]{0,59}$');
  END IF;
  IF (NOT REGEXP_LIKE(APP_PATH, '^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$')) THEN
    RETURN OBJECT_CONSTRUCT('verdict', 'ERROR', 'error', 'APP_PATH must be a relative folder (letters, digits, _ - /)');
  END IF;
  -- callers can only scan their own folder
  IF (NOT REGEXP_LIKE(CURRENT_USER(), '^[A-Za-z0-9_.@-]+$')) THEN
    RETURN OBJECT_CONSTRUCT('verdict', 'ERROR', 'error', 'user name not supported as an inbox folder');
  END IF;
  full_path := CURRENT_USER() || '/' || APP_PATH;
  CALL SAR_GATE.CORE._RUN_SCAN_JOB('scan', :sid, :APP_NAME, :full_path, NULL) INTO :r;
  RETURN r;
END;
$$;

CREATE OR REPLACE PROCEDURE APPLY_REWRITE(PARENT_SCAN_ID STRING)
RETURNS VARIANT LANGUAGE SQL
COMMENT = 'Apply the safe rewrites from a REWRITE scan once, then rescan.'
EXECUTE AS OWNER
AS
$$
DECLARE
  sid STRING DEFAULT UUID_STRING();
  p_owner STRING; p_verdict STRING; p_mode STRING; p_app STRING;
  children INT;
  r VARIANT;
BEGIN
  SELECT MAX(submitted_by), MAX(verdict), MAX(mode), MAX(app_name)
    INTO :p_owner, :p_verdict, :p_mode, :p_app
    FROM SAR_GATE.CORE.SCAN_RUNS WHERE scan_id = :PARENT_SCAN_ID;
  SELECT COUNT(*) INTO :children FROM SAR_GATE.CORE.SCAN_RUNS WHERE parent_scan_id = :PARENT_SCAN_ID;
  IF (p_owner IS NULL OR p_owner <> CURRENT_USER()) THEN
    RETURN OBJECT_CONSTRUCT('verdict', 'ERROR', 'error', 'unknown scan, or not yours');
  END IF;
  IF (p_verdict <> 'REWRITE') THEN
    RETURN OBJECT_CONSTRUCT('verdict', 'ERROR', 'error', 'only REWRITE scans can be rewritten (got ' || p_verdict || ')');
  END IF;
  IF (p_mode <> 'scan' OR children > 0) THEN
    RETURN OBJECT_CONSTRUCT('verdict', 'ERROR', 'error', 'one rewrite pass per submission; fix the code and submit again');
  END IF;
  CALL SAR_GATE.CORE._RUN_SCAN_JOB('rewrite', :sid, :p_app, NULL, :PARENT_SCAN_ID) INTO :r;
  RETURN r;
END;
$$;

GRANT USAGE ON PROCEDURE SUBMIT_SCAN(STRING, STRING) TO ROLE SAR_GATE_BUILDER;
GRANT USAGE ON PROCEDURE APPLY_REWRITE(STRING) TO ROLE SAR_GATE_BUILDER;

-- ---------------------------------------------------------------------------
-- Publish: owned by SAR_GATE_PUBLISH. Builders can CALL it, never hold the role.
-- ---------------------------------------------------------------------------
USE ROLE SAR_GATE_PUBLISH;
USE SCHEMA SAR_GATE.CORE;

CREATE OR REPLACE PROCEDURE _READ_PUBLISH_RESULT(FNAME STRING)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS OWNER AS
$$
DECLARE
  rs RESULTSET;
  v VARIANT DEFAULT NULL;
BEGIN
  IF (NOT REGEXP_LIKE(FNAME, '^[A-Za-z0-9_.-]+\\.publish\\.json$')) THEN
    RETURN OBJECT_CONSTRUCT('status', 'FAILED', 'error', 'bad file name');
  END IF;
  rs := (EXECUTE IMMEDIATE 'SELECT $1 AS V FROM @SAR_GATE.CORE.RESULTS/' || FNAME ||
                           ' (FILE_FORMAT => ''SAR_GATE.CORE.JSON_FF'')');
  FOR r IN rs DO v := r.V; END FOR;
  RETURN v;
END;
$$;

CREATE OR REPLACE PROCEDURE REQUEST_PUBLISH(SCAN_ID STRING)
RETURNS VARIANT LANGUAGE SQL
COMMENT = 'Publish a PASS scan: deploys the frozen digest to SAR_GATE.PROD and grants USAGE to consumers.'
EXECUTE AS OWNER
AS
$$
DECLARE
  s_owner STRING; s_verdict STRING; s_digest STRING; s_app STRING; s_err STRING;
  other_owner STRING;
  pid STRING DEFAULT UUID_STRING();
  spec STRING;
  res VARIANT;
  job STRING DEFAULT 'SAR_GATE.CORE.PUB_' || UPPER(REPLACE(:SCAN_ID, '-', '_'));
BEGIN
  SELECT MAX(submitted_by), MAX(verdict), MAX(digest), MAX(app_name), MAX(error)
    INTO :s_owner, :s_verdict, :s_digest, :s_app, :s_err
    FROM SAR_GATE.CORE.SCAN_RUNS WHERE scan_id = :SCAN_ID;
  IF (s_owner IS NULL OR s_owner <> CURRENT_USER()) THEN
    RETURN OBJECT_CONSTRUCT('status', 'REFUSED', 'error', 'unknown scan, or not yours');
  END IF;
  IF (s_verdict <> 'PASS' OR s_err IS NOT NULL) THEN
    RETURN OBJECT_CONSTRUCT('status', 'REFUSED', 'error', 'scan verdict is ' || s_verdict || ', only PASS publishes');
  END IF;
  IF (NOT REGEXP_LIKE(s_digest, '^[0-9a-f]{64}$') OR NOT REGEXP_LIKE(s_app, '^[A-Z][A-Z0-9_]{0,59}$')) THEN
    RETURN OBJECT_CONSTRUCT('status', 'REFUSED', 'error', 'invalid digest or app name');
  END IF;
  -- an app name belongs to whoever published it first
  SELECT MAX(requested_by) INTO :other_owner FROM SAR_GATE.CORE.PUBLISH_LOG
    WHERE app_name = :s_app AND status = 'PUBLISHED' AND requested_by <> CURRENT_USER();
  IF (other_owner IS NOT NULL) THEN
    RETURN OBJECT_CONSTRUCT('status', 'REFUSED', 'error', 'app name ' || s_app || ' is owned by another user');
  END IF;

  spec := 'spec:\n  containers:\n  - name: publisher\n    image: /sar_gate/core/images/sar-gate-publisher:latest\n'
       || '    env:\n'
       || '      SCAN_ID: "' || :SCAN_ID || '"\n'
       || '      DIGEST: "' || :s_digest || '"\n'
       || '      APP_NAME: "' || :s_app || '"\n'
       || '      TARGET_DB: "SAR_GATE"\n      TARGET_SCHEMA: "PROD"\n'
       || '      QUERY_WAREHOUSE: "' || SAR_GATE.CORE.CFG('WAREHOUSE') || '"\n'
       || '      CONSUMER_ROLE: "' || SAR_GATE.CORE.CFG('CONSUMER_ROLE') || '"\n'
       || '      BUILD_JOB_LOCATION: "SAR_GATE.BUILD"\n'
       || '    volumeMounts:\n    - {name: frozen, mountPath: /frozen}\n    - {name: results, mountPath: /results}\n'
       || '  volumes:\n'
       || '  - {name: frozen, source: "@SAR_GATE.CORE.FROZEN", uid: 1001, gid: 1001}\n'
       || '  - {name: results, source: "@SAR_GATE.CORE.RESULTS", uid: 1001, gid: 1001}\n';
  BEGIN
    EXECUTE IMMEDIATE 'EXECUTE JOB SERVICE IN COMPUTE POOL ' || SAR_GATE.CORE.CFG('COMPUTE_POOL')
      || ' NAME = ' || :job || ' QUERY_WAREHOUSE = ' || SAR_GATE.CORE.CFG('WAREHOUSE')
      || ' FROM SPECIFICATION $' || '$' || :spec || '$' || '$';
  EXCEPTION
    WHEN OTHER THEN NULL;  -- job exits non-zero on failure; the result file has the reason
  END;
  CALL SAR_GATE.CORE._READ_PUBLISH_RESULT(:SCAN_ID || '.publish.json') INTO :res;
  IF (res IS NULL) THEN
    res := OBJECT_CONSTRUCT('status', 'FAILED', 'error', 'publisher wrote no result');
  END IF;
  INSERT INTO SAR_GATE.CORE.PUBLISH_LOG (publish_id, scan_id, digest, app_name, requested_by, status,
                                         service, url, detail)
    SELECT :pid, :SCAN_ID, :s_digest, :s_app, CURRENT_USER(), :res:status::STRING, :res:service::STRING,
           :res:url::STRING, OBJECT_DELETE(:res, 'deploy_log_tail');
  RETURN OBJECT_CONSTRUCT('status', :res:status, 'service', :res:service, 'url', :res:url,
                          'error', :res:error, 'scan_id', :SCAN_ID, 'digest', :s_digest);
END;
$$;

GRANT USAGE ON PROCEDURE REQUEST_PUBLISH(STRING) TO ROLE SAR_GATE_BUILDER;
