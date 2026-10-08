#!/usr/bin/env bash
# End-to-end gate tests as the BUILDER test user (PAT), through the real procedures.
#   tests/e2e/run_e2e.sh <builder-sql-wrapper>
# The wrapper runs `snow sql` as the builder, e.g. a script that adds
#   -x --authenticator programmatic_access_token --user <builder> --token-file-path <pat> --role SAR_GATE_BUILDER
set -uo pipefail
B=${1:?builder sql wrapper}
E=$(cd "$(dirname "$0")" && pwd)
U=SAR_GATE_BUILDER_U

upload() {  # upload <local dir> <inbox folder>
  (cd "$E/$1" && find . -type f | while read -r f; do
     d=$(dirname "$f" | sed 's#^\./##; s#^\.$##')
     "$B" -q "PUT file://$E/$1/${f#./} @SAR_GATE.CORE.INBOX/$U/$2/$d AUTO_COMPRESS=FALSE OVERWRITE=TRUE" >/dev/null 2>&1
   done)
}
call() {  # call "<SQL CALL>" -> prints the VARIANT result
  "$B" --format json -q "$1" 2>&1 | python3 -c "
import json,sys
t=sys.stdin.read()
try:
  d=json.loads(t); print(list(d[0].values())[0])
except Exception: print(json.dumps({'raw': t[-800:]}))"
}
field() { python3 -c "import json,sys;v=json.loads(sys.argv[1]);print(v.get(sys.argv[2]) if isinstance(v,dict) else '')" "$1" "$2"; }

echo "== 1. form exfil -> REFUSE, publish refused"
upload form_exfil form_exfil
R=$(call "CALL SAR_GATE.CORE.SUBMIT_SCAN('GATE_FORM','form_exfil')"); S=$(field "$R" scan_id)
echo "   verdict: $(field "$R" verdict)"
P=$(call "CALL SAR_GATE.CORE.REQUEST_PUBLISH('$S')"); echo "   publish: $(field "$P" status) - $(field "$P" error)"

echo "== 2. external script -> REWRITE -> rewrite+rescan -> publish"
upload ext_script ext_script
R=$(call "CALL SAR_GATE.CORE.SUBMIT_SCAN('GATE_EXTSCRIPT','ext_script')"); S=$(field "$R" scan_id)
echo "   verdict: $(field "$R" verdict)"
P=$(call "CALL SAR_GATE.CORE.REQUEST_PUBLISH('$S')"); echo "   publish REWRITE scan directly: $(field "$P" status) - $(field "$P" error)"
W=$(call "CALL SAR_GATE.CORE.APPLY_REWRITE('$S')"); S2=$(field "$W" scan_id)
echo "   after rewrite: $(field "$W" verdict)"; echo "   diff:"; field "$W" diff | sed 's/^/      /'
W2=$(call "CALL SAR_GATE.CORE.APPLY_REWRITE('$S')"); echo "   second rewrite pass: $(field "$W2" verdict) - $(field "$W2" error)"
P=$(call "CALL SAR_GATE.CORE.REQUEST_PUBLISH('$S2')"); echo "   publish: $(field "$P" status) $(field "$P" url) $(field "$P" error)"
echo "$(field "$P" url)" > /tmp/sar_gate/extscript.url

echo "== 3. TOCTOU: scan clean, swap in exfil code, then publish"
upload ext_script toctou   # placeholder so folder exists
"$B" -q "REMOVE @SAR_GATE.CORE.INBOX/$U/toctou/" >/dev/null 2>&1
mkdir -p /tmp/sar_gate/toctou && cp -R "$E/hello/." /tmp/sar_gate/toctou/ && sed -i '' 's/GATE_HELLO/GATE_TOCTOU/' /tmp/sar_gate/toctou/app.yml
(cd /tmp/sar_gate/toctou && for f in server.js package.json app.yml; do "$B" -q "PUT file://$PWD/$f @SAR_GATE.CORE.INBOX/$U/toctou/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE" >/dev/null 2>&1; done)
R=$(call "CALL SAR_GATE.CORE.SUBMIT_SCAN('GATE_TOCTOU','toctou')"); S=$(field "$R" scan_id); D=$(field "$R" digest)
echo "   clean scan: $(field "$R" verdict) digest ${D:0:16}"
cat > /tmp/sar_gate/toctou/server.js <<'EOF'
const http = require("http");
http.createServer((req, res) => { res.end("SWAPPED AFTER SCAN: " + JSON.stringify(req.headers)); }).listen(8080, "0.0.0.0");
EOF
"$B" -q "PUT file:///tmp/sar_gate/toctou/server.js @SAR_GATE.CORE.INBOX/$U/toctou/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE" >/dev/null 2>&1
echo -n "   builder overwrite of FROZEN/$D: "; "$B" -q "PUT file:///tmp/sar_gate/toctou/server.js @SAR_GATE.CORE.FROZEN/$D/ OVERWRITE=TRUE" 2>&1 | grep -oiE 'not authorized|UPLOADED' | head -1
P=$(call "CALL SAR_GATE.CORE.REQUEST_PUBLISH('$S')"); echo "   publish: $(field "$P" status) digest $(field "$P" digest | cut -c1-16) url $(field "$P" url)"
echo "$(field "$P" url)" > /tmp/sar_gate/toctou.url

echo "== 4. obfuscated exfil (rules miss it) -> AI advisory must HOLD"
upload obfuscated obfuscated
R=$(call "CALL SAR_GATE.CORE.SUBMIT_SCAN('GATE_OBF','obfuscated')"); S=$(field "$R" scan_id)
echo "   verdict: $(field "$R" verdict)"; echo "   ai_review: $(field "$R" ai_review)"
P=$(call "CALL SAR_GATE.CORE.REQUEST_PUBLISH('$S')"); echo "   publish: $(field "$P" status) - $(field "$P" error)"

echo "== 5. someone else's scan id"
OTHER=$("$B" --format json -q "SELECT 'x'" >/dev/null; echo 00000000-0000-0000-0000-000000000000)
P=$(call "CALL SAR_GATE.CORE.REQUEST_PUBLISH('$OTHER')"); echo "   publish: $(field "$P" status) - $(field "$P" error)"
