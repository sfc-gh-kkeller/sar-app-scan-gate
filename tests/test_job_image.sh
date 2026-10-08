#!/usr/bin/env bash
# Offline test of the SPCS job image: scan -> rewrite -> path-escape attempt.
# Runs with --network none, so it also proves the scanner needs no egress.
set -euo pipefail
IMG=${IMG:-sar-gate-scanner:test}
T=$(mktemp -d)
mkdir -p "$T/inbox" "$T/frozen" "$T/results"
cp -R "$(dirname "$0")/fixtures/bad/external-script" "$T/inbox/app1"
chmod -R 777 "$T"

run() {
  docker run --rm --platform linux/amd64 --network none \
    -v "$T/inbox:/inbox" -v "$T/frozen:/frozen" -v "$T/results:/results" \
    -e BLESSED_REGISTRY=http://blessed.test/ "$@" "$IMG"
}

echo "== scan (expect REWRITE)";            run -e MODE=scan -e APP_PATH=app1 -e SCAN_ID=s1
echo "== rewrite + rescan (expect PASS)";   run -e MODE=rewrite -e PARENT_SCAN_ID=s1 -e SCAN_ID=s2
echo "== path escape (expect ERROR)";       run -e MODE=scan -e APP_PATH=../frozen -e SCAN_ID=s3 || true
echo "== frozen digests"; ls "$T/frozen"
echo "== s2 rewrite diff"; cat "$T/results/s2.diff"
python3 - "$T" <<'EOF'
import json, sys
t = sys.argv[1]
v = {s: json.load(open(f"{t}/results/{s}.json"))["verdict"] for s in ("s1", "s2", "s3")}
print("verdicts", v)
assert v == {"s1": "REWRITE", "s2": "PASS", "s3": "ERROR"}, v
EOF
# The publisher re-hashes the frozen tree; it must match what the rewrite scan recorded.
D=$(python3 -c "import json;print(json.load(open('$T/results/s2.json'))['digest'])")
docker run --rm --platform linux/amd64 --network none -v "$T/frozen:/frozen" --entrypoint python3 "$IMG" -c "
import sys, shutil, tempfile; sys.path.insert(0, '/gate/scanner'); import gate
w = tempfile.mkdtemp() + '/a'
shutil.copytree('/frozen/$D', w, ignore=shutil.ignore_patterns(*gate.SKIP_DIRS, '.gate_frozen'))
d = gate.digest(w)[0]; print('rehash of frozen rewrite tree matches:', d == '$D'); assert d == '$D'"
echo "JOB IMAGE OK"
