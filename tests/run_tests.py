#!/usr/bin/env python3
"""Run gate.py over every fixture and compare with expected.json.

  python3 tests/run_tests.py            # all fixtures
  python3 tests/run_tests.py -v         # show findings on failure
Exit 0 only if every fixture matches its verdict and all expected rules fired.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scanner"))
import gate  # noqa: E402

BLESSED = "http://blessed.test/"
FIX = os.path.join(HERE, "fixtures")


def fixtures():
    for group in ("bad", "good"):
        base = os.path.join(FIX, group)
        for name in sorted(os.listdir(base)):
            yield f"{group}/{name}", os.path.join(base, name)


def rewrite_roundtrip(name, path, res):
    """REWRITE fixtures: rewrite.py then rescan must give PASS."""
    with tempfile.TemporaryDirectory() as tmp:
        scan_json = os.path.join(tmp, "scan.json")
        json.dump(res, open(scan_json, "w"))
        out = os.path.join(tmp, "app")
        p = subprocess.run([sys.executable, os.path.join(HERE, "..", "scanner", "rewrite.py"),
                            path, scan_json, out, "--diff", os.path.join(tmp, "d.diff")],
                           capture_output=True, text=True)
        if p.returncode:
            return "rewrite failed: " + p.stderr[-200:]
        again = gate.scan(out, BLESSED)
        left = [f["rule"] for f in again["findings"] if f["class"] != "INFO"]
        return None if again["verdict"] == "PASS" else f"rescan {again['verdict']} {left}"


def main():
    # Fixtures are generated (the fake .env one is gitignored on purpose), so always rebuild them.
    subprocess.run([sys.executable, os.path.join(HERE, "make_fixtures.py")], check=True)
    verbose = "-v" in sys.argv
    fails = 0
    for name, path in fixtures():
        exp = json.load(open(os.path.join(path, "expected.json")))
        res = gate.scan(path, BLESSED)
        fired = {f["rule"] for f in res["findings"]}
        missing = [r for r in exp["rules"] if r not in fired]
        ok = res["verdict"] == exp["verdict"] and not missing
        note = ""
        if ok and exp["verdict"] == "REWRITE":
            err = rewrite_roundtrip(name, path, res)
            ok, note = err is None, (" rewrite->rescan PASS" if err is None else f" {err}")
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name:38} expected {exp['verdict']:8} got {res['verdict']:8}"
              + (f" missing {missing}" if missing else "") + note)
        if not ok and verbose:
            for f in res["findings"]:
                print(f"       {f['class']:8} {f['rule']:30} {f['file']}:{f['line']}")
    total = sum(1 for _ in fixtures())
    print(f"\n{total - fails}/{total} fixtures pass")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
