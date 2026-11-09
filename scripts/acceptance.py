#!/usr/bin/env python3
"""Integration acceptance: deliberately broken patches should be correctly rejected."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def run(name, expected, extra=()):
    out = ROOT / "artifacts" / "acceptance" / name
    p = subprocess.run([sys.executable, str(ROOT / "validate.py"), "--out", str(out), *extra], cwd=ROOT)
    if p.returncode != expected:
        raise AssertionError(f"{name}: expected exit {expected}, got {p.returncode}")
    report = json.loads((out / "report.json").read_text())
    assert report["exit_code"] == expected
    return report, out


def main():
    subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, check=True)
    summaries = []
    for patch, code in (("correct", 0), ("incomplete", 10), ("regression", 20)):
        r, out = run(patch, code, ["--patched", patch])
        assert not any(x["timed_out"] for x in r["runs"])
        f = next(x for x in r["findings"] if x.get("observed_on") == "base")
        assert f["minimized_size"] == 16 and f["minimization"]["one_minimal"]
        assert f["stable"] and len(f["minimized_replays"]) >= 3
        assert f["patch_correlation"]["relation"] == "supported"
        for i in ("base", "patched"):
            assert r["hardening"][i]["nx"] is True
            assert r["hardening"][i]["relro"] == "full"
            assert r["hardening"][i]["canary_evidence"] is True
        if patch == "correct":
            replay = out / f["id"] / "bundle" / "replay.py"
            p = subprocess.run([sys.executable, str(replay)], capture_output=True, text=True, timeout=30)
            assert p.returncode != 0 and "stack-buffer-overflow" in p.stderr
        summaries.append(dict(case=patch, expected=code, actual=r["exit_code"], status=r["status"], runs=len(r["runs"])))
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        # Unseen filename and a syntactically different equivalent guard.
        source = td / "unseen.c"
        source.write_text((ROOT / "targets/name-length/correct.c").read_text().replace(
            "strlen(argv[1]) >= sizeof(name)", "sizeof(name) <= strlen(argv[1])"))
        r, _ = run("unseen", 0, ["--patched-source", str(source)])
        assert r["loaded_regression_tests"] >= 1
        summaries.append(dict(case="unseen-equivalent-guard", expected=0, actual=r["exit_code"]))
        # Correct named source can be vulnerable: no name-based decisions.
        source.write_text((ROOT / "targets/name-length/base.c").read_text())
        r, _ = run("unseen-vulnerable", 10, ["--patched-source", str(source)])
        summaries.append(dict(case="unseen-vulnerable", expected=10, actual=r["exit_code"]))
        # A new confirmed error must remain visible independently of the old one.
        source.write_text('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
 if (argc != 2) return 1;
 char name[16];
 if (strlen(argv[1]) >= 16) {
  char *p = malloc(8); p[0] = 'x'; free(p);
  volatile char x = p[0]; (void)x; return 2;
 }
 strcpy(name, argv[1]); printf("%zu\\n", strlen(name)); return 0;
}
''')
        r, _ = run("new-issue", 10, ["--patched-source", str(source)])
        assert any(x["status"] == "New Issue" for x in r["findings"])
        assert r["flags"]["security_issue"] and not r["flags"]["functional_regression"]
        summaries.append(dict(case="new-issue", expected=10, actual=r["exit_code"]))
        # Baseline fails to reproduce: must not pass merely because patched looks fine.
        r, _ = run("no-baseline-bug", 40, ["--base-source", str(ROOT / "targets/name-length/correct.c")])
        summaries.append(dict(case="no-baseline-bug", expected=40, actual=r["exit_code"]))
        bad = td / "bad.c"
        bad.write_text("this is not valid C;")
        r, _ = run("build-error", 30, ["--patched-source", str(bad)])
        summaries.append(dict(case="build-error", expected=30, actual=r["exit_code"]))
        r, _ = run("missing-config", 30, ["--config", str(td / "missing.json")])
        summaries.append(dict(case="missing-config", expected=30, actual=r["exit_code"]))
        # Same engine, different buffer size and independent oracle/config.
        config = json.loads((ROOT / "configs/name-length.json").read_text())
        config["name"] = "unseen-capacity-32"
        for key in ("base", "correct", "incomplete", "regression"):
            path = td / f"capacity32-{key}.c"
            path.write_text((ROOT / f"targets/name-length/{key}.c").read_text().replace("name[16]", "name[32]"))
            config["sources"][key] = str(path)
        config["security_tests"] = [dict(id="length-32", input="A"*32, expected_exit=2, expected_stdout=""),
                                    dict(id="length-40", input="A"*40, expected_exit=2, expected_stdout="")]
        config["functional_tests"].append(dict(id="length-31", input="B"*31, expected_exit=0, expected_stdout="31\n"))
        cfg = td / "capacity32.json"
        cfg.write_text(json.dumps(config))
        r, _ = run("capacity32", 0, ["--config", str(cfg)])
        assert r["findings"][0]["minimized_size"] == 32
        summaries.append(dict(case="unseen-capacity-32", expected=0, actual=r["exit_code"]))
    (ROOT / "artifacts/acceptance/summary.json").write_text(json.dumps(summaries, indent=2))
    print("ALL ACCEPTANCE CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()
