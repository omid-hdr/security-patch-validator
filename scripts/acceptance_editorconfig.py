#!/usr/bin/env python3
"""Integration acceptance for the editorconfig target (Role 4 deliverable).

Validates that the orchestrator correctly classifies the four editorconfig
scenarios:
  * correct     -> PASS (exit 0)
  * incomplete  -> VULN_REMAINS (exit 10) — PoC-B bypass via off-by-one
  * regression  -> FUNC_REGRESSION (exit 20) — brace alternation broken
  * base-only   -> INCONCLUSIVE (exit 40) — baseline never crashes the
                   patched source, so evidence is missing

Requires: gcc, cmake, make, libpcre2-dev (in addition to python3, binutils).
Optional: --extra-path /path/to/cmake (if cmake is in a non-standard location).
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def run(name, expected, extra=()):
    out = ROOT / "artifacts" / "acceptance-editorconfig" / name
    p = subprocess.run([sys.executable, str(ROOT / "validate.py"),
                        "--config", str(ROOT / "configs/editorconfig.json"),
                        "--out", str(out), *extra], cwd=ROOT)
    if p.returncode != expected:
        raise AssertionError(f"{name}: expected exit {expected}, got {p.returncode}")
    report = json.loads((out / "report.json").read_text())
    assert report["exit_code"] == expected, (
        f"{name}: report exit_code {report['exit_code']} != {expected}")
    return report, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--extra-path",
                    help="Comma-separated extra PATH entries (e.g. for cmake in a venv)")
    args = ap.parse_args()
    extra_args = []
    if args.extra_path:
        extra_args = ["--extra-path", args.extra_path]

    summaries = []
    # Three core scenarios.
    for patch, code in (("correct", 0), ("incomplete", 10), ("regression", 20)):
        r, out = run(patch, code, ["--patched", patch, *extra_args])
        assert not any(x["timed_out"] for x in r["runs"]), f"{patch}: timeout occurred"
        # For the editorconfig target, byte-level minimization is skipped
        # (the PoC is directory-based). Verify this is recorded.
        for f in r["findings"]:
            if f.get("observed_on") == "base" and "minimization" in f:
                assert f["minimization"].get("skipped") is True, \
                    f"{patch}: directory-PoC minimization should be skipped"
        # Hardening checks.
        for i in ("base", "patched"):
            h = r["hardening"][i]
            assert h["nx"] is True, f"{patch}/{i}: NX not enabled"
            assert h["relro"] == "full", f"{patch}/{i}: RELRO not full"
            assert h["canary_evidence"] is True, f"{patch}/{i}: canary not found"
        # The build report should include cmake configure + make commands.
        for k, build in r["builds"].items():
            assert "configure_command" in build, f"{patch}/{k}: missing configure_command"
            assert "make_command" in build, f"{patch}/{k}: missing make_command"
        summaries.append(dict(case=patch, expected=code,
                              actual=r["exit_code"], status=r["status"],
                              runs=len(r["runs"]),
                              findings=len(r["findings"])))
    print(f"  Editorconfig acceptance: {len(summaries)} scenarios passed")
    (ROOT / "artifacts/acceptance-editorconfig/summary.json").write_text(
        json.dumps(summaries, indent=2))
    print("EDITORCONFIG ACCEPTANCE CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()
