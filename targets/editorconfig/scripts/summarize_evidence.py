#!/usr/bin/env python3
"""Generate a summary table of all evidence runs.

Reads the per-test log files under evidence/<version>/<build>/<test-id>.log
and prints a compact summary table. Used by Role 1 to produce the evidence
summary referenced by TARGETS.md.
"""
import os
import re
import sys
from pathlib import Path


def parse_log(path: Path) -> dict:
    """Extract exit code, signal, sanitizer detection from a log file."""
    text = path.read_text()
    rc_match = re.search(r"exit_code=(\S+)", text)
    rc = rc_match.group(1) if rc_match else "?"
    asan = "AddressSanitizer" in text
    ubsan = "runtime error:" in text
    stack_smash = "stack smashing detected" in text
    fortify = "buffer overflow detected" in text
    # First non-empty content line after the `$ ...` echo.
    out_line = ""
    for line in text.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("exit_code="):
            break
        out_line = line[:70]
        break
    return dict(rc=rc, asan=asan, ubsan=ubsan, stack_smash=stack_smash,
                fortify=fortify, out_line=out_line)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    evidence = root / "evidence"
    if not evidence.exists():
        print(f"No evidence directory at {evidence}", file=sys.stderr)
        return 2

    versions = ["base", "correct", "incomplete", "regression"]
    builds = ["normal", "asan"]
    tests = ["poc-A-original", "poc-B-bypass",
             "func-brace-match", "func-brace-nomatch"]

    print(f"# Evidence summary (Role 1, target: editorconfig)")
    print()
    print(f"| Version | Build | Test | rc | ASan | StackSmash | Output (first line) |")
    print(f"|---|---|---|---|---|---|---|")
    for v in versions:
        for b in builds:
            for t in tests:
                p = evidence / v / b / f"{t}.log"
                if not p.exists():
                    continue
                info = parse_log(p)
                asan = "✓" if info["asan"] else ""
                smash = "✓" if info["stack_smash"] else ""
                out = info["out_line"].replace("|", "\\|")
                print(f"| {v} | {b} | {t} | {info['rc']} | {asan} | {smash} | {out} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
