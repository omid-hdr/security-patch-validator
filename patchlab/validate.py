import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from .runner import controlled_env, execute, same_error, sha256
from .evidence import bundle, correlate, hardening, minimize

ROOT = Path(__file__).resolve().parents[1]
STATUS = {0: "PASS", 10: "VULN_REMAINS", 20: "FUNC_REGRESSION",
          30: "BUILD_OR_CONFIG_ERROR", 40: "INCONCLUSIVE"}


def git(*args):
    p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=15)
    return p.stdout.strip() if p.returncode == 0 else None


def load_config(path):
    c = json.loads(Path(path).read_text())
    for key in ("name", "sources", "builds", "run", "security_tests", "functional_tests", "expected_error", "hardening_required"):
        if key not in c:
            raise ValueError(f"Missing config field: {key}")
    if not all(b in c["builds"] for b in ("normal", "sanitized")):
        raise ValueError("Both normal and sanitized build commands are required")
    if c["run"]["mode"] not in ("argv", "file", "stdin") or not isinstance(c["run"]["argv"], list):
        raise ValueError("run requires argv list and mode argv/file/stdin")
    if c["run"].get("replays", 3) < 3:
        raise ValueError("At least three replays required")
    if not c["security_tests"] or not c["functional_tests"]:
        raise ValueError("Security and independent functional tests cannot be empty")
    if not (0 < c["run"].get("timeout", 15) <= 60):
        raise ValueError("Timeout must be in (0,60]")
    return c


def data_for(test):
    if "input_repeat" in test:
        value, count = test["input_repeat"]
        if not isinstance(count, int) or not 0 <= count <= 100000:
            raise ValueError("Invalid input_repeat count")
        return (value * count).encode()
    if "hex" in test:
        return bytes.fromhex(test["hex"])
    return test["input"].encode("utf-8")


def oracle(result, case):
    return (not result["timed_out"] and not result["abnormal"]
            and result["exit_code"] == case["expected_exit"]
            and result["stdout"] == case["expected_stdout"])


def decide(flags):
    # Assignment precedence, independent of file names or expected scenario.
    for code, key in ((30, "build_or_config_error"), (40, "inconclusive"),
                      (20, "functional_regression"), (10, "security_issue")):
        if flags.get(key):
            return code
    return 0


def validate(config_path, patched, output, base="base", patched_source=None, base_source=None):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "status": None, "exit_code": None,
              "flags": dict(build_or_config_error=False, inconclusive=False,
                            functional_regression=False, security_issue=False),
              "runs": [], "findings": [], "functional_tests": [], "hardening": {},
              "regression_tests": [], "errors": [], "builds": {},
              "scope": "one educational target; observed tests are not proof of universal safety"}
    flags = report["flags"]

    def finish():
        code = decide(flags)
        report.update(exit_code=code, status=STATUS[code])
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
        text = [f"{report['status']} (exit {code})", f"Findings: {len(report['findings'])}",
                f"Functional regression: {flags['functional_regression']}",
                f"Incomplete evidence: {flags['inconclusive']}"]
        text += [f"- {x['status']}: {x.get('error_type')}" for x in report["findings"]]
        text += [f"ERROR: {x}" for x in report["errors"]]
        (output / "summary.txt").write_text("\n".join(text) + "\n")
        print("\n".join(text))
        print(f"Evidence: {output / 'report.json'}")
        return code

    try:
        c = load_config(config_path)
        sources = {"base": Path(base_source).resolve() if base_source else ROOT / c["sources"][base],
                   "patched": Path(patched_source).resolve() if patched_source else ROOT / c["sources"][patched]}
        for source in sources.values():
            if not source.is_file():
                raise ValueError(f"Missing source: {source}")
        report["target"] = c["name"]
        report["config"] = c
        report["provenance"] = dict(commit=git("rev-parse", "HEAD"),
            dirty=bool(git("status", "--porcelain")), platform=platform.platform(),
            source_sha256={k: sha256(v) for k, v in sources.items()},
            source_paths={k: str(v) for k, v in sources.items()},
            environment=controlled_env())
        binaries = {}
        for version, source in sources.items():
            for build, template in c["builds"].items():
                binary = output / f"{version}-{build}"
                command = [x.replace("{source}", str(source)).replace("{binary}", str(binary)) for x in template]
                result = execute(command, ROOT, timeout=60)
                report["builds"][f"{version}/{build}"] = dict(command=command, result=result)
                if result["exit_code"] != 0 or result["timed_out"] or not binary.exists():
                    raise ValueError(f"Build failed: {version}/{build}: {result['stderr'][:1000]}")
                report["builds"][f"{version}/{build}"]["binary_sha256"] = sha256(binary)
                binaries[version, build] = binary
        print("Built corresponding normal/sanitized binaries", flush=True)
        for version in sources:
            h = hardening(binaries[version, "normal"])
            report["hardening"][version] = h
            for k, v in c["hardening_required"].items():
                if h.get(k) != v:
                    flags["inconclusive"] = True
                    report["errors"].append(f"Required hardening mismatch {version}: {k}, got {h.get(k)}, expected {v}")
        for field in ("nx", "pie", "relro", "canary_evidence"):
            a, b = report["hardening"]["base"][field], report["hardening"]["patched"][field]
            if a != b:
                report.setdefault("hardening_changes", []).append(dict(field=field, base=a, patched=b))

        corpus = ROOT / "regressions" / c["name"]
        corpus.mkdir(parents=True, exist_ok=True)
        generated = [json.loads(p.read_text()) for p in corpus.glob("*.json")]
        # Corpus entries are security replays, not an oracle for valid behavior.
        security_cases = c["security_tests"] + [dict(id="saved-" + x["id"], hex=x["hex"],
            expected_exit=x["expected_exit"], expected_stdout=x["expected_stdout"]) for x in generated]
        report["loaded_regression_tests"] = len(generated)
        input_counter = 0

        def run_case(version, build, data, label):
            nonlocal input_counter
            input_counter += 1
            input_path = output / "inputs" / f"{input_counter:05d}.bin"
            input_path.parent.mkdir(exist_ok=True)
            input_path.write_bytes(data)
            mode = c["run"]["mode"]
            if mode == "argv" and b"\x00" in data:
                raise ValueError("NUL is not representable in argv; use file/stdin for binary inputs")
            text = data.decode("utf-8") if mode == "argv" else ""
            argv = [x.replace("{binary}", str(binaries[version, build])).replace("{input}", text)
                    .replace("{input_file}", str(input_path)) for x in c["run"]["argv"]]
            r = execute(argv, output, c["run"].get("timeout", 15), data if mode == "stdin" else None)
            r.update(version=version, build=build, label=label, input_file=str(input_path),
                     input_hex=data.hex(), input_sha256=sha256(input_path))
            report["runs"].append(r)
            return r

        paired = {}
        all_cases = [("security", x) for x in security_cases] + [("functional", x) for x in c["functional_tests"]] + [("invalid", x) for x in c.get("invalid_tests", [])]
        for kind, case in all_cases:
            data = data_for(case)
            outcomes = {}
            for version in sources:
                for build in ("normal", "sanitized"):
                    outcomes[version, build] = run_case(version, build, data, case["id"])
            paired[case["id"]] = outcomes
            for version in sources:
                sanitized = outcomes[version, "sanitized"]
                if sanitized["timed_out"] or (sanitized["abnormal"] and not sanitized["signature"]):
                    flags["inconclusive"] = True
                normal = outcomes[version, "normal"]
                if normal["timed_out"] or (normal["abnormal"] and not sanitized["signature"]):
                    flags["inconclusive"] = True
            if kind == "functional":
                for build in ("normal", "sanitized"):
                    before, after = outcomes["base", build], outcomes["patched", build]
                    ok_before, ok_after = oracle(before, case), oracle(after, case)
                    report["functional_tests"].append(dict(id=case["id"], build=build,
                        base_matches_oracle=ok_before, patched_matches_oracle=ok_after))
                    if not ok_before:
                        flags["inconclusive"] = True
                    elif not ok_after:
                        flags["functional_regression"] = True
            if kind in ("security", "invalid"):
                after = outcomes["patched", "sanitized"]
                if not after["abnormal"] and not oracle(after, case):
                    flags["inconclusive"] = True

        print("Paired security/functional/boundary tests finished", flush=True)
        seen = set()
        baseline_confirmed = False
        for kind, case in all_cases:
            data = data_for(case)
            outcomes = paired[case["id"]]
            before, after = outcomes["base", "sanitized"], outcomes["patched", "sanitized"]
            for version, run in (("base", before), ("patched", after)):
                sig = run["signature"]
                if not sig:
                    continue
                if kind == "security" and version == "base":
                    expected = c["expected_error"]
                    if sig["error_type"] == expected["type"] and expected["function"] in sig["functions"]:
                        baseline_confirmed = True
                token = (version, json.dumps(sig, sort_keys=True))
                if token in seen:
                    continue
                seen.add(token)
                replays = [run_case(version, "sanitized", data, "replay") for _ in range(c["run"].get("replays", 3))]
                stable = all(same_error(sig, r["signature"]) and not r["timed_out"] for r in replays)
                if not stable:
                    flags["inconclusive"] = True
                paired_replays = [run_case("patched" if version == "base" else "base", "sanitized", data, "paired-replay") for _ in range(3)]
                other_signatures = [r["signature"] for r in paired_replays]
                if version == "base":
                    remains = all(same_error(sig, x) for x in other_signatures)
                    absent = all((not r["abnormal"] and oracle(r, case)) or
                                 (r["signature"] is not None and not same_error(sig, r["signature"]))
                                 for r in paired_replays)
                    state = "Incomplete Fix" if remains else "Fixed" if absent else "Inconclusive"
                else:
                    remains = all(same_error(sig, x) for x in other_signatures)
                    state = "Incomplete Fix" if remains else "New Issue"
                    # Newly observed is not by itself causal proof of introduction by patch.
                if not stable or state == "Inconclusive" or any(r["timed_out"] for r in paired_replays):
                    flags["inconclusive"] = True
                    state = "Inconclusive"
                if version == "patched" and stable:
                    flags["security_issue"] = True
                if version == "base" and state == "Incomplete Fix":
                    flags["security_issue"] = True
                finding_id = f"finding-{len(report['findings']) + 1}"

                def predicate(candidate):
                    try:
                        a = run_case(version, "sanitized", candidate, "minimize")
                        return same_error(sig, a["signature"]) and not a["timed_out"]
                    except (UnicodeDecodeError, ValueError):
                        return False

                small, min_log = minimize(data, predicate) if stable else (data, {"one_minimal": False, "calls": 0})
                min_replays = [run_case(version, "sanitized", small, "minimized-replay") for _ in range(3)]
                if not all(same_error(sig, r["signature"]) and not r["timed_out"] for r in min_replays):
                    flags["inconclusive"] = True
                minimized_comparison = []
                for v in sources:
                    for build in ("normal", "sanitized"):
                        check = run_case(v, build, small, "minimized-paired")
                        minimized_comparison.append(check)
                        if build == "sanitized" or check["abnormal"]:
                            for _ in range(2):
                                minimized_comparison.append(run_case(v, build, small, "minimized-paired-replay"))
                # A minimized witness can reveal a bypass that the original input missed.
                min_patched = [r for r in minimized_comparison if r["version"] == "patched" and r["build"] == "sanitized"]
                if version == "base" and all(same_error(sig, r["signature"]) for r in min_patched):
                    state = "Incomplete Fix"
                    flags["security_issue"] = True
                if any(r["timed_out"] for r in minimized_comparison):
                    state = "Inconclusive"
                    flags["inconclusive"] = True
                directory = output / finding_id
                directory.mkdir(exist_ok=True)
                (directory / "original.bin").write_bytes(data)
                (directory / "minimized.bin").write_bytes(small)
                correlation = correlate(sources["base"], sources["patched"], before["frames"], after["frames"],
                    [{"base": before, "patched": after}])
                (directory / "patch.diff").write_text(correlation.pop("diff"))
                report["findings"].append(dict(id=finding_id, observed_on=version,
                    status=state, error_type=sig["error_type"], signature=sig, stable=stable,
                    replays=replays, paired_replays=paired_replays, minimization=min_log,
                    original_size=len(data), minimized_size=len(small), minimized_replays=min_replays,
                    minimized_comparison=minimized_comparison,
                    patch_correlation=correlation))
                bkey = f"{version}/sanitized"
                bundle(directory / "bundle", sources[version], binaries[version, "sanitized"], small,
                    report["builds"][bkey]["command"], min_replays[0],
                    dict(environment=controlled_env(), commit=report["provenance"]["commit"],
                         dirty=report["provenance"]["dirty"], signature=sig,
                         compiler=subprocess.check_output([c["builds"]["sanitized"][0], "--version"], text=True).splitlines()[0]),
                    c["run"]["mode"], c["run"]["argv"])
                if version == "base" and stable:
                    ident = __import__("hashlib").sha256(small).hexdigest()[:16]
                    entry = dict(id=ident, hex=small.hex(), signature=sig,
                                 expected_exit=case["expected_exit"], expected_stdout=case["expected_stdout"])
                    (corpus / f"{ident}.json").write_text(json.dumps(entry, indent=2))
                    report["regression_tests"].append(entry)
        if not baseline_confirmed:
            flags["inconclusive"] = True
            report["errors"].append("Configured baseline vulnerability was not reproduced")
        for test in report["functional_tests"]:
            if test["base_matches_oracle"] and not test["patched_matches_oracle"]:
                report["findings"].append(dict(status="Functional Regression", error_type="oracle-mismatch", test=test))
        return finish()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        flags["build_or_config_error"] = True
        report["errors"].append(f"{type(exc).__name__}: {exc}")
        return finish()


def main():
    p = argparse.ArgumentParser(description="Validate a patch with paired dynamic executions")
    p.add_argument("--config", default=str(ROOT / "configs/name-length.json"))
    p.add_argument("--base", default="base")
    p.add_argument("--patched", default="correct", help="Source key from config; not an expected status")
    p.add_argument("--patched-source", help="Evaluate an unseen C source with the existing config")
    p.add_argument("--base-source")
    p.add_argument("--out", default=str(ROOT / "artifacts/latest"))
    a = p.parse_args()
    return validate(a.config, a.patched, a.out, a.base, a.patched_source, a.base_source)


if __name__ == "__main__":
    sys.exit(main())
