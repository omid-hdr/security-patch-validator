"""Orchestrator (Role 4): loads config, builds each version (single-file
or cmake), runs paired dynamic tests, classifies errors, minimizes, bundles
evidence, checks hardening, links diffs, and produces the final JSON report
with the standard exit-code precedence.

This is a refactor of the original validate.py to support BOTH:
  * single-file targets (name-length: gcc one .c file)
  * multi-file cmake targets (editorconfig: cmake + make + LD_LIBRARY_PATH)

The build shape is determined by config["build_type"]:
  * "single-file" (default): uses config["builds"]["normal"|"sanitized"]
    as a list of argv, with {source} and {binary} substitutions
  * "cmake": uses config["builds"]["normal"|"sanitized"]["cmake_flags"]
    and ["make_targets"]; builds into {source}/build-{flavor}

The runtime shape is identical: config["run"]["argv"] with {binary},
{input}, {input_file} substitutions, plus optional {library_path} for
shared-library targets.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import platform

from .runner import controlled_env, execute, same_error, sha256
from .evidence import (bundle, correlate, hardening, minimize,
                       project_correlate, project_bundle)
from .builder import (build_single_file, build_cmake, locate_binary,
                      locate_library, remove_build_dir)

ROOT = Path(__file__).resolve().parents[1]
STATUS = {0: "PASS", 10: "VULN_REMAINS", 20: "FUNC_REGRESSION",
          30: "BUILD_OR_CONFIG_ERROR", 40: "INCONCLUSIVE"}


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def git(*args):
    p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                       text=True, timeout=15)
    return p.stdout.strip() if p.returncode == 0 else None


# ---------------------------------------------------------------------------
# Config loader (validates the unified schema)
# ---------------------------------------------------------------------------

def load_config(path):
    c = json.loads(Path(path).read_text())
    # Required top-level fields.
    for key in ("name", "sources", "builds", "run", "security_tests",
                "functional_tests", "expected_error", "hardening_required"):
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
    if not (0 < c["run"].get("timeout", 15) <= 120):
        raise ValueError("Timeout must be in (0,120]")

    # Build type: "single-file" (default) or "cmake".
    bt = c.get("build_type", "single-file")
    if bt not in ("single-file", "cmake"):
        raise ValueError(f"Unknown build_type: {bt}")
    c["build_type"] = bt

    # For cmake, each build entry must be a dict with cmake_flags + make_targets.
    if bt == "cmake":
        for flavor in ("normal", "sanitized"):
            entry = c["builds"][flavor]
            if not isinstance(entry, dict):
                raise ValueError(f"cmake build entry {flavor} must be a dict")
            if "cmake_flags" not in entry or "make_targets" not in entry:
                raise ValueError(f"cmake build entry {flavor} needs cmake_flags + make_targets")
    else:
        # single-file: each build entry must be a list of argv.
        for flavor in ("normal", "sanitized"):
            entry = c["builds"][flavor]
            if not isinstance(entry, list):
                raise ValueError(f"single-file build entry {flavor} must be a list of argv")

    return c


# ---------------------------------------------------------------------------
# Test data preparation
# ---------------------------------------------------------------------------

def data_for(test):
    if "input_repeat" in test:
        value, count = test["input_repeat"]
        if not isinstance(count, int) or not 0 <= count <= 100000:
            raise ValueError("Invalid input_repeat count")
        return (value * count).encode()
    if "hex" in test:
        return bytes.fromhex(test["hex"])
    return test["input"].encode("utf-8")


def prepare_poc(test, output_dir):
    """If a test uses `poc_script` and `trigger_finder`, run them and
    return (data, trigger_path). Otherwise return (data_for(test), None).

    poc_script:    a shell command that builds the PoC tree (writes to
                   $POC_ROOT, which is set to output_dir/poc-trees/<id>).
    trigger_finder: a shell command that prints the trigger file path.
    Both scripts are run with cwd = ROOT (the repo root), so relative
    paths in the scripts resolve against the repo, not the output dir.
    The $POC_ROOT env var tells the script where to write its outputs.
    """
    if "poc_script" not in test:
        return data_for(test), None
    poc_id = test["id"]
    poc_root = output_dir / "poc-trees" / poc_id
    if poc_root.exists():
        shutil.rmtree(poc_root)
    poc_root.mkdir(parents=True)
    # Run the scripts with cwd = ROOT (so repo-relative paths work),
    # but $POC_ROOT points to the per-test output directory.
    env = dict(os.environ, POC_ROOT=str(poc_root))
    r = subprocess.run(test["poc_script"], shell=True, cwd=ROOT,
                       env=env, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise ValueError(f"poc_script failed for {poc_id}: {r.stderr}")
    # Run the trigger_finder to get the trigger path.
    if "trigger_finder" not in test:
        raise ValueError(f"poc_script requires trigger_finder for {poc_id}")
    r = subprocess.run(test["trigger_finder"], shell=True, cwd=ROOT,
                       env=env, capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise ValueError(f"trigger_finder failed for {poc_id}: {r.stderr}")
    trigger_path = Path(r.stdout.strip()).resolve()
    if not trigger_path.exists():
        raise ValueError(f"trigger_finder returned non-existent path: {trigger_path}")
    # data is the trigger path itself (passed as the argv argument).
    return str(trigger_path).encode(), trigger_path


def oracle(result, case):
    """Check if a run matches the expected behavior in the case.

    A case may specify either:
      * expected_exit + expected_stdout        (exact match), OR
      * expected_exit + expected_stdout_contains (substring match)
    If neither expected_stdout nor expected_stdout_contains is given,
    only the exit_code is checked.
    """
    if result["timed_out"] or result["abnormal"]:
        return False
    if result["exit_code"] != case["expected_exit"]:
        return False
    if "expected_stdout" in case and result["stdout"] != case["expected_stdout"]:
        return False
    if "expected_stdout_contains" in case and case["expected_stdout_contains"] not in result["stdout"]:
        return False
    return True


# ---------------------------------------------------------------------------
# Exit-code precedence (Role 4)
# ---------------------------------------------------------------------------

def decide(flags):
    # Assignment precedence, independent of file names or expected scenario.
    for code, key in ((30, "build_or_config_error"), (40, "inconclusive"),
                      (20, "functional_regression"), (10, "security_issue")):
        if flags.get(key):
            return code
    return 0


# ---------------------------------------------------------------------------
# Build dispatcher (single-file vs cmake)
# ---------------------------------------------------------------------------

def build_version(version, source_path, build_specs, build_type, output_dir,
                  extra_path=None):
    """Build one version in two flavors. Returns dict of binary paths:
    {(version, flavor): binary_path} and dict of build reports."""
    reports = {}
    binaries = {}
    for flavor in ("normal", "sanitized"):
        if build_type == "single-file":
            binary = output_dir / f"{version}-{flavor}"
            reports[f"{version}/{flavor}"] = build_single_file(
                source_path, binary, build_specs[flavor], ROOT, timeout=60)
            if reports[f"{version}/{flavor}"]["exit_code"] != 0 or not binary.exists():
                raise ValueError(f"Build failed: {version}/{flavor}: "
                                 + reports[f"{version}/{flavor}"]["stderr"][:1000])
            binaries[version, flavor] = binary
        else:  # cmake
            build_dir = source_path / f"build-{flavor}"
            remove_build_dir(build_dir)
            entry = build_specs[flavor]
            report = build_cmake(
                source_dir=source_path, build_dir=build_dir, flavor=flavor,
                cmake_flags=entry["cmake_flags"],
                make_targets=entry["make_targets"],
                cwd=ROOT, extra_path=extra_path, timeout=120)
            reports[f"{version}/{flavor}"] = report
            if report["make_result"] is None or report["make_result"]["exit_code"] != 0:
                cfg_err = report["configure_result"]["stderr"][:1000] \
                          if report["make_result"] is None else report["make_result"]["stderr"][:1000]
                raise ValueError(f"Build failed: {version}/{flavor}: {cfg_err}")
            # Locate the binary and (optional) shared library.
            binary_name = build_specs.get("binary_name", "editorconfig")
            binary = locate_binary(build_dir, binary_name)
            if binary is None:
                raise ValueError(f"Could not locate {binary_name} in {build_dir}/bin/")
            binaries[version, flavor] = binary
    return binaries, reports


# ---------------------------------------------------------------------------
# Main validation pipeline
# ---------------------------------------------------------------------------

def validate(config_path, patched, output, base="base",
             patched_source=None, base_source=None,
             extra_path=None):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 2,
        "status": None,
        "exit_code": None,
        "flags": dict(build_or_config_error=False, inconclusive=False,
                      functional_regression=False, security_issue=False),
        "runs": [],
        "findings": [],
        "functional_tests": [],
        "hardening": {},
        "regression_tests": [],
        "errors": [],
        "builds": {},
        "scope": "configured targets; observed tests are not proof of universal safety",
    }
    flags = report["flags"]

    def finish():
        code = decide(flags)
        report.update(exit_code=code, status=STATUS[code])
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        text = [
            f"{report['status']} (exit {code})",
            f"Findings: {len(report['findings'])}",
            f"Functional regression: {flags['functional_regression']}",
            f"Incomplete evidence: {flags['inconclusive']}",
        ]
        text += [f"- {x['status']}: {x.get('error_type')}" for x in report["findings"]]
        text += [f"ERROR: {x}" for x in report["errors"]]
        (output / "summary.txt").write_text("\n".join(text) + "\n")
        print("\n".join(text))
        print(f"Evidence: {output / 'report.json'}")
        return code

    try:
        c = load_config(config_path)
        # Resolve source paths (support both --patched <key> and --patched-source <path>).
        if base_source:
            sources = {"base": Path(base_source).resolve()}
        else:
            sources = {"base": ROOT / c["sources"][base]
                       if not Path(c["sources"][base]).is_absolute()
                       else Path(c["sources"][base])}
        if patched_source:
            sources["patched"] = Path(patched_source).resolve()
        else:
            sources["patched"] = ROOT / c["sources"][patched] \
                if not Path(c["sources"][patched]).is_absolute() \
                else Path(c["sources"][patched])

        # Validate source paths exist.
        for k, v in sources.items():
            if c["build_type"] == "single-file":
                if not v.is_file():
                    raise ValueError(f"Missing source file: {v}")
            else:
                if not v.is_dir():
                    raise ValueError(f"Missing source dir: {v}")
                if not (v / "CMakeLists.txt").is_file():
                    raise ValueError(f"No CMakeLists.txt in {v}")

        report["target"] = c["name"]
        report["config"] = c
        report["provenance"] = dict(
            commit=git("rev-parse", "HEAD"),
            dirty=bool(git("status", "--porcelain")),
            platform=platform.platform(),
            source_sha256={k: (sha256(v) if v.is_file() else "<dir>") for k, v in sources.items()},
            source_paths={k: str(v) for k, v in sources.items()},
            environment=controlled_env(),
        )

        # Build both versions (base + patched), each in two flavors.
        binaries = {}
        for version, source_path in sources.items():
            version_binaries, version_reports = build_version(
                version, source_path, c["builds"], c["build_type"],
                output, extra_path=extra_path)
            binaries.update(version_binaries)
            report["builds"].update(version_reports)

        print("Built corresponding normal/sanitized binaries", flush=True)

        # Hardening check on the normal build of each version.
        for version in sources:
            h = hardening(binaries[version, "normal"])
            report["hardening"][version] = h
            for k, v in c["hardening_required"].items():
                if h.get(k) != v:
                    flags["inconclusive"] = True
                    report["errors"].append(
                        f"Required hardening mismatch {version}: {k}, got {h.get(k)}, expected {v}")
        for field in ("nx", "pie", "relro", "canary_evidence"):
            a, b = report["hardening"]["base"][field], report["hardening"]["patched"][field]
            if a != b:
                report.setdefault("hardening_changes", []).append(dict(field=field, base=a, patched=b))

        # Resolve library_path for cmake targets (for LD_LIBRARY_PATH).
        # We need both the normal and sanitized library paths, since the
        # binary at runtime must load the matching build's libeditorconfig.so.
        library_paths = {}
        if c["build_type"] == "cmake":
            for version in sources:
                library_paths[version] = {}
                for flavor in ("normal", "sanitized"):
                    build_dir = sources[version] / f"build-{flavor}"
                    library_paths[version][flavor] = locate_library(build_dir)

        # Load saved regression corpus.
        corpus = ROOT / "regressions" / c["name"]
        corpus.mkdir(parents=True, exist_ok=True)
        generated = [json.loads(p.read_text()) for p in corpus.glob("*.json")]
        security_cases = list(c["security_tests"]) + [
            dict(id="saved-" + x["id"], hex=x["hex"],
                 expected_exit=x["expected_exit"],
                 expected_stdout=x["expected_stdout"]) for x in generated
        ]
        report["loaded_regression_tests"] = len(generated)
        input_counter = 0

        def run_case(version, build, data, label, *, trigger_path=None):
            """Run one test case. `data` is the byte-level input (for the
            standard input shape). `trigger_path` is an optional path to a
            file that the binary should be asked to parse (overrides the
            standard input — used for directory-based PoCs).
            """
            nonlocal input_counter
            input_counter += 1
            input_path = output / "inputs" / f"{input_counter:05d}.bin"
            input_path.parent.mkdir(exist_ok=True)
            input_path.write_bytes(data)
            mode = c["run"]["mode"]
            if mode == "argv" and b"\x00" in data and trigger_path is None:
                raise ValueError("NUL is not representable in argv; use file/stdin for binary inputs")
            # For directory-based PoCs the "input" is the trigger path itself.
            text_arg = str(trigger_path) if trigger_path is not None else (
                data.decode("utf-8") if mode == "argv" else "")
            # Build the argv with all known substitutions.
            argv = [x.replace("{binary}", str(binaries[version, build]))
                       .replace("{input}", text_arg)
                       .replace("{input_file}", str(input_path))
                    for x in c["run"]["argv"]]
            # Extra env for shared-library targets.
            extra_env = None
            if c["build_type"] == "cmake" and library_paths.get(version, {}).get(build):
                extra_env = {"LD_LIBRARY_PATH": str(library_paths[version][build].parent)}
            r = execute(argv, output, c["run"].get("timeout", 15),
                        data if mode == "stdin" and trigger_path is None else None,
                        extra_env=extra_env, extra_path=extra_path)
            r.update(version=version, build=build, label=label,
                     input_file=str(trigger_path if trigger_path else input_path),
                     input_hex=data.hex() if trigger_path is None else "<trigger>",
                     input_sha256=(sha256(input_path) if trigger_path is None
                                   else (sha256(trigger_path) if Path(trigger_path).is_file() else "<dir>")))
            report["runs"].append(r)
            return r

        # Paired tests on all four (version, build) combinations.
        all_cases = ([(s_label, s) for s_label, s in zip(
            ["security"] * len(security_cases), security_cases)] +
            [("functional", x) for x in c["functional_tests"]] +
            [("invalid", x) for x in c.get("invalid_tests", [])])

        paired = {}
        for kind, case in all_cases:
            # Allow poc_script to build a directory-based PoC; otherwise use data_for.
            data, trigger = prepare_poc(case, output)
            outcomes = {}
            for version in sources:
                for build in ("normal", "sanitized"):
                    outcomes[version, build] = run_case(
                        version, build, data, case["id"], trigger_path=trigger)
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
                    report["functional_tests"].append(dict(
                        id=case["id"], build=build,
                        base_matches_oracle=ok_before,
                        patched_matches_oracle=ok_after))
                    if not ok_before:
                        flags["inconclusive"] = True
                    elif not ok_after:
                        flags["functional_regression"] = True
            if kind == "invalid":
                # Only invalid_tests have a strict oracle (expected_exit,
                # expected_stdout). Security tests with poc_script are
                # validated via the finding pipeline, not the oracle.
                after = outcomes["patched", "sanitized"]
                if not after["abnormal"] and not oracle(after, case):
                    flags["inconclusive"] = True
            elif kind == "security" and "input" in case and "expected_exit" in case:
                # Plain byte-level security tests (name-length shape) still
                # get a quick oracle check: if patched doesn't crash AND
                # doesn't match expected_exit, that's inconclusive.
                after = outcomes["patched", "sanitized"]
                if not after["abnormal"] and not oracle(after, case):
                    flags["inconclusive"] = True

        print("Paired security/functional/boundary tests finished", flush=True)

        # Findings + minimization.
        seen = set()
        baseline_confirmed = False
        for kind, case in all_cases:
            data, trigger = prepare_poc(case, output)
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
                replays = [run_case(version, "sanitized", data, "replay",
                                    trigger_path=trigger)
                           for _ in range(c["run"].get("replays", 3))]
                stable = all(same_error(sig, r["signature"]) and not r["timed_out"]
                             for r in replays)
                if not stable:
                    flags["inconclusive"] = True
                paired_replays = [run_case("patched" if version == "base" else "base",
                                           "sanitized", data, "paired-replay",
                                           trigger_path=trigger)
                                  for _ in range(3)]
                other_signatures = [r["signature"] for r in paired_replays]
                if version == "base":
                    remains = all(same_error(sig, x) for x in other_signatures)
                    # For security tests, "absent" means the patched version
                    # either does not crash at all (abnormal=False and exit_code
                    # is reasonable) OR crashes with a DIFFERENT signature.
                    # For functional tests, the patched run must match the oracle.
                    if kind == "security":
                        absent = all(
                            (not r["abnormal"] and r["exit_code"] in (0, 1, 2)) or
                            (r["signature"] is not None and not same_error(sig, r["signature"]))
                            for r in paired_replays)
                    else:
                        absent = all(
                            (not r["abnormal"] and oracle(r, case)) or
                            (r["signature"] is not None and not same_error(sig, r["signature"]))
                            for r in paired_replays)
                    state = "Incomplete Fix" if remains else "Fixed" if absent else "Inconclusive"
                else:
                    remains = all(same_error(sig, x) for x in other_signatures)
                    state = "Incomplete Fix" if remains else "New Issue"
                if not stable or state == "Inconclusive" or any(r["timed_out"] for r in paired_replays):
                    flags["inconclusive"] = True
                    state = "Inconclusive"
                if version == "patched" and stable:
                    flags["security_issue"] = True
                if version == "base" and state == "Incomplete Fix":
                    flags["security_issue"] = True
                finding_id = f"finding-{len(report['findings']) + 1}"

                # Minimization only applies to byte-level inputs (no poc_script).
                # For directory-based PoCs we keep the original trigger file as the
                # minimized witness; structural minimization is a future Role-3 task.
                if trigger is None and stable:
                    def predicate(candidate):
                        try:
                            a = run_case(version, "sanitized", candidate, "minimize")
                            return same_error(sig, a["signature"]) and not a["timed_out"]
                        except (UnicodeDecodeError, ValueError):
                            return False
                    small, min_log = minimize(data, predicate)
                else:
                    small, min_log = data, {"one_minimal": (trigger is not None),
                                            "calls": 0,
                                            "skipped": trigger is not None,
                                            "reason": "directory-based PoC (byte-level minimization skipped)"}
                min_replays = [run_case(version, "sanitized", small, "minimized-replay",
                                        trigger_path=trigger)
                               for _ in range(3)]
                if not all(same_error(sig, r["signature"]) and not r["timed_out"]
                           for r in min_replays):
                    flags["inconclusive"] = True
                minimized_comparison = []
                for v in sources:
                    for build in ("normal", "sanitized"):
                        check = run_case(v, build, small, "minimized-paired",
                                         trigger_path=trigger)
                        minimized_comparison.append(check)
                        if build == "sanitized" or check["abnormal"]:
                            for _ in range(2):
                                minimized_comparison.append(
                                    run_case(v, build, small, "minimized-paired-replay",
                                             trigger_path=trigger))
                min_patched = [r for r in minimized_comparison
                               if r["version"] == "patched" and r["build"] == "sanitized"]
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

                # Diff correlation — single-file or multi-file (project).
                if c["build_type"] == "single-file":
                    correlation = correlate(sources["base"], sources["patched"],
                                            before["frames"], after["frames"],
                                            [{"base": before, "patched": after}])
                else:
                    correlation = project_correlate(sources["base"], sources["patched"],
                                                    before["frames"], after["frames"],
                                                    [{"base": before, "patched": after}])
                (directory / "patch.diff").write_text(correlation.pop("diff"))
                report["findings"].append(dict(
                    id=finding_id, observed_on=version, status=state,
                    error_type=sig["error_type"], signature=sig, stable=stable,
                    replays=replays, paired_replays=paired_replays,
                    minimization=min_log,
                    original_size=len(data), minimized_size=len(small),
                    minimized_replays=min_replays,
                    minimized_comparison=minimized_comparison,
                    patch_correlation=correlation))

                # Reproducer bundle — single-file or multi-file.
                if c["build_type"] == "single-file":
                    bkey = f"{version}/sanitized"
                    bundle(directory / "bundle", sources[version],
                           binaries[version, "sanitized"], small,
                           report["builds"][bkey]["command"], min_replays[0],
                           dict(environment=controlled_env(),
                                commit=report["provenance"]["commit"],
                                dirty=report["provenance"]["dirty"],
                                signature=sig,
                                compiler=subprocess.check_output(
                                    [c["builds"]["sanitized"][0], "--version"],
                                    text=True).splitlines()[0]),
                           c["run"]["mode"], c["run"]["argv"])
                else:
                    # Multi-file bundle: ship the whole source tree.
                    library_path = library_paths.get(version, {}).get("sanitized")
                    build_meta = dict(
                        flavor="sanitized",
                        source_dir=str(sources[version]),
                        build_dir=str(sources[version] / "build-sanitized"),
                        configure_command=report["builds"][f"{version}/sanitized"]["configure_command"],
                        make_command=report["builds"][f"{version}/sanitized"]["make_command"],
                    )
                    run_meta = dict(
                        environment=controlled_env(),
                        commit=report["provenance"]["commit"],
                        dirty=report["provenance"]["dirty"],
                        signature=sig,
                        compiler=subprocess.check_output(
                            [c["builds"]["sanitized"]["cmake_flags"][0]
                             if False else "gcc", "--version"],
                            text=True).splitlines()[0],
                        mode=c["run"]["mode"], run_argv=c["run"]["argv"],
                    )
                    # The trigger file is the input file we wrote above.
                    trigger = output / "inputs" / f"{input_counter:05d}.bin"
                    project_bundle(directory / "bundle", sources[version],
                                   binaries[version, "sanitized"],
                                   library_path, trigger,
                                   build_meta, run_meta)

                # Regression corpus.
                if version == "base" and stable:
                    ident = __import__("hashlib").sha256(small).hexdigest()[:16]
                    entry = dict(id=ident, hex=small.hex(), signature=sig,
                                 expected_exit=case["expected_exit"],
                                 expected_stdout=case["expected_stdout"])
                    (corpus / f"{ident}.json").write_text(json.dumps(entry, indent=2))
                    report["regression_tests"].append(entry)

        if not baseline_confirmed:
            flags["inconclusive"] = True
            report["errors"].append("Configured baseline vulnerability was not reproduced")

        for test in report["functional_tests"]:
            if test["base_matches_oracle"] and not test["patched_matches_oracle"]:
                report["findings"].append(dict(status="Functional Regression",
                                                error_type="oracle-mismatch", test=test))
        return finish()
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError) as exc:
        flags["build_or_config_error"] = True
        report["errors"].append(f"{type(exc).__name__}: {exc}")
        return finish()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Validate a patch with paired dynamic executions")
    p.add_argument("--config", default=str(ROOT / "configs/name-length.json"),
                   help="Path to the target config JSON")
    p.add_argument("--base", default="base",
                   help="Source key from config (default: base)")
    p.add_argument("--patched", default="correct",
                   help="Source key from config; not an expected status")
    p.add_argument("--patched-source",
                   help="Evaluate an unseen source path with the existing config "
                        "(single-file) or an unseen source dir (cmake)")
    p.add_argument("--base-source",
                   help="Override the base source path")
    p.add_argument("--out", default=str(ROOT / "artifacts/latest"))
    p.add_argument("--extra-path",
                   help="Comma-separated extra PATH entries (e.g. for cmake in a venv)")
    a = p.parse_args()
    extra_path = a.extra_path.split(",") if a.extra_path else None
    return validate(a.config, a.patched, a.out, a.base,
                    a.patched_source, a.base_source, extra_path)


if __name__ == "__main__":
    sys.exit(main())
