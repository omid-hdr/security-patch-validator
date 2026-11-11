"""Evidence analysis (Role 3): minimization, hardening, diff correlation,
reproducer bundle.

All routines are backward-compatible with the original single-file target
API; multi-file (CMake) targets use the new project_* helpers.
"""
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from .runner import sha256


# ---------------------------------------------------------------------------
# Input minimization (byte-level ddmin)
# ---------------------------------------------------------------------------

def minimize(data, predicate, max_runs=150):
    """ddmin chunk deletion followed by a single-byte deletion audit (1-minimal)."""
    current = data
    calls = 0
    trace = []
    cache = {}

    def keeps(candidate):
        nonlocal calls
        if candidate in cache:
            return cache[candidate]
        if calls >= max_runs:
            return False
        calls += 1
        good = predicate(candidate)
        cache[candidate] = good
        trace.append({"size": len(candidate), "kept_signature": good})
        return good

    n = 2
    while len(current) > 0 and calls < max_runs:
        size = max(1, (len(current) + n - 1) // n)
        changed = False
        for start in range(0, len(current), size):
            candidate = current[:start] + current[start + size:]
            if keeps(candidate):
                current = candidate
                n = max(2, n - 1)
                changed = True
                break
        if not changed:
            if n >= len(current):
                break
            n = min(len(current), n * 2)
    i = 0
    while i < len(current) and calls < max_runs:
        if keeps(current[:i] + current[i + 1:]):
            current = current[:i] + current[i + 1:]
            i = 0
        else:
            i += 1
    return current, dict(calls=calls, budget_exhausted=calls >= max_runs,
                         one_minimal=i >= len(current), trace=trace)


# ---------------------------------------------------------------------------
# Structural minimization for directory + .editorconfig PoCs
# ---------------------------------------------------------------------------

def minimize_poc_tree(make_poc_callable, predicate, *, variants=None, max_runs=20):
    """Shrink a directory-based PoC while preserving the same crash signature.

    make_poc_callable:  a function that takes (root, variant_id) and returns
                        (base_dir, trigger_file, stats). The variant_id is a
                        string identifying which size variant to build.
    predicate:          a function that takes the trigger path and returns
                        True iff the same crash signature is still observed.
    variants:           ordered list of variant IDs to try (smallest last).
                        Default: ["A", "B"] — A is the larger original PoC,
        B is the smaller off-by-one bypass PoC.

    Returns: (chosen_variant_id, chosen_trigger_path, stats, all_attempts)
    """
    variants = variants or ["A", "B"]
    attempts = []
    chosen = None
    chosen_trigger = None
    chosen_stats = None
    for v in variants:
        # Each variant writes to its own root to avoid cross-contamination.
        # The caller should pass a make_poc_callable that knows where to write.
        try:
            base_dir, trigger, stats = make_poc_callable(root=None, variant=v)
        except TypeError:
            # The make_poc callable may take only variant; let the caller handle root.
            base_dir, trigger, stats = make_poc_callable(variant=v)
        attempts.append(dict(variant=v, stats=stats, trigger=str(trigger)))
        if predicate(trigger):
            chosen = v
            chosen_trigger = trigger
            chosen_stats = stats
            break
    return chosen, chosen_trigger, chosen_stats, attempts


# ---------------------------------------------------------------------------
# Binary hardening check (NX, PIE, RELRO, Canary)
# ---------------------------------------------------------------------------

def hardening(binary):
    evidence = {}
    for key, args in {"header": ["-hW"], "segments": ["-lW"],
                      "dynamic": ["-dW"], "symbols": ["-sW"]}.items():
        p = subprocess.run(["readelf", *args, str(binary)], text=True,
                           capture_output=True, timeout=15, check=True)
        evidence[key] = p.stdout
    stack = next((x for x in evidence["segments"].splitlines() if "GNU_STACK" in x), "")
    flags = re.search(r"GNU_STACK\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)", stack)
    nx = ("E" not in flags.group(1)) if flags else None
    has_relro = "GNU_RELRO" in evidence["segments"]
    now = "BIND_NOW" in evidence["dynamic"] or bool(re.search(r"FLAGS_1.*\bNOW\b", evidence["dynamic"]))
    pie = bool(re.search(r"Type:\s+DYN", evidence["header"]))
    return dict(nx=nx, pie=pie, relro="full" if has_relro and now else "partial" if has_relro else "none",
                canary_evidence="__stack_chk_fail" in evidence["symbols"], evidence=evidence,
                limitations=["PIE does not prove runtime ASLR", "Canary symbol does not prove all functions are protected"])


# ---------------------------------------------------------------------------
# Diff linker — single file (legacy, still used by name-length)
# ---------------------------------------------------------------------------

def correlate(base_source, patched_source, base_frames, patched_frames, comparisons):
    """Single-file diff correlation. See project_correlate for multi-file."""
    old = Path(base_source).read_text().splitlines(True)
    new = Path(patched_source).read_text().splitlines(True)
    diff_result = subprocess.run(
        ["git", "diff", "--no-index", "--no-ext-diff", "--",
         str(base_source), str(patched_source)],
        capture_output=True, text=True, timeout=15)
    if diff_result.returncode not in (0, 1):
        raise ValueError("git diff failed: " + diff_result.stderr)
    diff = diff_result.stdout
    matcher = difflib.SequenceMatcher(a=old, b=new)
    changes = []

    def enclosing(lines, idx):
        for line in reversed(lines[:idx + 1]):
            m = re.match(r"\s*[\w *]+\s+(\w+)\([^;]*\)\s*\{", line)
            if m:
                return m.group(1)
        return None

    for op, a, b, c, d in matcher.get_opcodes():
        if op != "equal":
            changes.append(dict(operation=op, old_lines=[a + 1, b], new_lines=[c + 1, d],
                                old_function=enclosing(old, a),
                                new_function=enclosing(new, c),
                                file=Path(base_source).name))
    matches = []
    expected_base = Path(base_source).name
    expected_patched = Path(patched_source).name
    for version, frames in (("base", base_frames), ("patched", patched_frames)):
        expected = expected_base if version == "base" else expected_patched
        for f in frames:
            if Path(f["file"]).name == expected:
                for change in changes:
                    if f["function"] == change["old_function" if version == "base" else "new_function"]:
                        matches.append(dict(version=version, frame=f, change=change))
    return dict(diff=diff, changes=changes, matches=matches,
                relation="supported" if matches and comparisons else "inconclusive",
                reason="Dynamic application stack frame intersects changed function; paired runs attached" if matches else
                       "No changed-function/stack match; proximity alone is insufficient",
                causal_proof=False, paired_runs=comparisons)


# ---------------------------------------------------------------------------
# Diff linker — multi-file project
# ---------------------------------------------------------------------------

def project_correlate(base_dir, patched_dir, base_frames, patched_frames,
                      comparisons, exclude_patterns=None):
    """Multi-file diff correlation. Walks the source trees and produces a
    unified git diff for all changed files. Matches stack frames against
    changed functions in any of those files (not just one).

    exclude_patterns: list of substrings to exclude (e.g. ['.git/', 'build-',
                      'CMakeFiles/']) — typically build outputs and metadata.
    """
    base_dir = Path(base_dir).resolve()
    patched_dir = Path(patched_dir).resolve()
    exclude_patterns = exclude_patterns or ["/.git/", "/build-", "/CMakeFiles/",
                                            "/CMakeCache.txt", "/cmake_install.cmake",
                                            "/Makefile", "/CTestTestfile.cmake"]

    # List source files in both trees, ignoring build outputs.
    def list_sources(d):
        files = {}
        for p in d.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(d).as_posix()
            if any(x in ("/" + rel + "/") or rel.startswith(x.lstrip("/")) for x in exclude_patterns):
                continue
            # Skip files that look like build artifacts.
            if any(rel.startswith(pat) or ("/" + pat) in ("/" + rel) for pat in ("build-", "CMakeFiles")):
                continue
            # Skip .git entirely.
            if rel.startswith(".git/") or rel == ".git":
                continue
            # Skip common build outputs.
            if rel.endswith((".o", ".so", ".a", ".so.0", ".so.0.12.11")):
                continue
            files[rel] = p
        return files

    base_files = list_sources(base_dir)
    patched_files = list_sources(patched_dir)
    all_rels = sorted(set(base_files) | set(patched_files))

    diff_parts = []
    changes = []  # one entry per changed region per file

    def enclosing(lines, idx):
        for line in reversed(lines[:idx + 1]):
            m = re.match(r"\s*[\w *]+\s+(\w+)\([^;]*\)\s*\{", line)
            if m:
                return m.group(1)
        return None

    for rel in all_rels:
        bp = base_files.get(rel)
        pp = patched_files.get(rel)
        if bp and pp and sha256(bp) == sha256(pp):
            continue
        if bp and not pp:
            # Removed in patched.
            diff_parts.append(f"--- a/{rel}\n+++ /dev/null\n")
            changes.append(dict(file=rel, operation="delete", old_function=None,
                                new_function=None, old_lines=None, new_lines=None))
            continue
        if pp and not bp:
            # Added in patched.
            new_lines = pp.read_text().splitlines(True)
            diff_parts.append(f"--- /dev/null\n+++ b/{rel}\n")
            for i, line in enumerate(new_lines):
                diff_parts.append(f"+{line}")
            changes.append(dict(file=rel, operation="add", old_function=None,
                                new_function=enclosing(new_lines, 0),
                                old_lines=None, new_lines=[1, len(new_lines)]))
            continue
        # Both exist and differ.
        old = bp.read_text().splitlines(True)
        new = pp.read_text().splitlines(True)
        diff_result = subprocess.run(
            ["git", "diff", "--no-index", "--no-ext-diff", "--",
             str(bp), str(pp)],
            capture_output=True, text=True, timeout=15)
        if diff_result.returncode in (0, 1):
            diff_parts.append(diff_result.stdout)
        matcher = difflib.SequenceMatcher(a=old, b=new)
        for op, a, b, c, d in matcher.get_opcodes():
            if op != "equal":
                changes.append(dict(file=rel, operation=op,
                                    old_lines=[a + 1, b], new_lines=[c + 1, d],
                                    old_function=enclosing(old, a),
                                    new_function=enclosing(new, c)))

    diff = "".join(diff_parts)

    # Match stack frames against changes in any file.
    matches = []
    for version, frames in (("base", base_frames), ("patched", patched_frames)):
        for f in frames:
            frame_file = Path(f["file"]).name
            for change in changes:
                if change.get("file", "").endswith(frame_file) or \
                   Path(change["file"]).name == frame_file:
                    target_fn = change["old_function" if version == "base" else "new_function"]
                    if f["function"] == target_fn:
                        matches.append(dict(version=version, frame=f, change=change))
    return dict(diff=diff, changes=changes, matches=matches,
                relation="supported" if matches and comparisons else "inconclusive",
                reason="Dynamic application stack frame intersects changed function in changed file; paired runs attached" if matches else
                       "No changed-function/stack match; proximity alone is insufficient",
                causal_proof=False, paired_runs=comparisons,
                files_compared=len(all_rels), files_changed=len({c["file"] for c in changes}))


# ---------------------------------------------------------------------------
# Reproducer bundle — single file (legacy)
# ---------------------------------------------------------------------------

def bundle(destination, source, binary, input_bytes, build_command, result, metadata, mode, run_argv):
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination / "source.c")
    shutil.copy2(binary, destination / "target")
    (destination / "input.bin").write_bytes(input_bytes)
    (destination / "manifest.json").write_text(json.dumps(dict(
        **metadata, binary_sha256=sha256(binary), source_sha256=sha256(source),
        input_sha256=sha256(destination / "input.bin"), original_build_command=build_command,
        build_command=[x.replace(str(source), "source.c").replace(str(binary), "target") for x in build_command],
        original_result=result, mode=mode, run_argv=run_argv,
        bundle_type="single-file"), indent=2))
    (destination / "replay.py").write_text('''import hashlib,json,os,pathlib,subprocess,sys
p=pathlib.Path(__file__).resolve().parent
m=json.loads((p/'manifest.json').read_text())
assert hashlib.sha256((p/'target').read_bytes()).hexdigest()==m['binary_sha256']
os.chmod(p/'target',0o700)
data=(p/'input.bin').read_bytes()
text=data.decode('utf-8') if m['mode']=='argv' else ''
argv=[x.replace('{binary}',str(p/'target')).replace('{input_file}',str(p/'input.bin')).replace('{input}',text) for x in m['run_argv']]
env=dict(m['environment'])
try:
 r=subprocess.run(argv,cwd=p,env=env,input=data if m['mode']=='stdin' else None,timeout=15)
 sys.exit(r.returncode if r.returncode>=0 else 128-r.returncode)
except subprocess.TimeoutExpired:
 sys.exit(124)
''')


# ---------------------------------------------------------------------------
# Reproducer bundle — multi-file (CMake) project
# ---------------------------------------------------------------------------

def project_bundle(destination, source_dir, binary, library, trigger_file,
                   build_metadata, run_metadata, *, exclude_patterns=None):
    """Build a self-contained reproducer bundle for a multi-file target.

    destination:    the bundle directory (created)
    source_dir:     the project root (e.g. targets/editorconfig/base)
    binary:         the built executable to ship
    library:        the shared library (e.g. libeditorconfig.so.0) — optional
    trigger_file:   the trigger file path (the input that reproduces the bug)
    build_metadata: dict with at least {flavor, configure_command, make_command,
                   build_dir_relative, binary_relative, library_relative}
    run_metadata:   dict with at least {environment, commit, dirty, signature,
                   compiler, mode, run_argv}

    The bundle layout is:
      destination/
        source/          <- copy of the source tree (no build outputs)
        target           <- copy of the binary
        lib<name>.so     <- copy of the shared library (if any)
        trigger.bin      <- copy of the trigger file
        manifest.json
        replay.py
    """
    destination.mkdir(parents=True, exist_ok=True)
    source_dir = Path(source_dir).resolve()
    exclude_patterns = exclude_patterns or ["/.git/", "/build-", "/CMakeFiles/",
                                             "/CMakeCache.txt", "/cmake_install.cmake"]

    # Copy the source tree, excluding build outputs.
    src_dst = destination / "source"
    if src_dst.exists():
        shutil.rmtree(src_dst)
    for p in source_dir.rglob("*"):
        rel = p.relative_to(source_dir).as_posix()
        if any(x in ("/" + rel + "/") or rel.startswith(x.lstrip("/")) for x in exclude_patterns):
            continue
        if rel.startswith(".git/") or rel == ".git":
            continue
        if rel.endswith((".o", ".so", ".a", ".so.0", ".so.0.12.11")):
            continue
        if "/build-" in ("/" + rel + "/") or rel.startswith("build-"):
            continue
        target = src_dst / rel
        if p.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)

    # Copy the binary.
    shutil.copy2(binary, destination / "target")
    os.chmod(destination / "target", 0o700)

    # Copy the shared library if provided.
    library_name = None
    if library and Path(library).exists():
        library_name = Path(library).name
        shutil.copy2(library, destination / library_name)

    # Copy the trigger file.
    trigger_path = Path(trigger_file)
    if trigger_path.exists():
        if trigger_path.is_file():
            shutil.copy2(trigger_path, destination / "trigger.bin")
        else:
            # The trigger could be inside a directory tree (PoC-A/B shape).
            # We copy the whole tree as trigger_tree/.
            tree_dst = destination / "trigger_tree"
            if tree_dst.exists():
                shutil.rmtree(tree_dst)
            shutil.copytree(trigger_path.parent, tree_dst)

    manifest = dict(
        bundle_type="multi-file",
        source_dir=str(source_dir),
        source_sha256=_dir_sha256(src_dst),
        binary_sha256=sha256(binary),
        library_sha256=sha256(library) if library and Path(library).exists() else None,
        library_name=library_name,
        trigger_path=str(trigger_path),
        trigger_sha256=sha256(trigger_path) if Path(trigger_path).is_file() else None,
        build=build_metadata,
        run=run_metadata,
    )
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))

    # Generate a replay.py that rebuilds and re-runs the bundle.
    replay_script = _build_project_replay_script(library_name is not None)
    (destination / "replay.py").write_text(replay_script)


def _build_project_replay_script(has_library: bool) -> str:
    """Generate a replay.py for a multi-file bundle. The script:
    1. Rebuilds the project from source/ using cmake + make (in a tmp build dir).
    2. Locates the binary and the shared library.
    3. Re-runs the binary against the saved trigger.
    """
    return '''#!/usr/bin/env python3
"""Replay the bug from a multi-file bundle (Role 3).

Rebuilds the source tree with cmake, then runs the binary against the
saved trigger file. Requires: gcc, cmake, make, libpcre2-dev (or whatever
the target needs). The bundle is self-contained except for the build
toolchain.
"""
import hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile

p = pathlib.Path(__file__).resolve().parent
m = json.loads((p / "manifest.json").read_text())

# Verify the trigger file integrity.
if m.get("trigger_sha256"):
    assert hashlib.sha256((p / "trigger.bin").read_bytes()).hexdigest() == m["trigger_sha256"], \\
        "trigger.bin corrupted"

# Rebuild the project from source/ in a temporary build directory.
src = p / "source"
build_dir = p / "_replay_build"
if build_dir.exists():
    shutil.rmtree(build_dir)
build_dir.mkdir()

build_meta = m["build"]
configure_cmd = list(build_meta["configure_command"])
# Replace the absolute source path with our local source/ dir.
configure_cmd = [str(src) if x == build_meta["source_dir"] else x for x in configure_cmd]
configure_cmd = [str(build_dir) if x == build_meta.get("build_dir", "_replay_build") else x for x in configure_cmd]

print(f"$ {' '.join(configure_cmd)}")
r = subprocess.run(configure_cmd, cwd=p)
if r.returncode != 0:
    print(f"cmake configure failed (exit {r.returncode})", file=sys.stderr)
    sys.exit(30)

make_cmd = list(build_meta["make_command"])
print(f"$ {' '.join(make_cmd)}")
r = subprocess.run(make_cmd, cwd=p)
if r.returncode != 0:
    print(f"make failed (exit {r.returncode})", file=sys.stderr)
    sys.exit(30)

# Locate the built binary.
bin_dir = build_dir / "bin"
if not bin_dir.is_dir():
    print(f"No build/bin/ directory in {build_dir}", file=sys.stderr)
    sys.exit(30)
binary = None
for f in bin_dir.iterdir():
    if f.is_file() and (f.stat().st_mode & 0o111) and (f.name == "editorconfig" or f.name.startswith("editorconfig-")):
        binary = f
        break
if binary is None:
    print(f"No editorconfig binary in {bin_dir}", file=sys.stderr)
    sys.exit(30)

# Locate the shared library.
lib_dir = build_dir / "lib"
library_path = None
if lib_dir.is_dir():
    for f in lib_dir.iterdir():
        if f.name.startswith("libeditorconfig") and ".so" in f.name and f.is_file():
            library_path = f
            break

# Set up the environment.
env = dict(m["run"]["environment"])
if library_path:
    env["LD_LIBRARY_PATH"] = str(library_path.parent)

# Find the trigger file to feed to the binary.
trigger_path = p / "trigger.bin"
if not trigger_path.exists():
    # Fall back to the saved trigger_tree/ directory.
    tree = p / "trigger_tree"
    if tree.is_dir():
        for root, _, files in os.walk(tree):
            for fn in files:
                if fn == "trigger.py":
                    trigger_path = pathlib.Path(root) / fn
                    break
            if trigger_path != p / "trigger.bin":
                break

print(f"$ {binary} {trigger_path}")
r = subprocess.run([str(binary), str(trigger_path)], env=env, cwd=p)
sys.exit(r.returncode if r.returncode >= 0 else 128 - r.returncode)
'''


def _dir_sha256(d: Path) -> str:
    """Compute a stable hash for all files in a directory tree."""
    h = hashlib.sha256()
    for p in sorted(d.rglob("*")):
        if p.is_file():
            # Use the relative path string + file contents.
            h.update(str(p.relative_to(d)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()
