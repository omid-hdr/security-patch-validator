import difflib
import json
from pathlib import Path
import re
import shutil
import subprocess

from .runner import sha256


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
    # Repeat until no deletion preserves the signature.
    i = 0
    while i < len(current) and calls < max_runs:
        if keeps(current[:i] + current[i + 1:]):
            current = current[:i] + current[i + 1:]
            i = 0
        else:
            i += 1
    return current, dict(calls=calls, budget_exhausted=calls >= max_runs,
                         one_minimal=i >= len(current), trace=trace)


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


def correlate(base_source, patched_source, base_frames, patched_frames, comparisons):
    old = Path(base_source).read_text().splitlines(True)
    new = Path(patched_source).read_text().splitlines(True)
    diff_result = subprocess.run(["git", "diff", "--no-index", "--no-ext-diff", "--", str(base_source), str(patched_source)],
                                 capture_output=True, text=True, timeout=15)
    if diff_result.returncode not in (0, 1):
        raise ValueError("git diff failed: " + diff_result.stderr)
    diff = diff_result.stdout
    matcher = difflib.SequenceMatcher(a=old, b=new)
    changes = []
    # Find enclosing functions in these C sources; no claim of general C AST analysis.
    def enclosing(lines, idx):
        for line in reversed(lines[:idx + 1]):
            m = re.match(r"\s*[\w *]+\s+(\w+)\([^;]*\)\s*\{", line)
            if m:
                return m.group(1)
        return None
    for op, a, b, c, d in matcher.get_opcodes():
        if op != "equal":
            changes.append(dict(operation=op, old_lines=[a + 1, b], new_lines=[c + 1, d],
                                old_function=enclosing(old, a), new_function=enclosing(new, c)))
    matches = []
    for version, frames in (("base", base_frames), ("patched", patched_frames)):
        expected = Path(base_source if version == "base" else patched_source).name
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


def bundle(destination, source, binary, input_bytes, build_command, result, metadata, mode, run_argv):
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination / "source.c")
    shutil.copy2(binary, destination / "target")
    (destination / "input.bin").write_bytes(input_bytes)
    # Replay uses paths relative to this self-contained directory.
    (destination / "manifest.json").write_text(json.dumps(dict(
        **metadata, binary_sha256=sha256(binary), source_sha256=sha256(source),
        input_sha256=sha256(destination / "input.bin"), original_build_command=build_command,
        build_command=[x.replace(str(source), "source.c").replace(str(binary), "target") for x in build_command],
        original_result=result, mode=mode, run_argv=run_argv), indent=2))
    (destination / "replay.py").write_text('''import hashlib,json,os,pathlib,subprocess,sys
p=pathlib.Path(__file__).resolve().parent
m=json.loads((p/'manifest.json').read_text())
assert hashlib.sha256((p/'target').read_bytes()).hexdigest()==m['binary_sha256']
os.chmod(p/'target',0o700)
data=(p/'input.bin').read_bytes()
argv=[x.replace('{binary}',str(p/'target')).replace('{input_file}',str(p/'input.bin')).replace('{input}',data.decode('utf-8')) for x in m['run_argv']]
env=dict(m['environment'])
try:
 r=subprocess.run(argv,cwd=p,env=env,input=data if m['mode']=='stdin' else None,timeout=15)
 sys.exit(r.returncode if r.returncode>=0 else 128-r.returncode)
except subprocess.TimeoutExpired:
 sys.exit(124)
''')
