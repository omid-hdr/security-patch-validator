"""Bounded process execution and sanitizer diagnostics. No shell execution."""
import hashlib
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import tempfile
import time


def controlled_env():
    # Persist only effective settings below, never a dump of the user's secrets.
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "DEBUGINFOD_URLS": "",
            "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:symbolize=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def execute(argv, cwd, timeout=15, input_bytes=None):
    started = time.monotonic()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.Popen(argv, cwd=cwd, env=controlled_env(),
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=out, stderr=err, start_new_session=True, preexec_fn=limits)
        timed_out = False
        try:
            p.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
        finally:
            # Also reap any remaining descendants in the process group.
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        out.seek(0)
        err.seek(0)
        stdout = out.read(2 * 1024 * 1024).decode("utf-8", "replace")
        stderr = err.read(2 * 1024 * 1024).decode("utf-8", "replace")
    result = dict(argv=argv, cwd=str(cwd), exit_code=p.returncode,
                  signal=-p.returncode if p.returncode < 0 else None,
                  timed_out=timed_out, stdout=stdout, stderr=stderr,
                  duration_seconds=round(time.monotonic() - started, 4))
    result.update(classify(stderr, result["signal"], timed_out))
    return result


def classify(stderr, sig=None, timed_out=False):
    match = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", stderr)
    summary = re.search(r"SUMMARY: (?:AddressSanitizer|UndefinedBehaviorSanitizer): ([\w-]+)", stderr)
    error_type = match.group(1) if match else summary.group(1) if summary else None
    mechanism = "ASan" if "AddressSanitizer" in stderr else None
    if not mechanism and "runtime error:" in stderr:
        mechanism = "UBSan"
        error_type = "undefined-behavior"
    if not mechanism and ("stack smashing detected" in stderr or "__stack_chk_fail" in stderr):
        mechanism = "stack-canary"
    if not mechanism and sig:
        mechanism = "os-signal"
    frames = []
    # Include application frames; ignore ASan interceptors/runtime frames.
    for line in stderr.splitlines():
        if not re.search(r"#\d+", line):
            continue
        m = re.search(r"\bin\s+(\S+).*?\s(/[^\s]+\.(?:c|cc|cpp|cxx)):(\d+)", line)
        if m and not any(x in m.group(2) for x in ("/compiler-rt/", "/sanitizer_", "/asan/", "/ubsan/")):
            frames.append(dict(function=m.group(1), file=m.group(2), line=int(m.group(3))))
    signature = None
    if error_type and frames:
        # Source basenames/line numbers may change across a patch; function chain remains comparable.
        signature = {"error_type": error_type, "functions": [x["function"] for x in frames[:3]]}
    return dict(error_type=error_type, detection_mechanism=mechanism,
                frames=frames, signature=signature,
                abnormal=bool(timed_out or sig or mechanism))


def same_error(a, b):
    return a is not None and b is not None and a == b


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
