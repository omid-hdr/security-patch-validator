"""Bounded process execution and sanitizer diagnostics. No shell execution.

Role 2 (Execution & Dynamic Testing Core): owns RunResult / ErrorSignature
dataclasses, the runner that wraps subprocess with resource limits and
environment isolation, and the sanitizer-output classifier.

Backwards compatible with the previous dict-based API: execute() still returns
a dict, but consumers that prefer the dataclass can call run_to_result().

Two new capabilities (compared to the original single-file target runner):
  * extra_env: callers can extend the controlled environment, e.g. to set
    LD_LIBRARY_PATH for binaries linked against shared libraries
    (editorconfig-core-c builds libeditorconfig.so and links the CLI
    against it; without LD_LIBRARY_PATH the binary cannot find the .so).
  * extra_path: a list of additional PATH entries (e.g. venv cmake).
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import hashlib
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import tempfile
import time
from typing import Optional


# ---------------------------------------------------------------------------
# Dataclasses (Role 2 — explicit per the role-1 docx hand-off)
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    """Outcome of one process execution."""
    argv: list
    cwd: str
    exit_code: int
    signal: Optional[int]              # SIGSEGV, SIGABRT, ...
    stdout: str
    stderr: str
    timed_out: bool
    sanitizer_detected: bool
    error_type: Optional[str]          # "stack-buffer-overflow", "heap-use-after-free", ...
    error_location: Optional[str]      # "process /tmp/vuln.c:5" (best-effort)
    crashed: bool

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ErrorSignature:
    """A comparable signature for "same error" across two runs."""
    error_type: str
    functions: list = field(default_factory=list)
    file: Optional[str] = None
    line: Optional[int] = None

    def matches(self, other: "ErrorSignature") -> bool:
        """Two signatures match iff the error type AND the top-3 function
        chain are equal. Addresses, line numbers and source basenames are
        intentionally ignored — they shift across a patch without changing
        the underlying bug class."""
        if other is None:
            return False
        return (self.error_type == other.error_type
                and self.functions == other.functions)


# ---------------------------------------------------------------------------
# Environment and resource limits
# ---------------------------------------------------------------------------

# Persistent base environment; never persists the user's secrets.
_BASE_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "DEBUGINFOD_URLS": "",
    "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:symbolize=1",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
}


def controlled_env(extra_env: Optional[dict] = None,
                   extra_path: Optional[list] = None) -> dict:
    """Build the environment for a controlled subprocess.

    extra_env:   overrides that WIN — callers may set LD_LIBRARY_PATH,
                 ASAN_OPTIONS extensions, etc.
    extra_path:  extra PATH entries prepended before the default.
    """
    env = dict(_BASE_ENV)
    if extra_path:
        env["PATH"] = ":".join([str(p) for p in extra_path]) + ":" + env["PATH"]
    if extra_env:
        for k, v in extra_env.items():
            if v is None:
                continue
            # For ASAN_OPTIONS/UBSAN_OPTIONS, append rather than overwrite so
            # callers can add options without losing halt_on_error/symbolize.
            if k in ("ASAN_OPTIONS", "UBSAN_OPTIONS") and env.get(k):
                env[k] = env[k] + ":" + str(v)
            else:
                env[k] = str(v)
    return env


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def execute(argv, cwd, timeout=15, input_bytes=None, extra_env=None, extra_path=None):
    """Run `argv` in `cwd` with resource limits and isolation.

    Returns a dict (backward-compatible with the original API). To get the
    typed RunResult, call run_to_result() instead.
    """
    started = time.monotonic()
    env = controlled_env(extra_env=extra_env, extra_path=extra_path)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.Popen(argv, cwd=str(cwd), env=env,
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
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        out.seek(0)
        err.seek(0)
        stdout = out.read(2 * 1024 * 1024).decode("utf-8", "replace")
        stderr = err.read(2 * 1024 * 1024).decode("utf-8", "replace")
    sig = -p.returncode if p.returncode < 0 else None
    cls = classify(stderr, sig, timed_out)
    result = dict(argv=list(argv), cwd=str(cwd), exit_code=p.returncode,
                  signal=sig, timed_out=timed_out, stdout=stdout, stderr=stderr,
                  duration_seconds=round(time.monotonic() - started, 4))
    result.update(cls)
    return result


def run_to_result(argv, cwd, timeout=15, input_bytes=None,
                  extra_env=None, extra_path=None) -> RunResult:
    """Same as execute(), but returns a typed RunResult."""
    r = execute(argv, cwd, timeout, input_bytes, extra_env, extra_path)
    return RunResult(
        argv=r["argv"], cwd=r["cwd"], exit_code=r["exit_code"],
        signal=r["signal"], stdout=r["stdout"], stderr=r["stderr"],
        timed_out=r["timed_out"],
        sanitizer_detected=bool(r.get("detection_mechanism")),
        error_type=r.get("error_type"),
        error_location=_extract_location(r.get("frames")),
        crashed=bool(r.get("abnormal")),
    )


def _extract_location(frames):
    """Pick the most useful application frame as the error location."""
    if not frames:
        return None
    f = frames[0]
    return f"{f.get('function', '?')} {f.get('file', '?')}:{f.get('line', '?')}"


# ---------------------------------------------------------------------------
# Sanitizer-output classifier
# ---------------------------------------------------------------------------

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
    if not mechanism and ("buffer overflow detected" in stderr or "__fortify_fail" in stderr):
        mechanism = "fortify"
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
        # Source basenames/line numbers may change across a patch; the
        # function chain remains comparable.
        signature = {"error_type": error_type,
                     "functions": [x["function"] for x in frames[:3]]}
    return dict(error_type=error_type, detection_mechanism=mechanism,
                frames=frames, signature=signature,
                abnormal=bool(timed_out or sig or mechanism))


def signature_to_dataclass(sig_dict: Optional[dict]) -> Optional[ErrorSignature]:
    """Convert the legacy dict signature into an ErrorSignature dataclass."""
    if sig_dict is None:
        return None
    return ErrorSignature(
        error_type=sig_dict["error_type"],
        functions=list(sig_dict.get("functions", [])),
    )


def same_error(a, b):
    """Compare two signatures (dict OR ErrorSignature) for equivalence.

    Backward-compatible with the original dict-based API. Accepts either
    shape so existing callers don't need updating.
    """
    if a is None or b is None:
        return False
    if isinstance(a, ErrorSignature) and isinstance(b, ErrorSignature):
        return a.matches(b)
    # Dict path: error_type AND top-3 function chain equal.
    return (a.get("error_type") == b.get("error_type")
            and a.get("functions") == b.get("functions"))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()