"""Build Manager (Role 2).

Builds the target program in two flavors:
  * normal:    release-style build, no sanitizer, with hardening flags
  * sanitized: ASan/UBSan instrumented build with FORTIFY disabled

Two build shapes are supported via the config:
  * single-file:  sources.<v> is a .c path; build via gcc <flags> {source} -o {binary}
  * cmake:        sources.<v> is a directory; build via cmake + make

For cmake builds the runner needs LD_LIBRARY_PATH so the resulting binary
can find the shared library it links against. This is handled by the
runner via extra_env in the run step.
"""
from __future__ import annotations
import shutil
from pathlib import Path
from typing import Optional

from .runner import execute, sha256

# ---------------------------------------------------------------------------
# Single-file build (existing name-length target shape)
# ---------------------------------------------------------------------------

def build_single_file(source: Path, binary: Path, command_template: list, cwd: Path,
                     timeout: int = 60) -> dict:
    """Build a single .c file using the command template (list of argv)."""
    binary.parent.mkdir(parents=True, exist_ok=True)
    command = [x.replace("{source}", str(source)).replace("{binary}", str(binary))
               for x in command_template]
    result = execute(command, cwd, timeout=timeout)
    result["command"] = command
    if result["exit_code"] == 0 and not result["timed_out"] and binary.exists():
        result["binary_sha256"] = sha256(binary)
    return result

# ---------------------------------------------------------------------------
# CMake multi-file build (new editorconfig target shape)
# ---------------------------------------------------------------------------

def build_cmake(source_dir: Path, build_dir: Path, flavor: str,
                cmake_flags: list, make_targets: list,
                cwd: Path, extra_path: Optional[list] = None,
                timeout: int = 120) -> dict:
    """Build a cmake project with the given flavor (normal/sanitized).

    source_dir:   the project root containing CMakeLists.txt
    build_dir:    the directory to build in (created if absent)
    flavor:       "normal" or "sanitized" (only used for logging)
    cmake_flags:  list of flags to pass to cmake (already includes the
                  per-flavor -DCMAKE_C_FLAGS, -DCMAKE_EXE_LINKER_FLAGS, etc.)
    make_targets: list of make targets to build (e.g. ["editorconfig_bin"])

    Returns a dict with: command (the cmake invocation), configure_result,
    make_result, binary path(s), and sha256 of each built binary.
    """
    source_dir = Path(source_dir).resolve()
    build_dir = Path(build_dir).resolve()
    if not source_dir.is_dir():
        raise ValueError(f"CMake source dir not found: {source_dir}")
    if not (source_dir / "CMakeLists.txt").is_file():
        raise ValueError(f"No CMakeLists.txt in {source_dir}")
    build_dir.mkdir(parents=True, exist_ok=True)

    # Phase 1: configure.
    configure_cmd = ["cmake", *cmake_flags, str(source_dir), "-B", str(build_dir)]
    configure = execute(configure_cmd, cwd, timeout=timeout,
                        extra_env={"ASAN_OPTIONS": "detect_leaks=0"},
                        extra_path=extra_path)
    if configure["exit_code"] != 0 or configure["timed_out"]:
        return dict(flavor=flavor, source_dir=str(source_dir),
                    build_dir=str(build_dir),
                    configure_command=configure_cmd,
                    configure_result=configure,
                    make_result=None, binaries={})

    # Phase 2: build.
    make_cmd = ["make", "-C", str(build_dir), "-j4", *make_targets]
    make = execute(make_cmd, cwd, timeout=timeout,
                   extra_env={"ASAN_OPTIONS": "detect_leaks=0"},
                   extra_path=extra_path)
    if make["exit_code"] != 0 or make["timed_out"]:
        return dict(flavor=flavor, source_dir=str(source_dir),
                    build_dir=str(build_dir),
                    configure_command=configure_cmd,
                    configure_result=configure,
                    make_command=make_cmd,
                    make_result=make, binaries={})

    # Phase 3: locate built binaries (typically in build_dir/bin/).
    binaries = {}
    bin_dir = build_dir / "bin"
    if bin_dir.is_dir():
        for f in bin_dir.iterdir():
            if f.is_file() and f.stat().st_mode & 0o111:
                binaries[f.name] = dict(path=str(f), sha256=sha256(f))

    return dict(flavor=flavor, source_dir=str(source_dir),
                build_dir=str(build_dir),
                configure_command=configure_cmd,
                configure_result=configure,
                make_command=make_cmd,
                make_result=make,
                binaries=binaries)

def locate_binary(build_dir: Path, name: str = "editorconfig") -> Optional[Path]:
    """Locate the built binary inside a CMake build directory."""
    bin_dir = Path(build_dir) / "bin"
    if not bin_dir.is_dir():
        return None
    # Exact match first, then suffix match (e.g. editorconfig-0.12.11).
    exact = bin_dir / name
    if exact.exists():
        return exact
    for f in bin_dir.iterdir():
        if f.name.startswith(name) and f.is_file() and f.stat().st_mode & 0o111:
            return f
    return None

def locate_library(build_dir: Path, name: str = "libeditorconfig") -> Optional[Path]:
    """Locate the shared library inside a CMake build directory."""
    lib_dir = Path(build_dir) / "lib"
    if not lib_dir.is_dir():
        return None
    for f in lib_dir.iterdir():
        # libeditorconfig.so, libeditorconfig.so.0, libeditorconfig.so.0.12.11
        if f.name.startswith(name) and ".so" in f.name and f.is_file():
            return f
    return None

def remove_build_dir(build_dir: Path) -> None:
    """Remove a build directory if it exists (used for clean rebuilds)."""
    if Path(build_dir).exists():
        shutil.rmtree(build_dir)