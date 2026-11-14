"""Reproducer bundles (Role 3).

A bundle is a self-contained directory that a human can carry to any
Linux machine (with the build toolchain installed) and re-run to see the
exact same sanitizer report — no access to the original repo needed.

Two shapes:

  * bundle()        — single-file targets (name-length): source.c,
                      the compiled target, input.bin, manifest.json,
                      replay.py. The replay re-runs the shipped binary
                      directly.
  * project_bundle() — multi-file cmake targets (editorconfig): the
                      whole source tree (build outputs excluded), the
                      built binary + shared library, the COMPLETE PoC
                      trigger tree (deep directory + .editorconfig +
                      trigger file — not just the trigger file, because
                      the crash depends on the whole tree), manifest.json
                      and a replay.py that REBUILDS from source with
                      cmake+make in a local _replay_build/ directory and
                      then runs the fresh binary against the trigger tree.

Everything the replay needs is either stored RELATIVE to the bundle or
rebuilt from the shipped source — the bundle must never reference
absolute paths of the machine that produced it (a previous version did,
which made bundles fail on every other machine; that is fixed here).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Optional, Union

from .runner import sha256

PathLike = Union[str, Path]


# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------

_BUILD_EXCLUDES = ("/.git/", "/build-", "/CMakeFiles/", "/CMakeCache.txt",
                   "/cmake_install.cmake", "/CTestTestfile.cmake")
_ARTIFACT_SUFFIXES = (".o", ".so", ".a", ".so.0", ".so.0.12.11")


def copy_source_tree(source_dir: Path, dst: Path) -> int:
    """Copy a source tree, excluding build outputs and VCS metadata.

    Returns the number of files copied."""
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    count = 0
    for p in sorted(Path(source_dir).rglob("*")):
        rel = p.relative_to(source_dir).as_posix()
        if rel.startswith(".git/") or rel == ".git":
            continue
        if any(x in ("/" + rel + "/") for x in _BUILD_EXCLUDES):
            continue
        if rel.endswith(_ARTIFACT_SUFFIXES):
            continue
        target = dst / rel
        if p.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
            count += 1
    return count


def dir_sha256(d: Path) -> str:
    """Stable hash over a directory tree (relative paths + contents)."""
    h = hashlib.sha256()
    for p in sorted(Path(d).rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(d)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()


# Characters that editorconfig's ini_handler escapes with a backslash
# (must mirror src/lib/ec_glob.c:43 / make_poc.py EC_SPECIAL_CHARS).
_EC_SPECIAL_CHARS = set("?[]\\*-{},")


def _special_count(path_str: str) -> int:
    """Count chars that get backslash-escaped in a directory path."""
    return sum(1 for c in path_str if c in _EC_SPECIAL_CHARS)


# ---------------------------------------------------------------------------
# Single-file bundle (name-length shape)
# ---------------------------------------------------------------------------

def bundle(destination: PathLike, source: PathLike, binary: PathLike,
           input_bytes: bytes, build_command: list, result: dict,
           metadata: dict, mode: str, run_argv: list) -> None:
    """Assemble the single-file reproducer bundle."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination / "source.c")
    shutil.copy2(binary, destination / "target")
    (destination / "input.bin").write_bytes(input_bytes)
    (destination / "manifest.json").write_text(json.dumps(dict(
        **metadata,
        binary_sha256=sha256(binary),
        source_sha256=sha256(source),
        input_sha256=sha256(destination / "input.bin"),
        original_build_command=build_command,
        build_command=[x.replace(str(source), "source.c")
                         .replace(str(binary), "target") for x in build_command],
        original_result=result, mode=mode, run_argv=run_argv,
        bundle_type="single-file"), indent=2))
    (destination / "replay.py").write_text(_SINGLE_FILE_REPLAY)


_SINGLE_FILE_REPLAY = '''import hashlib,json,os,pathlib,subprocess,sys
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
'''


# ---------------------------------------------------------------------------
# Multi-file (cmake) bundle — editorconfig shape
# ---------------------------------------------------------------------------

def project_bundle(destination: PathLike, source_dir: PathLike,
                   binary: PathLike, library: Optional[PathLike],
                   trigger_file: PathLike,
                   build_metadata: dict, run_metadata: dict,
                   *, exclude_patterns: Optional[list] = None) -> None:
    """Assemble a multi-file reproducer bundle.

    Layout:
      destination/
        source/        <- source tree, build outputs excluded (relative!)
        target         <- the shipped binary (for direct inspection)
        lib*.so*       <- the shared library, if any
        trigger_tree/  <- the COMPLETE PoC directory tree containing the
                          trigger file (the crash needs the .editorconfig
                          and the deep path, not just the trigger file)
        manifest.json  <- everything relative, plus cmake/make commands
                          rewritten to run inside this bundle
        replay.py      <- rebuild from source/ + re-run against trigger_tree

    build_metadata needs: {flavor, configure_command, make_command,
    cmake_flags, make_targets, binary_name, library_name}
    run_metadata needs:   {environment, commit, dirty, signature,
                           compiler, mode, run_argv}
    """
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    source_dir = Path(source_dir).resolve()

    # 1) Source tree (relative, no build outputs, no absolute paths).
    src_dst = destination / "source"
    files_copied = copy_source_tree(source_dir, src_dst)

    # 2) Binary + library for direct inspection.
    shutil.copy2(binary, destination / "target")
    os.chmod(destination / "target", 0o700)
    library_name = None
    if library and Path(library).exists():
        library_name = Path(library).name
        shutil.copy2(library, destination / library_name)

    # 3) The complete trigger tree (PoC directory), not just one file.
    trigger_file = Path(trigger_file).resolve()
    tree_dst = destination / "trigger_tree"
    if tree_dst.exists():
        shutil.rmtree(tree_dst)
    trigger_rel = None
    if trigger_file.exists():
        # The PoC tree root: the outermost directory that make_poc created
        # (the parent of the "e/..." nested path). We copy the whole tree so
        # the relative directory depth — which the overflow depends on — is
        # preserved exactly.
        tree_root = _poc_tree_root(trigger_file, source_dir)
        shutil.copytree(tree_root, tree_dst)
        try:
            trigger_rel = trigger_file.relative_to(tree_root).as_posix()
        except ValueError:
            trigger_rel = None
        # If the trigger is not inside the tree root (unexpected), fall
        # back to copying its parent directory.
        if trigger_rel is None or trigger_rel.startswith(".."):
            shutil.rmtree(tree_dst)
            shutil.copytree(trigger_file.parent, tree_dst)
            trigger_rel = trigger_file.name

    # 4) Manifest — all paths RELATIVE to the bundle.
    bm = dict(build_metadata)
    # Rewrite the recorded configure/make commands into bundle-local ones.
    # The builder may record relative or absolute source/build dirs, and the
    # command arguments may not match those recorded strings exactly, so
    # rewrite by ROLE rather than by exact string equality:
    #   configure: cmake <flags> <source_dir> -B <build_dir>
    #     -> cmake <flags> source -B _replay_build
    #   make:      make -C <build_dir> [flags] <targets>
    #     -> make -C _replay_build [flags] <targets>
    source_dir_s = str(bm.get("source_dir", ""))
    build_dir_s = str(bm.get("build_dir", ""))
    configure_command = [str(x) for x in bm["configure_command"]]
    make_command = [str(x) for x in bm["make_command"]]

    def _is_source_path(x: str) -> bool:
        if not source_dir_s:
            return False
        if x == source_dir_s:
            return True
        return x.endswith("/" + source_dir_s) if source_dir_s.startswith(".") \
            else x == source_dir_s or x.endswith("/" + source_dir_s)

    def _is_build_path(x: str) -> bool:
        if not build_dir_s:
            return False
        if x == build_dir_s:
            return True
        return x.endswith("/" + build_dir_s)

    def _rewrite_configure(argv):
        out = []
        expect_build = False
        for x in argv:
            if x == "-B":
                out.append(x)
                expect_build = True
                continue
            if expect_build:
                out.append("_replay_build")
                expect_build = False
                continue
            if _is_source_path(x):
                out.append("source")
                continue
            out.append(x)
        # If the source dir never matched (unexpected shape), replace the
        # last absolute path argument with source/.
        if "source" not in out:
            for i in range(len(out) - 1, -1, -1):
                if out[i].startswith("/") and not out[i].startswith("-"):
                    out[i] = "source"
                    break
        return out

    def _rewrite_make(argv):
        out = []
        expect_dir = False
        for x in argv:
            if x == "-C":
                out.append(x)
                expect_dir = True
                continue
            if expect_dir:
                out.append("_replay_build")
                expect_dir = False
                continue
            if _is_build_path(x):
                out.append("_replay_build")
                continue
            out.append(x)
        return out

    configure_command = _rewrite_configure(configure_command)
    make_command = _rewrite_make(make_command)

    manifest = dict(
        bundle_type="multi-file",
        files_copied=files_copied,
        source_sha256=dir_sha256(src_dst),
        binary_sha256=sha256(binary),
        library_name=library_name,
        library_sha256=sha256(library) if library and Path(library).exists() else None,
        trigger_rel=trigger_rel,
        trigger_sha256=sha256(trigger_file) if trigger_file.is_file() else None,
        # The ABSOLUTE LENGTH and SPECIAL-CHAR COUNT of the original
        # trigger path both matter: the editorconfig overflow is computed
        # from len(dir) + count(special chars in dir), so replay must
        # materialize the trigger at a path matching BOTH (padded with
        # harmless '{x}'/ 'a' components if the bundle lives elsewhere).
        trigger_path_length=len(str(trigger_file)),
        trigger_specials=_special_count(os.fspath(os.path.dirname(trigger_file))),
        build=dict(bm, configure_command=configure_command,
                   make_command=make_command),
        run=run_metadata,
    )
    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2, default=str))

    # 5) replay.py — rebuild locally, run against trigger_tree.
    (destination / "replay.py").write_text(_MULTI_FILE_REPLAY)


def _poc_tree_root(trigger_file: Path, source_dir: Path) -> Path:
    """Find the PoC tree root for a trigger file.

    make_poc.py builds trees of the shape <root>/e/<nested>/trigger.py
    where <root> was $POC_ROOT (…/poc-trees/<id>). The nested path under
    "e" is what overflows the buffer, so we must copy from the directory
    that CONTAINS "e". We walk up from the trigger until we find a
    directory whose immediate child chain starts with "e", capped at the
    filesystem root; if nothing matches we fall back to the trigger's
    parent (a 1-level tree).
    """
    node = trigger_file.parent
    for _ in range(60):  # deep trees exist; do not loop forever
        if node.name == "e":
            return node.parent
        if node.parent == node:
            break
        node = node.parent
    return trigger_file.parent


_MULTI_FILE_REPLAY = '''#!/usr/bin/env python3
"""Replay a multi-file bundle (Role 3).

Rebuilds the shipped source tree with cmake + make inside this bundle
(_replay_build/), then runs the fresh binary against the saved trigger
tree. Requires: gcc, cmake, make and the target's library dependencies
(e.g. libpcre2-dev). No file outside this bundle is used.
"""
import hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile

p = pathlib.Path(__file__).resolve().parent
m = json.loads((p / "manifest.json").read_text())

# 1) Verify the shipped binary integrity (the one we re-run is rebuilt,
#    but the shipped copy must still match the recorded hash).
assert hashlib.sha256((p / "target").read_bytes()).hexdigest() == m["binary_sha256"], \\
    "target corrupted"

# 2) Rebuild the project from source/ in a local build directory.
src = p / "source"
build_dir = p / "_replay_build"
if build_dir.exists():
    shutil.rmtree(build_dir)
build_dir.mkdir()

bm = m["build"]
configure_cmd = [str(x) for x in bm["configure_command"]]
# Any absolute path argument that somehow survived refers to the original
# machine; replace the recorded source/build dirs with bundle-local ones.
configure_cmd = [str(src) if x == "source" else
                 str(build_dir) if x == "_replay_build" else x
                 for x in configure_cmd]
print(f"$ {' '.join(configure_cmd)}", flush=True)
r = subprocess.run(configure_cmd, cwd=p)
if r.returncode != 0:
    print(f"cmake configure failed (exit {r.returncode})", file=sys.stderr)
    sys.exit(30)

make_cmd = [str(x) for x in bm["make_command"]]
make_cmd = [str(build_dir) if x == "_replay_build" else x for x in make_cmd]
print(f"$ {' '.join(make_cmd)}", flush=True)
r = subprocess.run(make_cmd, cwd=p)
if r.returncode != 0:
    print(f"make failed (exit {r.returncode})", file=sys.stderr)
    sys.exit(30)

# 3) Locate the rebuilt binary (exact name first, then prefix match).
binary_name = bm.get("binary_name", "editorconfig")
bin_dir = build_dir / "bin"
binary = None
if bin_dir.is_dir():
    exact = bin_dir / binary_name
    if exact.is_file() and (exact.stat().st_mode & 0o111):
        binary = exact
    else:
        for f in sorted(bin_dir.iterdir()):
            if (f.name.startswith(binary_name) and f.is_file()
                    and (f.stat().st_mode & 0o111)):
                binary = f
                break
if binary is None:
    print(f"No {binary_name} binary in {bin_dir}", file=sys.stderr)
    sys.exit(30)

# 4) Locate the shared library for LD_LIBRARY_PATH.
library_path = None
lib_dir = build_dir / "lib"
if lib_dir.is_dir():
    lib_prefix = bm.get("library_name") or "lib" + binary_name
    for f in sorted(lib_dir.iterdir()):
        if f.name.startswith(lib_prefix.split(".")[0]) and ".so" in f.name \\
                and f.is_file():
            library_path = f
            break

# 5) Locate the trigger file inside the shipped trigger tree.
tree = p / "trigger_tree"
trigger_path = None
rel = m.get("trigger_rel")
if rel:
    candidate = tree / rel
    if candidate.is_file():
        trigger_path = candidate
if trigger_path is None:
    for root, _, files in os.walk(tree):
        for fn in files:
            if (os.path.basename(rel) if rel else "trigger.py") == fn:
                trigger_path = pathlib.Path(root) / fn
                break
        if trigger_path:
            break
if trigger_path is None:
    print("No trigger file found in trigger_tree/", file=sys.stderr)
    sys.exit(30)

# 6) Re-materialize the trigger at a path with the SAME escape-relevant
#    length as the original. The editorconfig overflow depends on
#    escaped_dir = len(dir_path) + count_of_special_chars(dir_path)
#    where the special chars are ?[]\\*-{}, — each one gets a backslash.
#    This bundle may live at a shorter/different path than the machine
#    that produced it, so we copy the PoC tree under a temporary prefix
#    built from '{x}' and 'a'-run components chosen so that BOTH the
#    plain length AND the special-char count match the recorded values.
target_total = m.get("trigger_path_length")   # plain path length
target_specials = m.get("trigger_specials")   # special chars in dir part
SPECIALS = set("?[]\\\\*-{},")
if (target_total or target_specials) and trigger_path.is_file():
    d = os.path.dirname(str(trigger_path))
    cur_len = len(str(trigger_path))
    cur_spec = sum(1 for c in d if c in SPECIALS)
    if cur_len != target_total or cur_spec != target_specials:
        pad_root = pathlib.Path(tempfile.gettempdir()) / "patchlab_pad"
        if pad_root.exists():
            shutil.rmtree(pad_root)
        # rel_part is the PoC-relative tail after trigger_tree/. The
        # prefix we are about to build REPLACES the whole current prefix
        # (bundle path), so the budget is computed from rel_part alone:
        #   final = <pad_root>/<parts>/<rel_part>
        # and every component's plain contribution includes its leading
        # slash, EXCEPT the first part which hangs off pad_root.
        rel_part = str(trigger_path.relative_to(tree))
        rel_dir_specials = sum(1 for c in os.path.dirname(rel_part) if c in SPECIALS)
        # Plain chars the prefix must contribute:
        #   target_total = len(pad_root) + 1 + (sum(len(p) for parts) + (len(parts)-1)) + 1 + len(rel_part)
        need_len = target_total - len(rel_part) - len(str(pad_root)) - 2
        # Specials the prefix must contribute (only from parts; rel_part
        # keeps its own specials, pad_root has none).
        need_spec = target_specials - rel_dir_specials
        if need_len < 1 or need_spec < 0:
            print(f"cannot pad: need_len={need_len}, need_spec={need_spec}",
                  file=sys.stderr)
            sys.exit(30)
        # Solve exactly. The prefix contributes:
        #   sum(len(p) for p in parts) + len(parts) - 1   (chars + inner slashes)
        # and the full path is:
        #   pad_root + '/' + '/'.join(parts) + '/' + rel_part
        # so: sum(len(p)) + len(parts) - 1 == need_len  (exact equality).
        nbrace = need_spec // 2
        odd = need_spec % 2
        parts = ["{x}"] * nbrace + (["b,c"] if odd else [])
        spent = sum(len(p) for p in parts) + len(parts) - 1
        f = need_len - spent
        if f < 0:
            print(f"cannot pad: negative filler ({f})", file=sys.stderr)
            sys.exit(30)
        if f > 0:
            if f == 1:
                # A 1-char filler component adds 2 chars (1 char + 1
                # slash) — pad with a longer single component instead.
                print("cannot pad: 1-char filler remainder", file=sys.stderr)
                sys.exit(30)
            parts.append("a" * (f - 1))  # f-1 chars + 1 slash = f chars
        # Verify the algebra before touching the filesystem.
        assert sum(len(p) for p in parts) + len(parts) - 1 == need_len, \\
            "padding algebra error"
        dst_root = pad_root.joinpath(*parts)
        final = dst_root / rel_part
        # Verify BOTH budgets landed exactly before copying anything.
        d2 = os.path.dirname(str(final))
        if len(str(final)) != target_total or \\
                sum(1 for c in d2 if c in SPECIALS) != target_specials:
            print(f"padding verify failed: len={len(str(final))}/"
                  f"{target_total}, specials="
                  f"{sum(1 for c in d2 if c in SPECIALS)}/{target_specials}",
                  file=sys.stderr)
            sys.exit(30)
        # Find the PoC tree root (parent of the top 'e' component).
        node = trigger_path.parent
        for _ in range(200):
            if node.name == "e" or node.parent == node:
                break
            node = node.parent
        src_tree_root = node.parent if node.name == "e" else tree
        dst_root.mkdir(parents=True, exist_ok=True)
        for root, dirs, files in os.walk(src_tree_root):
            rel_dir = os.path.relpath(root, src_tree_root)
            target_dir = dst_root if rel_dir == "." else dst_root / rel_dir
            target_dir.mkdir(parents=True, exist_ok=True)
            for fn in files:
                shutil.copy2(os.path.join(root, fn), target_dir / fn)
        trigger_path = final
        print(f"padded trigger to len={target_total}, specials={target_specials}")

# 7) Run the rebuilt binary against the trigger.
env = dict(m["run"]["environment"])
if library_path:
    env["LD_LIBRARY_PATH"] = str(library_path.parent)
print(f"$ {binary} {trigger_path}", flush=True)
try:
    r = subprocess.run([str(binary), str(trigger_path)], env=env, cwd=p,
                       timeout=120)
    sys.exit(r.returncode if r.returncode >= 0 else 128 - r.returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
'''
