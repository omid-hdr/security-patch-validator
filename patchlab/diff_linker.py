"""Diff linker (Role 3): correlate the static patch diff with the dynamic
crash stack traces.

Given the base and patched sources plus the stack frames observed during
the paired dynamic runs, this module answers ONE question honestly:

    Does a crashing stack frame land inside a function that the patch
    changed?

  * "supported":  at least one crashing frame's function matches a changed
                  region's enclosing function in the same file. This is
                  *evidence* that the patch touched the code path involved
                  in the crash — NOT proof of causation.
  * "inconclusive": no overlap was found. Proximity of line numbers alone
                  is never reported as support.

Two entry points:
  * correlate():         single-file targets (name-length).
  * project_correlate(): multi-file targets (editorconfig) — walks both
                  source trees, diffs every changed file, and matches
                  frames against changed functions in ANY file.

Both handle the two common C brace styles for finding the enclosing
function of a changed region:

    K&R:      int main(void) {      <- signature and brace on ONE line
    Allman:   int main(void)        <- signature ...
              {                     <- ... brace on the NEXT line

and skip non-function control statements (if/for/while/switch) whose
parenthesized heads look like signatures.
"""
from __future__ import annotations

import difflib
import re
import subprocess
from pathlib import Path

from .runner import sha256

# C keywords whose parenthesized heads must NOT be treated as functions.
_NON_FUNCTION_HEADS = {
    "if", "for", "while", "switch", "return", "sizeof", "catch", "do",
    "else", "elseif",
}

# A bare opening brace line (Allman style).
_OPEN_BRACE = re.compile(r"^\s*\{\s*$")

# A line is a candidate function head only if it ENDS like one:
#   "static int foo(int a, char *b)"   (Allman head, brace on next line)
#   "int main(void) {"                 (K&R, brace on same line)
# We anchor on the END of the line and keep the quantifiers flat —
# nested quantifiers like (?:[\w *]+\s+)+ cause catastrophic
# backtracking on comment-heavy lines (e.g. "*  word  word  word ...").
_SIG_END_KR = re.compile(
    r"([\w]+)\s*\(([^;{}]*)\)\s*\{?\s*\Z")
_SIG_END_NOBRACE = re.compile(
    r"([\w]+)\s*\(([^;{}]*)\)\s*\Z")


def _looks_like_function_head(line: str):
    """(name, has_brace) if the line ends like a function head, else None.

    Works from the END of the line (anchored at \\Z) so the pattern stays
    linear-time. The prefix before the name is NOT matched with a
    quantifier, which avoids the exponential backtracking that hung
    project_correlate() on files with wide comment blocks.
    """
    m = _SIG_END_KR.search(line)
    if m and m.group(1) not in _NON_FUNCTION_HEADS:
        return m.group(1), True
    m = _SIG_END_NOBRACE.search(line)
    if m and m.group(1) not in _NON_FUNCTION_HEADS:
        return m.group(1), False
    return None


def enclosing_function(lines, idx: int):
    """Name of the function containing line `idx` (0-based), or None.

    Walks upward looking for a function head. Handles both brace styles
    (K&R: signature and brace on one line; Allman: brace on the next
    line) and ignores if/for/while/switch heads. Attribute-macro lines
    (e.g. EDITORCONFIG_LOCAL) and comments do not reset a pending
    Allman signature, because they can legitimately sit between the
    signature and its opening brace.
    """
    pending_signature = None  # last signature seen without its brace yet
    for line in reversed(lines[:idx + 1]):
        head = _looks_like_function_head(line)
        if head is not None:
            name, has_brace = head
            if has_brace:
                return name            # complete head: done.
            pending_signature = name   # Allman: brace may be on next line.
            continue
        if _OPEN_BRACE.match(line):
            if pending_signature:
                return pending_signature
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(("/", "*", "//", "#")):
            continue  # comments/blank/directives never reset a signature
        pending_signature = None
    return pending_signature


def _git_diff_no_index(path_a: Path, path_b: Path) -> str:
    """Unified diff between two files (no repository needed)."""
    r = subprocess.run(
        ["git", "diff", "--no-index", "--no-ext-diff", "--",
         str(path_a), str(path_b)],
        capture_output=True, text=True, timeout=15)
    if r.returncode not in (0, 1):
        raise ValueError("git diff failed: " + r.stderr)
    return r.stdout


def correlate(base_source, patched_source, base_frames, patched_frames,
              comparisons):
    """Single-file diff correlation (name-length shape)."""
    old = Path(base_source).read_text().splitlines(True)
    new = Path(patched_source).read_text().splitlines(True)
    diff = _git_diff_no_index(Path(base_source), Path(patched_source))
    matcher = difflib.SequenceMatcher(a=old, b=new)
    changes = []
    for op, a, b, c, d in matcher.get_opcodes():
        if op != "equal":
            changes.append(dict(
                operation=op, old_lines=[a + 1, b], new_lines=[c + 1, d],
                old_function=enclosing_function(old, a),
                new_function=enclosing_function(new, c),
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
                reason=("Dynamic application stack frame intersects changed "
                        "function; paired runs attached") if matches else
                       ("No changed-function/stack match; proximity alone is "
                        "insufficient"),
                causal_proof=False, paired_runs=comparisons)


# ---------------------------------------------------------------------------
# Multi-file (project) correlation
# ---------------------------------------------------------------------------

_DEFAULT_EXCLUDES = ["/.git/", "/build-", "/CMakeFiles/",
                     "/CMakeCache.txt", "/cmake_install.cmake",
                     "/CTestTestfile.cmake"]


def _list_sources(tree: Path, exclude_patterns):
    """Map relative path -> absolute path for source files, skipping build
    outputs and VCS metadata."""
    files = {}
    for p in tree.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(tree).as_posix()
        if any(x in ("/" + rel + "/") or rel.startswith(x.lstrip("/"))
               for x in exclude_patterns):
            continue
        if rel.startswith(".git/") or rel == ".git":
            continue
        if rel.endswith((".o", ".so", ".a", ".so.0", ".so.0.12.11")):
            continue
        files[rel] = p
    return files


def project_correlate(base_dir, patched_dir, base_frames, patched_frames,
                      comparisons, exclude_patterns=None):
    """Multi-file diff correlation (editorconfig shape).

    Walks both source trees, produces one unified git diff covering every
    changed file, and matches the dynamic stack frames against changed
    functions in ANY file (not just one). Build outputs (.git/, build-*/,
    CMakeFiles/, *.o, *.so) are excluded from the comparison.
    """
    base_dir = Path(base_dir).resolve()
    patched_dir = Path(patched_dir).resolve()
    excludes = list(exclude_patterns) if exclude_patterns else list(_DEFAULT_EXCLUDES)

    base_files = _list_sources(base_dir, excludes)
    patched_files = _list_sources(patched_dir, excludes)
    all_rels = sorted(set(base_files) | set(patched_files))

    diff_parts = []
    changes = []  # one entry per changed region per file

    for rel in all_rels:
        bp = base_files.get(rel)
        pp = patched_files.get(rel)
        if bp and pp and sha256(bp) == sha256(pp):
            continue
        if bp and not pp:
            diff_parts.append(f"--- a/{rel}\n+++ /dev/null\n")
            changes.append(dict(file=rel, operation="delete",
                                old_function=None, new_function=None,
                                old_lines=None, new_lines=None))
            continue
        if pp and not bp:
            new_lines = pp.read_text().splitlines(True)
            diff_parts.append(f"--- /dev/null\n+++ b/{rel}\n")
            for line in new_lines:
                diff_parts.append(f"+{line}")
            changes.append(dict(file=rel, operation="add",
                                old_function=None,
                                new_function=enclosing_function(new_lines, 0),
                                old_lines=None, new_lines=[1, len(new_lines)]))
            continue
        # Both exist and differ.
        old = bp.read_text().splitlines(True)
        new = pp.read_text().splitlines(True)
        diff_parts.append(_git_diff_no_index(bp, pp))
        matcher = difflib.SequenceMatcher(a=old, b=new)
        for op, a, b, c, d in matcher.get_opcodes():
            if op != "equal":
                changes.append(dict(
                    file=rel, operation=op,
                    old_lines=[a + 1, b], new_lines=[c + 1, d],
                    old_function=enclosing_function(old, a),
                    new_function=enclosing_function(new, c)))

    diff = "".join(diff_parts)

    # Match stack frames against changes in any file.
    matches = []
    for version, frames in (("base", base_frames), ("patched", patched_frames)):
        for f in frames:
            frame_file = Path(f["file"]).name
            for change in changes:
                if change.get("file", "").endswith(frame_file) or \
                        Path(change["file"]).name == frame_file:
                    target_fn = change["old_function" if version == "base"
                                       else "new_function"]
                    if f["function"] == target_fn:
                        matches.append(dict(version=version, frame=f,
                                            change=change))
    return dict(diff=diff, changes=changes, matches=matches,
                relation="supported" if matches and comparisons else "inconclusive",
                reason=("Dynamic application stack frame intersects changed "
                        "function in changed file; paired runs attached")
                       if matches else
                       ("No changed-function/stack match; proximity alone is "
                        "insufficient"),
                causal_proof=False, paired_runs=comparisons,
                files_compared=len(all_rels),
                files_changed=len({c["file"] for c in changes}))
