"""Input minimization (Role 3).

Two strategies:
  * byte-level ddmin (``minimize``) for plain byte inputs (name-length shape);
  * structural minimization for directory-based PoCs (``minimize_poc_tree``),
    used by the editorconfig target: the PoC generator can produce smaller
    size variants of the same crash, so we try them from smallest to largest
    and keep the first that still reproduces the SAME crash signature.

The result must preserve the error signature (same error type + same top-3
function chain) — a smaller input that merely crashes differently is NOT a
valid minimization.
"""
from __future__ import annotations

from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Byte-level ddmin
# ---------------------------------------------------------------------------

def minimize(data: bytes, predicate: Callable[[bytes], bool],
             max_runs: int = 150):
    """Classic delta debugging (ddmin) on raw bytes.

    data:     the original crashing input.
    predicate: returns True iff the candidate still reproduces the SAME
               crash signature (the caller closes over the signature).
    max_runs: hard budget on predicate invocations (each one is a process
              run, so this bounds the total time).

    Strategy: chunk deletion (n = 2, 4, 8, ... ) until no chunk can be
    removed, then a single-byte deletion audit so the result is 1-minimal:
    removing ANY single byte must destroy the crash.

    Returns (minimized_bytes, info_dict).
    """
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

    # Phase 1: coarse chunk deletion.
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
    # Phase 2: single-byte deletion audit -> 1-minimality.
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
# Structural (variant-based) minimization for directory PoCs
# ---------------------------------------------------------------------------

def minimize_poc_tree(make_poc: Callable[..., tuple],
                      predicate: Callable[[object], bool],
                      *, variants: Optional[list] = None,
                      max_runs: int = 20):
    """Minimize a directory-based PoC by trying smaller generator variants.

    Some PoCs (the editorconfig CVE-2026-40489 one) are produced by a
    generator script that can emit several size variants of the same bug:

      * variant "A": the original, larger overflow (~8201 bytes of pattern);
      * variant "B": the smaller off-by-one bypass (exactly 8194 bytes).

    Byte-level ddmin cannot run here because the "input" is a whole
    directory tree (deep path + .editorconfig with a long section name);
    deleting bytes from a path string usually produces a non-existent path.
    Instead we ask the generator for each variant, ordered by the caller
    (conventionally smallest first), and keep the first variant whose
    trigger file still reproduces the SAME crash signature.

    make_poc:  callable invoked as make_poc(variant=v) that creates the
               PoC tree and returns (base_dir, trigger_file, stats_dict).
    predicate: callable(trigger_file) -> True iff the same crash signature
               is still observed on that trigger.
    variants:  variant IDs ordered by the caller. Default ["B", "A"]
               (smallest first — B is the 8194-byte bypass, A is 8201).
    max_runs:  budget on predicate invocations (each is a process run).

    Returns (chosen_variant, chosen_trigger, chosen_stats, attempts) where
    chosen_* are None if no variant reproduced the signature.
    """
    variants = list(variants) if variants else ["B", "A"]
    attempts = []
    chosen = None
    chosen_trigger = None
    chosen_stats = None
    reproduced = False
    runs = 0
    for v in variants:
        if runs >= max_runs:
            break
        base_dir, trigger, stats = make_poc(variant=v)
        runs += 1
        attempts.append(dict(variant=v, stats=stats, trigger=str(trigger)))
        if predicate(trigger):
            chosen = v
            chosen_trigger = trigger
            chosen_stats = stats
            reproduced = True
            break
    info = dict(calls=runs, budget_exhausted=runs >= max_runs,
                one_minimal=reproduced,
                reproduced=reproduced,
                strategy="structural-variant",
                variants_tried=[a["variant"] for a in attempts],
                attempts=attempts)
    if not reproduced:
        # Nothing reproduced the signature: fall back to the FIRST variant
        # (the original PoC) so the caller still has a witness on disk —
        # but mark it clearly as a fallback, NOT as a successful
        # minimization (one_minimal stays False).
        if attempts:
            chosen = attempts[0]["variant"]
            chosen_trigger = Path_like(attempts[0]["trigger"])
            chosen_stats = attempts[0]["stats"]
        info["one_minimal"] = False
        info["reason"] = "no smaller variant reproduced the same signature"
    return chosen, chosen_trigger, chosen_stats, info


def Path_like(value):
    """Best-effort import of pathlib.Path without a hard dependency here."""
    from pathlib import Path
    return Path(value)
