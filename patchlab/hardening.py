"""Binary hardening check (Role 3).

Uses readelf (binutils) on the *normal* (non-sanitized) build to report:

  * nx:             GNU_STACK is non-executable (W, not E)
  * pie:            ELF type is DYN (position independent)
  * relro:          "full" (GNU_RELRO + BIND_NOW), "partial" or "none"
  * canary_evidence: __stack_chk_fail appears in the symbol table

Honesty notes (kept in the report): PIE in the ELF header does not prove
the runtime actually uses ASLR, and a __stack_chk_fail symbol does not
prove every function is protected — only that the canary machinery is
linked in.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Union

_READELF_SECTIONS = {
    "header": ["-hW"],
    "segments": ["-lW"],
    "dynamic": ["-dW"],
    "symbols": ["-sW"],
}


def hardening(binary: Union[str, Path]) -> dict:
    """Collect hardening evidence for an ELF binary via readelf."""
    evidence = {}
    for key, args in _READELF_SECTIONS.items():
        p = subprocess.run(["readelf", *args, str(binary)], text=True,
                           capture_output=True, timeout=15, check=True)
        evidence[key] = p.stdout

    # NX: GNU_STACK flags must contain W but not E.
    stack = next((x for x in evidence["segments"].splitlines()
                  if "GNU_STACK" in x), "")
    flags = re.search(r"GNU_STACK\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)", stack)
    nx = ("E" not in flags.group(1)) if flags else None

    # RELRO: GNU_RELRO segment; "full" additionally needs BIND_NOW.
    has_relro = "GNU_RELRO" in evidence["segments"]
    now = ("BIND_NOW" in evidence["dynamic"]
           or bool(re.search(r"FLAGS_1.*\bNOW\b", evidence["dynamic"])))

    # PIE: dynamic ELF type (Type: DYN).
    pie = bool(re.search(r"Type:\s+DYN", evidence["header"]))

    # Canary: the failure handler symbol is linked in.
    canary = "__stack_chk_fail" in evidence["symbols"]

    return dict(
        nx=nx,
        pie=pie,
        relro="full" if has_relro and now else "partial" if has_relro else "none",
        canary_evidence=canary,
        evidence=evidence,
        limitations=[
            "PIE does not prove runtime ASLR",
            "Canary symbol does not prove all functions are protected",
        ],
    )
