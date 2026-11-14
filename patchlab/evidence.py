"""Evidence analysis (Role 3) — package façade.

  * patchlab/minimizer.py   — ddmin + structural PoC-tree minimization
  * patchlab/hardening.py   — readelf-based hardening evidence
  * patchlab/diff_linker.py — single- and multi-file diff correlation
  * patchlab/bundle.py      — single- and multi-file reproducer bundles
"""
from .minimizer import minimize, minimize_poc_tree
from .hardening import hardening
from .diff_linker import correlate, project_correlate
from .bundle import (bundle, project_bundle, dir_sha256,
                     copy_source_tree)

__all__ = [
    "minimize", "minimize_poc_tree",
    "hardening",
    "correlate", "project_correlate",
    "bundle", "project_bundle", "dir_sha256", "copy_source_tree",
]
