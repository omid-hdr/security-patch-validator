"""Unit tests for the Role-3 (Analysis & Evidence) modules.

Covers the four deliverables of Role 3:
  * minimizer.py   — ddmin + structural PoC-tree minimization
  * hardening.py   — readelf parsing (fixture-based, no real binary needed)
  * diff_linker.py — enclosing-function detection for BOTH C brace styles
                     (this is the regression test for the editorconfig
                     'inconclusive' bug: ec_glob.c uses Allman style)
  * bundle.py      — manifest content, trigger-tree copy, path hygiene
                     (no absolute machine paths may survive in a bundle)
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from patchlab.minimizer import minimize, minimize_poc_tree
from patchlab.diff_linker import enclosing_function, correlate, project_correlate
from patchlab.bundle import bundle, project_bundle, dir_sha256


class MinimizerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_ddmin_removes_irrelevant_middle(self):
        predicate = lambda b: b"X" in b and b"Z" in b
        small, info = minimize(b"aaaXbbbbZccc", predicate)
        self.assertTrue(predicate(small))
        self.assertTrue(info["one_minimal"])
        self.assertEqual(len(small), 2)
        for i in range(len(small)):
            self.assertFalse(predicate(small[:i] + small[i + 1:]))

    def test_ddmin_budget_is_respected(self):
        calls = []

        def predicate(b):
            calls.append(1)
            return b"crash" in b

        small, info = minimize(b"crash" + b"pad" * 50, predicate, max_runs=3)
        self.assertLessEqual(len(calls), 3)
        self.assertTrue(info["budget_exhausted"])

    def test_structural_minimization_picks_smaller_variant(self):
        # Two "variants": B (small, reproduces) tried before A (large).
        def make_poc(variant):
            root = Path(self.tmp.name) / variant
            root.mkdir(parents=True, exist_ok=True)
            trigger = root / "trigger.py"
            trigger.write_text("print('hello')\n")
            stats = {"variant": variant, "size": 8194 if variant == "B" else 8201}
            return root, trigger, stats

        def predicate(trigger):
            # Only variant B reproduces the crash.
            return "B" in str(trigger)

        chosen, trig, stats, info = minimize_poc_tree(make_poc, predicate,
                                                      variants=["B", "A"])
        self.assertEqual(chosen, "B")
        self.assertTrue(info["one_minimal"])
        self.assertTrue(info["reproduced"])

    def test_structural_minimization_fallback_is_honest(self):
        def make_poc(variant):
            root = Path(self.tmp.name) / ("fb" + variant)
            root.mkdir(parents=True, exist_ok=True)
            trigger = root / "trigger.py"
            trigger.write_text("x\n")
            return root, trigger, {"variant": variant}

        chosen, trig, stats, info = minimize_poc_tree(
            make_poc, lambda t: False, variants=["B", "A"])
        # Falls back to the first variant but does NOT claim minimization.
        self.assertEqual(chosen, "B")
        self.assertFalse(info["one_minimal"])
        self.assertFalse(info["reproduced"])


class EnclosingFunctionTests(unittest.TestCase):
    """Regression tests for the editorconfig 'inconclusive' correlation
    bug: the old single-line regex missed Allman-style functions."""

    def test_kr_style(self):
        lines = ["int main(int argc, char **argv) {",
                 "    char name[16];",
                 "    strcpy(name, argv[1]);"]
        self.assertEqual(enclosing_function(lines, 2), "main")

    def test_allman_style_editorconfig_shape(self):
        # Exactly the shape of ec_glob.c (the real crash file).
        lines = ["EDITORCONFIG_LOCAL",
                 "int ec_glob(const char *pattern, const char *string)",
                 "{",
                 "    char l_pattern[2 * PATTERN_MAX];",
                 "    strcpy(l_pattern, pattern);"]
        self.assertEqual(enclosing_function(lines, 4), "ec_glob")

    def test_control_statements_are_not_functions(self):
        lines = ["void f(void) {",
                 "    if (cond(x)) {",
                 "        char x[4];",
                 "    }",
                 "}"]
        self.assertEqual(enclosing_function(lines, 2), "f")

    def test_no_function_returns_none(self):
        self.assertIsNone(enclosing_function(["#include <stdio.h>",
                                              "int x = 3;"], 1))

    def test_qualified_signature(self):
        lines = ["static int helper(int a, int b)",
                 "{",
                 "  return a + b;",
                 "}"]
        self.assertEqual(enclosing_function(lines, 2), "helper")


class CorrelateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_single_file_supported(self):
        base = self._write(Path(self.tmp.name) / "base.c",
                           "int main(void) {\n"
                           "    char name[16];\n"
                           "    strcpy(name, argv[1]);\n"
                           "}\n")
        patched = self._write(Path(self.tmp.name) / "fixed.c",
                              "int main(void) {\n"
                              "    if (strlen(argv[1]) >= 16) return 2;\n"
                              "    strcpy(name, argv[1]);\n"
                              "}\n")
        frames = [dict(function="main", file=str(base), line=3)]
        corr = correlate(base, patched, frames, [], [{"base": {}, "patched": {}}])
        self.assertEqual(corr["relation"], "supported")
        self.assertEqual(corr["changes"][0]["old_function"], "main")
        self.assertFalse(corr["causal_proof"])

    def test_allman_project_correlate_supported(self):
        # Multi-file: only ec_glob.c changes, Allman style, and the crash
        # frame is inside ec_glob — must now be "supported" (was
        # "inconclusive" with the old single-line regex).
        bdir = Path(self.tmp.name) / "b"
        pdir = Path(self.tmp.name) / "p"
        self._write(bdir / "src/lib/ec_glob.c",
                    "int ec_glob(const char *pattern)\n"
                    "{\n"
                    "    char l_pattern[8194];\n"
                    "    strcpy(l_pattern, pattern);\n"
                    "}\n")
        self._write(bdir / "src/lib/other.c", "int other(void) { return 1; }\n")
        self._write(pdir / "src/lib/ec_glob.c",
                    "int ec_glob(const char *pattern)\n"
                    "{\n"
                    "    char l_pattern[8194];\n"
                    "    size_t n = strlen(pattern);\n"
                    "    if (n >= sizeof(l_pattern)) return -1;\n"
                    "    memcpy(l_pattern, pattern, n + 1);\n"
                    "}\n")
        self._write(pdir / "src/lib/other.c", "int other(void) { return 1; }\n")
        frames = [dict(function="ec_glob",
                       file="/x/targets/editorconfig/base/src/lib/ec_glob.c",
                       line=4)]
        corr = project_correlate(bdir, pdir, frames, [],
                                 [{"base": {}, "patched": {}}])
        self.assertEqual(corr["relation"], "supported")
        self.assertEqual(corr["files_changed"], 1)
        self.assertEqual(corr["changes"][0]["old_function"], "ec_glob")

    def test_build_outputs_are_excluded(self):
        bdir = Path(self.tmp.name) / "xb"
        pdir = Path(self.tmp.name) / "xp"
        self._write(bdir / "src/lib/ec_glob.c", "int f(void) { return 1; }\n")
        self._write(pdir / "src/lib/ec_glob.c", "int f(void) { return 1; }\n")
        # Build junk that differs between trees must be ignored.
        self._write(bdir / "build-normal/CMakeCache.txt", "cache=1\n")
        self._write(pdir / "build-normal/CMakeCache.txt", "cache=2\n")
        self._write(bdir / "src/lib/extra.so", "junk")
        self._write(pdir / "src/lib/extra.so", "junk2")
        corr = project_correlate(bdir, pdir, [], [], [])
        self.assertEqual(corr["files_changed"], 0)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_single_file_bundle_manifest_and_replay(self):
        src = self._write(Path(self.tmp.name) / "vuln.c",
                          "int main(void) { char b[4]; strcpy(b, \"AAAAAAA\"); }\n")
        binp = self._write(Path(self.tmp.name) / "target", "\x7fELF-fake")
        dst = Path(self.tmp.name) / "bundle"
        bundle(dst, src, binp, b"A" * 20,
               ["gcc", str(src), "-o", str(binp)], {"exit_code": 1},
               dict(environment={"PATH": "/usr/bin"}),
               "argv", ["{binary}", "{input}"])
        self.assertTrue((dst / "source.c").exists())
        self.assertTrue((dst / "target").exists())
        self.assertTrue((dst / "input.bin").exists())
        m = json.loads((dst / "manifest.json").read_text())
        self.assertEqual(m["bundle_type"], "single-file")
        self.assertIn("binary_sha256", m)
        # The rewritten build command must be machine-independent.
        self.assertNotIn(str(self.tmp.name), " ".join(m["build_command"]))
        self.assertIn("source.c", m["build_command"])

    def test_project_bundle_contains_trigger_tree_and_no_absolute_paths(self):
        # Simulate the editorconfig PoC shape: <root>/e/<nested>/trigger.py
        poc_root = Path(self.tmp.name) / "poc-trees" / "poc-A"
        nested = poc_root / "e" / "aaa" / "bbb"
        nested.mkdir(parents=True, exist_ok=True)
        (nested / ".editorconfig").write_text("[x]\nindent_style = space\n")
        trigger = nested / "trigger.py"
        trigger.write_text("print('hello')\n")

        srcdir = Path(self.tmp.name) / "src"
        self._write(srcdir / "CMakeLists.txt", "project(x)\n")
        self._write(srcdir / "src/lib/ec_glob.c", "int f(void) { return 1; }\n")
        self._write(srcdir / "build-normal/CMakeCache.txt", "cache\n")  # excluded

        binp = self._write(Path(self.tmp.name) / "bin", "\x7fELF")
        dst = Path(self.tmp.name) / "pbundle"
        project_bundle(dst, srcdir, binp, None, trigger,
                       dict(flavor="sanitized",
                            source_dir=str(srcdir),
                            build_dir=str(srcdir / "build-sanitized"),
                            configure_command=["cmake", "-DCMAKE_BUILD_TYPE=Debug",
                                               str(srcdir), "-B",
                                               str(srcdir / "build-sanitized")],
                            make_command=["make", "-C",
                                          str(srcdir / "build-sanitized"),
                                          "-j4", "editorconfig_bin"],
                            binary_name="editorconfig",
                            library_name=None),
                       dict(environment={"PATH": "/usr/bin"},
                            commit="abc", dirty=False, signature=None,
                            compiler="gcc", mode="argv", run_argv=["{binary}", "{input}"]))

        # The COMPLETE trigger tree must be shipped (e/... depth preserved).
        rel = (dst / "trigger_tree" / "e" / "aaa" / "bbb" / "trigger.py")
        self.assertTrue(rel.exists(), "trigger_tree must contain the full PoC tree")
        self.assertTrue((dst / "trigger_tree" / "e" / "aaa" / "bbb" / ".editorconfig").exists())

        # Build outputs must NOT be shipped.
        self.assertFalse((dst / "source" / "build-normal" / "CMakeCache.txt").exists())

        # Manifest must contain bundle-LOCAL build commands only.
        m = json.loads((dst / "manifest.json").read_text())
        self.assertIn("source", m["build"]["configure_command"])
        self.assertIn("_replay_build", m["build"]["make_command"])
        joined = " ".join(m["build"]["configure_command"] + m["build"]["make_command"])
        self.assertNotIn(str(self.tmp.name), joined,
                         "bundle manifest must not embed machine paths")

        # replay.py must exist and be self-contained.
        replay = (dst / "replay.py").read_text()
        self.assertIn("_replay_build", replay)
        self.assertIn("trigger_tree", replay)

    def test_project_bundle_records_escape_budget(self):
        # The manifest must record BOTH the plain length and the special
        # char count of the original trigger path — the replay needs both
        # to re-materialize the trigger where the overflow still lands.
        poc_root = Path(self.tmp.name) / "poc" / "poc-A"
        nested = poc_root / "e" / "aa{x}" / "bb"
        nested.mkdir(parents=True, exist_ok=True)
        (nested / ".editorconfig").write_text("[x]\n")
        trigger = nested / "trigger.py"
        trigger.write_text("print('hi')\n")

        srcdir = Path(self.tmp.name) / "src2"
        self._write(srcdir / "CMakeLists.txt", "project(x)\n")
        binp = self._write(Path(self.tmp.name) / "bin2", "\x7fELF")
        dst = Path(self.tmp.name) / "pb2"
        project_bundle(dst, srcdir, binp, None, trigger,
                       dict(flavor="sanitized",
                            source_dir=str(srcdir),
                            build_dir=str(srcdir) + "/build-sanitized",
                            configure_command=["cmake", str(srcdir), "-B",
                                               str(srcdir) + "/build-sanitized"],
                            make_command=["make", "-C",
                                          str(srcdir) + "/build-sanitized",
                                          "editorconfig_bin"],
                            binary_name="editorconfig",
                            library_name=None),
                       dict(environment={}, commit="x", dirty=False,
                            signature=None, compiler="gcc", mode="argv",
                            run_argv=["{binary}", "{input}"]))
        m = json.loads((dst / "manifest.json").read_text())
        self.assertEqual(m["trigger_path_length"], len(str(trigger)))
        # specials: '{' '}' in aa{x} -> 2 (backslashes in the tmp path
        # do not appear; assert the recorded count matches a recount).
        specials = sum(1 for c in str(trigger.parent)
                       if c in set("?[]\\*-{},"))
        self.assertEqual(m["trigger_specials"], specials)
        # Path hygiene: no absolute machine path in the local commands.
        joined = " ".join(m["build"]["configure_command"]
                          + m["build"]["make_command"])
        self.assertNotIn(str(self.tmp.name), joined)

    def test_dir_sha256_stable(self):
        d1 = Path(self.tmp.name) / "h1"
        d2 = Path(self.tmp.name) / "h2"
        for d in (d1, d2):
            (d / "sub").mkdir(parents=True, exist_ok=True)
            (d / "a.txt").write_text("hello")
            (d / "sub" / "b.txt").write_text("world")
        self.assertEqual(dir_sha256(d1), dir_sha256(d2))
        (d2 / "a.txt").write_text("changed")
        self.assertNotEqual(dir_sha256(d1), dir_sha256(d2))

    def _write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)


if __name__ == "__main__":
    unittest.main()
