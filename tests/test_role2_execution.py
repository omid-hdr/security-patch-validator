import tempfile
import unittest
from pathlib import Path

from patchlab.runner import classify, ErrorSignature, execute, run_to_result
from patchlab.builder import build_single_file

class Role2ExecutionTests(unittest.TestCase):
    def test_classify_ubsan(self):
        # بررسی تشخیص UndefinedBehaviorSanitizer
        stderr = "vuln.c:10:5: runtime error: index out of bounds\nSUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /tmp/test.c:10:5"
        result = classify(stderr)
        self.assertEqual(result["error_type"], "undefined-behavior")
        self.assertEqual(result["detection_mechanism"], "UBSan")
        self.assertTrue(result["abnormal"])

    def test_classify_stack_canary(self):
        # بررسی تشخیص Stack Canary
        stderr = "*** stack smashing detected ***: terminated\n"
        result = classify(stderr)
        self.assertEqual(result["detection_mechanism"], "stack-canary")
        self.assertTrue(result["abnormal"])

    def test_classify_os_signal(self):
        # بررسی تشخیص کرش با سیگنال سیستم‌عامل
        result = classify("Segmentation fault (core dumped)", sig=11)
        self.assertEqual(result["detection_mechanism"], "os-signal")
        self.assertTrue(result["abnormal"])

    def test_error_signature_dataclass_matches(self):
        # بررسی منطق مقایسه همان خطا در کلاس ErrorSignature
        sig1 = ErrorSignature(error_type="stack-buffer-overflow", functions=["main", "foo"])
        sig2 = ErrorSignature(error_type="stack-buffer-overflow", functions=["main", "foo"], file="vuln.c")
        sig3 = ErrorSignature(error_type="heap-use-after-free", functions=["main", "foo"])
        
        self.assertTrue(sig1.matches(sig2))
        self.assertFalse(sig1.matches(sig3))

    def test_builder_single_file(self):
        # بررسی کارکرد ماژول ساخت (builder.py)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "test.c"
            bin_path = td / "test_bin"
            src.write_text("int main() { return 42; }")
            
            cmd_template = ["gcc", "{source}", "-o", "{binary}"]
            result = build_single_file(src, bin_path, cmd_template, td)
            
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(bin_path.exists())
            self.assertIn("binary_sha256", result)

    def test_runner_file_mode_and_empty_input(self):
        # بررسی ارسال ورودی با طول صفر و حالت خواندن از فایل
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            empty_file = td / "empty.txt"
            empty_file.write_bytes(b"")
            
            result = run_to_result(
                argv=["python3", "-c", "import sys, pathlib; print(len(pathlib.Path(sys.argv[1]).read_bytes()))", str(empty_file)],
                cwd=td
            )
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout.strip(), "0")
            self.assertFalse(result.crashed)

if __name__ == "__main__":
    unittest.main()