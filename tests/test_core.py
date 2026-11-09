import tempfile
from pathlib import Path
import sys
import unittest

from patchlab.evidence import minimize
from patchlab.runner import classify, execute, same_error
from patchlab.validate import decide


class CoreTests(unittest.TestCase):
    def test_nonzero_is_not_a_security_bug(self):
        r = execute([sys.executable, "-c", "raise SystemExit(2)"], Path.cwd())
        self.assertEqual(r["exit_code"], 2)
        self.assertFalse(r["abnormal"])
        self.assertIsNone(r["signature"])

    def test_timeout_is_not_vulnerability(self):
        r = execute([sys.executable, "-c", "import time; time.sleep(5)"], Path.cwd(), timeout=.1)
        self.assertTrue(r["timed_out"])
        self.assertIsNone(r["error_type"])

    def test_stdin_binary_including_nul(self):
        data = b"a\x00b\xff"
        r = execute([sys.executable, "-c", "import sys; print(len(sys.stdin.buffer.read()))"], Path.cwd(), input_bytes=data)
        self.assertEqual(r["stdout"], "4\n")

    def test_signature_ignores_addresses_lines_and_version_filename(self):
        a = classify("ERROR: AddressSanitizer: stack-buffer-overflow\n #1 0x123 in main /tmp/base.c:7:5")
        b = classify("ERROR: AddressSanitizer: stack-buffer-overflow\n #1 0x456 in main /tmp/fixed.c:8:5")
        self.assertTrue(same_error(a["signature"], b["signature"]))
        c = classify("ERROR: AddressSanitizer: heap-buffer-overflow\n #1 0x456 in main /tmp/fixed.c:8:5")
        self.assertFalse(same_error(a["signature"], c["signature"]))

    def test_minimization_removes_irrelevant_middle(self):
        # Tests actual ddmin capability beyond deleting a repeated suffix.
        predicate = lambda b: b"X" in b and b"Z" in b
        small, info = minimize(b"aaaXbbbbZccc", predicate)
        self.assertTrue(predicate(small))
        self.assertTrue(info["one_minimal"])
        self.assertEqual(len(small), 2)
        for i in range(len(small)):
            self.assertFalse(predicate(small[:i] + small[i+1:]))

    def test_exit_precedence(self):
        self.assertEqual(decide(dict(build_or_config_error=True, inconclusive=True,
                                     functional_regression=True, security_issue=True)), 30)
        self.assertEqual(decide(dict(inconclusive=True, functional_regression=True, security_issue=True)), 40)
        self.assertEqual(decide(dict(functional_regression=True, security_issue=True)), 20)
        self.assertEqual(decide(dict(security_issue=True)), 10)
        self.assertEqual(decide({}), 0)


if __name__ == "__main__":
    unittest.main()
