import unittest
from patchlab.config import ROOT, load_config, data_for
from patchlab.report import STATUS, oracle, decide
from patchlab.git_utils import git
class Role4OrchestrationTests(unittest.TestCase):
    def test_configs(self):
        self.assertEqual(load_config(ROOT/"configs/name-length.json")["build_type"], "single-file")
        self.assertEqual(load_config(ROOT/"configs/editorconfig.json")["build_type"], "cmake")
    def test_decide_and_oracle(self):
        self.assertEqual(decide({"security_issue": True, "functional_regression": True}), 20)
        self.assertEqual(decide({"inconclusive": True, "build_or_config_error": True}), 30)
        self.assertTrue(oracle({"timed_out": False, "abnormal": False, "exit_code": 0, "stdout": "ok"}, {"expected_exit": 0, "expected_stdout_contains": "ok"}))
    def test_git_and_data(self):
        self.assertTrue(git("rev-parse", "HEAD"))
        self.assertEqual(data_for({"input_repeat": ["A", 3]}), b"AAA")
