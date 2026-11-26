"""Exercise the benchmark release gate with fabricated reports."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

GATE = Path(__file__).resolve().parents[1] / "bench" / "gate.py"


def tool(recall, precision=1.0, time_s=0.1, leaked=0):
    families = {family: {"recall": value} for family, value in recall.items()}
    return {"families": families, "precision": precision, "time_s": time_s, "leaked_values": leaked}


def report(basset, gitleaks=None, trufflehog=None):
    gitleaks = gitleaks or tool({"token": 0.9, "api-key": 1.0})
    trufflehog = trufflehog or tool({"token": 1.0, "api-key": 0.5}, time_s=3.0)
    return {"tools": {"basset": basset, "gitleaks": gitleaks, "trufflehog": trufflehog}}


class GateTests(unittest.TestCase):
    def run_gate(self, data):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(data))
            result = subprocess.run([sys.executable, str(GATE), str(path)], capture_output=True, text=True)
            gate_file = Path(tmp) / "gate.json"
            return result, json.loads(gate_file.read_text()) if gate_file.exists() else None

    def test_pass_records_report(self) -> None:
        result, gate = self.run_gate(report(tool({"token": 1.0, "api-key": 1.0}, time_s=0.2)))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(gate["passed"])
        self.assertEqual(len(gate["report_sha256"]), 64)

    def test_fail_names_family_and_threshold(self) -> None:
        basset = tool({"token": 0.95, "api-key": 1.0}, precision=0.9, time_s=0.3, leaked=1)
        result, gate = self.run_gate(report(basset))
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(gate)
        for expected in ("recall[token]: basset 0.95 < best rival 1.0", "precision:", "time:", "leak: 1"):
            self.assertIn(expected, result.stdout)
        self.assertNotIn("recall[api-key]", result.stdout)

    def test_family_missing_in_basset_fails(self) -> None:
        result, _ = self.run_gate(report(tool({"token": 1.0})))
        self.assertIn("recall[api-key]: basset 0.0", result.stdout)


if __name__ == "__main__":
    unittest.main()
