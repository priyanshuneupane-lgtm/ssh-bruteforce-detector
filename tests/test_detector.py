import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detector import analyze, max_in_window
from datetime import datetime, timedelta

LOG = os.path.join(os.path.dirname(__file__), "..", "sample_logs", "auth.log")

class DetectorTests(unittest.TestCase):
    def setUp(self):
        with open(LOG) as fh:
            self.findings = analyze(fh, year=2026)

    def test_flags_only_attackers(self):
        self.assertEqual({f["ip"] for f in self.findings}, {"203.0.113.45", "198.51.100.7"})

    def test_critical_when_login_succeeds(self):
        top = self.findings[0]
        self.assertEqual((top["ip"], top["severity"]), ("198.51.100.7", "CRITICAL"))

    def test_window_logic(self):
        base = datetime(2026, 1, 1)
        times = [base + timedelta(minutes=m) for m in (0, 1, 2, 30)]
        self.assertEqual(max_in_window(times, timedelta(minutes=5)), 3)

if __name__ == "__main__":
    unittest.main()
