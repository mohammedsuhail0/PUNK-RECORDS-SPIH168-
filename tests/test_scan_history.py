import os
import unittest

from scan_history import (
    HISTORY_FILE,
    add_scan_record,
    clear_scan_history,
    get_scan_history,
    update_action_taken,
)


class ScanHistoryTests(unittest.TestCase):
    def setUp(self):
        clear_scan_history()

    def tearDown(self):
        clear_scan_history()

    def test_add_and_get_scan_record(self):
        rec1 = add_scan_record(
            target_type="url",
            target="http://198.51.100.7/verify",
            score=85,
            verdict="dangerous",
            findings_summary="Raw IP host and credential language.",
            action_taken="quarantined",
        )
        history = get_scan_history(limit=5)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["id"], rec1["id"])
        self.assertEqual(history[0]["score"], 85)
        self.assertEqual(history[0]["verdict"], "dangerous")

    def test_history_order_and_limit(self):
        add_scan_record("url", "http://example1.com", 0, "low_risk", "Safe")
        add_scan_record("url", "http://example2.com", 40, "suspicious", "Shortener")
        add_scan_record("url", "http://example3.com", 90, "dangerous", "Phishing")

        history = get_scan_history(limit=2)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["target"], "http://example3.com")
        self.assertEqual(history[1]["target"], "http://example2.com")

    def test_update_action_taken(self):
        rec = add_scan_record("email", "Test subject", 70, "dangerous", "Double extension")
        updated = update_action_taken(rec["id"], "moved_to_safe_review")
        self.assertTrue(updated)

        history = get_scan_history(limit=1)
        self.assertEqual(history[0]["action_taken"], "moved_to_safe_review")


if __name__ == "__main__":
    unittest.main()
