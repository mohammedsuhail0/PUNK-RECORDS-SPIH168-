import unittest

from security_scan import scan_email


class SecurityScanTests(unittest.TestCase):
    def test_known_safe_control_is_low_risk(self):
        result = scan_email(
            "Google Calendar <calendar-notification@google.com>",
            "Weekly calendar summary",
            "Your weekly summary is ready at https://calendar.google.com/calendar/.",
        )
        self.assertEqual(result["verdict"], "low_risk")
        self.assertEqual(result["score"], 0)

    def test_phishing_message_is_dangerous(self):
        result = scan_email(
            "PayPal Security <alerts@paypal-verify-example.com>",
            "URGENT: account suspended",
            "Verify your password and OTP immediately at http://198.51.100.7/verify?redirect=https://example.com",
        )
        self.assertEqual(result["verdict"], "dangerous")
        self.assertGreaterEqual(result["score"], 60)
        self.assertTrue(any(item["code"] == "sender.brand_domain_mismatch" for item in result["findings"]))
        self.assertTrue(any(item["code"] == "url.raw_ip_host" for item in result["findings"]))

    def test_disguised_executable_is_dangerous(self):
        result = scan_email(
            "Billing <billing@example.com>",
            "Invoice attached",
            "Please see the invoice.",
            attachments=[{"filename": "invoice.pdf.exe", "mime_type": "application/x-msdownload"}],
        )
        self.assertEqual(result["verdict"], "dangerous")
        self.assertTrue(any(item["code"] == "attachment.double_extension" for item in result["findings"]))

    def test_urgent_but_non_credential_email_is_suspicious_not_dangerous(self):
        result = scan_email(
            "College Office <office@college.edu>",
            "Urgent deadline reminder",
            "Please submit the form within 24 hours.",
        )
        self.assertEqual(result["verdict"], "low_risk")
        self.assertEqual(result["score"], 8)


if __name__ == "__main__":
    unittest.main()
