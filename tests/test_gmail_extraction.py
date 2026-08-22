import base64
import unittest

from check_emails import (
    clean_email_headers,
    extract_attachment_metadata,
    parse_email_body,
)


class GmailExtractionTests(unittest.TestCase):
    def test_clean_email_headers_standard(self):
        message_detail = {
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Test Security Alert"},
                    {"name": "From", "value": "Security Team <security@example.com>"},
                    {"name": "Reply-To", "value": "reply@example.com"},
                    {"name": "Date", "value": "Sat, 22 Aug 2026 21:00:00 +0530"},
                    {"name": "Message-ID", "value": "<12345@example.com>"},
                    {"name": "X-Custom-Header", "value": "Ignored"},
                ]
            }
        }
        headers = clean_email_headers(message_detail)
        self.assertEqual(headers["Subject"], "Test Security Alert")
        self.assertEqual(headers["From"], "Security Team <security@example.com>")
        self.assertEqual(headers["Reply-To"], "reply@example.com")
        self.assertEqual(headers["Date"], "Sat, 22 Aug 2026 21:00:00 +0530")
        self.assertEqual(headers["Message-ID"], "<12345@example.com>")

    def test_clean_email_headers_missing_and_case_insensitive(self):
        message_detail = {
            "payload": {
                "headers": [
                    {"name": "subject", "value": "Lowercase Subject"},
                    {"name": "from", "value": "user@example.com"},
                ]
            }
        }
        headers = clean_email_headers(message_detail)
        self.assertEqual(headers["Subject"], "Lowercase Subject")
        self.assertEqual(headers["From"], "user@example.com")
        self.assertEqual(headers["Reply-To"], "")
        self.assertEqual(headers["Date"], "")
        self.assertEqual(headers["Message-ID"], "")

    def test_parse_email_body_single_part(self):
        raw_text = "Hello, this is a test email body."
        encoded = base64.urlsafe_b64encode(raw_text.encode("utf-8")).decode("utf-8")
        payload = {
            "mimeType": "text/plain",
            "body": {"data": encoded},
        }
        body = parse_email_body(payload)
        self.assertEqual(body, raw_text)

    def test_parse_email_body_multipart(self):
        plain_text = "Plain text body content."
        html_text = "<html><body>HTML body content</body></html>"
        encoded_plain = base64.urlsafe_b64encode(plain_text.encode("utf-8")).decode("utf-8")
        encoded_html = base64.urlsafe_b64encode(html_text.encode("utf-8")).decode("utf-8")

        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                {"mimeType": "text/plain", "body": {"data": encoded_plain}},
                {"mimeType": "text/html", "body": {"data": encoded_html}},
            ],
        }
        body = parse_email_body(payload)
        self.assertIn("Plain text body content.", body)

    def test_extract_attachment_metadata_multipart(self):
        payload = {
            "mimeType": "multipart/mixed",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": ""},
                },
                {
                    "filename": "invoice.pdf.exe",
                    "mimeType": "application/x-msdownload",
                    "body": {"size": 2048},
                },
                {
                    "mimeType": "multipart/related",
                    "parts": [
                        {
                            "filename": "statement.docm",
                            "mimeType": "application/vnd.ms-word.document.macroEnabled.12",
                            "body": {"size": 4096},
                        }
                    ],
                },
            ],
        }
        attachments = extract_attachment_metadata(payload)
        self.assertEqual(len(attachments), 2)
        filenames = [a["filename"] for a in attachments]
        self.assertIn("invoice.pdf.exe", filenames)
        self.assertIn("statement.docm", filenames)

        # Check metadata attributes
        exe_meta = next(a for a in attachments if a["filename"] == "invoice.pdf.exe")
        self.assertEqual(exe_meta["mime_type"], "application/x-msdownload")
        self.assertEqual(exe_meta["size"], 2048)

    def test_extract_attachment_metadata_empty(self):
        payload = {"mimeType": "text/plain", "body": {"data": ""}}
        attachments = extract_attachment_metadata(payload)
        self.assertEqual(attachments, [])


if __name__ == "__main__":
    unittest.main()
