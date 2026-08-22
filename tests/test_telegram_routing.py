import os
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from api.telegram_webhook import app, extract_draft_from_message


class TelegramRoutingTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        # Patch module level config variables so the webhook logic receives test values
        self.chat_id_patcher = patch("api.telegram_webhook.TELEGRAM_CHAT_ID", "123456789")
        self.secret_patcher = patch("api.telegram_webhook.WEBHOOK_SECRET_TOKEN", "test_secret_token")
        self.chat_id_patcher.start()
        self.secret_patcher.start()

    def tearDown(self):
        self.chat_id_patcher.stop()
        self.secret_patcher.stop()

    def test_extract_draft_from_message_markdown(self):
        msg = (
            "🔴 *URGENT EMAIL DETECTED*\n\n"
            "📧 *From:* sender@example.com\n"
            "📌 *Subject:* Test\n\n"
            "📝 *Drafted Reply:*\n"
            "```text\n"
            "Thank you for reaching out. I will get back to you soon.\n"
            "```"
        )
        draft = extract_draft_from_message(msg)
        self.assertEqual(draft, "Thank you for reaching out. I will get back to you soon.")

    def test_extract_draft_from_message_fallback(self):
        msg = "Drafted Reply:\nThank you for reaching out."
        draft = extract_draft_from_message(msg)
        self.assertEqual(draft, "Thank you for reaching out.")

    def test_extract_draft_from_message_invalid(self):
        msg = "No draft present in this message."
        draft = extract_draft_from_message(msg)
        self.assertIsNone(draft)

    def test_webhook_unauthorized_secret_token(self):
        response = self.client.post(
            "/api/telegram_webhook",
            json={"message": {"chat": {"id": 123456789}, "message_id": 1, "text": "/start"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "invalid_secret"},
        )
        self.assertEqual(response.status_code, 403)

    def test_webhook_unauthorized_chat_id(self):
        response = self.client.post(
            "/api/telegram_webhook",
            json={"message": {"chat": {"id": 999999999}, "message_id": 1, "text": "/start"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret_token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "unauthorized"})

    @patch("api.telegram_webhook.edit_telegram_message")
    def test_callback_ignore_routing(self, mock_edit):
        payload = {
            "callback_query": {
                "message": {"chat": {"id": 123456789}, "message_id": 42, "text": "Alert text"},
                "data": "ign:thread_001",
            }
        }
        response = self.client.post(
            "/api/telegram_webhook",
            json=payload,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret_token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ignored"})
        mock_edit.assert_called_once()
        self.assertIn("Archived Alert (Ignored)", mock_edit.call_args[0][2])

    @patch("api.telegram_webhook.edit_telegram_message")
    def test_callback_security_acknowledge_routing(self, mock_edit):
        payload = {
            "callback_query": {
                "message": {"chat": {"id": 123456789}, "message_id": 43, "text": "Security Alert text"},
                "data": "secok:thread_002",
            }
        }
        response = self.client.post(
            "/api/telegram_webhook",
            json=payload,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret_token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "security_review_acknowledged"})
        mock_edit.assert_called_once()
        self.assertIn("marked for your review", mock_edit.call_args[0][2])

    @patch("api.telegram_webhook.get_gmail_service")
    @patch("api.telegram_webhook.move_thread_to_safe_review")
    @patch("api.telegram_webhook.edit_telegram_message")
    def test_callback_security_quarantine_routing(self, mock_edit, mock_move, mock_gmail):
        mock_gmail.return_value = MagicMock()
        payload = {
            "callback_query": {
                "message": {"chat": {"id": 123456789}, "message_id": 44, "text": "Phishing Alert text"},
                "data": "secq:thread_003",
            }
        }
        response = self.client.post(
            "/api/telegram_webhook",
            json=payload,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret_token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "security_review_moved"})
        mock_move.assert_called_once_with(mock_gmail.return_value, "thread_003")
        mock_edit.assert_called_once()
        self.assertIn("moved to Safe Review", mock_edit.call_args[0][2])

    @patch("api.telegram_webhook.get_gmail_service")
    @patch("api.telegram_webhook.send_gmail_reply")
    @patch("api.telegram_webhook.edit_telegram_message")
    def test_callback_approve_reply_routing(self, mock_edit, mock_send_reply, mock_gmail):
        mock_gmail.return_value = MagicMock()
        mock_send_reply.return_value = ({}, "recipient@example.com")
        msg_text = (
            "🔴 *URGENT EMAIL DETECTED*\n\n"
            "📝 *Drafted Reply:*\n"
            "```text\n"
            "Approved response text.\n"
            "```"
        )
        payload = {
            "callback_query": {
                "message": {"chat": {"id": 123456789}, "message_id": 45, "text": msg_text},
                "data": "app:thread_004",
            }
        }
        response = self.client.post(
            "/api/telegram_webhook",
            json=payload,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret_token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "sent"})
        mock_send_reply.assert_called_once_with(mock_gmail.return_value, "thread_004", "Approved response text.")
        mock_edit.assert_called_once()
        self.assertIn("Email Sent successfully", mock_edit.call_args[0][2])

    @patch("api.telegram_webhook.send_telegram_reply")
    def test_command_start_routing(self, mock_reply):
        payload = {
            "message": {
                "chat": {"id": 123456789},
                "message_id": 50,
                "text": "/start",
            }
        }
        response = self.client.post(
            "/api/telegram_webhook",
            json=payload,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret_token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "command_processed", "command": "/start"})
        mock_reply.assert_called_once()


if __name__ == "__main__":
    unittest.main()
