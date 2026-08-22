import os
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from api.telegram_webhook import app


class AgentFeaturesTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.chat_id_patcher = patch("api.telegram_webhook.TELEGRAM_CHAT_ID", "123456789")
        self.secret_patcher = patch("api.telegram_webhook.WEBHOOK_SECRET_TOKEN", "test_secret_token")
        self.chat_id_patcher.start()
        self.secret_patcher.start()

    def tearDown(self):
        self.chat_id_patcher.stop()
        self.secret_patcher.stop()

    def test_web_dashboard_render(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("ShieldSense", response.text)
        hub_response = self.client.get("/hub")
        self.assertEqual(hub_response.status_code, 200)
        self.assertIn("Analyst Hub Operations Center", hub_response.text)

    def test_api_scan_endpoint(self):
        payload = {
            "text": "Please verify your OTP at http://198.51.100.7/verify",
            "sender": "Bank Alert <alert@fake-bank.com>",
            "subject": "Urgent verification",
        }
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("score", data)
        self.assertIn("verdict", data)
        self.assertGreaterEqual(data["score"], 30)

    def test_api_history_endpoint(self):
        response = self.client.get("/api/history")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)

    @patch("api.telegram_webhook.send_telegram_reply")
    def test_telegram_check_command(self, mock_reply):
        payload = {
            "message": {
                "chat": {"id": 123456789},
                "message_id": 101,
                "text": "/check http://198.51.100.7/login",
            }
        }
        response = self.client.post(
            "/api/telegram_webhook",
            json=payload,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret_token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "command_processed", "command": "/check"})
        mock_reply.assert_called_once()

    @patch("api.telegram_webhook.send_telegram_reply")
    def test_telegram_history_command(self, mock_reply):
        payload = {
            "message": {
                "chat": {"id": 123456789},
                "message_id": 102,
                "text": "/history",
            }
        }
        response = self.client.post(
            "/api/telegram_webhook",
            json=payload,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret_token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "command_processed", "command": "/history"})
        mock_reply.assert_called_once()

    @patch("api.telegram_webhook.send_telegram_reply")
    def test_telegram_conversational_chat(self, mock_reply):
        payload = {
            "message": {
                "chat": {"id": 123456789},
                "message_id": 103,
                "text": "Hello who are you?",
            }
        }
        response = self.client.post(
            "/api/telegram_webhook",
            json=payload,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret_token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "chat_processed"})
        mock_reply.assert_called_once()


if __name__ == "__main__":
    unittest.main()
