import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.telegram_webhook import app


class FrontendRoutesTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_landing_page_route(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("ShieldSense", response.text)
        self.assertIn("Sign In to Access Console", response.text)

    def test_hub_page_route(self):
        response = self.client.get("/hub")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Universal AI Threat Analyst", response.text)
        self.assertIn("Universal Threat Inspection Console", response.text)

    def test_dashboard_page_route(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Usage Analysis Dashboard", response.text)
        self.assertIn("Recent Scan Activity Audit Log", response.text)

    def test_api_signup_route(self):
        payload = {"fullName": "Test Analyst", "workEmail": "analyst@example.com", "company": "Security Corp"}
        response = self.client.post("/api/signup", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")
        self.assertEqual(response.json()["redirect"], "/hub")

    def test_api_stats_route(self):
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_signals_scanned", data)
        self.assertIn("threat_detection_rate_pct", data)
        self.assertIn("dangerous_count", data)


if __name__ == "__main__":
    unittest.main()
