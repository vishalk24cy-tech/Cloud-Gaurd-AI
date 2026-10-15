# ============================================================
# CloudGuardAI - Production Health & Readiness Endpoint Tests
# Phase 6: Deployment Readiness & Liveness/Readiness Validation
# ============================================================

import os
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_NAME", "cloudguardai_test")

from app.main import app


class TestHealthAndReadinessEndpoints(unittest.TestCase):
    """
    Validates production liveness and readiness endpoints, ensuring
    safe status reporting without disclosing internal credentials or stack traces.
    """

    def setUp(self):
        self.client = TestClient(app)

    def test_liveness_probe_returns_200(self):
        """GET /health must return 200 OK with expected service metadata."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("service"), "cloudguardai-api")
        self.assertEqual(data.get("version"), "1.0.0")
        self.assertIn("timestamp", data)
        # Verify no database connection strings or internals are exposed
        for sensitive_key in ["url", "mongodb", "password", "secret", "credentials"]:
            self.assertNotIn(sensitive_key, str(data).lower())

    @patch("app.main.db.command")
    def test_readiness_probe_success(self, mock_db_command):
        """GET /health/ready must return 200 OK when database is responsive."""
        mock_db_command.return_value = {"ok": 1.0}
        resp = self.client.get("/health/ready")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "ready")
        self.assertEqual(data.get("database"), "connected")

    @patch("app.main.db.command")
    def test_readiness_probe_fails_closed_on_db_outage(self, mock_db_command):
        """GET /health/ready must fail closed with 503 if database ping throws an error."""
        mock_db_command.side_effect = Exception("Connection timed out to mongodb+srv://cluster.internal")
        resp = self.client.get("/health/ready")
        self.assertEqual(resp.status_code, 503)
        data = resp.json()
        self.assertEqual(data.get("status"), "error")
        # Ensure connection details / internal exception details are NOT exposed to caller
        self.assertNotIn("mongodb+srv", resp.text.lower())
        self.assertNotIn("cluster.internal", resp.text.lower())
        self.assertEqual(data.get("message"), "Service dependencies unavailable")

    def test_legacy_home_and_test_db_preserved(self):
        """Legacy / and /test-db endpoints remain functioning for backwards compatibility."""
        resp_home = self.client.get("/")
        self.assertEqual(resp_home.status_code, 200)
        self.assertEqual(resp_home.json().get("status"), "success")


if __name__ == "__main__":
    unittest.main()
