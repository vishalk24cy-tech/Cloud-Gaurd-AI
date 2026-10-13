# Regression tests for import-time safety (no live services, no secrets).
import importlib
import os
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

BACKEND_DIR = pathlib.Path(__file__).resolve().parent


class GeminiLazyClientTest(unittest.TestCase):
    def test_import_and_call_without_api_key_does_not_crash(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GEMINI_API_KEY", None)
            with patch("google.genai.Client") as mock_client:
                mock_client.side_effect = RuntimeError("Real Gemini client must not be constructed in test")
                import app.ai.gemini as gemini
                gemini = importlib.reload(gemini)  # must not raise
                gemini._client = None
                result = gemini.ask_gemini("test findings")
                mock_client.assert_not_called()
        self.assertEqual(result["summary"], "AI Analysis Failed")
        self.assertIn("GEMINI_API_KEY", result["error"])


class DatabaseGuardTest(unittest.TestCase):
    def test_test_mode_refuses_non_test_database(self):
        env = dict(os.environ)
        env.update(
            APP_ENV="test",
            DATABASE_NAME="cloudguardai",
            MONGODB_URL="mongodb://localhost:27017",
        )
        proc = subprocess.run(
            [sys.executable, "-c", "import app.database.connection"],
            cwd=BACKEND_DIR, env=env, capture_output=True, text=True, timeout=60,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Refusing to connect", proc.stderr)

    def test_no_hardcoded_hosts_or_placeholders_in_connection_module(self):
        source = (BACKEND_DIR / "app" / "database" / "connection.py").read_text()
        self.assertNotIn("mongodb.net", source)
        self.assertNotIn("xxxxx", source)


if __name__ == "__main__":
    unittest.main()
