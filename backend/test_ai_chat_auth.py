# Regression tests: /ai/chat must require authentication and must not
# need GEMINI_API_KEY just to import.
import unittest
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import ai_chat
from app.middleware.auth_middleware import verify_token


def _make_app():
    app = FastAPI()
    app.include_router(ai_chat.router, prefix="/ai")
    return app


class AIChatAuthTest(unittest.TestCase):
    def test_unauthenticated_request_is_rejected(self):
        client = TestClient(_make_app())
        with patch.object(ai_chat, "_get_client") as get_client:
            resp = client.post("/ai/chat", json={"question": "hi"})
        self.assertIn(resp.status_code, (401, 403))
        get_client.assert_not_called()  # no Gemini call without auth

    def test_authenticated_request_reaches_gemini(self):
        app = _make_app()
        app.dependency_overrides[verify_token] = lambda: {"_id": "u1"}
        fake = MagicMock()
        fake.models.generate_content.return_value.text = "mock answer"
        with patch.object(ai_chat, "_get_client", return_value=fake):
            resp = TestClient(app).post("/ai/chat", json={"question": "hi"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["answer"], "mock answer")


if __name__ == "__main__":
    unittest.main()
