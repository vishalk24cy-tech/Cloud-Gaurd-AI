from fastapi import APIRouter, Depends
from pydantic import BaseModel
from google import genai
from dotenv import load_dotenv
import os
from app.middleware.auth_middleware import verify_token

if os.getenv("APP_ENV", "").strip().lower() != "test":
    load_dotenv()

router = APIRouter()

_client = None


def _get_client():
    """
    Create the Gemini client on first use, not at import time, so a
    missing GEMINI_API_KEY cannot crash the whole application.
    """

    global _client

    if _client is None:

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured")

        _client = genai.Client(api_key=api_key)

    return _client


class ChatRequest(BaseModel):
    question: str


@router.post("/chat")
def chat(
    request: ChatRequest,
    current_user=Depends(verify_token),
):
    prompt = f"""
You are CloudGuardAI Enterprise AI Assistant.

You are an expert in:

- AWS Security
- IAM
- S3
- EC2
- VPC
- CloudTrail
- GuardDuty
- AWS Config
- CIS Benchmark
- NIST
- Terraform
- AWS CLI

Answer professionally.

Question:

{request.question}
"""

    try:

        response = _get_client().models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt
        )

        return {
            "answer": response.text
        }

    except Exception as e:

        return {
            "answer": str(e)
        }