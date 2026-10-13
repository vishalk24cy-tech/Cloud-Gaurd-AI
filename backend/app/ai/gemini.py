import os
import json
from dotenv import load_dotenv
from google import genai

if os.getenv("APP_ENV", "").strip().lower() != "test":
    load_dotenv()

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


def ask_gemini(findings):
    """
    Sends AWS findings to Gemini AI and returns structured JSON.
    """

    prompt = f"""
You are CloudGuardAI Enterprise AI.

Analyze the following AWS Cloud Security Findings.

Return ONLY valid JSON.

Format:

{{
    "summary": "",
    "risk_score": 0,
    "overall_severity": "",
    "recommendations": [
        {{
            "issue": "",
            "severity": "",
            "explanation": "",
            "business_impact": "",
            "aws_cli_fix": "",
            "terraform_fix": "",
            "best_practice": ""
        }}
    ]
}}

AWS Findings:

{findings}
"""

    try:

        response = _get_client().models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt
        )

        text = response.text.strip()

        # Remove markdown formatting if present
        if text.startswith("```json"):
            text = text.replace("```json", "").replace("```", "").strip()

        elif text.startswith("```"):
            text = text.replace("```", "").strip()

        return json.loads(text)

    except Exception as e:

        return {
            "summary": "AI Analysis Failed",
            "risk_score": 0,
            "overall_severity": "Unknown",
            "recommendations": [],
            "error": str(e)
        }