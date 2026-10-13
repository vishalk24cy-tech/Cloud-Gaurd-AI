import os
import json
from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)


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

        response = client.models.generate_content(
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