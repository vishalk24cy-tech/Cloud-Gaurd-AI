from fastapi import APIRouter
from pydantic import BaseModel
from google import genai
from dotenv import load_dotenv
import os

load_dotenv()

router = APIRouter()

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)


class ChatRequest(BaseModel):
    question: str


@router.post("/chat")
def chat(request: ChatRequest):
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

        response = client.models.generate_content(
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