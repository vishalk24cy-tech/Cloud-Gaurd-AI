# Manual smoke script for the live Gemini API.
# It is NOT an automated test: run it yourself with
#   python test_gemini.py
# so that pytest never makes a real (billable) API call.
from app.ai.gemini import ask_gemini

prompt = """
Explain why an S3 bucket without encryption is dangerous.

Provide:

1. Explanation
2. Severity
3. Business Impact
4. AWS CLI Fix
5. Terraform Fix
6. Best Practices
"""

if __name__ == "__main__":
    print(ask_gemini(prompt))