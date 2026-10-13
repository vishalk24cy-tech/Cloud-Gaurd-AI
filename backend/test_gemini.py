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

print(ask_gemini(prompt))