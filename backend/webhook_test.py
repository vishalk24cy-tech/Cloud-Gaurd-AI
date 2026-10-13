import os
import hmac
import hashlib
import requests
import time
from dotenv import load_dotenv

load_dotenv()

body = '{"event":"cloudguardai.idempotency_test","payload":{}}'

secret = os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip()

if not secret:
    print("ERROR: RAZORPAY_WEBHOOK_SECRET is not configured")
    raise SystemExit(1)

signature = hmac.new(
    secret.encode(),
    body.encode(),
    hashlib.sha256
).hexdigest()

headers = {
    "Content-Type": "application/json",
    "X-Razorpay-Signature": signature,
    "X-Razorpay-Event-Id": "cloudguardai-idempotency-test-001"
}

print("Sending FIRST request...")
r1 = requests.post(
    "http://127.0.0.1:8000/webhooks/razorpay",
    data=body,
    headers=headers
)

print("FIRST:", r1.status_code)
print(r1.text)

time.sleep(1)

print("\nSending SECOND request with SAME event ID...")
r2 = requests.post(
    "http://127.0.0.1:8000/webhooks/razorpay",
    data=body,
    headers=headers
)

print("SECOND:", r2.status_code)
print(r2.text)