# Pytest bootstrap: make every test run safe by default.
# - APP_ENV=test activates the guard in app/database/connection.py
# - tests always use a separate database, never the production one
#   (override the name with CLOUDGUARD_TEST_DATABASE; it must contain "test")
import os

os.environ["APP_ENV"] = "test"
os.environ["DATABASE_NAME"] = os.environ.get(
    "CLOUDGUARD_TEST_DATABASE", "cloudguardai_test"
)
