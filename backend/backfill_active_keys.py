from app.database.connection import db

COLLECTION = db.scan_jobs

ACTIVE_STATUSES = ["queued", "running", "retrying"]

active_jobs = list(
    COLLECTION.find(
        {
            "status": {"$in": ACTIVE_STATUSES}
        }
    )
)

print(f"Found {len(active_jobs)} active scan job(s).")

updated = 0

for job in active_jobs:
    organization_id = str(job.get("organization_id", "")).strip()
    account_id = str(job.get("account_id", "")).strip()

    if not organization_id or not account_id:
        print(f"[SKIP] Missing organization/account: {job.get('_id')}")
        continue

    active_job_key = f"{organization_id}:{account_id}"

    result = COLLECTION.update_one(
        {"_id": job["_id"]},
        {"$set": {"active_job_key": active_job_key}}
    )

    if result.modified_count:
        updated += 1
        print(
            f"[OK] {job['_id']} -> "
            f"{active_job_key}"
        )
    else:
        print(f"[SKIP] Already set: {job['_id']}")

print(f"Updated {updated} active job(s).")