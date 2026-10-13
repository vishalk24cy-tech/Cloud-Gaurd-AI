from app.database.connection import db

pipeline = [
    {
        "$match": {
            "status": {
                "$in": [
                    "queued",
                    "running",
                    "retrying"
                ]
            }
        }
    },
    {
        "$group": {
            "_id": {
                "organization_id": "$organization_id",
                "account_id": "$account_id"
            },
            "count": {
                "$sum": 1
            },
            "jobs": {
                "$push": "$_id"
            }
        }
    },
    {
        "$match": {
            "count": {
                "$gt": 1
            }
        }
    }
]

duplicates = list(
    db.scan_jobs.aggregate(pipeline)
)

print("ACTIVE DUPLICATES:")
print(duplicates)