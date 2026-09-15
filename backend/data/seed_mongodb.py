from __future__ import annotations

from datetime import datetime, timezone

from backend.config import MONGODB_DATABASE
from backend.data.seed import APPLICATIONS, USERS
from backend.db.mongodb import close_mongodb, get_mongo_database, health, init_mongodb


def seed_mongodb() -> None:
    init_mongodb()
    db = get_mongo_database()
    if db is None:
        status = health()
        detail = status.get("detail") or "MongoDB is not initialized"
        print(f"MongoDB seed failed: {status['status']} ({detail})")
        return

    now = datetime.now(timezone.utc)
    organization = {
        "name": "CloudSentinel Demo",
        "slug": "cloudsentinel-demo",
        "status": "ACTIVE",
        "environment": "DEMO",
        "created_at": now,
        "updated_at": now,
    }
    db.organizations.update_one(
        {"slug": organization["slug"]},
        {"$set": organization},
        upsert=True,
    )
    org_doc = db.organizations.find_one({"slug": "cloudsentinel-demo"})
    org_id = str(org_doc["_id"])

    for user in USERS:
        db.users.update_one(
            {"organization_id": org_id, "username": user["username"]},
            {
                "$set": {
                    "organization_id": org_id,
                    "username": user["username"],
                    "email": user["email"],
                    "display_name": user["display_name"],
                    "role": user["role"].upper() if user["role"] != "analyst" else "SECURITY_ANALYST",
                    "status": "ACTIVE",
                    "environment": "DEMO",
                    "updated_at": now,
                },
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )
        user_doc = db.users.find_one({"organization_id": org_id, "username": user["username"]})
        db.devices.update_one(
            {"organization_id": org_id, "device_id": user["device_id"]},
            {
                "$set": {
                    "organization_id": org_id,
                    "user_id": str(user_doc["_id"]),
                    "device_id": user["device_id"],
                    "device_name": f"{user['display_name']}'s Laptop",
                    "hostname": f"{user['username']}-win11",
                    "platform": "Windows",
                    "platform_version": "Windows 11 Enterprise 23H2",
                    "agent_version": "0.1.0",
                    "device_fingerprint": f"demo-{user['username']}-{user['device_id']}",
                    "status": "ONLINE",
                    "posture_status": "HEALTHY",
                    "last_seen": now,
                    "environment": "DEMO",
                    "updated_at": now,
                },
                "$setOnInsert": {"registered_at": now, "created_at": now},
            },
            upsert=True,
        )

    for app in APPLICATIONS:
        db.applications.update_one(
            {"organization_id": org_id, "name": app["name"]},
            {"$set": {**app, "organization_id": org_id, "is_active": True, "environment": "DEMO", "updated_at": now}},
            upsert=True,
        )
    print(f"Seeded MongoDB database '{MONGODB_DATABASE}' with CloudSentinel demo control-plane records.")
    close_mongodb()


if __name__ == "__main__":
    seed_mongodb()
