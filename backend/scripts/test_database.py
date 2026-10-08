import asyncio
from datetime import datetime, timezone

from app.database import close_database, connect_database


async def run_test() -> None:
    database = await connect_database()
    print("[1/3] Connected to MongoDB Atlas")

    test_event = {
        "asset_id": "demo-store",
        "timestamp": datetime.now(timezone.utc),
        "source": "database-test",
        "ip": "192.0.2.10",
        "method": "GET",
        "path": "/health",
        "status": 200,
        "latency_ms": 12.5,
        "user_agent": "logsentinel-db-test",
        "message": "MongoDB round-trip test",
        "raw": "GET /health 200 12.5ms",
    }

    result = await database.events.insert_one(test_event)
    print(f"[2/3] Inserted test event: {result.inserted_id}")

    stored_event = await database.events.find_one({"_id": result.inserted_id})
    if stored_event is None or stored_event["message"] != test_event["message"]:
        raise RuntimeError("Inserted event could not be read back correctly")

    await database.events.delete_one({"_id": result.inserted_id})
    print("[3/3] Read succeeded; test event removed")
    print("Database round-trip test passed.")


async def main() -> None:
    try:
        await run_test()
    finally:
        await close_database()


if __name__ == "__main__":
    asyncio.run(main())

